//! Radio-thread capacity admission. Central tokens fence old serving cells.
use super::*;

/// One TDMA multiframe: suppress audible queue indications on fast admission.
const SETUP_QUEUE_GRACE_MS: u64 = 1020;
use std::time::Instant;
use tetra_pdus::cmce::enums::call_status::CallStatus;
use tetra_swmi_protocol::capacity_queue::{CapacityQueue, Entry};
use tetra_swmi_protocol::{CapacityAction, CapacityMessage, CapacityPolicy, CapacityStatus};

pub(super) struct RadioCapacity {
    pub policy: CapacityPolicy,
    clock: Instant,
    pub queue: CapacityQueue,
    contexts: HashMap<u64, SwmiMessage>,
    refresh: HashMap<u64, u64>,
    pub reserved_groups: HashMap<u16, CmceCircuit>,
    suspending: HashMap<u64, (u64, Vec<TxReporter>)>,
    suspend_guard: HashMap<u64, TdmaTime>,
    pub suspended_groups: HashMap<u16, ActiveCall>,
    pub suspended_setups: HashMap<u16, (DSetup, TetraAddress, Option<TxReporter>)>,
    pub resuming: HashSet<u16>,
    pub committing: bool,
    pub limited_groups: HashSet<u16>,
    next_local: u64,
    network_was_connected: bool,
    next_retry: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn offer(cc: &mut CcBsSubentity, q: &mut MessageQueue, token: u64, id: u64, priority: u8, existing: bool) {
        let context = SwmiMessage::GroupCallStart {
            call_id: id,
            owner_itsi: 430892,
            gssi: 204,
            priority,
            floor_itsi: 0,
            talking_party: None,
            acknowledged: false,
            protection: Default::default(),
        }
        .encode()
        .unwrap();
        cc.capacity_handle(
            q,
            CapacityMessage::Offer {
                token,
                call_id: id,
                priority,
                existing,
                timeout_ms: if existing { 0 } else { 15000 },
                context,
            },
        );
    }
    fn control(cc: &mut CcBsSubentity, q: &mut MessageQueue, token: u64, action: CapacityAction) {
        cc.capacity_handle(q, CapacityMessage::Control { token, action });
    }
    fn private_offer(cc: &mut CcBsSubentity, q: &mut MessageQueue) {
        cc.handle_swmi_action(
            q,
            SwmiMessage::PrivateCallWaitingSync {
                call_id: 10,
                caller_itsi: 430892,
                callee_itsi: 430905,
                hook: false,
                duplex: false,
                request_to_transmit: true,
                priority: 1,
                endpoint_mask: 1,
                waiting_required: false,
                invoked: false,
            },
        );
        let context = SwmiMessage::PrivateCallReserve {
            call_id: 10,
            caller_itsi: 430892,
            callee_itsi: 430905,
            endpoint_mask: 1,
            duplex: false,
            initial_floor_itsi: 430892,
        }
        .encode()
        .unwrap();
        cc.capacity_handle(
            q,
            CapacityMessage::Offer {
                token: 10,
                call_id: 10,
                priority: 1,
                existing: false,
                timeout_ms: 15000,
                context,
            },
        );
    }
    #[test]
    fn capacity_private_fast_commit_sends_no_queued_info() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        private_offer(&mut cc, &mut q);
        assert!(!cc.capacity.refresh.contains_key(&10));
        control(&mut cc, &mut q, 10, CapacityAction::Prepare);
        control(&mut cc, &mut q, 10, CapacityAction::Commit);
        cc.capacity.clock = Instant::now() - std::time::Duration::from_millis(SETUP_QUEUE_GRACE_MS + 100);
        cc.capacity_tick(&mut q);
        while let Some(msg) = q.pop_front() {
            if let SapMsgInner::LcmcMleUnitdataReq(p) = msg.msg {
                assert_ne!(p.sdu.peek_bits(5), Some(CmcePduTypeDl::DInfo.into_raw()));
            }
        }
        assert!(cc.private_calls[&10].connected);
        assert!(!cc.capacity.refresh.contains_key(&10));
    }
    #[test]
    fn capacity_duplex_sync_does_not_repage_and_queue_info_reaches_both_endpoints() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        let sync = SwmiMessage::PrivateCallWaitingSync {
            call_id: 10,
            caller_itsi: 430892,
            callee_itsi: 430905,
            hook: true,
            duplex: true,
            request_to_transmit: true,
            priority: 1,
            endpoint_mask: 3,
            waiting_required: false,
            invoked: false,
        };
        cc.handle_swmi_action(&mut q, sync.clone());
        let mut initial_setup = 0;
        while let Some(msg) = q.pop_front() {
            if let SapMsgInner::LcmcMleUnitdataReq(p) = msg.msg {
                if p.sdu.peek_bits(5) == Some(CmcePduTypeDl::DSetup.into_raw()) {
                    initial_setup += 1;
                }
            }
        }
        assert_eq!(initial_setup, 1, "new callee still gets the offer");
        cc.handle_swmi_action(&mut q, sync);
        assert!(q.pop_front().is_none(), "admission sync must not send another D-SETUP");
        let context = SwmiMessage::PrivateCallReserve {
            call_id: 10,
            caller_itsi: 430892,
            callee_itsi: 430905,
            endpoint_mask: 3,
            duplex: true,
            initial_floor_itsi: 430892,
        }
        .encode()
        .unwrap();
        cc.capacity_handle(
            &mut q,
            CapacityMessage::Offer {
                token: 10,
                call_id: 10,
                priority: 1,
                existing: false,
                timeout_ms: 30000,
                context,
            },
        );
        while q.pop_front().is_some() {}
        cc.capacity.clock = Instant::now() - std::time::Duration::from_millis(SETUP_QUEUE_GRACE_MS + 100);
        cc.capacity_notify_wait(&mut q, 10);
        let mut recipients = Vec::new();
        while let Some(msg) = q.pop_front() {
            if let SapMsgInner::LcmcMleUnitdataReq(mut p) = msg.msg {
                let info = DInfo::from_bitbuf(&mut p.sdu).unwrap();
                assert_eq!(info.call_status, Some(1));
                recipients.push(p.main_address.ssi);
            }
        }
        recipients.sort_unstable();
        assert_eq!(recipients, vec![430892, 430905]);
    }
    #[test]
    fn capacity_private_slow_admission_sends_one_info_after_grace() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        private_offer(&mut cc, &mut q);
        assert!(!cc.capacity.refresh.contains_key(&10));
        let mut air = MessageQueue::new();
        cc.capacity.clock = Instant::now() - std::time::Duration::from_millis(SETUP_QUEUE_GRACE_MS + 100);
        cc.capacity_tick(&mut air);
        cc.capacity_tick(&mut air);
        let mut count = 0;
        while let Some(msg) = air.pop_front() {
            if let SapMsgInner::LcmcMleUnitdataReq(mut p) = msg.msg {
                if p.sdu.peek_bits(5) == Some(CmcePduTypeDl::DInfo.into_raw()) {
                    let pdu = DInfo::from_bitbuf(&mut p.sdu).unwrap();
                    assert_eq!(pdu.call_status, Some(1));
                    count += 1;
                }
            }
        }
        assert_eq!(count, 1);
    }
    #[test]
    fn capacity_fast_group_admission_suppresses_queue_refresh() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        offer(&mut cc, &mut q, 1, 1, 1, false);
        assert!(!cc.capacity.refresh.contains_key(&1));
        control(&mut cc, &mut q, 1, CapacityAction::Prepare);
        control(&mut cc, &mut q, 1, CapacityAction::Commit);
        cc.capacity.clock = Instant::now() - std::time::Duration::from_millis(SETUP_QUEUE_GRACE_MS + 1);
        cc.capacity_tick(&mut q);
        assert!(!cc.capacity.refresh.contains_key(&1));
    }
    #[test]
    fn capacity_slow_group_admission_notifies_after_grace_once_then_refreshes() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        for id in 1..=3 {
            offer(&mut cc, &mut q, id, id, 1, false);
            control(&mut cc, &mut q, id, CapacityAction::Prepare);
            control(&mut cc, &mut q, id, CapacityAction::Commit);
        }
        offer(&mut cc, &mut q, 4, 4, 1, false);
        cc.pending_swmi_setups.insert(
            (430892, 204),
            CcBsSubentity::build_sapmsg(
                BitBuffer::new_autoexpand(8),
                None,
                TetraAddress::issi(430892),
                Layer2Service::Acknowledged,
                None,
            ),
        );
        let mut air = MessageQueue::new();
        cc.capacity_notify_wait(&mut air, 4);
        assert!(air.pop_front().is_none());
        assert!(!cc.capacity.refresh.contains_key(&4));
        cc.capacity.clock = Instant::now() - std::time::Duration::from_millis(SETUP_QUEUE_GRACE_MS + 100);
        cc.capacity_tick(&mut q);
        let due = cc.capacity.refresh[&4];
        assert!(due > SETUP_QUEUE_GRACE_MS);
        let mut queued = 0;
        while let Some(msg) = q.pop_front() {
            if let SapMsgInner::LcmcMleUnitdataReq(mut p) = msg.msg {
                assert_ne!(
                    p.sdu.peek_bits(5),
                    Some(CmcePduTypeDl::DInfo.into_raw()),
                    "no duplicate initial queued indication"
                );
                if p.sdu.peek_bits(5) == Some(CmcePduTypeDl::DCallProceeding.into_raw()) {
                    let pdu = DCallProceeding::from_bitbuf(&mut p.sdu).unwrap();
                    assert_eq!(pdu.call_status, Some(CallStatus::Callqueued));
                    queued += 1;
                }
            }
        }
        assert_eq!(queued, 1);
        cc.capacity_tick(&mut q);
        assert_eq!(cc.capacity.refresh[&4], due);
    }
    #[test]
    fn capacity_normal_priority_does_not_preempt_but_emergency_does() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        for id in 1..=3 {
            offer(&mut cc, &mut q, (1 << 63) | id, id, 1, false);
        }
        assert_eq!(cc.active_calls.len(), 3);
        offer(&mut cc, &mut q, 4, 4, 11, false);
        assert!(cc.capacity.suspending.is_empty());
        offer(&mut cc, &mut q, 5, 5, 12, false);
        assert_eq!(cc.capacity.suspending.len(), 1);
        assert!(cc.capacity.suspending.contains_key(&((1 << 63) | 1)));
    }
    #[test]
    fn capacity_local_release_removes_admission_record() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        offer(&mut cc, &mut q, (1 << 63) | 1, 1, 1, false);
        assert!(matches!(cc.active_calls[&1].origin, CallOrigin::Local { .. }));
        cc.release_call(&mut q, 1, DisconnectCause::UserRequestedDisconnection);
        assert!(cc.capacity.queue.entries.is_empty());
        assert!(cc.capacity.contexts.is_empty());
    }

    #[test]
    fn capacity_fourth_call_waits_and_stale_commit_cannot_allocate() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        for id in 1..=3 {
            offer(&mut cc, &mut q, id, id, 1, false);
            control(&mut cc, &mut q, id, CapacityAction::Prepare);
            control(&mut cc, &mut q, id, CapacityAction::Commit);
        }
        assert_eq!(cc.active_calls.len(), 3);
        offer(&mut cc, &mut q, 4, 4, 1, false);
        assert_eq!(cc.capacity.queue.entries[&4].status, CapacityStatus::Queued);
        control(&mut cc, &mut q, 4, CapacityAction::Commit);
        assert!(!cc.active_calls.contains_key(&4));
        cc.release_call(&mut q, 1, DisconnectCause::UserRequestedDisconnection);
        cc.dltime = cc.dltime.add_timeslots(72);
        cc.process_releasing_calls(&mut q);
        cc.capacity_tick(&mut q);
        assert_eq!(cc.capacity.queue.entries[&4].status, CapacityStatus::Ready);
        control(&mut cc, &mut q, 4, CapacityAction::Prepare);
        control(&mut cc, &mut q, 4, CapacityAction::Commit);
        assert!(cc.active_calls.contains_key(&4));
    }
    #[test]
    fn capacity_suspension_waits_for_actual_transmission() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        offer(&mut cc, &mut q, 1, 1, 1, false);
        control(&mut cc, &mut q, 1, CapacityAction::Prepare);
        control(&mut cc, &mut q, 1, CapacityAction::Commit);
        let ts = cc.active_calls[&1].ts;
        control(&mut cc, &mut q, 1, CapacityAction::Suspend);
        cc.capacity_tick(&mut q);
        assert_eq!(cc.circuits.call_id_at(ts, Direction::Both), Some(1));
        for reporter in &cc.capacity.suspending[&1].1 {
            reporter.mark_transmitted();
        }
        cc.capacity_tick(&mut q);
        cc.dltime = cc.dltime.add_timeslots(8);
        cc.capacity_tick(&mut q);
        assert_eq!(cc.circuits.call_id_at(ts, Direction::Both), None);
        assert!(cc.capacity.resuming.contains(&1));
    }
    #[test]
    fn capacity_expired_reservation_frees_slot_without_connecting() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        offer(&mut cc, &mut q, 1, 1, 1, false);
        control(&mut cc, &mut q, 1, CapacityAction::Prepare);
        cc.capacity.queue.entries.get_mut(&1).unwrap().reserved_until = Some(0);
        cc.capacity_tick(&mut q);
        assert!(cc.capacity.reserved_groups.is_empty());
        control(&mut cc, &mut q, 1, CapacityAction::Commit);
        assert!(cc.active_calls.is_empty());
    }
    #[test]
    fn capacity_new_generation_fences_roaming_reply() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        offer(&mut cc, &mut q, 1, 1, 1, true);
        control(&mut cc, &mut q, 1, CapacityAction::Prepare);
        offer(&mut cc, &mut q, 2, 1, 1, true);
        control(&mut cc, &mut q, 1, CapacityAction::Commit);
        assert!(cc.active_calls.is_empty());
        assert!(!cc.capacity.queue.entries.contains_key(&1));
        control(&mut cc, &mut q, 2, CapacityAction::Prepare);
        control(&mut cc, &mut q, 2, CapacityAction::Commit);
        assert!(cc.active_calls.contains_key(&1));
    }
    #[test]
    fn capacity_private_restore_queues_without_channel_then_resumes_same_call() {
        let mut cc = super::super::tests::test_cc_with_group(204);
        let mut q = MessageQueue::new();
        for id in 1..=3 {
            offer(&mut cc, &mut q, id, id, 1, false);
            control(&mut cc, &mut q, id, CapacityAction::Prepare);
            control(&mut cc, &mut q, id, CapacityAction::Commit);
        }
        let context = SwmiMessage::PrivateCallRestore {
            call_id: 4,
            caller_itsi: 430892,
            callee_itsi: 430905,
            hook: false,
            duplex: false,
            request_to_transmit: true,
            priority: 1,
            initial_floor_itsi: 430892,
            endpoint_mask: 1,
        }
        .encode()
        .unwrap();
        cc.capacity_handle(
            &mut q,
            CapacityMessage::Offer {
                token: 4,
                call_id: 4,
                priority: 1,
                existing: true,
                timeout_ms: 60000,
                context,
            },
        );
        let restore = UCallRestore {
            call_identifier: 4,
            request_to_transmit_send_data: true,
            other_party_type_identifier: 1,
            other_party_short_number_address: None,
            other_party_ssi: Some(430905),
            other_party_extension: None,
            basic_service_information: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let mut response = MessageQueue::new();
        assert!(cc.capacity_waiting_restore(&mut response, 430892, &restore));
        let SapMsgInner::LcmcMleUnitdataReq(mut prim) = response.pop_front().unwrap().msg else {
            panic!("restore response")
        };
        assert!(prim.chan_alloc.is_none());
        let restored = DCallRestore::from_bitbuf(&mut prim.sdu).unwrap();
        assert_eq!(restored.call_status, Some(1));
        assert_eq!(restored.transmission_grant, 2);
        cc.release_call(&mut q, 1, DisconnectCause::UserRequestedDisconnection);
        cc.dltime = cc.dltime.add_timeslots(72);
        cc.process_releasing_calls(&mut q);
        cc.capacity_tick(&mut q);
        control(&mut cc, &mut q, 4, CapacityAction::Prepare);
        let mut air = MessageQueue::new();
        control(&mut cc, &mut air, 4, CapacityAction::Commit);
        assert!(cc.private_calls[&4].connected);
        assert!(cc.private_circuits.contains_key(&(4, 430892)));
        let mut grants = 0;
        while let Some(message) = air.pop_front() {
            if let SapMsgInner::LcmcMleUnitdataReq(p) = message.msg {
                let kind = p.sdu.peek_bits(5);
                assert_ne!(kind, Some(CmcePduTypeDl::DConnect.into_raw()));
                if kind == Some(CmcePduTypeDl::DTxGranted.into_raw()) && p.chan_alloc.is_some() {
                    grants += 1;
                }
            }
        }
        assert!(grants > 0, "resumption carries a fresh channel allocation");
    }
}
impl Default for RadioCapacity {
    fn default() -> Self {
        Self {
            policy: CapacityPolicy::default(),
            clock: Instant::now(),
            queue: CapacityQueue::default(),
            contexts: HashMap::new(),
            refresh: HashMap::new(),
            reserved_groups: HashMap::new(),
            suspending: HashMap::new(),
            suspend_guard: HashMap::new(),
            suspended_groups: HashMap::new(),
            suspended_setups: HashMap::new(),
            resuming: HashSet::new(),
            committing: false,
            next_local: 1,
            network_was_connected: false,
            next_retry: 0,
            limited_groups: HashSet::new(),
        }
    }
}
impl CcBsSubentity {
    fn capacity_now(&self) -> u64 {
        self.capacity.clock.elapsed().as_millis() as u64
    }
    fn capacity_report(&self, token: u64, status: CapacityStatus) {
        if token & (1 << 63) == 0 {
            if let Some(swmi) = &self.swmi {
                let _ = swmi.submit(SwmiMessage::Capacity(CapacityMessage::Report { token, status }));
            }
        }
        tracing::info!(token, ?status, "radio capacity transition");
    }
    pub(super) fn capacity_handle(&mut self, queue: &mut MessageQueue, message: CapacityMessage) {
        match message {
            CapacityMessage::Policy(policy) => {
                if policy.validate() {
                    self.capacity.policy = policy;
                }
            }
            CapacityMessage::Offer {
                token,
                call_id,
                priority,
                existing,
                timeout_ms,
                context,
            } => {
                if self.capacity.queue.entries.contains_key(&token) {
                    return;
                }
                let Ok(context) = SwmiMessage::decode(&context) else {
                    return;
                };
                let context_id = match &context {
                    SwmiMessage::GroupCallStart { call_id, .. }
                    | SwmiMessage::PrivateCallReserve { call_id, .. }
                    | SwmiMessage::PrivateCallRestore { call_id, .. } => *call_id,
                    _ => return,
                };
                if context_id != call_id {
                    return;
                }
                // A replacement offer invalidates the old token before it can commit.
                let old: Vec<_> = self
                    .capacity
                    .queue
                    .entries
                    .values()
                    .filter(|e| e.call_id == call_id)
                    .map(|e| e.token)
                    .collect();
                for old in old {
                    self.capacity_forget(queue, old, false);
                }
                let now = self.capacity_now();
                let entry = Entry {
                    token,
                    call_id,
                    priority,
                    existing,
                    entered: now,
                    deadline: (timeout_ms > 0).then_some(now + u64::from(timeout_ms)),
                    reserved_until: None,
                    status: CapacityStatus::Queued,
                };
                match self.capacity.queue.insert(entry, self.capacity.policy) {
                    Err(_) => {
                        self.capacity_report(token, CapacityStatus::Rejected);
                        return;
                    }
                    Ok(Some(victim)) => {
                        self.capacity_forget(queue, victim.token, false);
                        self.capacity_report(victim.token, CapacityStatus::Rejected);
                    }
                    Ok(None) => {}
                }
                self.capacity.contexts.insert(token, context);
                self.capacity_prepare_context(token);
                self.capacity_tick(queue);
                if let Some(entry) = self.capacity.queue.entries.get(&token) {
                    self.capacity_report(token, entry.status);
                }
            }
            CapacityMessage::Control { token, action } => {
                let Some(entry) = self.capacity.queue.entries.get(&token).cloned() else {
                    return;
                };
                match action {
                    CapacityAction::Prepare => {
                        if matches!(entry.status, CapacityStatus::Reserved | CapacityStatus::Active) {
                            self.capacity_report(token, entry.status);
                            return;
                        }
                        if matches!(entry.status, CapacityStatus::Ready) && self.capacity_allocate(queue, token) {
                            let now = self.capacity_now();
                            let e = self.capacity.queue.entries.get_mut(&token).unwrap();
                            e.status = CapacityStatus::Reserved;
                            e.reserved_until = Some(now + u64::from(self.capacity.policy.reservation_ms));
                            self.capacity_report(token, CapacityStatus::Reserved);
                        } else {
                            if let Some(e) = self.capacity.queue.entries.get_mut(&token) {
                                e.status = CapacityStatus::Queued;
                            }
                            self.capacity_report(token, CapacityStatus::Queued);
                        }
                    }
                    CapacityAction::Commit => {
                        if entry.status != CapacityStatus::Reserved || entry.reserved_until.is_some_and(|d| self.capacity_now() >= d) {
                            return;
                        }
                        let Some(mut context) = self.capacity.contexts.get(&token).cloned() else {
                            return;
                        };
                        let e = self.capacity.queue.entries.get_mut(&token).unwrap();
                        e.status = CapacityStatus::Active;
                        e.reserved_until = None;
                        e.deadline = None;
                        self.capacity.committing = true;
                        let id = entry.call_id as u16;
                        let resuming = self.capacity.resuming.contains(&id);
                        if !resuming {
                            if let SwmiMessage::PrivateCallReserve {
                                call_id,
                                caller_itsi,
                                callee_itsi,
                                duplex,
                                initial_floor_itsi,
                                ..
                            } = context
                            {
                                context = SwmiMessage::PrivateCallConnected {
                                    call_id,
                                    caller_itsi,
                                    callee_itsi,
                                    duplex,
                                    initial_floor_itsi,
                                    talking_party: None,
                                };
                            }
                        }
                        if resuming && matches!(context, SwmiMessage::PrivateCallReserve { .. }) {
                            if let Some(c) = self.private_calls.get(&id) {
                                context = SwmiMessage::PrivateCallRestore {
                                    call_id: u64::from(id),
                                    caller_itsi: c.caller_itsi.into(),
                                    callee_itsi: c.callee_itsi.into(),
                                    hook: c.hook,
                                    duplex: c.duplex,
                                    request_to_transmit: c.request_to_transmit,
                                    priority: c.priority,
                                    initial_floor_itsi: c.floor_itsi.into(),
                                    endpoint_mask: c.local_mask,
                                };
                            }
                        }
                        let local_owner = match &context {
                            SwmiMessage::GroupCallStart { owner_itsi, .. } if token & (1 << 63) != 0 => Some(*owner_itsi as u32),
                            _ => None,
                        };
                        self.handle_swmi_action(queue, context);
                        if let Some(owner) = local_owner {
                            if let Some(c) = self.active_calls.get_mut(&id) {
                                c.origin = CallOrigin::Local {
                                    caller_addr: TetraAddress::issi(owner),
                                };
                            }
                        }
                        if resuming {
                            self.capacity_resume_air(queue, id);
                            self.capacity.resuming.remove(&id);
                            self.capacity.suspended_groups.remove(&id);
                            self.capacity.suspended_setups.remove(&id);
                        }
                        self.capacity.committing = false;
                        self.capacity_report(token, CapacityStatus::Active);
                    }
                    CapacityAction::Cancel => {
                        if entry.status == CapacityStatus::Active {
                            return;
                        }
                        self.capacity_release_reserved(queue, entry.call_id as u16);
                        if let Some(e) = self.capacity.queue.entries.get_mut(&token) {
                            e.status = CapacityStatus::Queued;
                            e.reserved_until = None;
                        }
                    }
                    CapacityAction::Suspend => self.capacity_suspend(queue, token),
                    CapacityAction::Forget => self.capacity_forget(queue, token, false),
                }
            }
            CapacityMessage::Report { .. } => {}
            CapacityMessage::EndpointMoved { token, itsi } => {
                if let Some(e) = self.capacity.queue.entries.get(&token) {
                    let id = e.call_id as u16;
                    if let Some(
                        SwmiMessage::PrivateCallReserve {
                            caller_itsi,
                            callee_itsi,
                            endpoint_mask,
                            ..
                        }
                        | SwmiMessage::PrivateCallRestore {
                            caller_itsi,
                            callee_itsi,
                            endpoint_mask,
                            ..
                        },
                    ) = self.capacity.contexts.get_mut(&token)
                    {
                        if *caller_itsi == u64::from(itsi) {
                            *endpoint_mask &= !1;
                        }
                        if *callee_itsi == u64::from(itsi) {
                            *endpoint_mask &= !2;
                        }
                    }
                    self.detach_roamed_private_endpoint(queue, id, itsi);
                    if !self.private_calls.contains_key(&id) {
                        self.capacity_forget(queue, token, false);
                    }
                }
            }
            CapacityMessage::Coverage { token, limited } => {
                if let Some(e) = self.capacity.queue.entries.get(&token) {
                    let id = e.call_id as u16;
                    if limited {
                        self.capacity.limited_groups.insert(id);
                    } else {
                        self.capacity.limited_groups.remove(&id);
                    }
                }
            }
        }
    }
    fn capacity_prepare_context(&mut self, token: u64) {
        let Some(SwmiMessage::PrivateCallRestore {
            call_id,
            caller_itsi,
            callee_itsi,
            hook,
            duplex,
            request_to_transmit,
            priority,
            initial_floor_itsi,
            endpoint_mask,
        }) = self.capacity.contexts.get(&token).cloned()
        else {
            return;
        };
        self.private_calls
            .entry(call_id as u16)
            .and_modify(|c| {
                c.local_mask |= endpoint_mask;
                c.connected = true;
            })
            .or_insert(PrivateCallLocal {
                caller_itsi: caller_itsi as u32,
                callee_itsi: callee_itsi as u32,
                hook,
                duplex,
                request_to_transmit,
                priority,
                external_number: None,
                waiting_required: false,
                waiting_invoked: false,
                floor_itsi: initial_floor_itsi as u32,
                connected: true,
                local_mask: endpoint_mask,
                talking_party: None,
            });
        self.capacity.resuming.insert(call_id as u16);
    }
    fn capacity_slots_needed(&self, token: u64) -> usize {
        match self.capacity.contexts.get(&token) {
            Some(SwmiMessage::GroupCallStart { call_id, gssi, .. }) => {
                if self.active_calls.contains_key(&(*call_id as u16)) {
                    0
                } else if self.has_listener(*gssi) || self.pending_swmi_setups.keys().any(|(_, g)| g == gssi) {
                    1
                } else {
                    usize::MAX
                }
            }
            Some(SwmiMessage::PrivateCallReserve {
                call_id,
                endpoint_mask,
                duplex,
                ..
            })
            | Some(SwmiMessage::PrivateCallRestore {
                call_id,
                endpoint_mask,
                duplex,
                ..
            }) => {
                let mask = self
                    .private_calls
                    .get(&(*call_id as u16))
                    .map(|c| c.local_mask | endpoint_mask)
                    .unwrap_or(*endpoint_mask);
                let existing = self.private_circuits.keys().filter(|(id, _)| *id == *call_id as u16).count();
                if !duplex && mask == 3 {
                    usize::from(existing == 0)
                } else {
                    (mask.count_ones() as usize).saturating_sub(existing)
                }
            }
            _ => usize::MAX,
        }
    }
    fn capacity_allocate(&mut self, queue: &mut MessageQueue, token: u64) -> bool {
        match self.capacity.contexts.get(&token).cloned() {
            Some(SwmiMessage::GroupCallStart { call_id, acknowledged, .. }) => {
                let id = call_id as u16;
                if self.active_calls.contains_key(&id) || self.capacity.reserved_groups.contains_key(&id) {
                    return true;
                }
                let allocated = {
                    let mut s = self.config.state_write();
                    self.circuits
                        .allocate_circuit_with_allocator_and_call_id(
                            Direction::Both,
                            if acknowledged {
                                CommunicationType::P2MpAcked
                            } else {
                                CommunicationType::P2Mp
                            },
                            &mut s.timeslot_alloc,
                            TimeslotOwner::Cmce,
                            id,
                        )
                        .cloned()
                };
                if let Ok(c) = allocated {
                    self.capacity.reserved_groups.insert(id, c);
                    true
                } else {
                    false
                }
            }
            Some(SwmiMessage::PrivateCallReserve {
                call_id,
                caller_itsi,
                callee_itsi,
                endpoint_mask,
                duplex,
                ..
            })
            | Some(SwmiMessage::PrivateCallRestore {
                call_id,
                caller_itsi,
                callee_itsi,
                endpoint_mask,
                duplex,
                ..
            }) => self.allocate_private_call_resources(queue, call_id as u16, caller_itsi, callee_itsi, endpoint_mask, duplex),
            _ => false,
        }
    }
    fn capacity_release_reserved(&mut self, queue: &mut MessageQueue, id: u16) {
        let mut circuits = Vec::new();
        if let Some(c) = self.capacity.reserved_groups.remove(&id) {
            circuits.push(c);
        }
        if !self
            .capacity
            .queue
            .entries
            .values()
            .any(|e| e.call_id == u64::from(id) && e.status == CapacityStatus::Active)
        {
            self.private_circuits.retain(|(call, _), c| {
                if *call == id {
                    circuits.push(c.clone());
                    false
                } else {
                    true
                }
            });
        }
        let mut seen = HashSet::new();
        for c in circuits {
            if seen.insert(c.ts) && self.circuits.call_id_at(c.ts, Direction::Both) == Some(id) {
                let _ = self.circuits.close_circuit(Direction::Both, c.ts);
                Self::signal_umac_circuit_close(queue, c.clone());
                self.release_timeslot(c.ts);
            }
        }
    }
    fn capacity_forget(&mut self, queue: &mut MessageQueue, token: u64, release: bool) {
        if let Some(e) = self.capacity.queue.entries.remove(&token) {
            if e.status != CapacityStatus::Active {
                self.capacity_release_reserved(queue, e.call_id as u16);
            }
            if release {
                self.release_call(queue, e.call_id as u16, DisconnectCause::CongestionInInfrastructure);
            }
        }
        self.capacity.contexts.remove(&token);
        self.capacity.refresh.remove(&token);
        self.capacity.suspending.remove(&token);
        self.capacity.suspend_guard.remove(&token);
    }
    pub(super) fn capacity_tick(&mut self, queue: &mut MessageQueue) {
        let connected = self.config.state_read().network_connected;
        if self.capacity.network_was_connected && !connected {
            let calls: Vec<_> = self
                .capacity
                .queue
                .entries
                .values()
                .filter(|e| e.token & (1 << 63) == 0)
                .map(|e| e.call_id)
                .collect();
            for id in calls {
                let private = self.private_calls.contains_key(&(id as u16));
                self.handle_swmi_action(
                    queue,
                    if private {
                        SwmiMessage::PrivateCallRelease {
                            call_id: id,
                            itsi: 0,
                            cause: 5,
                        }
                    } else {
                        SwmiMessage::CallRelease { call_id: id, cause: 5 }
                    },
                );
            }
        }
        self.capacity.network_was_connected = connected;
        let now = self.capacity_now();
        let retry = now >= self.capacity.next_retry;
        if retry {
            self.capacity.next_retry = now + u64::from(self.capacity.policy.retry_ms);
        }
        for (token, expired) in self.capacity.queue.expire(now) {
            let id = self.capacity.queue.entries[&token].call_id as u16;
            self.capacity_release_reserved(queue, id);
            self.capacity_report(token, if expired { CapacityStatus::Expired } else { CapacityStatus::Queued });
            if expired && token & (1 << 63) != 0 {
                self.handle_swmi_action(
                    queue,
                    SwmiMessage::CallRelease {
                        call_id: u64::from(id),
                        cause: 5,
                    },
                );
            }
        }
        let pending: Vec<_> = self.capacity.suspending.keys().copied().collect();
        for token in pending {
            let (due, reporters) = &self.capacity.suspending[&token];
            if reporters.iter().all(TxReporter::is_transmitted) {
                // Reporter confirms scheduling. Keep the old allocation for two
                // additional TDMA frames so the scheduled burst can reach RF.
                let guard = *self
                    .capacity
                    .suspend_guard
                    .entry(token)
                    .or_insert_with(|| self.dltime.add_timeslots(8));
                if self.dltime.diff(guard) >= 0 {
                    self.capacity_finish_suspend(queue, token);
                }
            } else if now >= *due {
                self.capacity.suspending.remove(&token);
                self.capacity_report(token, CapacityStatus::SuspendFailed);
            }
        }
        let mut free = {
            let state = self.config.state_read();
            (2..=4).filter(|ts| state.timeslot_alloc.is_free(*ts)).count()
        };
        for token in self.capacity.queue.ordered() {
            if self.capacity.queue.entries[&token].deadline.is_some_and(|d| now >= d) {
                continue;
            }
            let need = self.capacity_slots_needed(token);
            let ready = need <= free;
            if ready {
                free -= need;
            }
            let status = if ready { CapacityStatus::Ready } else { CapacityStatus::Queued };
            let entry = self.capacity.queue.entries.get_mut(&token).unwrap();
            let priority = entry.priority;
            if entry.status != status || retry {
                entry.status = status;
                self.capacity_report(token, status);
            }
            if !ready && priority >= 12 {
                let victim = self
                    .capacity
                    .queue
                    .entries
                    .values()
                    .filter(|e| {
                        e.status == CapacityStatus::Active && e.priority < priority && !self.capacity.suspending.contains_key(&e.token)
                    })
                    .min_by_key(|e| {
                        (
                            e.priority,
                            self.active_calls
                                .get(&(e.call_id as u16))
                                .is_none_or(|c| c.hangtime_start.is_none()),
                            e.call_id,
                        )
                    })
                    .map(|e| e.token);
                if let Some(victim) = victim {
                    if victim & (1 << 63) != 0 {
                        self.capacity_suspend(queue, victim);
                    } else {
                        self.capacity_report(victim, CapacityStatus::NeedsPause);
                    }
                }
            }
            if now >= *self.capacity.refresh.get(&token).unwrap_or(&0) {
                self.capacity_notify_wait(queue, token);
            }
        }
        let local_ready: Vec<_> = self
            .capacity
            .queue
            .ordered()
            .into_iter()
            .filter(|t| t & (1 << 63) != 0 && self.capacity.queue.entries[t].status == CapacityStatus::Ready)
            .collect();
        for token in local_ready {
            self.capacity_handle(
                queue,
                CapacityMessage::Control {
                    token,
                    action: CapacityAction::Prepare,
                },
            );
            self.capacity_handle(
                queue,
                CapacityMessage::Control {
                    token,
                    action: CapacityAction::Commit,
                },
            );
        }
    }

    pub(super) fn capacity_local_setup(&mut self, queue: &mut MessageQueue, request: SapMsg, pdu: &USetup, caller: TetraAddress) -> bool {
        if self.capacity.committing {
            return false;
        }
        let Some(gssi) = pdu.called_party_ssi else {
            return false;
        };
        let gssi = gssi as u32;
        if self.active_calls.values().any(|c| c.dest_gssi == gssi) {
            return false;
        }
        if self.pending_swmi_setups.contains_key(&(caller.ssi, gssi)) {
            return true;
        }
        let id = loop {
            let id = self.circuits.get_next_call_id();
            if !self.capacity.queue.entries.values().any(|e| e.call_id == u64::from(id))
                && !self.active_calls.contains_key(&id)
                && !self.private_calls.contains_key(&id)
            {
                break id;
            }
        };
        let token = (1 << 63) | self.capacity.next_local;
        self.capacity.next_local += 1;
        let context = SwmiMessage::GroupCallStart {
            call_id: id.into(),
            owner_itsi: caller.ssi.into(),
            gssi,
            priority: pdu.call_priority,
            floor_itsi: caller.ssi.into(),
            talking_party: None,
            acknowledged: pdu.basic_service_information.communication_type == CommunicationType::P2MpAcked,
            protection: Default::default(),
        }
        .encode()
        .expect("local group context");
        self.pending_swmi_setups.insert((caller.ssi, gssi), request);
        self.capacity_handle(
            queue,
            CapacityMessage::Offer {
                token,
                call_id: id.into(),
                priority: pdu.call_priority,
                existing: false,
                timeout_ms: self.capacity.policy.setup_wait_ms,
                context,
            },
        );
        if !self.capacity.queue.entries.contains_key(&token) {
            if let Some(request) = self.pending_swmi_setups.remove(&(caller.ssi, gssi)) {
                self.send_d_release_for_setup_reject(queue, &request, DisconnectCause::CongestionInInfrastructure);
            }
        }
        if let Some(c) = self.active_calls.get_mut(&id) {
            c.origin = CallOrigin::Local { caller_addr: caller };
        }
        true
    }
    fn capacity_notify_wait(&mut self, queue: &mut MessageQueue, token: u64) {
        let Some(entry) = self.capacity.queue.entries.get(&token) else {
            return;
        };
        if entry.existing
            || matches!(
                entry.status,
                CapacityStatus::Active | CapacityStatus::Expired | CapacityStatus::Rejected
            )
        {
            return;
        }
        let first = !self.capacity.refresh.contains_key(&token);
        if first && self.capacity_now().saturating_sub(entry.entered) < SETUP_QUEUE_GRACE_MS {
            return;
        }
        let id = entry.call_id as u16;
        let setup_timer = match self.capacity.policy.setup_timer_seconds {
            1 => CallTimeoutSetupPhase::T1s,
            2 => CallTimeoutSetupPhase::T2s,
            5 => CallTimeoutSetupPhase::T5s,
            20 => CallTimeoutSetupPhase::T20s,
            30 => CallTimeoutSetupPhase::T30s,
            60 => CallTimeoutSetupPhase::T60s,
            _ => CallTimeoutSetupPhase::T10s,
        };
        let mut addresses = Vec::new();
        if let Some(SwmiMessage::GroupCallStart { gssi, .. }) = self.capacity.contexts.get(&token) {
            addresses.extend(self.pending_swmi_setups.keys().filter(|(_, g)| g == gssi).map(|(i, _)| *i));
            if first {
                for itsi in &addresses {
                    let p = DCallProceeding {
                        call_identifier: id,
                        call_time_out_set_up_phase: setup_timer,
                        hook_method_selection: false,
                        simplex_duplex_selection: false,
                        basic_service_information: None,
                        call_status: Some(CallStatus::Callqueued),
                        notification_indicator: None,
                        facility: None,
                        proprietary: None,
                    };
                    let mut b = BitBuffer::new_autoexpand(64);
                    if p.to_bitbuf(&mut b).is_ok() {
                        b.seek(0);
                        queue.push_back(Self::build_sapmsg(
                            b,
                            None,
                            TetraAddress::issi(*itsi),
                            Layer2Service::Acknowledged,
                            None,
                        ));
                    }
                }
            }
        } else if let Some(c) = self.private_calls.get(&id) {
            for (mask, itsi) in [(1, c.caller_itsi), (2, c.callee_itsi)] {
                if c.local_mask & mask != 0 {
                    addresses.push(itsi);
                }
            }
        }
        // The first group notification is already D-CALL-PROCEEDING.
        // Sending D-INFO(Call queued) as well can trigger a second wait tone.
        if first && matches!(self.capacity.contexts.get(&token), Some(SwmiMessage::GroupCallStart { .. })) {
            let next = self.capacity_now() + u64::from(self.capacity.policy.setup_refresh_ms);
            self.capacity.refresh.insert(token, next);
            return;
        }
        for itsi in addresses {
            let p = DInfo {
                call_identifier: id,
                reset_call_time_out_timer_t310_: false,
                poll_request: false,
                new_call_identifier: None,
                call_time_out: None,
                call_time_out_set_up_phase_t301_t302_: Some(setup_timer.into_raw()),
                call_ownership: None,
                modify: None,
                call_status: Some(1),
                temporary_address: None,
                notification_indicator: None,
                poll_response_percentage: None,
                poll_response_number: None,
                dtmf: None,
                facility: None,
                poll_response_addresses: None,
                proprietary: None,
            };
            let mut b = BitBuffer::new_autoexpand(64);
            if p.to_bitbuf(&mut b).is_ok() {
                b.seek(0);
                queue.push_back(Self::build_sapmsg(
                    b,
                    None,
                    TetraAddress::issi(itsi),
                    Layer2Service::Acknowledged,
                    None,
                ));
            }
        }
        let next = self.capacity_now() + u64::from(self.capacity.policy.setup_refresh_ms);
        self.capacity.refresh.insert(token, next);
    }
    fn capacity_suspend(&mut self, queue: &mut MessageQueue, token: u64) {
        if self.capacity.suspending.contains_key(&token) {
            return;
        }
        let Some(e) = self.capacity.queue.entries.get(&token) else {
            return;
        };
        let id = e.call_id as u16;
        let mut targets = Vec::new();
        if let Some(c) = self.active_calls.get(&id) {
            targets.push((TetraAddress::new(c.dest_gssi, SsiType::Gssi), c.ts));
        }
        if let Some(c) = self.private_calls.get(&id) {
            for itsi in [c.caller_itsi, c.callee_itsi] {
                if let Some(circuit) = self.private_circuits.get(&(id, itsi)) {
                    targets.push((TetraAddress::issi(itsi), circuit.ts));
                }
            }
        }
        let mut reporters = Vec::new();
        for (addr, ts) in targets {
            let p = DTxWait {
                call_identifier: id,
                transmission_request_permission: false,
                notification_indicator: None,
                facility: None,
                dm_ms_address: None,
                proprietary: None,
            };
            let mut b = BitBuffer::new_autoexpand(64);
            if p.to_bitbuf(&mut b).is_err() {
                continue;
            }
            b.seek(0);
            let reporter = TxReporter::new_unacked();
            let mut msg = Self::build_sapmsg(
                b,
                Some(CmceChanAllocReq {
                    usage: None,
                    alloc_type: ChanAllocType::Replace,
                    carrier: None,
                    timeslots: [true, false, false, false],
                    cell_change_flag: false,
                    ul_dl_assigned: UlDlAssignment::Both,
                }),
                addr,
                Layer2Service::Unacknowledged,
                Some(reporter.clone()),
            );
            if let SapMsgInner::LcmcMleUnitdataReq(ref mut p) = msg.msg {
                p.stealing_permission = true;
                p.associated_channel = Some(AssociatedChannel {
                    call_id: id,
                    timeslot: ts,
                    usage: self
                        .active_calls
                        .get(&id)
                        .map(|c| c.usage)
                        .or_else(|| {
                            self.private_circuits
                                .values()
                                .find(|c| c.call_id == id && c.ts == ts)
                                .map(|c| c.usage)
                        })
                        .unwrap_or(0),
                    best_effort_key: None,
                });
            }
            // Pin to the old traffic channel; ordinary routing must not send
            // the pause only on MCCH while the MS is still transmitting.
            let _ = ts;
            queue.push_back(msg);
            reporters.push(reporter);
        }
        let due = self.capacity_now() + u64::from(self.capacity.policy.suspend_send_ms);
        self.capacity.suspending.insert(token, (due, reporters));
    }
    fn capacity_finish_suspend(&mut self, queue: &mut MessageQueue, token: u64) {
        self.capacity.suspending.remove(&token);
        self.capacity.suspend_guard.remove(&token);
        let Some(e) = self.capacity.queue.entries.get_mut(&token) else {
            return;
        };
        let id = e.call_id as u16;
        e.status = CapacityStatus::Suspended;
        e.existing = true;
        if let Some(c) = self.active_calls.remove(&id) {
            self.capacity.suspended_groups.insert(id, c.clone());
            if let Some(s) = self.cached_setups.remove(&id) {
                self.capacity.suspended_setups.insert(id, s);
            }
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Swmi,
                msg: SapMsgInner::CmceCallControl(CallControl::CallEnded { call_id: id, ts: c.ts }),
            });
            if let Ok(circuit) = self.circuits.close_circuit(Direction::Both, c.ts) {
                Self::signal_umac_circuit_close(queue, circuit);
                self.release_timeslot(c.ts);
            }
        }
        let timeslots: HashSet<_> = self
            .private_circuits
            .iter()
            .filter(|((call, _), _)| *call == id)
            .map(|(_, c)| c.ts)
            .collect();
        for ts in timeslots {
            self.stop_private_media(queue, id, ts);
        }
        self.capacity_release_reserved(queue, id);
        self.capacity.resuming.insert(id);
        self.capacity_report(token, CapacityStatus::Suspended);
    }

    pub(super) fn capacity_waiting_restore(&mut self, queue: &mut MessageQueue, itsi: u32, pdu: &UCallRestore) -> bool {
        let id = pdu.call_identifier;
        let waiting = self
            .capacity
            .queue
            .entries
            .values()
            .any(|e| e.call_id == u64::from(id) && e.status != CapacityStatus::Active);
        if !waiting {
            return false;
        }
        let allowed=self.private_calls.get(&id).is_some_and(|c|c.caller_itsi==itsi||c.callee_itsi==itsi)||
            self.capacity.contexts.values().any(|c|matches!(c,SwmiMessage::GroupCallStart {call_id,gssi,..} if *call_id==u64::from(id)&&self.subscriber_groups.get(&itsi).is_some_and(|g|g.contains(gssi))));
        if !allowed {
            return false;
        }
        let p = DCallRestore {
            call_identifier: id,
            transmission_grant: TransmissionGrant::RequestQueued.into_raw() as u8,
            transmission_request_permission: false,
            reset_call_time_out_timer_t310_: true,
            new_call_identifier: None,
            call_time_out: None,
            call_status: Some(1),
            modify: None,
            notification_indicator: None,
            facility: None,
            temporary_address: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let mut b = BitBuffer::new_autoexpand(64);
        if p.to_bitbuf(&mut b).is_err() {
            return false;
        }
        b.seek(0);
        queue.push_back(Self::build_sapmsg(
            b,
            None,
            TetraAddress::issi(itsi),
            Layer2Service::Acknowledged,
            None,
        ));
        self.capacity.resuming.insert(id);
        true
    }

    pub(super) fn capacity_resume_air(&self, queue: &mut MessageQueue, id: u16) {
        let mut targets = Vec::new();
        if let Some(c) = self.private_calls.get(&id) {
            for itsi in [c.caller_itsi, c.callee_itsi] {
                if let Some(circuit) = self.private_circuits.get(&(id, itsi)) {
                    targets.push((
                        TetraAddress::issi(itsi),
                        circuit.ts,
                        circuit.usage,
                        if c.duplex || c.floor_itsi == itsi {
                            TransmissionGrant::Granted
                        } else if c.floor_itsi != 0 {
                            TransmissionGrant::GrantedToOtherUser
                        } else {
                            TransmissionGrant::NotGranted
                        },
                        c.floor_itsi,
                    ));
                }
            }
        } else if let Some(c) = self.active_calls.get(&id) {
            targets.push((
                TetraAddress::new(c.dest_gssi, SsiType::Gssi),
                c.ts,
                c.usage,
                if c.tx_active {
                    TransmissionGrant::GrantedToOtherUser
                } else {
                    TransmissionGrant::NotGranted
                },
                c.source_issi,
            ));
            if c.tx_active && self.subscriber_groups.contains_key(&c.source_issi) {
                targets.push((
                    TetraAddress::issi(c.source_issi),
                    c.ts,
                    c.usage,
                    TransmissionGrant::Granted,
                    c.source_issi,
                ));
            }
        }
        for (addr, ts, usage, grant, floor) in targets {
            let resume = tetra_pdus::cmce::pdus::d_tx_continue::DTxContinue {
                call_identifier: id,
                do_continue: false,
                transmission_request_permission: false,
                notification_indicator: None,
                facility: None,
                dm_ms_address: None,
                proprietary: None,
            };
            let mut resume_bits = BitBuffer::new_autoexpand(64);
            if resume.to_bitbuf(&mut resume_bits).is_ok() {
                resume_bits.seek(0);
                queue.push_back(Self::build_sapmsg(resume_bits, None, addr, Layer2Service::Unacknowledged, None));
            }
            let p = DTxGranted {
                call_identifier: id,
                transmission_grant: grant.into_raw() as u8,
                transmission_request_permission: false,
                encryption_control: false,
                reserved: false,
                notification_indicator: None,
                transmitting_party_type_identifier: Some(1),
                transmitting_party_address_ssi: Some(u64::from(floor)),
                transmitting_party_extension: None,
                external_subscriber_number: None,
                facility: None,
                dm_ms_address: None,
                proprietary: None,
            };
            let mut b = BitBuffer::new_autoexpand(100);
            if p.to_bitbuf(&mut b).is_err() {
                continue;
            }
            b.seek(0);
            let mut timeslots = [false; 4];
            timeslots[ts as usize - 1] = true;
            queue.push_back(Self::build_sapmsg(
                b,
                Some(CmceChanAllocReq {
                    usage: Some(usage),
                    alloc_type: ChanAllocType::Replace,
                    carrier: None,
                    timeslots,
                    cell_change_flag: false,
                    ul_dl_assigned: UlDlAssignment::Both,
                }),
                addr,
                Layer2Service::Unacknowledged,
                None,
            ));
        }
    }

    pub(super) fn capacity_observe(&mut self, queue: &mut MessageQueue, message: &SwmiMessage) {
        let release = match message {
            SwmiMessage::CallRelease { call_id, .. } | SwmiMessage::PrivateCallRelease { call_id, itsi: 0, .. } => Some(*call_id),
            _ => None,
        };
        if let Some(id) = release {
            if let Some((_, addr, _)) = self.capacity.suspended_setups.remove(&(id as u16)) {
                let cause = match message {
                    SwmiMessage::CallRelease { cause, .. } => *cause,
                    _ => 5,
                };
                let p = DRelease {
                    call_identifier: id as u16,
                    disconnect_cause: DisconnectCause::try_from(u64::from(cause)).unwrap_or(DisconnectCause::CongestionInInfrastructure),
                    notification_indicator: None,
                    facility: None,
                    proprietary: None,
                };
                let mut b = BitBuffer::new_autoexpand(64);
                if p.to_bitbuf(&mut b).is_ok() {
                    b.seek(0);
                    queue.push_back(Self::build_sapmsg(b, None, addr, Layer2Service::Unacknowledged, None));
                }
            }
            let tokens: Vec<_> = self
                .capacity
                .queue
                .entries
                .values()
                .filter(|e| e.call_id == id)
                .map(|e| e.token)
                .collect();
            for token in tokens {
                if let Some(SwmiMessage::GroupCallStart { gssi, .. }) = self.capacity.contexts.get(&token) {
                    let keys: Vec<_> = self.pending_swmi_setups.keys().filter(|(_, g)| g == gssi).copied().collect();
                    for key in keys {
                        if let Some(request) = self.pending_swmi_setups.remove(&key) {
                            self.send_d_release_for_setup_reject(queue, &request, DisconnectCause::CongestionInInfrastructure);
                        }
                    }
                }
                self.capacity_forget(queue, token, false);
            }
            self.capacity.limited_groups.remove(&(id as u16));
            self.capacity.suspended_groups.remove(&(id as u16));
            self.capacity.suspended_setups.remove(&(id as u16));
            self.capacity.resuming.remove(&(id as u16));
        }
        for (token, context) in &mut self.capacity.contexts {
            match (context, message) {
                (
                    SwmiMessage::GroupCallStart {
                        call_id,
                        floor_itsi,
                        talking_party,
                        ..
                    },
                    SwmiMessage::FloorGranted {
                        call_id: id,
                        itsi,
                        talking_party: profile,
                    },
                ) if call_id == id => {
                    *floor_itsi = *itsi;
                    *talking_party = profile.clone();
                }
                (SwmiMessage::GroupCallStart { call_id, floor_itsi, .. }, SwmiMessage::FloorReleased { call_id: id, .. })
                    if call_id == id =>
                {
                    *floor_itsi = 0;
                }
                (
                    SwmiMessage::GroupCallStart { call_id, priority, .. },
                    SwmiMessage::GroupCallPriorityChanged {
                        call_id: id, priority: p, ..
                    },
                ) if call_id == id => {
                    *priority = *p;
                    if let Some(e) = self.capacity.queue.entries.get_mut(token) {
                        e.priority = *p;
                    }
                }
                (
                    SwmiMessage::PrivateCallReserve {
                        call_id,
                        initial_floor_itsi,
                        ..
                    }
                    | SwmiMessage::PrivateCallRestore {
                        call_id,
                        initial_floor_itsi,
                        ..
                    },
                    SwmiMessage::PrivateFloorReleased { call_id: id, .. },
                ) if call_id == id => {
                    *initial_floor_itsi = 0;
                }
                (
                    SwmiMessage::PrivateCallReserve {
                        call_id,
                        initial_floor_itsi,
                        ..
                    }
                    | SwmiMessage::PrivateCallRestore {
                        call_id,
                        initial_floor_itsi,
                        ..
                    },
                    SwmiMessage::PrivateFloorGranted { call_id: id, itsi, .. },
                ) if call_id == id => {
                    *initial_floor_itsi = *itsi;
                }
                _ => {}
            }
        }
    }
}
