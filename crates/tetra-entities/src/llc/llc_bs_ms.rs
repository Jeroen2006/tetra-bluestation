use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::panic;

use crate::{MessageQueue, TetraEntityTrait};
use tetra_config::bluestation::SharedConfig;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{AieRequest, AieScope, AieSubject, BitBuffer, Layer2Service, Sap, SsiType, TdmaTime, TetraAddress, TxReporter, TxState};
use tetra_saps::lcmc::enums::alloc_type::ChanAllocType;
use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
use tetra_saps::lcmc::fields::chan_alloc_req::CmceChanAllocReq;
use tetra_saps::tla::{TlaTlDataIndBl, TlaTlUnitdataIndBl};
use tetra_saps::tma::TmaUnitdataReq;
use tetra_saps::{SapMsg, SapMsgInner};

use crate::llc::components::fcs;
use tetra_pdus::llc::consts::consts::N252_BL_MAX_TLSDU_RETRANSMITS_ACKED;
use tetra_pdus::llc::consts::timers::T251_SENDER_RETRY_TIMER;
use tetra_pdus::llc::consts::timers::T252_ACK_WAITING_TIMER;
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::llc::pdus::al::{AlAck, AlDataHeader, AlDisconnect, AlReconnect, AlSetup};
use tetra_pdus::llc::pdus::bl_ack::BlAck;
use tetra_pdus::llc::pdus::bl_adata::BlAdata;
use tetra_pdus::llc::pdus::bl_data::BlData;
use tetra_pdus::llc::pdus::bl_udata::BlUdata;
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;

// T.251 is expressed in downlink signalling frames for the channel on which
// the response is expected (TS 100 392-2 Annex A). While an active traffic
// channel owns FN1..17, SACCH has one such frame per 18-frame multiframe.
// Convert the four-frame T.251 value to four actual SACCH opportunities.
const ASSIGNED_CHANNEL_ACK_RETRY_TIMER_MULTIPLIER: u32 = 18;
const ASSIGNED_CHANNEL_ACK_EXTRA_RETRANSMITS: u8 = 2;
// A routed copy may still be queued or fragmented when another concurrent
// copy completes and starts T.251.  Allow enough channel opportunities for a
// maximum-sized basic-link PDU to finish before replacing the whole attempt.
// The estimate below deliberately includes one extra MAC frame for headers,
// a grant, or a mandatory broadcast interruption.
const CONSERVATIVE_SCH_F_PAYLOAD_BITS: usize = 200;
// Keep a common-channel basic-link transaction alive for one complete TETRA
// frame after N.252 is exhausted. An MS can only put its BL-ACK on air a few
// slots after receiving the last fragmented retry.
const COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS: u32 = 4;
// An assigned-channel retry can reach an MS immediately before it returns to
// MCCH. The MS may then send the BL-ACK through MCCH random access. ETSI
// TS 100 392-2 annex B permits T.205 to be as short as five multiframes, so
// retain the outstanding LLC transaction for that minimum random-access
// window instead of classifying the valid ACK as a late duplicate.
const ASSIGNED_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS: u32 = 5 * 18 * 4;
const AL_SEGMENT_PAYLOAD_BITS: usize = 160;
const PACKET_DATA_USAGE: u8 = 48;

/// Struct that maintains state expected acknowledgement data for a transmitted message.
/// Aka, we still expect an ack for this.
pub struct ExpectedInAck {
    /// Timeslot on which the original message was sent
    pub ts: u8,
    /// Address to which the message was sent
    pub addr: TetraAddress,

    /// Expected ack sequence number for the original message
    pub ns: u8,

    pub bl_type: Layer2Service,

    /// Time this message was received from the MLE
    pub t_first: TdmaTime,
    /// Time this message was actually passed down to the Umac. If a previous message on the basic link is already
    /// submitted, the message has to wait until that previous message was sent and acknowledged, or lost.
    pub t_submitted_to_umac: Option<TdmaTime>,
    /// Time the RxReporter signalled the message was fully transmitted. Also set if the Umac discarded the message
    /// This helps attempting to retransmit the message after a brief delay.
    pub t_umac_done: Option<TdmaTime>,
    /// At least one attempt reached the air interface.  Keep this across
    /// retries because their shared reporter is reset to Pending while the MS
    /// may still return a valid, delayed BL-ACK for an earlier copy.
    pub has_transmitted_attempt: bool,
    /// TxReporter struct. Used by Umac to signal Tx time to Llc, so llc can do retransmissions if needed.
    /// Also used by Llc to signal Ack to upper layer (if appliccable)
    pub tx_reporter: TxReporter,
    /// Per-route reporters for the copies which make up the current radio
    /// attempt.  A scanning MS can be listening on only one of several active
    /// group bearers.  Each copy needs its own reporter so one congested route
    /// cannot mark a concurrently transmitted copy as discarded.
    pub attempt_reporters: Vec<TxReporter>,
    /// Physical bearer for each entry in `attempt_reporters`; TS1 denotes the
    /// MCCH and TS2..4 denote associated traffic-channel control.
    attempt_timeslots: Vec<u8>,
    /// Number of route copies whose complete over-air transmission has already
    /// been observed. A later copy completing restarts T.251 for that copy.
    observed_transmitted_copies: usize,

    // Optional retransmission buffer, to allow for automatic retransmission of the PDU if no acknowledgement is received
    pub retransmission_buf: SapMsg,
    /// Number of retransmissions performed so far
    pub retransmit_count: u8,
}

/// Struct that maintains state for an ACK we still need to send back.
pub struct ScheduledOutAck {
    pub addr: TetraAddress,
    pub t_start: TdmaTime,
    /// Received sequence number
    pub nr: u8,
    /// Timeslot on which the original message was received
    pub ts: u8,
    /// Key-free AIE policy of the PDU being acknowledged.  A BL-ACK is not
    /// allowed to downgrade an SC2-protected basic-link PDU to clear.
    pub aie_request: AieRequest,
}

#[derive(Debug, Clone)]
struct AdvancedRxSdu {
    ns: u8,
    segments: BTreeMap<u8, BitBuffer>,
    final_segment: Option<u8>,
}

#[derive(Debug, Clone)]
struct AdvancedTxSdu {
    ns: u8,
    segments: Vec<BitBuffer>,
    routes: Vec<tetra_saps::tma::AssociatedChannel>,
    chan_alloc: Option<CmceChanAllocReq>,
    endpoint_id: u32,
    aie_request: AieRequest,
    reporter: TxReporter,
    attempt_reporter: Option<TxReporter>,
    sent_at: Option<TdmaTime>,
    retransmissions: u8,
    segment_retransmissions: Vec<u8>,
    pending_segments: Option<Vec<usize>>,
}

#[derive(Debug, Clone)]
struct AdvancedLink {
    link_number: u8,
    maximum_sdu: u8,
    slots: u8,
    window_size: u8,
    max_sdu_retransmissions: u8,
    max_segment_retransmissions: u8,
    endpoint_id: u32,
    next_tx_ns: u8,
    next_rx_ns: u8,
    last_rx_ns: Option<u8>,
    receiver_ready: bool,
    rx: Option<AdvancedRxSdu>,
    tx: VecDeque<AdvancedTxSdu>,
}

pub struct Llc {
    config: SharedConfig,
    dltime: TdmaTime,

    /// When we receive a message, and it needs to be acknowledged, we store it here for later
    /// integration into a response message, or we will make a separate BL-ACK for it.
    scheduled_out_acks: VecDeque<ScheduledOutAck>,

    /// Outbound messages, that are either already submitted to the Umac, and wait for ack,
    /// or, messages that can't be sent until previous messages for the same SSI have been
    /// acknowledged, first.
    outbound_messages: VecDeque<ExpectedInAck>,
    outbound_udata_messages: VecDeque<SapMsg>,

    /// Per-link send sequence variable per SSI. Alternates between 0 and 1.
    link_send_seq: HashMap<u32, u8>,
    advanced_links: HashMap<u32, AdvancedLink>,
}

impl Llc {
    pub fn new(config: SharedConfig) -> Self {
        Self {
            dltime: TdmaTime::default(),
            config,
            scheduled_out_acks: VecDeque::new(),
            outbound_messages: VecDeque::new(),
            outbound_udata_messages: VecDeque::new(),
            link_send_seq: HashMap::new(),
            advanced_links: HashMap::new(),
        }
    }

    /// Schedule an ACK to be sent at a later time
    pub fn schedule_outgoing_ack(&mut self, dltime: TdmaTime, addr: TetraAddress, ns: u8, aie_request: AieRequest) {
        self.scheduled_out_acks.push_back(ScheduledOutAck {
            t_start: dltime,
            nr: ns,
            addr,
            ts: dltime.t,
            aie_request,
        });
    }

    /// Resolve the best channel on which the addressed MS is listening now.
    /// A fresh MAC-ACCESS response deliberately stays on MCCH; otherwise an
    /// active call route wins so MM/OTAR is not sent to a channel the MS has
    /// stopped monitoring.  The lookup is repeated for every BL attempt.
    fn delivery_routes(config: &SharedConfig, issi: u32, dltime: TdmaTime) -> Vec<tetra_saps::tma::AssociatedChannel> {
        let mut state = config.state_write();
        // Registration/authentication is a common-channel procedure. A stale
        // call listener can remain in the CC routing table while the MS has
        // already returned to MCCH for location updating, so never inherit a
        // traffic route until D-LOCATION UPDATE ACCEPT is link-acknowledged.
        if state.subscribers.is_registration_pending(issi) || state.subscribers.direct_response_window_active(issi, dltime) {
            return Vec::new();
        }
        state
            .subscriber_delivery_routes
            .get(&issi)
            .into_iter()
            .flat_map(|routes| routes.iter())
            .filter(|route| (2..=4).contains(&route.timeslot))
            .map(|route| tetra_saps::tma::AssociatedChannel {
                call_id: route.call_id,
                timeslot: route.timeslot,
                usage: route.usage,
                best_effort_key: None,
            })
            .collect()
    }

    /// Returns details for outstanding to-be-sent ACK, if any. Returned u8 is the sequence number.
    /// ETSI 22.3.2.3 case d: when a waiting ACK and outgoing TL-DATA exist for the same link, the
    /// LLC shall emit a combined BL-ADATA PDU. The ACK must belong to both the
    /// same SSI/protection context and the channel on which the MS is
    /// listening; an FN18 ACK must never be bundled into MCCH BL-DATA.
    fn get_out_ack_seq_if_any(&mut self, addr: TetraAddress, timeslot: u8, aie_request: AieRequest) -> Option<u8> {
        for i in 0..self.scheduled_out_acks.len() {
            if self.scheduled_out_acks[i].addr.ssi == addr.ssi
                && self.scheduled_out_acks[i].ts == timeslot
                && self.scheduled_out_acks[i].aie_request.same_protection_as(aie_request)
            {
                let n = self.scheduled_out_acks[i].nr;
                self.scheduled_out_acks.remove(i);
                return Some(n);
            }
        }
        None
    }

    /// Returns the next send sequence number V(S) for this link, then toggles it.
    /// Each link independently starts at 0 and alternates 0,1,0,1,...
    fn get_next_send_seq(&mut self, addr: &TetraAddress) -> u8 {
        let vs = self.link_send_seq.entry(addr.ssi).or_insert(0);
        let ns = *vs;
        *vs ^= 1;
        ns
    }

    /// Returns and removes the expected ACK entry for the given SSI, if any
    fn take_expected_ack_for_ssi(&mut self, ssi: u32) -> Option<ExpectedInAck> {
        for i in 0..self.outbound_messages.len() {
            let msg = &self.outbound_messages[i];
            if msg.addr.ssi == ssi && msg.t_submitted_to_umac.is_some() {
                return self.outbound_messages.remove(i);
            }
        }
        None
    }

    /// A clear post-SC2 MAC-DATA is accepted only when it is either the bare
    /// BL-ACK that completes a clear bootstrap downlink, or carries an MM
    /// PDU. The latter is not a general exception: MLE then permits only MM
    /// and MM validates its narrow location-update/OTAR bootstrap allow-list.
    /// The BL-ACK check remains against the exact outstanding clear basic-link
    /// message and its sequence number; it is not a temporary all-clear
    /// window.
    fn clear_transition_ack_expected(&self, addr: TetraAddress, nr: u8) -> bool {
        let state = self.config.state_read();
        if !state.aie.enabled || !state.subscribers.is_registered(addr.ssi) || state.aie_sessions.terminal_allows_clear(addr.ssi) {
            return false;
        }
        self.outbound_messages.iter().any(|expected| {
            expected.addr.ssi == addr.ssi
                && expected.ns == nr
                && expected.t_submitted_to_umac.is_some()
                && (expected.has_transmitted_attempt
                    || expected.t_umac_done.is_some()
                    || expected.tx_reporter.is_transmitted()
                    || expected.attempt_reporters.iter().any(TxReporter::is_transmitted))
                && matches!(
                    &expected.retransmission_buf.msg,
                    SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                        air_interface_encryption: Some(AieRequest::Clear { .. }) | None,
                        ..
                    })
                )
        })
    }

    /// Process incoming ACK per ETSI 22.3.2.3(k).
    /// Matches by SSI and N(R) so that retransmitted BL-DATA entries are matched correctly.
    fn process_incoming_ack(&mut self, addr: TetraAddress, nr: u8, aie_request: AieRequest) {
        // Get the expected ACK entry
        let Some(mut expected_ack) = self.take_expected_ack_for_ssi(addr.ssi) else {
            // A repeated BL-ACK after the first copy completed the transaction
            // is harmless and common when the MS heard a repeated downlink.
            // Keep sequence mismatches against a live transaction at WARN,
            // but do not flood operational logs for this late duplicate.
            tracing::debug!("received late/duplicate ACK for SSI {} N(R) {}", addr.ssi, nr);
            return;
        };

        // UMAC may receive the response in the scheduler turn immediately
        // after it reported the downlink as transmitted, before LLC's normal
        // retry tick has copied that report into `t_umac_done`. Treat that
        // concrete reporter state as transmitted here so a clear bootstrap
        // BL-ACK cannot race the deferred SC2 activation.
        if expected_ack.t_umac_done.is_none()
            && (expected_ack.tx_reporter.is_transmitted() || expected_ack.attempt_reporters.iter().any(TxReporter::is_transmitted))
        {
            expected_ack.has_transmitted_attempt = true;
            if !expected_ack.tx_reporter.is_transmitted() {
                expected_ack.tx_reporter.reset();
                expected_ack.tx_reporter.mark_transmitted();
            }
        }

        // Check it was indeed already transmitted by the Umac
        if expected_ack.t_umac_done.is_none() && !expected_ack.has_transmitted_attempt {
            // This may be an old retransmission of an ack for the before-last basic link message
            // Let's push the ack back into the head of the queue (not tail)..
            tracing::warn!(
                "received ACK for SSI {} N(R) {} that was not yet transmitted by Umac. Ignoring",
                addr.ssi,
                nr
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        let expected_aie_request = match &expected_ack.retransmission_buf.msg {
            SapMsgInner::TmaUnitdataReq(prim) => prim
                .air_interface_encryption
                .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource)),
            _ => unreachable!("basic-link acknowledgement must retain a TMA request"),
        };
        if !expected_aie_request.same_protection_as(aie_request) {
            tracing::warn!(
                issi = addr.ssi,
                nr,
                "rejecting BL-ACK whose AIE status differs from its outstanding basic-link PDU"
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        // Check N(R)
        if expected_ack.ns == nr {
            // Successful ACK: N(R) matches N(S)
            tracing::debug!("received ACK for SSI {} N(R) {}", addr.ssi, expected_ack.ns);
            // A retry may already be queued with the shared reporter reset to
            // Pending (or have been discarded) when an ACK for an earlier,
            // transmitted copy arrives.  Restore the legal reporter transition
            // without requiring that redundant retry to finish first.
            if !expected_ack.tx_reporter.is_transmitted() {
                expected_ack.tx_reporter.reset();
                expected_ack.tx_reporter.mark_transmitted();
            }
            expected_ack.tx_reporter.mark_acknowledged();
            Self::cancel_pending_attempt_copies(&expected_ack);
            return;
        } else {
            // N(R) mismatch — per ETSI 22.3.2.3(k), not a successful ACK. Maybe a retransmission?
            // Let's push it back into the queue head (not the tail) and see if an ack arrives later
            tracing::warn!(
                "received unexpected ACK for SSI {}: N(R)={}, expected N(S)={}. Ignoring",
                addr.ssi,
                nr,
                expected_ack.ns
            );
            self.outbound_messages.push_front(expected_ack);
            return;
        }

        // The expected_ack is confirmed as matched and goes out of scope here
    }

    /// Stop copies which have not reached the air yet.  UMAC treats the
    /// discarded per-route reporter as cancellation and removes the queued
    /// resource or fragment.  Copies already transmitted remain valid parts
    /// of this one basic-link transaction.
    fn cancel_pending_attempt_copies(ack: &ExpectedInAck) {
        for reporter in &ack.attempt_reporters {
            if reporter.get_state() == tetra_core::TxState::Pending {
                reporter.mark_discarded();
            }
        }
    }

    fn rx_tma_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tma_prim");
        match message.msg {
            SapMsgInner::TmaUnitdataInd(_) => {
                self.rx_tma_unitdata_ind(queue, message);
            }
            SapMsgInner::TmaReportInd(_) => {
                self.rx_tma_report_ind(queue, message);
            }
            _ => {
                panic!();
            }
        }
    }

    fn rx_tla_tlunitdata_req_bl(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_tlunitdata_req_bl");
        let SapMsgInner::TlaTlUnitdataReqBl(mut prim) = message.msg else {
            panic!()
        };

        let mut pdu_buf = BitBuffer::new_autoexpand(32);
        let pdu = BlUdata { has_fcs: false };
        pdu.to_bitbuf(&mut pdu_buf);
        let sdu_len = prim.tl_sdu.get_len_remaining();
        pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
        pdu_buf.seek(0);
        tracing::debug!("-> {:?} sdu {}", pdu, pdu_buf.dump_bin());

        let sapmsg = SapMsg {
            sap: Sap::TmaSap,
            src: self.entity(),
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: prim.req_handle,
                pdu: pdu_buf,
                main_address: prim.main_address,
                endpoint_id: prim.endpoint_id,
                stealing_permission: prim.stealing_permission,
                subscriber_class: prim.subscriber_class,
                air_interface_encryption: prim.air_interface_encryption,
                stealing_repeats_flag: None, // fixme
                data_category: prim.data_class_info,
                chan_alloc: prim.chan_alloc,
                associated_channel: prim.associated_channel,
                tx_reporter: prim.tx_reporter.take(),
            }),
        };

        // Put into transmit queue
        self.outbound_udata_messages.push_back(sapmsg);
    }

    /// Schedules a message that was not acked in time for a retransmission
    fn submit_for_acknowledged_transmission(config: &SharedConfig, queue: &mut MessageQueue, ack: &mut ExpectedInAck, dltime: TdmaTime) {
        let preferred_route = match &ack.retransmission_buf.msg {
            SapMsgInner::TmaUnitdataReq(req) => req.associated_channel.clone(),
            _ => None,
        };
        let mut routes = Self::delivery_routes(config, ack.addr.ssi, dltime);
        if let Some(route) = preferred_route.filter(|route| (2..=4).contains(&route.timeslot)) {
            // CMCE may have selected a traffic bearer while registration or a
            // direct-response window deliberately suppresses inferred LLC
            // routing. Keep that explicit SDS route: UMAC validates that the
            // circuit is still active immediately before enqueueing it.
            routes.retain(|candidate| candidate.timeslot != route.timeslot);
            routes.insert(0, route);
        }

        ack.t_submitted_to_umac = Some(dltime);
        ack.t_umac_done = None;
        Self::cancel_pending_attempt_copies(ack);
        ack.attempt_reporters.clear();
        ack.attempt_timeslots.clear();
        ack.observed_transmitted_copies = 0;

        tracing::info!(
            issi = ack.addr.ssi,
            traffic_copies = routes.len(),
            "sending acknowledged downlink on every plausible active bearer"
        );
        for route in routes {
            let mut sapmsg = ack.retransmission_buf.clone();
            let reporter = TxReporter::new();
            let SapMsgInner::TmaUnitdataReq(req) = &mut sapmsg.msg else {
                unreachable!("basic-link retransmission must retain a TMA request")
            };
            req.associated_channel = Some(route);
            req.tx_reporter = Some(reporter.clone());
            ack.attempt_reporters.push(reporter);
            ack.attempt_timeslots.push(route.timeslot);
            ack.ts = route.timeslot;
            tracing::info!(
                issi = ack.addr.ssi,
                timeslot = route.timeslot,
                call_id = route.call_id,
                usage = route.usage,
                "queued concurrent acknowledged downlink copy"
            );
            queue.push_back(sapmsg);
        }

        // Even a non-scanning MS can be on MCCH after missing D-SETUP or
        // returning from a released call.  Queue MCCH in the same attempt;
        // its independent reporter lets a traffic-channel ACK cancel this
        // copy before a deferred EE monitoring occasion transmits it.
        let mut sapmsg = ack.retransmission_buf.clone();
        let reporter = TxReporter::new();
        let SapMsgInner::TmaUnitdataReq(req) = &mut sapmsg.msg else {
            unreachable!("basic-link retransmission must retain a TMA request")
        };
        req.associated_channel = None;
        req.tx_reporter = Some(reporter.clone());
        ack.attempt_reporters.push(reporter);
        ack.attempt_timeslots.push(1);
        if ack.attempt_reporters.len() == 1 {
            ack.ts = 1;
        }
        tracing::info!(issi = ack.addr.ssi, "queued concurrent acknowledged downlink MCCH copy");
        queue.push_back(sapmsg);
    }

    fn has_assigned_channel_context(ack: &ExpectedInAck) -> bool {
        let SapMsgInner::TmaUnitdataReq(ref req) = ack.retransmission_buf.msg else {
            return false;
        };

        ack.ts != 1
            || req.associated_channel.is_some()
            || req
                .chan_alloc
                .as_ref()
                .is_some_and(|alloc| alloc.usage.is_some() || alloc.timeslots[1..].iter().any(|assigned| *assigned))
    }

    fn basic_link_retry_timer(ack: &ExpectedInAck) -> u32 {
        if Self::has_assigned_channel_context(ack) {
            T251_SENDER_RETRY_TIMER * ASSIGNED_CHANNEL_ACK_RETRY_TIMER_MULTIPLIER
        } else {
            T251_SENDER_RETRY_TIMER
        }
    }

    fn estimated_mac_frames(ack: &ExpectedInAck) -> u32 {
        let bits = match &ack.retransmission_buf.msg {
            SapMsgInner::TmaUnitdataReq(req) => req.pdu.get_len(),
            _ => 0,
        };
        ((bits + CONSERVATIVE_SCH_F_PAYLOAD_BITS - 1) / CONSERVATIVE_SCH_F_PAYLOAD_BITS) as u32 + 1
    }

    /// Maximum time from attempt submission for every still-pending route to
    /// get its complete PDU on air. This is separate from T.251: T.251 may
    /// already be running for an earlier concurrent copy.
    fn pending_route_completion_window(config: &SharedConfig, ack: &ExpectedInAck) -> u32 {
        let mac_frames = Self::estimated_mac_frames(ack);
        let ee_period_multiframes = config
            .state_read()
            .subscribers
            .energy_economy(ack.addr.ssi)
            .map(|(mode, _, _)| {
                if mode == 0 {
                    0
                } else {
                    // TETRA defines EG1..EG7. Treat a corrupt persisted value
                    // as the longest valid period instead of allowing an
                    // unchecked shift to panic the scheduler.
                    1_u32 << u32::from(mode.min(7) - 1)
                }
            })
            .unwrap_or(0);

        ack.attempt_reporters
            .iter()
            .zip(&ack.attempt_timeslots)
            .filter(|(reporter, _)| reporter.get_state() == tetra_core::TxState::Pending)
            .map(|(_, timeslot)| {
                if *timeslot == 1 {
                    // An EE-gated MCCH copy first waits for its monitoring
                    // occasion, then uses ordinary consecutive signalling
                    // frames for any MAC fragments.
                    ee_period_multiframes
                        .saturating_mul(18 * 4)
                        .saturating_add(mac_frames.saturating_mul(4))
                } else {
                    // Associated control has one opportunity per 18-frame
                    // multiframe. Include the normal T.251 interval as queue
                    // grace for another PDU already owning this SACCH.
                    Self::basic_link_retry_timer(ack).saturating_add(mac_frames.saturating_mul(18 * 4))
                }
            })
            .max()
            .unwrap_or(0)
    }

    fn max_over_air_retransmits(ack: &ExpectedInAck) -> u8 {
        if Self::has_assigned_channel_context(ack) {
            N252_BL_MAX_TLSDU_RETRANSMITS_ACKED.saturating_add(ASSIGNED_CHANNEL_ACK_EXTRA_RETRANSMITS)
        } else {
            N252_BL_MAX_TLSDU_RETRANSMITS_ACKED
        }
    }

    fn final_ack_grace_elapsed(age: i32, retry_timer: u32, assigned_channel: bool) -> bool {
        let grace = if assigned_channel {
            ASSIGNED_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS
        } else {
            COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS
        };
        age >= 0 && (age as u32) >= retry_timer.saturating_add(grace)
    }

    fn mark_reporter_lost(reporter: &TxReporter) {
        // The last retry can be discarded or still queued after an earlier
        // attempt reached the air.  TxReporter requires Transmitted -> Lost,
        // so normalize the per-attempt state before completing the overall
        // basic-link transaction.
        if !reporter.is_transmitted() {
            reporter.reset();
            reporter.mark_transmitted();
        }
        reporter.mark_lost();
    }

    fn packet_route(timeslot: u8) -> Option<tetra_saps::tma::AssociatedChannel> {
        (2..=4).contains(&timeslot).then_some(tetra_saps::tma::AssociatedChannel {
            call_id: 0,
            timeslot,
            usage: PACKET_DATA_USAGE,
            best_effort_key: None,
        })
    }

    fn queue_advanced_pdu(
        queue: &mut MessageQueue,
        address: TetraAddress,
        endpoint_id: u32,
        pdu: BitBuffer,
        route: Option<tetra_saps::tma::AssociatedChannel>,
        chan_alloc: Option<CmceChanAllocReq>,
        aie_request: AieRequest,
        tx_reporter: Option<TxReporter>,
    ) {
        queue.push_back(SapMsg::new(
            Sap::TmaSap,
            TetraEntity::Llc,
            TetraEntity::Umac,
            SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: 0,
                pdu,
                main_address: address,
                endpoint_id,
                stealing_permission: false,
                subscriber_class: 0,
                air_interface_encryption: Some(aie_request.with_scope(AieScope::MacResource)),
                stealing_repeats_flag: None,
                data_category: None,
                chan_alloc,
                associated_channel: route,
                tx_reporter,
            }),
        ));
    }

    fn advanced_segments(mut tl_sdu: BitBuffer) -> Vec<BitBuffer> {
        let mut protected = BitBuffer::new_autoexpand(tl_sdu.get_len_remaining() + 32);
        let length = tl_sdu.get_len_remaining();
        protected.copy_bits(&mut tl_sdu, length);
        let checksum = fcs::compute_fcs(&protected, 0, protected.get_len_written());
        protected.write_bits(checksum.into(), 32);
        protected.seek(0);

        let mut segments = Vec::new();
        while protected.get_len_remaining() > 0 {
            let length = protected.get_len_remaining().min(AL_SEGMENT_PAYLOAD_BITS);
            let mut segment = BitBuffer::new_autoexpand(length);
            segment.copy_bits(&mut protected, length);
            segment.seek(0);
            segments.push(segment);
        }
        segments
    }

    fn rx_tla_tldata_req_al(&mut self, prim: tetra_saps::tla::TlaTlDataReqBl) -> bool {
        let issi = prim.main_address.ssi;
        let Some(link) = self.advanced_links.get_mut(&issi) else {
            return false;
        };
        if link.link_number != 0 || link.tx.len() >= 64 {
            return false;
        }
        let reporter = prim.tx_reporter.unwrap_or_else(TxReporter::new);
        let segments = Self::advanced_segments(prim.tl_sdu);
        let mut routes = self
            .config
            .state_read()
            .timeslot_alloc
            .packet_slots()
            .into_iter()
            .take(link.slots as usize)
            .filter_map(Self::packet_route)
            .collect::<Vec<_>>();
        if let Some(primary) = prim.associated_channel {
            routes.retain(|route| route.timeslot != primary.timeslot);
            routes.insert(0, primary);
        }
        let ns = link.next_tx_ns;
        link.next_tx_ns = (link.next_tx_ns + 1) & 0x07;
        link.endpoint_id = prim.endpoint_id;
        link.tx.push_back(AdvancedTxSdu {
            ns,
            segment_retransmissions: vec![0; segments.len()],
            segments,
            routes,
            chan_alloc: prim.chan_alloc,
            endpoint_id: prim.endpoint_id,
            aie_request: prim
                .air_interface_encryption
                .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
            reporter,
            attempt_reporter: None,
            sent_at: None,
            retransmissions: 0,
            pending_segments: None,
        });
        true
    }

    fn send_al_ack(
        queue: &mut MessageQueue,
        address: TetraAddress,
        endpoint_id: u32,
        route: Option<tetra_saps::tma::AssociatedChannel>,
        aie_request: AieRequest,
        nr: u8,
        acknowledgement_length: u8,
        first_missing_segment: Option<u8>,
        acknowledgement_bitmap: Vec<bool>,
    ) {
        let mut pdu = BitBuffer::new_autoexpand(32);
        if (AlAck {
            receiver_ready: true,
            nr,
            acknowledgement_length,
            first_missing_segment,
            acknowledgement_bitmap,
        })
        .to_bitbuf(&mut pdu)
        .is_ok()
        {
            pdu.seek(0);
            Self::queue_advanced_pdu(queue, address, endpoint_id, pdu, route, None, aie_request, None);
        }
    }

    fn deliver_advanced_sdu(queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut sdu: BitBuffer) {
        sdu.seek(0);
        queue.push_back(SapMsg::new(
            Sap::TlaSap,
            TetraEntity::Llc,
            TetraEntity::Mle,
            SapMsgInner::TlaTlDataIndBl(TlaTlDataIndBl {
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: Some(sdu),
                scrambling_code: prim.scrambling_code,
                fcs_flag: true,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                req_handle: 0,
            }),
        ));
    }

    fn handle_al_setup(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(request) = AlSetup::from_bitbuf(&mut pdu) else {
            tracing::warn!(issi = prim.main_address.ssi, "invalid AL-SETUP");
            return;
        };
        if request.link_number != 0 || request.asymmetric {
            tracing::warn!(
                issi = prim.main_address.ssi,
                link_number = request.link_number,
                asymmetric = request.asymmetric,
                "unsupported TIP advanced-link profile"
            );
            return;
        }
        let requested_slots = request.uplink_slots.unwrap_or(1);
        let slots = requested_slots.clamp(1, 3);
        let maximum_sdu = request.maximum_sdu.min(6);
        let window_size = request.window_size.clamp(1, 3);
        let changed = slots != requested_slots || maximum_sdu != request.maximum_sdu || window_size != request.window_size;
        let response = AlSetup {
            acknowledged: true,
            link_number: 0,
            maximum_sdu,
            connection_width: slots > 1,
            asymmetric: false,
            uplink_slots: (slots > 1).then_some(slots),
            downlink_slots: None,
            throughput: request.throughput,
            window_size,
            sdu_retransmissions: request.sdu_retransmissions,
            segment_retransmissions: request.segment_retransmissions,
            report: if changed { 2 } else { 0 },
        };
        self.advanced_links.insert(
            prim.main_address.ssi,
            AdvancedLink {
                link_number: 0,
                maximum_sdu,
                slots,
                window_size,
                max_sdu_retransmissions: request.sdu_retransmissions,
                max_segment_retransmissions: request.segment_retransmissions,
                endpoint_id: prim.endpoint_id,
                next_tx_ns: 0,
                next_rx_ns: 0,
                last_rx_ns: None,
                receiver_ready: true,
                rx: None,
                tx: VecDeque::new(),
            },
        );
        let mut response_pdu = BitBuffer::new_autoexpand(32);
        if response.to_bitbuf(&mut response_pdu).is_ok() {
            response_pdu.seek(0);
            let route = Self::packet_route(self.dltime.add_timeslots(-2).t);
            let aie = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacResource,
                )
            });
            Self::queue_advanced_pdu(queue, prim.main_address, prim.endpoint_id, response_pdu, route, None, aie, None);
        }
        tracing::info!(
            issi = prim.main_address.ssi,
            slots,
            window_size,
            maximum_sdu,
            "established original acknowledged advanced link"
        );
    }

    fn handle_al_data(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(header) = AlDataHeader::from_bitbuf(&mut pdu) else {
            tracing::warn!(issi = prim.main_address.ssi, "invalid AL-DATA/FINAL");
            return;
        };
        let issi = prim.main_address.ssi;
        let route = Self::packet_route(self.dltime.add_timeslots(-2).t);
        let aie = prim
            .air_interface_encryption
            .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource));
        let Some(link) = self.advanced_links.get_mut(&issi) else {
            tracing::warn!(issi, "AL-DATA received without an established advanced link");
            return;
        };
        if link.last_rx_ns == Some(header.ns) {
            Self::send_al_ack(
                queue,
                prim.main_address,
                prim.endpoint_id,
                route,
                aie,
                header.ns,
                0,
                None,
                Vec::new(),
            );
            return;
        }
        if link.rx.as_ref().is_none_or(|rx| rx.ns != header.ns) {
            if header.ns != link.next_rx_ns {
                tracing::warn!(
                    issi,
                    expected = link.next_rx_ns,
                    received = header.ns,
                    "AL-DATA outside receive window"
                );
                return;
            }
            link.rx = Some(AdvancedRxSdu {
                ns: header.ns,
                segments: BTreeMap::new(),
                final_segment: None,
            });
        }
        let rx = link.rx.as_mut().expect("advanced receive state initialized");
        pdu.set_raw_start(pdu.get_raw_pos());
        pdu.seek(0);
        rx.segments.entry(header.segment).or_insert(pdu);
        if header.final_segment {
            rx.final_segment = Some(header.segment);
        }

        let complete = rx
            .final_segment
            .is_some_and(|last| (0..=last).all(|segment| rx.segments.contains_key(&segment)));
        if complete {
            let last = rx.final_segment.expect("complete receive state has final segment");
            let total_bits = (0..=last)
                .filter_map(|segment| rx.segments.get(&segment))
                .map(BitBuffer::get_len_remaining)
                .sum();
            let mut assembled = BitBuffer::new_autoexpand(total_bits);
            for segment in 0..=last {
                let mut bits = rx.segments.get(&segment).expect("complete receive state has segment").clone();
                let length = bits.get_len_remaining();
                assembled.copy_bits(&mut bits, length);
            }
            assembled.seek(0);
            if fcs::check_fcs(&assembled) {
                assembled.set_raw_end(assembled.get_raw_end() - 32);
                assembled.seek(0);
                Self::send_al_ack(
                    queue,
                    prim.main_address,
                    prim.endpoint_id,
                    route,
                    aie,
                    header.ns,
                    0,
                    None,
                    Vec::new(),
                );
                link.last_rx_ns = Some(header.ns);
                link.next_rx_ns = (header.ns + 1) & 0x07;
                link.rx = None;
                Self::deliver_advanced_sdu(queue, prim, assembled);
            } else {
                Self::send_al_ack(
                    queue,
                    prim.main_address,
                    prim.endpoint_id,
                    route,
                    aie,
                    header.ns,
                    63,
                    None,
                    Vec::new(),
                );
                link.rx = None;
            }
        } else if header.acknowledgement_requested {
            let highest = rx.final_segment.unwrap_or(header.segment);
            let missing = (0..=highest)
                .find(|segment| !rx.segments.contains_key(segment))
                .unwrap_or(highest.saturating_add(1));
            Self::send_al_ack(
                queue,
                prim.main_address,
                prim.endpoint_id,
                route,
                aie,
                header.ns,
                1,
                Some(missing),
                Vec::new(),
            );
        }
    }

    fn handle_al_ack(&mut self, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(ack) = AlAck::from_bitbuf(&mut pdu) else {
            tracing::warn!(issi = prim.main_address.ssi, "invalid AL-ACK/RNR");
            return;
        };
        let Some(link) = self.advanced_links.get_mut(&prim.main_address.ssi) else {
            return;
        };
        link.receiver_ready = ack.receiver_ready;
        let Some(position) = link.tx.iter().position(|sdu| sdu.ns == ack.nr) else {
            return;
        };
        if ack.acknowledgement_length == 0 {
            if let Some(sdu) = link.tx.remove(position) {
                if sdu.reporter.get_state() == TxState::Pending {
                    sdu.reporter.mark_transmitted();
                }
                if sdu.reporter.get_state() == TxState::Transmitted {
                    sdu.reporter.mark_acknowledged();
                }
            }
            return;
        }
        let sdu = &mut link.tx[position];
        if ack.acknowledgement_length == 63 {
            sdu.retransmissions = sdu.retransmissions.saturating_add(1);
            sdu.pending_segments = None;
        } else if let Some(first) = ack.first_missing_segment {
            let mut missing = vec![first as usize];
            for (offset, received) in ack.acknowledgement_bitmap.iter().copied().enumerate() {
                if !received {
                    missing.push(first as usize + offset + 1);
                }
            }
            missing.retain(|segment| *segment < sdu.segments.len());
            let segment_limit_exceeded = missing.iter().any(|segment| {
                sdu.segment_retransmissions[*segment] = sdu.segment_retransmissions[*segment].saturating_add(1);
                sdu.segment_retransmissions[*segment] > link.max_segment_retransmissions
            });
            if segment_limit_exceeded {
                sdu.retransmissions = sdu.retransmissions.saturating_add(1);
                sdu.pending_segments = None;
            } else {
                sdu.pending_segments = Some(missing);
            }
        }
        if sdu.reporter.get_state() == TxState::Transmitted {
            sdu.reporter.reset();
        }
        sdu.sent_at = None;
        sdu.attempt_reporter = None;
    }

    fn handle_al_reconnect(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(request) = AlReconnect::from_bitbuf(&mut pdu) else {
            return;
        };
        let accepted = request.link_number == 0 && self.advanced_links.contains_key(&prim.main_address.ssi);
        let response = AlReconnect {
            acknowledged: true,
            link_number: request.link_number,
            report: if accepted { 2 } else { 1 },
        };
        let mut response_pdu = BitBuffer::new_autoexpand(16);
        if response.to_bitbuf(&mut response_pdu).is_ok() {
            response_pdu.seek(0);
            let aie = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacResource,
                )
            });
            Self::queue_advanced_pdu(
                queue,
                prim.main_address,
                prim.endpoint_id,
                response_pdu,
                Self::packet_route(self.dltime.add_timeslots(-2).t),
                None,
                aie,
                None,
            );
        }
    }

    fn handle_al_disconnect(&mut self, queue: &mut MessageQueue, prim: &tetra_saps::tma::TmaUnitdataInd, mut pdu: BitBuffer) {
        let Ok(request) = AlDisconnect::from_bitbuf(&mut pdu) else {
            return;
        };
        if request.link_number != 0 {
            return;
        }
        self.advanced_links.remove(&prim.main_address.ssi);
        let mut response_pdu = BitBuffer::new_autoexpand(16);
        AlDisconnect {
            acknowledged: true,
            link_number: 0,
            report: 0,
        }
        .to_bitbuf(&mut response_pdu);
        response_pdu.seek(0);
        let aie = prim.air_interface_encryption.unwrap_or_else(|| {
            AieRequest::clear(
                AieSubject::Individual {
                    issi: prim.main_address.ssi,
                },
                AieScope::MacResource,
            )
        });
        Self::queue_advanced_pdu(
            queue,
            prim.main_address,
            prim.endpoint_id,
            response_pdu,
            Self::packet_route(self.dltime.add_timeslots(-2).t),
            None,
            aie,
            None,
        );
    }

    fn rx_tma_unitdata_ind_al(&mut self, queue: &mut MessageQueue, mut message: SapMsg, pdu_type: LlcPduType) {
        let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg else {
            return;
        };
        let Some(pdu) = prim.pdu.take() else {
            return;
        };
        match pdu_type {
            LlcPduType::AlSetup => self.handle_al_setup(queue, prim, pdu),
            LlcPduType::AlDataAlFinal => self.handle_al_data(queue, prim, pdu),
            LlcPduType::AlAckAlRnr => self.handle_al_ack(prim, pdu),
            LlcPduType::AlReconnect => self.handle_al_reconnect(queue, prim, pdu),
            LlcPduType::AlDisc => self.handle_al_disconnect(queue, prim, pdu),
            LlcPduType::AlAlUdataAlUfinal => {
                tracing::warn!(
                    issi = prim.main_address.ssi,
                    "unacknowledged advanced link is outside the TIP profile"
                )
            }
            _ => unreachable!(),
        }
    }

    fn submit_advanced_link_messages(&mut self, queue: &mut MessageQueue) -> bool {
        let now = self.dltime;
        let mut activity = false;
        for (issi, link) in &mut self.advanced_links {
            let mut remove = Vec::new();
            for (index, sdu) in link.tx.iter_mut().enumerate() {
                if let Some(attempt) = &sdu.attempt_reporter {
                    match attempt.get_state() {
                        TxState::Transmitted | TxState::Acknowledged => {
                            if sdu.reporter.get_state() == TxState::Pending {
                                sdu.reporter.mark_transmitted();
                            }
                            sdu.sent_at.get_or_insert(now);
                        }
                        TxState::Discarded | TxState::Lost => {
                            sdu.attempt_reporter = None;
                            sdu.sent_at = None;
                        }
                        TxState::Pending => {}
                    }
                }
                let timed_out = sdu.sent_at.is_some_and(|sent| now.diff(sent) >= T252_ACK_WAITING_TIMER as i32);
                if timed_out {
                    if sdu.retransmissions >= link.max_sdu_retransmissions {
                        if sdu.reporter.get_state() == TxState::Pending {
                            sdu.reporter.mark_transmitted();
                        }
                        if sdu.reporter.get_state() == TxState::Transmitted {
                            sdu.reporter.mark_lost();
                        }
                        remove.push(index);
                    } else {
                        sdu.retransmissions += 1;
                        if sdu.reporter.get_state() == TxState::Transmitted {
                            sdu.reporter.reset();
                        }
                        sdu.attempt_reporter = None;
                        sdu.sent_at = None;
                        sdu.pending_segments = None;
                    }
                }
            }
            for index in remove.into_iter().rev() {
                link.tx.remove(index);
            }

            if !link.receiver_ready {
                continue;
            }
            let in_flight = link
                .tx
                .iter()
                .filter(|sdu| sdu.attempt_reporter.is_some() || sdu.sent_at.is_some())
                .count();
            let mut available = link.window_size as usize - in_flight.min(link.window_size as usize);
            for sdu in link
                .tx
                .iter_mut()
                .filter(|sdu| sdu.attempt_reporter.is_none() && sdu.sent_at.is_none())
            {
                if available == 0 || sdu.retransmissions > link.max_sdu_retransmissions {
                    break;
                }
                let selected = sdu
                    .pending_segments
                    .clone()
                    .filter(|segments| !segments.is_empty())
                    .unwrap_or_else(|| (0..sdu.segments.len()).collect());
                let attempt_reporter = TxReporter::new_unacked();
                for (selected_index, segment_index) in selected.iter().copied().enumerate() {
                    let mut pdu = BitBuffer::new_autoexpand(AL_SEGMENT_PAYLOAD_BITS + 24);
                    let last_selected = selected_index + 1 == selected.len();
                    let final_segment = segment_index + 1 == sdu.segments.len();
                    let header = AlDataHeader {
                        final_segment,
                        acknowledgement_requested: last_selected,
                        ns: sdu.ns,
                        segment: segment_index as u8,
                    };
                    if header.to_bitbuf(&mut pdu).is_err() {
                        continue;
                    }
                    let mut payload = sdu.segments[segment_index].clone();
                    let length = payload.get_len_remaining();
                    pdu.copy_bits(&mut payload, length);
                    pdu.seek(0);
                    Self::queue_advanced_pdu(
                        queue,
                        TetraAddress::issi(*issi),
                        sdu.endpoint_id,
                        pdu,
                        if sdu.routes.is_empty() {
                            None
                        } else {
                            Some(sdu.routes[segment_index % sdu.routes.len()])
                        },
                        last_selected.then(|| sdu.chan_alloc.clone()).flatten(),
                        sdu.aie_request,
                        last_selected.then(|| attempt_reporter.clone()),
                    );
                }
                sdu.attempt_reporter = Some(attempt_reporter);
                sdu.pending_segments = None;
                available -= 1;
                activity = true;
            }
        }
        activity
    }

    /// See Clause 22.3.2.3 for Acknowledged data transmission in basic link
    fn rx_tla_tldata_req_bl(&mut self, _queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_tldata_req_bl");
        let SapMsgInner::TlaTlDataReqBl(mut prim) = message.msg else {
            panic!()
        };

        if prim.packet_data_flag && self.rx_tla_tldata_req_al(prim.clone()) {
            return;
        }

        if prim.stealing_permission {
            panic!("Can't send BL-DATA for STCH message");
        }
        if prim.main_address.ssi_type == SsiType::Gssi {
            panic!("Can't send BL-DATA for GSSI-addressed message. ");
        }

        // If an ack still needs to be sent, get the relevant expected sequence number
        let outgoing_aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
            AieRequest::clear(
                AieSubject::Individual {
                    issi: prim.main_address.ssi,
                },
                AieScope::MacResource,
            )
        });
        let delivery_timeslot = prim
            .associated_channel
            .as_ref()
            .map(|channel| channel.timeslot)
            .or_else(|| {
                Self::delivery_routes(&self.config, prim.main_address.ssi, self.dltime)
                    .first()
                    .map(|channel| channel.timeslot)
            })
            .unwrap_or(1);
        let out_ack_n = self.get_out_ack_seq_if_any(prim.main_address, delivery_timeslot, outgoing_aie_request);

        // Get per-link send sequence number N(S) = V(S), then toggle V(S)
        let ns = self.get_next_send_seq(&prim.main_address);

        // Construct PDU, write header
        let mut pdu_buf = BitBuffer::new_autoexpand(32);

        // Determine message type and build
        if let Some(out_ack_n) = out_ack_n {
            // BL-ADATA (acknowledged, with or without FCS)
            let pdu = BlAdata {
                has_fcs: prim.fcs_flag,
                nr: out_ack_n,
                ns,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            // Append SDU
            let sdu_len = prim.tl_sdu.get_len_remaining();
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());
        } else {
            // BL-DATA (acknowledged, with or without FCS) — ETSI Clause 22.3.2.3
            let pdu = BlData {
                has_fcs: prim.fcs_flag,
                ns,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            // Append SDU
            let sdu_len = prim.tl_sdu.get_len_remaining();
            pdu_buf.copy_bits(&mut prim.tl_sdu, sdu_len);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} sdu {}", pdu, pdu_buf.dump_bin());
        }

        // Either take tx_reporter passed down or create a new one
        let tx_reporter = prim.tx_reporter.take().unwrap_or_else(|| TxReporter::new());

        let sapmsg = SapMsg {
            sap: Sap::TmaSap,
            src: self.entity(),
            dest: TetraEntity::Umac,
            msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: prim.req_handle,
                pdu: pdu_buf,
                main_address: prim.main_address,
                endpoint_id: prim.endpoint_id,
                stealing_permission: prim.stealing_permission,
                subscriber_class: prim.subscriber_class,
                air_interface_encryption: prim.air_interface_encryption,
                stealing_repeats_flag: prim.stealing_repeats_flag,
                data_category: prim.data_class_info,
                chan_alloc: prim.chan_alloc,
                associated_channel: prim.associated_channel,
                tx_reporter: Some(tx_reporter.clone()),
            }),
        };

        // The basic-link acknowledgement returns on the associated traffic
        // channel when this message was delivered through FN18; otherwise it
        // uses the MCCH.  Keep that context for retransmission/accounting.
        let ack_timeslot = prim.associated_channel.as_ref().map(|channel| channel.timeslot).unwrap_or(1);
        self.outbound_messages.push_back(ExpectedInAck {
            ns,
            addr: prim.main_address,
            ts: ack_timeslot,
            bl_type: Layer2Service::Acknowledged,
            tx_reporter,
            attempt_reporters: Vec::new(),
            attempt_timeslots: Vec::new(),
            observed_transmitted_copies: 0,
            t_first: self.dltime,
            t_submitted_to_umac: None,
            t_umac_done: None,
            has_transmitted_attempt: false,
            retransmission_buf: sapmsg, // Clone the message to keep a copy for potential retransmission
            retransmit_count: 0,
        });

        // The message will now be picked up for transmission at end-of-tick, if the ssi does not yet have
        // a pending message waiting for an ack.
    }

    fn rx_tla_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_prim");
        match &message.msg {
            SapMsgInner::TlaTlDataReqBl(_) => {
                self.rx_tla_tldata_req_bl(queue, message);
            }
            SapMsgInner::TlaTlUnitdataReqBl(_) => {
                self.rx_tla_tlunitdata_req_bl(queue, message);
            }
            _ => panic!(),
        }
    }

    fn rx_tma_report_ind(&mut self, _queue: &mut MessageQueue, mut _message: SapMsg) {
        tracing::trace!("rx_tma_report_ind, ignoring");
    }

    /// Clause 20.4.1.1.4 TMA-UNITDATA primitive
    /// TMA-UNITDATA indication: this primitive shall be used by the MAC to deliver a received TM-SDU. This primitive
    /// may also be used with no TM-SDU if the MAC needs to inform the higher layers of a channel allocation received
    /// without an associated TM-SDU.
    fn rx_tma_unitdata_ind(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tma_unitdata_ind");

        // Determine which type of TL-SDU we have
        let pdu_type = if let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg {
            let Some(pdu) = prim.pdu.as_ref() else {
                panic!("no pdu");
            };
            let Some(bits) = pdu.peek_bits(4) else {
                tracing::warn!("insufficient bits: {}", pdu.dump_bin());
                return;
            };
            let Ok(pdu_type) = LlcPduType::try_from(bits) else {
                tracing::warn!("invalid pdu type: {} in {}", bits, pdu.dump_bin());
                return;
            };

            pdu_type
        } else {
            panic!();
        };

        // Supplementary LLC and layer-2 signalling PDUs are standard LLC
        // types, even though this BS does not yet implement their services.
        // Keep their subtype and sender for diagnostics, but never let an
        // unsupported radio PDU take the complete base station down.
        let (issi, llc_subtype) = if let SapMsgInner::TmaUnitdataInd(prim) = &message.msg {
            let llc_subtype = prim.pdu.as_ref().and_then(|pdu| pdu.peek_bits(8)).map(|bits| (bits & 0x0f) as u8);
            (prim.main_address.ssi, llc_subtype)
        } else {
            unreachable!("TMA indication checked above");
        };

        // Call handler function
        match pdu_type {
            // All Basic Link types can be handled by the same function
            LlcPduType::BlAdata
            | LlcPduType::BlAdataFcs
            | LlcPduType::BlData
            | LlcPduType::BlDataFcs
            | LlcPduType::BlUdata
            | LlcPduType::BlUdataFcs
            | LlcPduType::BlAck
            | LlcPduType::BlAckFcs => {
                self.rx_tma_unitdata_ind_bl(queue, message);
            }

            LlcPduType::AlSetup
            | LlcPduType::AlDataAlFinal
            | LlcPduType::AlAlUdataAlUfinal
            | LlcPduType::AlAckAlRnr
            | LlcPduType::AlReconnect
            | LlcPduType::AlDisc => {
                self.rx_tma_unitdata_ind_al(queue, message, pdu_type);
            }

            LlcPduType::SuppLlcPdu | LlcPduType::L2SigPdu => {
                tracing::warn!(
                    issi,
                    ?pdu_type,
                    llc_subtype,
                    "discarding unsupported supplementary/layer-2 signalling LLC PDU"
                );
            }
        }
    }

    fn rx_tma_unitdata_ind_bl(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tma_unitdata_ind_bl");

        // Get header bits (again) and prepare MLE message
        let SapMsgInner::TmaUnitdataInd(prim) = &mut message.msg else {
            panic!();
        };
        let Some(mut pdu) = prim.pdu.take() else {
            panic!("no pdu");
        };
        let Some(bits) = pdu.peek_bits(4) else {
            tracing::warn!("insufficient bits: {}", pdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = LlcPduType::try_from(bits) else {
            tracing::warn!("invalid pdu type: {} in {}", bits, pdu.dump_bin());
            return;
        };

        let (has_fcs, ns, nr) = match pdu_type {
            LlcPduType::BlAdata | LlcPduType::BlAdataFcs => match BlAdata::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, Some(pdu.ns), Some(pdu.nr))
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlAdata: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },

            LlcPduType::BlData | LlcPduType::BlDataFcs => match BlData::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, Some(pdu.ns), None)
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlData: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            LlcPduType::BlAck | LlcPduType::BlAckFcs => match BlAck::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, None, Some(pdu.nr))
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlAck: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            LlcPduType::BlUdata | LlcPduType::BlUdataFcs => match BlUdata::from_bitbuf(&mut pdu) {
                Ok(pdu) => {
                    tracing::debug!(ts=%self.dltime, "<- {:?}", pdu);
                    (pdu.has_fcs, None, None)
                }
                Err(e) => {
                    tracing::warn!("Failed parsing BlUdata: {:?} {}", e, pdu.dump_bin());
                    return;
                }
            },
            _ => {
                panic!();
            }
        };

        // If FCS is present, check it. If wrong, we bail here
        if has_fcs && !fcs::check_fcs(&pdu) {
            tracing::warn!("FCS check failed");
            return;
        }

        let clear_from_bound_sc2_terminal = matches!(prim.air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled
                && state.subscribers.is_registered(prim.main_address.ssi)
                && !state.aie_sessions.terminal_allows_clear(prim.main_address.ssi)
        };
        if clear_from_bound_sc2_terminal {
            let bare_ack_bits = if has_fcs { 36 } else { 4 };
            let transition_ack = matches!(pdu_type, LlcPduType::BlAck | LlcPduType::BlAckFcs)
                && pdu.get_len_remaining() <= bare_ack_bits
                && nr.is_some_and(|ack_nr| self.clear_transition_ack_expected(prim.main_address, ack_nr));
            let mm_bootstrap = matches!(
                pdu.peek_bits(3).and_then(|bits| MleProtocolDiscriminator::try_from(bits).ok()),
                Some(MleProtocolDiscriminator::Mm)
            );
            if !transition_ack && !mm_bootstrap {
                tracing::warn!(
                    issi = prim.main_address.ssi,
                    ?pdu_type,
                    "rejecting clear post-SC2 basic-link PDU outside MM bootstrap and transition ACK allow-lists"
                );
                return;
            }
        }

        // If ns is present, we need to send an ACK
        let msg_dltime = self.dltime.add_timeslots(-2); // Msg on uplink was sent two timeslots ago. 
        if let Some(ns) = ns {
            // Send ACK
            let incoming_aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacData,
                )
            });
            self.schedule_outgoing_ack(msg_dltime, prim.main_address, ns, incoming_aie_request);
        }

        // if nr is present, we have received an ACK on a previous message
        if let Some(nr) = nr {
            let incoming_aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
                AieRequest::clear(
                    AieSubject::Individual {
                        issi: prim.main_address.ssi,
                    },
                    AieScope::MacData,
                )
            });
            self.process_incoming_ack(prim.main_address, nr, incoming_aie_request);
        }

        if pdu_type == LlcPduType::BlAck || pdu_type == LlcPduType::BlAckFcs {
            // A bare BL-ACK can carry up to four radio-fill bits after its
            // five-bit header; those are not a TL-SDU.
            if pdu.get_len_remaining() <= 4 {
                return;
            }
            // Some MS implementations piggyback the acknowledged TL-SDU on
            // the BL-ACK that confirms its downlink.  In particular this is
            // how the tested terminals return an SS-DGNA ASSIGN ACK.  The
            // five LLC ACK bits have already been consumed, so pass the
            // remaining TL-SDU through the normal acknowledged-data path.
            tracing::debug!(
                ts = %self.dltime,
                payload_bits = pdu.get_len_remaining(),
                "delivering BL-ACK piggyback payload"
            );
        }

        // If unacknowledged data transfer service, we send a TL-UNITDATA indication
        // to MLE. If acknowledged data transfer service, we send a TL-DATA indication
        pdu.set_raw_start(pdu.get_raw_pos());
        let s = if pdu_type == LlcPduType::BlUdata || pdu_type == LlcPduType::BlUdataFcs {
            // Unacknowledged data transfer service
            let m = TlaTlUnitdataIndBl {
                // address_type: 0, // TODO FIXME
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: if pdu.get_len_remaining() > 0 { Some(pdu) } else { None },
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                report: None, // TODO FIXME
            };
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlUnitdataIndBl(m),
            }
        } else {
            // Acknowledged data transfer service
            let m = TlaTlDataIndBl {
                // address_type: 0, // TODO FIXME
                main_address: prim.main_address,
                link_id: 0,
                endpoint_id: prim.endpoint_id,
                new_endpoint_id: prim.new_endpoint_id,
                css_endpoint_id: prim.css_endpoint_id,
                tl_sdu: if pdu.get_len_remaining() > 0 { Some(pdu) } else { None },
                scrambling_code: prim.scrambling_code,
                fcs_flag: has_fcs,
                air_interface_encryption: prim.air_interface_encryption,
                chan_change_resp_req: prim.chan_change_response_req,
                chan_change_handle: prim.chan_change_handle,
                chan_info: prim.chan_info,
                req_handle: 0, // TODO FIXME
            };
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::TlaTlDataIndBl(m),
            }
        };

        queue.push_back(s);
    }

    fn submit_retransmissions_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let mut had_activity = false;
        let dltime = self.dltime;
        let mut removals: Option<Vec<u32>> = None;

        // if !self.outbound_messages.is_empty() {
        //     tracing::error!("{}", Self::format_expected_ack_list(&self.outbound_messages));
        // }

        for ack in self.outbound_messages.iter_mut() {
            // First, check which have newly been txed, or discarded by Umac. If so, start t_umac_done.
            let transmitted_route_count = ack.attempt_reporters.iter().filter(|reporter| reporter.is_transmitted()).count();
            let all_routes_done = !ack.attempt_reporters.is_empty()
                && ack
                    .attempt_reporters
                    .iter()
                    .all(|reporter| reporter.is_transmitted() || reporter.is_discarded());
            if transmitted_route_count > ack.observed_transmitted_copies {
                // T.251 belongs to the basic-link transmission, so start it as
                // soon as a concurrent copy reaches the air. If another copy
                // completes later, restart it from that complete transmission;
                // retransmitting while that route is still fragmented corrupts
                // the receiver's MAC reconstruction chain.
                ack.has_transmitted_attempt = true;
                ack.observed_transmitted_copies = transmitted_route_count;
                if !ack.tx_reporter.is_transmitted() {
                    ack.tx_reporter.reset();
                    ack.tx_reporter.mark_transmitted();
                }
                ack.t_umac_done = Some(self.dltime);
                tracing::trace!("schedule_retransmissions: {} umac_done at {}", ack.addr.ssi, dltime);
            } else if ack.t_umac_done.is_none() && all_routes_done {
                // Every route was discarded before transmission. Use the same
                // retry window before selecting a fresh live route set.
                ack.t_umac_done = Some(self.dltime);
                tracing::trace!("schedule_retransmissions: {} all routes discarded at {}", ack.addr.ssi, dltime);
            }

            // If we don't have a t_umac_done, there is no need for a retransmission in any case
            let Some(t_umac_done) = ack.t_umac_done else {
                continue;
            };

            // Retransmit scenario 1: it was transmitted but no ack received within the expected window (ETSI T.251 / N.252)
            // Retransmission scenario 2: it has been dropped by Umac due to congestion. Retransmit after same window
            let age = dltime.diff(t_umac_done); // Never fails
            let retry_timer = Self::basic_link_retry_timer(ack);
            let max_retransmits = Self::max_over_air_retransmits(ack);
            if age as u32 >= retry_timer {
                let pending_window = Self::pending_route_completion_window(&self.config, ack);
                let attempt_age = ack.t_submitted_to_umac.map(|submitted| dltime.diff(submitted)).unwrap_or(i32::MAX);
                if pending_window > 0 && attempt_age >= 0 && (attempt_age as u32) < pending_window {
                    tracing::debug!(
                        issi = ack.addr.ssi,
                        ns = ack.ns,
                        attempt_age,
                        pending_window,
                        "deferring basic-link retry while a concurrent route copy is unfinished"
                    );
                    continue;
                }
                // Time for either retransmitting or giving up
                if ack.retransmit_count < max_retransmits {
                    // Retransmit
                    ack.retransmit_count += 1;
                    tracing::info!(
                        "retransmitting SSI {} N(S) {} attempt {}{}",
                        ack.addr.ssi,
                        ack.ns,
                        ack.retransmit_count,
                        if Self::has_assigned_channel_context(ack) {
                            " after assigned-channel grace"
                        } else {
                            ""
                        }
                    );

                    Self::submit_for_acknowledged_transmission(&self.config, queue, ack, self.dltime.forward_to_timeslot(ack.t_first.t));
                    had_activity = true;
                } else if Self::final_ack_grace_elapsed(age, retry_timer, Self::has_assigned_channel_context(ack)) {
                    // Exhausted retransmissions, flag for discard
                    removals.get_or_insert(Vec::new()).push(ack.addr.ssi);
                }
            }
        }

        // Remove any expired entries
        if let Some(removals) = removals {
            for ssi in removals {
                let ack = self.take_expected_ack_for_ssi(ssi).unwrap(); // Never fails
                tracing::warn!(
                    "schedule_retransmissions: SSI {} N(S) {} exhausted retransmissions",
                    ack.addr.ssi,
                    ack.ns
                );
                Self::mark_reporter_lost(&ack.tx_reporter);
            }
            // The ack expires here
        }

        had_activity
    }

    fn submit_free_messages_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let mut had_activity = false;
        let mut ssi_blocked: HashSet<u32> = HashSet::new();
        for ack in self.outbound_messages.iter_mut() {
            // Check if already submitted to umac
            if ack.t_submitted_to_umac.is_some() {
                // This ssi currently waits for an ack, and is thus blocked
                ssi_blocked.insert(ack.addr.ssi);
                continue;
            }

            // Not submitted; check if blocked
            if ssi_blocked.contains(&ack.addr.ssi) {
                // SSI already has another message waiting for ack, so we cannot submit this one yet
                tracing::debug!(
                    "SSI {} N(S) {} still blocked by previous message, cannot submit next message",
                    ack.addr.ssi,
                    ack.ns
                );
                continue;
            }

            // Not submitted and not blocked. We can submit it now.
            // tracing::debug!("submitting message for SSI {} N(S) {} to umac", ack.addr.ssi, ack.ns);
            tracing::debug!(
                "submitting message for SSI {} N(S) {} to umac: {:?}",
                ack.addr.ssi,
                ack.ns,
                ack.retransmission_buf.msg
            );
            Self::submit_for_acknowledged_transmission(&self.config, queue, ack, self.dltime.forward_to_timeslot(ack.t_first.t));
            ssi_blocked.insert(ack.addr.ssi);
            had_activity = true;
        }

        had_activity
    }

    /// Pops all elements from the scheduled_out_acks queue, prepares BL-ACK messages, and send them down
    fn submit_ack_replies_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let had_activity = !self.scheduled_out_acks.is_empty();
        while let Some(ack) = self.scheduled_out_acks.pop_front() {
            tracing::debug!("auto-ack for ssi: {}, n: {}, ts: {}", ack.addr.ssi, ack.nr, ack.ts);

            // Send BL-ACK via FACCH (stealing) on the traffic timeslot if the original
            // message arrived on a traffic channel (TS2-4), otherwise via MCCH (TS1).
            let steal = matches!(ack.ts, 2..=4);
            let mut pdu_buf = BitBuffer::new_autoexpand(5);
            let pdu = BlAck {
                has_fcs: false,
                nr: ack.nr,
            };
            pdu.to_bitbuf(&mut pdu_buf);
            pdu_buf.seek(0);
            tracing::debug!(ts=%self.dltime, "-> {:?} {}", pdu, pdu_buf.dump_bin());

            // We're sending an ACK for a received uplink message, however, we don't have that message here
            // Since DL is two slots ahead of UL, we will correct that. We now have the dltime for reception
            // of the original message.
            let chan_alloc = match steal {
                true => {
                    let mut timeslots = [false; 4];
                    timeslots[(ack.ts - 1) as usize] = true;
                    Some(CmceChanAllocReq {
                        usage: None,
                        timeslots,
                        alloc_type: ChanAllocType::Replace,
                        cell_change_flag: false,
                        ul_dl_assigned: UlDlAssignment::Both,
                        carrier: None,
                    })
                }
                false => None,
            };
            let sapmsg = SapMsg {
                sap: Sap::TmaSap,
                src: TetraEntity::Llc,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                    req_handle: 0, // TODO FIXME
                    pdu: pdu_buf,
                    main_address: ack.addr,
                    endpoint_id: 0, // todo fixme
                    stealing_permission: steal,
                    subscriber_class: 0, // TODO FIXME
                    air_interface_encryption: Some(ack.aie_request.with_scope(AieScope::MacResource)),
                    stealing_repeats_flag: None, // TODO FIXME
                    data_category: None,         // TODO FIXME
                    chan_alloc,
                    associated_channel: None,
                    tx_reporter: None, // By definition, no higher layer entity is interested
                }),
            };
            queue.push_back(sapmsg);
        }
        had_activity
    }

    /// Pops all elements from the scheduled_out_acks queue, prepares BL-ACK messages, and send them down
    fn submit_udata_msgs_to_umac(&mut self, queue: &mut MessageQueue) -> bool {
        let had_activity = !self.outbound_udata_messages.is_empty();
        while let Some(msg) = self.outbound_udata_messages.pop_front() {
            tracing::debug!("submitting udata msg to umac: {:?}", msg.msg);
            queue.push_back(msg);
        }
        had_activity
    }

    fn format_expected_ack_list(ack_list: &VecDeque<ExpectedInAck>) -> String {
        let mut ret = String::new();
        ret.push_str("Expected in acks:\n");
        for ack in ack_list {
            ret.push_str(&format!(
                "  ssi: {}, n: {}, retransmissions: {}, t_first: {:?}, t_umac_done: {:?}, state: {:?}\n",
                ack.addr.ssi,
                ack.ns,
                ack.retransmit_count,
                ack.t_first,
                ack.t_umac_done,
                ack.tx_reporter.get_state()
            ));
        }
        ret
    }

    fn format_scheduled_ack_list(ack_list: &Vec<ScheduledOutAck>) -> String {
        let mut ret = String::new();
        ret.push_str("Scheduled out acks:\n");
        for ack in ack_list {
            ret.push_str(&format!("  t_start: {}, ssi: {}, n: {}\n", ack.t_start.t, ack.addr.ssi, ack.nr));
        }
        ret
    }
}

impl TetraEntityTrait for Llc {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Llc
    }

    fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::TmaSap => {
                self.rx_tma_prim(queue, message);
            }

            // TMB-SAP and TMC-SAP are skipped and passed straight between MAC and MLE
            Sap::TlaSap => {
                self.rx_tla_prim(queue, message);
            }
            _ => panic!(),
        }
    }

    fn tick_start(&mut self, _queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
    }

    fn tick_end(&mut self, queue: &mut MessageQueue, _ts: TdmaTime) -> bool {
        let mut had_activity = false;

        // Step 1 / 4: Check if we have any transmitted messages that were not acked within the expected window
        // Schedule a retransmission if appropriate.
        had_activity |= self.submit_retransmissions_to_umac(queue);

        // Step 2 / 4: Check if there are any messages that were not yet sent down, that we can now send down the stack
        // Messages may be kept since the target SSI has not yet acked them . If the link is now free, we can send the message down and register that we expect an ACK for it.
        had_activity |= self.submit_free_messages_to_umac(queue);

        // Step 3 / 4: Check if any unsent ACKs are still here
        // Take oldest element from scheduled_out_acks, and remove it from the list
        had_activity |= self.submit_ack_replies_to_umac(queue);

        // Step 4 / 4: Send any U-DATA messages
        had_activity |= self.submit_udata_msgs_to_umac(queue);

        // Packet data is deliberately submitted after all basic-link and
        // control work; UMAC applies the same ordering inside packet bearers.
        had_activity |= self.submit_advanced_link_messages(queue);

        had_activity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_saps::tma::TmaUnitdataInd;

    fn test_config() -> SharedConfig {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        SharedConfig::from_parts(config, None)
    }

    fn advanced_indication(issi: u32, pdu: BitBuffer) -> SapMsg {
        SapMsg::new(
            Sap::TmaSap,
            TetraEntity::Umac,
            TetraEntity::Llc,
            SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                pdu: Some(pdu),
                main_address: TetraAddress::issi(issi),
                scrambling_code: 0,
                endpoint_id: 7,
                new_endpoint_id: None,
                css_endpoint_id: None,
                air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacData)),
                chan_change_response_req: false,
                chan_change_handle: None,
                chan_info: None,
            }),
        )
    }

    fn establish_advanced_link(llc: &mut Llc, queue: &mut MessageQueue, issi: u32) {
        llc.dltime = TdmaTime { h: 0, m: 1, f: 2, t: 4 };
        let mut pdu = BitBuffer::new_autoexpand(32);
        AlSetup {
            acknowledged: true,
            link_number: 0,
            maximum_sdu: 6,
            connection_width: true,
            asymmetric: false,
            uplink_slots: Some(3),
            downlink_slots: None,
            throughput: 7,
            window_size: 2,
            sdu_retransmissions: 3,
            segment_retransmissions: 5,
            report: 1,
        }
        .to_bitbuf(&mut pdu)
        .unwrap();
        pdu.seek(0);
        llc.rx_tma_unitdata_ind(queue, advanced_indication(issi, pdu));
    }

    #[test]
    fn ms_al_setup_establishes_tip_link_and_is_answered() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);

        let link = llc.advanced_links.get(&77_468).expect("advanced link established");
        assert_eq!(link.link_number, 0);
        assert_eq!(link.slots, 3);
        assert_eq!(link.window_size, 2);
        let response = queue.pop_front().expect("AL-SETUP response");
        let SapMsgInner::TmaUnitdataReq(mut response) = response.msg else {
            panic!("expected TMA response")
        };
        assert_eq!(response.associated_channel.map(|route| route.timeslot), Some(2));
        assert_eq!(AlSetup::from_bitbuf(&mut response.pdu).unwrap().report, 0);
    }

    #[test]
    fn advanced_uplink_reassembles_and_checks_fcs() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let payload = BitBuffer::from_bitstr(&"10110010".repeat(40));
        let segments = Llc::advanced_segments(payload.clone());
        for (index, mut segment) in segments.iter().cloned().enumerate() {
            let mut pdu = BitBuffer::new_autoexpand(200);
            AlDataHeader {
                final_segment: index + 1 == segments.len(),
                acknowledgement_requested: index + 1 == segments.len(),
                ns: 0,
                segment: index as u8,
            }
            .to_bitbuf(&mut pdu)
            .unwrap();
            let length = segment.get_len_remaining();
            pdu.copy_bits(&mut segment, length);
            pdu.seek(0);
            llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, pdu));
        }

        let ack = queue.pop_front().unwrap();
        assert!(matches!(ack.msg, SapMsgInner::TmaUnitdataReq(_)));
        let delivered = queue.pop_front().unwrap();
        assert!(queue.pop_front().is_none());
        let SapMsgInner::TlaTlDataIndBl(delivered) = delivered.msg else {
            panic!("expected reassembled TL-DATA indication")
        };
        assert_eq!(delivered.tl_sdu.unwrap().dump_bin_unformatted(), payload.dump_bin_unformatted());
    }

    #[test]
    fn advanced_downlink_completes_only_after_al_ack() {
        let mut llc = Llc::new(test_config());
        let mut queue = MessageQueue::new();
        establish_advanced_link(&mut llc, &mut queue, 77_468);
        while queue.pop_front().is_some() {}
        let reporter = TxReporter::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(77_468),
                    link_id: 0,
                    endpoint_id: 7,
                    tl_sdu: BitBuffer::from_bitstr(&"11001010".repeat(30)),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: true,
                    packet_data_flag: true,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: Llc::packet_route(2),
                    tx_reporter: Some(reporter.clone()),
                }),
            ),
        );
        llc.submit_advanced_link_messages(&mut queue);
        assert_eq!(reporter.get_state(), TxState::Pending);
        assert!(queue.pop_front().is_some());
        assert!(queue.pop_front().is_some());
        assert!(queue.pop_front().is_none());

        let mut ack = BitBuffer::new_autoexpand(16);
        AlAck {
            receiver_ready: true,
            nr: 0,
            acknowledgement_length: 0,
            first_missing_segment: None,
            acknowledgement_bitmap: Vec::new(),
        }
        .to_bitbuf(&mut ack)
        .unwrap();
        ack.seek(0);
        llc.rx_tma_unitdata_ind(&mut queue, advanced_indication(77_468, ack));
        assert_eq!(reporter.get_state(), TxState::Acknowledged);
        assert!(llc.advanced_links.get(&77_468).unwrap().tx.is_empty());
    }

    #[test]
    fn sc2_bl_ack_keeps_the_received_aie_policy() {
        let mut llc = Llc::new(test_config());
        let addr = TetraAddress::issi(0x12_34_56);
        let request = AieRequest::sc2(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData);
        llc.schedule_outgoing_ack(TdmaTime::default(), addr, 1, request);

        let mut queue = MessageQueue::new();
        assert!(llc.submit_ack_replies_to_umac(&mut queue));
        let message = queue.pop_front().expect("BL-ACK must be queued");
        let SapMsgInner::TmaUnitdataReq(request) = message.msg else {
            panic!("expected a TMA request")
        };
        assert!(matches!(
            request.air_interface_encryption,
            Some(AieRequest::Sc2 {
                subject: AieSubject::Individual { issi },
                scope: AieScope::MacResource,
            }) if issi == addr.ssi
        ));
    }

    #[test]
    fn combined_bl_adata_never_mixes_clear_and_sc2_ack_status() {
        let mut llc = Llc::new(test_config());
        let addr = TetraAddress::issi(1234);
        let sc2 = AieRequest::sc2(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData);
        let clear = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        llc.schedule_outgoing_ack(TdmaTime::default(), addr, 0, sc2);

        assert_eq!(llc.get_out_ack_seq_if_any(addr, 1, clear), None);
        assert_eq!(llc.scheduled_out_acks.len(), 1, "mismatched ACK remains separate");
        assert_eq!(llc.get_out_ack_seq_if_any(addr, 1, sc2), Some(0));
    }

    #[test]
    fn acknowledged_downlink_uses_live_call_route_on_first_attempt() {
        let config = test_config();
        let issi = 0x12_34_56;
        config.state_write().subscriber_delivery_routes.insert(
            issi,
            vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                call_id: 7,
                timeslot: 2,
                usage: 10,
            }],
        );

        let route = Llc::delivery_routes(&config, issi, TdmaTime::default())
            .into_iter()
            .next()
            .expect("active call route");
        assert_eq!(route.call_id, 7);
        assert_eq!(route.timeslot, 2);
        assert_eq!(route.usage, 10);
    }

    #[test]
    fn discarded_associated_downlink_retries_over_mcch() {
        let config = test_config();
        let issi = 77_468;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        config.state_write().subscriber_delivery_routes.insert(
            issi,
            vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                call_id: 7,
                timeslot: 2,
                usage: 10,
            }],
        );

        let mut llc = Llc::new(config.clone());
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let first = queue.pop_front().expect("associated attempt queued");
        let SapMsgInner::TmaUnitdataReq(first) = first.msg else {
            panic!("expected TMA request")
        };
        assert_eq!(first.associated_channel.map(|route| route.timeslot), Some(2));

        let mcch = queue.pop_front().expect("concurrent MCCH attempt queued");
        let SapMsgInner::TmaUnitdataReq(mcch) = mcch.msg else {
            panic!("expected TMA request")
        };
        assert!(mcch.associated_channel.is_none());

        // UMAC removes both queued copies before transmission. Once the
        // traffic route disappears, the next attempt must contain MCCH only.
        llc.outbound_messages[0].attempt_reporters[0].mark_discarded();
        llc.outbound_messages[0].attempt_reporters[1].mark_discarded();
        config.state_write().subscriber_delivery_routes.remove(&issi);
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        llc.dltime = llc.dltime.add_timeslots(retry_timer as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));

        let retry = queue.pop_front().expect("MCCH retry queued");
        let SapMsgInner::TmaUnitdataReq(retry) = retry.msg else {
            panic!("expected TMA retry")
        };
        assert!(retry.associated_channel.is_none());
        assert_eq!(llc.outbound_messages[0].retransmit_count, 1);
    }

    #[test]
    fn explicit_associated_downlink_survives_direct_response_window() {
        let config = test_config();
        let issi = 77_479;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        {
            let mut state = config.state_write();
            state.subscribers.mark_direct_response_window(issi, start);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 8,
                    timeslot: 3,
                    usage: 11,
                }],
            );
        }

        let mut llc = Llc::new(config.clone());
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: Some(tetra_saps::tma::AssociatedChannel {
                        call_id: 8,
                        timeslot: 3,
                        usage: 11,
                        best_effort_key: None,
                    }),
                    tx_reporter: None,
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let first = queue.pop_front().expect("associated attempt queued");
        let SapMsgInner::TmaUnitdataReq(first) = first.msg else {
            panic!("expected TMA request")
        };
        assert_eq!(first.associated_channel.map(|route| route.timeslot), Some(3));
        let mcch = queue.pop_front().expect("concurrent MCCH attempt queued");
        let SapMsgInner::TmaUnitdataReq(mcch) = mcch.msg else {
            panic!("expected TMA request")
        };
        assert!(mcch.associated_channel.is_none());
        assert!(Llc::delivery_routes(&config, issi, start).is_empty());

        llc.outbound_messages[0].attempt_reporters[0].mark_transmitted();
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        assert_eq!(retry_timer, T251_SENDER_RETRY_TIMER * 18);

        // One elapsed multiframe is only one downlink signalling frame on
        // SACCH. In particular, it must not reproduce the live premature
        // retry that used to add another fragmented SDS after this delay.
        let one_sacch_opportunity = tetra_core::frames!(18);
        llc.dltime = llc.dltime.add_timeslots(one_sacch_opportunity);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));

        llc.dltime = llc.dltime.add_timeslots((retry_timer - one_sacch_opportunity as u32) as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));

        let retry_route = queue.pop_front().expect("traffic retry queued");
        let SapMsgInner::TmaUnitdataReq(retry_route) = retry_route.msg else {
            panic!("expected TMA retry")
        };
        assert_eq!(retry_route.associated_channel.map(|route| route.timeslot), Some(3));
        let retry_mcch = queue.pop_front().expect("MCCH retry queued");
        let SapMsgInner::TmaUnitdataReq(retry_mcch) = retry_mcch.msg else {
            panic!("expected TMA retry")
        };
        assert!(retry_mcch.associated_channel.is_none());
    }

    #[test]
    fn acknowledged_downlink_fans_out_over_scan_list_routes_and_mcch() {
        let config = test_config();
        let issi = 77_468;
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        config.state_write().subscriber_delivery_routes.insert(
            issi,
            vec![
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 9,
                    timeslot: 4,
                    usage: 12,
                },
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 8,
                    timeslot: 3,
                    usage: 11,
                },
                tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                },
            ],
        );

        let mut llc = Llc::new(config.clone());
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: TetraAddress::issi(issi),
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: None,
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        let mut initial_timeslots = Vec::new();
        while let Some(message) = queue.pop_front() {
            let SapMsgInner::TmaUnitdataReq(request) = message.msg else {
                panic!("expected TMA request")
            };
            initial_timeslots.push(request.associated_channel.map(|route| route.timeslot));
        }
        assert_eq!(initial_timeslots, vec![Some(4), Some(3), Some(2), None]);
        assert_eq!(llc.outbound_messages[0].attempt_reporters.len(), 4);
        assert!(
            llc.outbound_messages[0]
                .attempt_reporters
                .iter()
                .all(|reporter| reporter.get_state() == tetra_core::TxState::Pending)
        );

        // The first route starts T.251, but the other copies may still be
        // queued or fragmented on their own bearers.
        llc.outbound_messages[0].attempt_reporters[0].mark_transmitted();
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        assert_eq!(llc.outbound_messages[0].t_umac_done, Some(llc.dltime));
        assert!(llc.outbound_messages[0].tx_reporter.is_transmitted());

        let first_completion = llc.dltime;
        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        llc.dltime = first_completion.add_timeslots(retry_timer as i32);
        assert!(
            !llc.submit_retransmissions_to_umac(&mut queue),
            "an unfinished concurrent route must not be cut off at the first copy's T.251 boundary"
        );

        // A later complete copy restarts T.251. Once all remaining copies are
        // done, a retry is allowed only after that fresh interval.
        llc.outbound_messages[0].attempt_reporters[1].mark_transmitted();
        llc.outbound_messages[0].attempt_reporters[2].mark_discarded();
        llc.outbound_messages[0].attempt_reporters[3].mark_discarded();
        llc.dltime = llc.dltime.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        let latest_completion = llc.dltime;
        assert_eq!(llc.outbound_messages[0].t_umac_done, Some(latest_completion));

        let old_attempt_reporters = llc.outbound_messages[0].attempt_reporters.clone();
        llc.dltime = latest_completion.add_timeslots(retry_timer as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));
        assert_eq!(llc.outbound_messages[0].retransmit_count, 1);
        assert!(old_attempt_reporters[2..].iter().all(TxReporter::is_discarded));
        let mut retry_copies = 0;
        while queue.pop_front().is_some() {
            retry_copies += 1;
        }
        assert_eq!(retry_copies, 4);

        let ack = &mut llc.outbound_messages[0];
        ack.retransmit_count = 2;
        Llc::submit_for_acknowledged_transmission(&config, &mut queue, ack, start);
        let mut copies = 0;
        while queue.pop_front().is_some() {
            copies += 1;
        }
        assert_eq!(copies, 4, "every retry must cover all plausible bearers again");
    }

    #[test]
    fn delayed_ack_for_transmitted_attempt_survives_queued_retry() {
        let config = test_config();
        let issi = 77_479;
        let addr = TetraAddress::issi(issi);
        let start = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        config.state_write().subscriber_delivery_routes.insert(
            issi,
            vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                call_id: 8,
                timeslot: 2,
                usage: 11,
            }],
        );

        let reporter = TxReporter::new();
        let mut llc = Llc::new(config);
        llc.dltime = start;
        let mut queue = MessageQueue::new();
        llc.rx_tla_tldata_req_bl(
            &mut queue,
            SapMsg::new(
                Sap::TlaSap,
                TetraEntity::Mle,
                TetraEntity::Llc,
                SapMsgInner::TlaTlDataReqBl(tetra_saps::tla::TlaTlDataReqBl {
                    main_address: addr,
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: BitBuffer::from_bitstr("1010"),
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    packet_data_flag: false,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0,
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: Some(reporter.clone()),
                }),
            ),
        );
        assert!(llc.submit_free_messages_to_umac(&mut queue));
        queue.pop_front().expect("first attempt queued");
        queue.pop_front().expect("concurrent MCCH attempt queued");

        llc.outbound_messages[0].attempt_reporters[0].mark_transmitted();
        llc.dltime = start.add_timeslots(1);
        assert!(!llc.submit_retransmissions_to_umac(&mut queue));
        assert!(llc.outbound_messages[0].has_transmitted_attempt);

        let retry_timer = Llc::basic_link_retry_timer(&llc.outbound_messages[0]);
        llc.dltime = llc.dltime.add_timeslots(retry_timer as i32);
        assert!(llc.submit_retransmissions_to_umac(&mut queue));
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);

        let redundant_copies = llc.outbound_messages[0].attempt_reporters.clone();
        llc.process_incoming_ack(addr, 0, AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacData));
        assert!(llc.outbound_messages.is_empty());
        assert_eq!(reporter.get_state(), tetra_core::TxState::Acknowledged);
        assert!(redundant_copies.iter().all(TxReporter::is_discarded));
    }

    #[test]
    fn direct_mac_access_response_stays_on_mcch() {
        let config = test_config();
        let issi = 0x12_34_56;
        let now = TdmaTime::default();
        {
            let mut state = config.state_write();
            state.subscribers.mark_direct_response_window(issi, now);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                }],
            );
        }

        assert!(Llc::delivery_routes(&config, issi, now).is_empty());
    }

    #[test]
    fn registration_delivery_stays_on_mcch_after_direct_response_window() {
        let config = test_config();
        let issi = 0x12_34_56;
        let now = TdmaTime::default();
        {
            let mut state = config.state_write();
            state.subscribers.set_registration_delivery_pending(issi, true);
            state.subscriber_delivery_routes.insert(
                issi,
                vec![tetra_config::bluestation::SubscriberDeliveryRoute {
                    call_id: 7,
                    timeslot: 2,
                    usage: 10,
                }],
            );
        }

        assert!(Llc::delivery_routes(&config, issi, now.add_timeslots(500)).is_empty());
    }

    #[test]
    fn final_common_channel_ack_gets_one_frame_of_grace_after_retry_exhaustion() {
        let retry_timer = T251_SENDER_RETRY_TIMER;
        assert!(!Llc::final_ack_grace_elapsed(retry_timer as i32, retry_timer, false));
        assert!(!Llc::final_ack_grace_elapsed(
            (retry_timer + COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS - 1) as i32,
            retry_timer,
            false,
        ));
        assert!(Llc::final_ack_grace_elapsed(
            (retry_timer + COMMON_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS) as i32,
            retry_timer,
            false,
        ));
    }

    #[test]
    fn final_assigned_channel_ack_survives_mcch_random_access_window() {
        let retry_timer = T251_SENDER_RETRY_TIMER * ASSIGNED_CHANNEL_ACK_RETRY_TIMER_MULTIPLIER;
        let observed_late_ack_age = retry_timer + 3 * 18 * 4;
        assert!(
            !Llc::final_ack_grace_elapsed(observed_late_ack_age as i32, retry_timer, true),
            "a BL-ACK returning through MCCH after a call edge must remain associated with its delivery"
        );
        assert!(Llc::final_ack_grace_elapsed(
            (retry_timer + ASSIGNED_CHANNEL_FINAL_ACK_GRACE_TIMESLOTS) as i32,
            retry_timer,
            true,
        ));
    }

    #[test]
    fn discarded_final_attempt_reports_lost_without_panicking() {
        let reporter = TxReporter::new();
        reporter.mark_discarded();

        Llc::mark_reporter_lost(&reporter);

        assert_eq!(reporter.get_state(), tetra_core::TxState::Lost);
    }
}
