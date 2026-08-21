use std::collections::{HashMap, HashSet};

use tetra_config::bluestation::SharedConfig;
use tetra_core::{BitBuffer, Direction, Sap, SsiType, TdmaTime, TetraAddress, tetra_entities::TetraEntity, unimplemented_log};
use tetra_core::{Layer2Service, TimeslotOwner, TxReporter, TxState};
use tetra_pdus::cmce::enums::disconnect_cause::DisconnectCause;
use tetra_pdus::cmce::{
    enums::{
        call_timeout::CallTimeout, call_timeout_setup_phase::CallTimeoutSetupPhase, cmce_pdu_type_ul::CmcePduTypeUl,
        party_type_identifier::PartyTypeIdentifier, transmission_grant::TransmissionGrant,
    },
    fields::basic_service_information::BasicServiceInformation,
    pdus::{
        d_alert::DAlert, d_call_proceeding::DCallProceeding, d_connect::DConnect, d_connect_acknowledge::DConnectAcknowledge,
        d_info::DInfo, d_release::DRelease, d_setup::DSetup, d_tx_ceased::DTxCeased, d_tx_granted::DTxGranted, d_tx_wait::DTxWait,
        u_alert::UAlert, u_connect::UConnect, u_disconnect::UDisconnect, u_release::URelease, u_setup::USetup, u_tx_ceased::UTxCeased,
        u_tx_demand::UTxDemand,
    },
    structs::cmce_circuit::CmceCircuit,
};
use tetra_saps::{
    SapMsg, SapMsgInner,
    control::{
        brew::{BrewSubscriberAction, MmSubscriberUpdate},
        call_control::{CallControl, Circuit},
        enums::{circuit_mode_type::CircuitModeType, communication_type::CommunicationType},
    },
    lcmc::{
        LcmcMleUnitdataReq,
        enums::{alloc_type::ChanAllocType, ul_dl_assignment::UlDlAssignment},
        fields::chan_alloc_req::CmceChanAllocReq,
    },
};

use crate::net_brew;
use crate::net_swmi::SwmiCmceEndpoint;
use crate::{
    MessageQueue,
    cmce::components::circuit_mgr::{CircuitMgr, CircuitMgrCmd},
};
use tetra_swmi_protocol::SwmiMessage;

/// Clause 11 Call Control CMCE sub-entity
pub struct CcBsSubentity {
    config: SharedConfig,
    dltime: TdmaTime,
    /// Cached D-SETUP PDUs for late-entry re-sends: call_id -> (D-SETUP PDU, dest address, tx reporter)
    cached_setups: HashMap<u16, (DSetup, TetraAddress, Option<TxReporter>)>,
    circuits: CircuitMgr,
    /// Active group calls: call_id -> call info
    active_calls: HashMap<u16, ActiveCall>,
    /// Registered subscriber groups (ISSI -> set of GSSIs)
    subscriber_groups: HashMap<u32, HashSet<u32>>,
    /// Listener counts per GSSI
    group_listeners: HashMap<u32, usize>,
    /// Calls whose D-RELEASE has been sent and whose circuit teardown is deferred a few
    /// frames so the stolen D-RELEASE transmits. These are no longer in active_calls.
    releasing_calls: Vec<ReleasingCall>,
    /// Central SwMI control endpoint; absence or disconnection selects LST.
    swmi: Option<SwmiCmceEndpoint>,
    pending_swmi_setups: HashMap<(u32, u32), SapMsg>,
    central_setup_call_ids: HashMap<(u32, u32), u16>,
    central_setup_call_floors: HashMap<(u32, u32), u32>,
    /// GroupCallStart may arrive at CMCE before MM has applied the matching
    /// attachment decision because the SwMI worker fans messages out to two
    /// independent queues. Keep it until the local listener exists.
    pending_remote_swmi_calls: HashMap<u16, (u32, u32, u32)>,
    next_swmi_command: u64,
    /// Point-to-point calls are intentionally kept separate from group
    /// `active_calls`: a same-cell P2P call has two radio circuits sharing
    /// one call identifier.
    private_calls: HashMap<u16, PrivateCallLocal>,
    pending_private_setups: HashMap<u32, SapMsg>,
    private_circuits: HashMap<(u16, u32), CmceCircuit>,
    /// P2P circuits whose D-RELEASE has been stolen onto FACCH.  Keep their
    /// RF resources alive briefly so the addressed release reaches the MS.
    releasing_private_circuits: Vec<ReleasingPrivateCircuit>,
}

/// Origin of a group call
#[derive(Clone)]
enum CallOrigin {
    /// Local MS-initiated call, needs MLE routing for individual addressing
    Local {
        caller_addr: TetraAddress, // For D-CALL-PROCEEDING, D-CONNECT routing
    },
    /// Network-initiated call from TetraPack/Brew
    Network {
        brew_uuid: uuid::Uuid, // For Brew tracking
    },
    /// A call whose identifier and authority originate at the central SwMI.
    Swmi,
}

/// A call being released. The call is removed from active_calls when this is created, so
/// it cannot be re-keyed or reused. D-RELEASE is stolen onto the traffic channel (it only
/// transmits while the slot is in traffic mode) at sent_at, then the circuit is closed a
/// couple frames later. Carries everything teardown needs, since the active_calls entry is
/// already gone.
struct ReleasingCall {
    call_id: u16,
    ts: u8,
    dest_gssi: u32,
    is_local: bool,
    brew_uuid: Option<uuid::Uuid>,
    sent_at: TdmaTime,
}

struct ReleasingPrivateCircuit {
    call_id: u16,
    itsi: u32,
    circuit: CmceCircuit,
    sent_at: TdmaTime,
}

/// Tracks an active group call (local or network-initiated)
#[derive(Clone)]
struct ActiveCall {
    origin: CallOrigin,
    dest_gssi: u32,   // Destination group
    source_issi: u32, // Current speaker
    ts: u8,
    usage: u8,
    /// True if someone is currently transmitting
    tx_active: bool,
    /// When PTT was released (for hangtime). None if transmitting.
    hangtime_start: Option<TdmaTime>,
    /// Brew session UUID — set when a network speaker is active on this call,
    /// regardless of call origin. Cleared when the network speaker ends.
    brew_uuid: Option<uuid::Uuid>,
}

#[derive(Clone)]
struct PrivateCallLocal {
    caller_itsi: u32,
    callee_itsi: u32,
    hook: bool,
    duplex: bool,
    request_to_transmit: bool,
    priority: u8,
    connected: bool,
    local_mask: u8,
}

impl CcBsSubentity {
    pub fn new(config: SharedConfig, swmi: Option<SwmiCmceEndpoint>) -> Self {
        CcBsSubentity {
            config,
            dltime: TdmaTime::default(),
            cached_setups: HashMap::new(),
            circuits: CircuitMgr::new(),
            active_calls: HashMap::new(),
            subscriber_groups: HashMap::new(),
            group_listeners: HashMap::new(),
            releasing_calls: Vec::new(),
            swmi,
            pending_swmi_setups: HashMap::new(),
            central_setup_call_ids: HashMap::new(),
            central_setup_call_floors: HashMap::new(),
            pending_remote_swmi_calls: HashMap::new(),
            next_swmi_command: 1,
            private_calls: HashMap::new(),
            pending_private_setups: HashMap::new(),
            private_circuits: HashMap::new(),
            releasing_private_circuits: Vec::new(),
        }
    }

    pub fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn build_d_setup_prim(pdu: &DSetup, usage: u8, ts: u8, ul_dl: UlDlAssignment) -> (BitBuffer, CmceChanAllocReq) {
        let mut sdu = BitBuffer::new_autoexpand(80);
        pdu.to_bitbuf(&mut sdu).expect("Failed to serialize DSetup");
        sdu.seek(0);
        tracing::info!("-> {:?} sdu {}", pdu, sdu.dump_bin());

        // Construct ChanAlloc descriptor for the allocated timeslot
        let mut timeslots = [false; 4];
        timeslots[ts as usize - 1] = true;
        let chan_alloc = CmceChanAllocReq {
            usage: Some(usage),
            alloc_type: ChanAllocType::Replace,
            carrier: None,
            timeslots,
            ul_dl_assigned: ul_dl,
        };
        (sdu, chan_alloc)
    }

    fn build_sapmsg(
        sdu: BitBuffer,
        chan_alloc: Option<CmceChanAllocReq>,
        address: TetraAddress,
        layer2service: Layer2Service,
        reporter: Option<TxReporter>,
    ) -> SapMsg {
        // Construct prim
        SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: 0,
                endpoint_id: 0,
                link_id: 0,
                layer2service,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc,
                main_address: address,
                tx_reporter: reporter,
            }),
        }
    }

    fn build_sapmsg_stealing(sdu: BitBuffer, address: TetraAddress, ts: u8) -> SapMsg {
        // For FACCH stealing on traffic channel, must specify target timeslot
        let mut timeslots = [false; 4];
        timeslots[(ts - 1) as usize] = true;
        let chan_alloc = CmceChanAllocReq {
            usage: None,
            carrier: None,
            timeslots,
            alloc_type: ChanAllocType::Replace,
            ul_dl_assigned: UlDlAssignment::Both,
        };

        SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: 0,
                endpoint_id: 0,
                link_id: 0,
                layer2service: Layer2Service::Unacknowledged, // TODO FIXME check if indeed only unacked over STCH
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: true,
                stealing_repeats_flag: false,
                chan_alloc: Some(chan_alloc),
                main_address: address,
                tx_reporter: None,
            }),
        }
    }

    fn build_d_release_from_d_setup(d_setup_pdu: &DSetup, disconnect_cause: DisconnectCause) -> BitBuffer {
        let pdu = DRelease {
            call_identifier: d_setup_pdu.call_identifier,
            disconnect_cause,
            notification_indicator: None,
            facility: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).expect("Failed to serialize DRelease");
        sdu.seek(0);
        tracing::info!("-> {:?} sdu {}", pdu, sdu.dump_bin());

        sdu
    }

    fn has_listener(&self, gssi: u32) -> bool {
        self.group_listeners.get(&gssi).copied().unwrap_or(0) > 0
    }

    fn inc_group_listener(&mut self, gssi: u32) {
        let entry = self.group_listeners.entry(gssi).or_insert(0);
        *entry += 1;
    }

    fn dec_group_listener(&mut self, gssi: u32) {
        if let Some(entry) = self.group_listeners.get_mut(&gssi) {
            if *entry <= 1 {
                self.group_listeners.remove(&gssi);
            } else {
                *entry -= 1;
            }
        }
    }

    fn activate_pending_remote_swmi_calls(&mut self, queue: &mut MessageQueue, groups: &[u32]) {
        let pending: Vec<_> = self
            .pending_remote_swmi_calls
            .iter()
            .filter(|(_, (_, gssi, _))| groups.contains(gssi) && self.has_listener(*gssi))
            .map(|(call_id, (owner_itsi, gssi, floor_itsi))| (*call_id, *owner_itsi, *gssi, *floor_itsi))
            .collect();
        for (call_id, owner_itsi, gssi, floor_itsi) in pending {
            self.pending_remote_swmi_calls.remove(&call_id);
            self.start_remote_swmi_call(queue, call_id, owner_itsi, gssi, floor_itsi);
        }
    }

    fn drop_group_calls_if_unlistened(&mut self, queue: &mut MessageQueue, gssi: u32) {
        if self.has_listener(gssi) {
            return;
        }

        let to_drop: Vec<(u16, CallOrigin)> = self
            .active_calls
            .iter()
            .filter(|(_, call)| call.dest_gssi == gssi)
            .map(|(call_id, call)| (*call_id, call.origin.clone()))
            .collect();

        for (call_id, origin) in to_drop {
            tracing::info!("CMCE: dropping call_id={} gssi={} (no listeners)", call_id, gssi);
            if let CallOrigin::Network { brew_uuid } = origin {
                if net_brew::is_brew_gssi_routable(&self.config, gssi) {
                    queue.push_back(SapMsg {
                        sap: Sap::Control,
                        src: TetraEntity::Cmce,
                        dest: TetraEntity::Brew,
                        msg: SapMsgInner::CmceCallControl(CallControl::NetworkCallEnd { brew_uuid }),
                    });
                };
            };
            self.release_call(queue, call_id, DisconnectCause::SwmiRequestedDisconnection);
        }
    }

    pub fn handle_subscriber_update(&mut self, queue: &mut MessageQueue, update: MmSubscriberUpdate) {
        let issi = update.issi;
        let groups = update.groups;

        match update.action {
            BrewSubscriberAction::Register => {
                let known = self.subscriber_groups.contains_key(&issi);
                self.subscriber_groups.entry(issi).or_insert_with(HashSet::new);
                tracing::info!("CMCE: subscriber register issi={} known={}", issi, known);
            }
            BrewSubscriberAction::Deregister => {
                if let Some(existing) = self.subscriber_groups.remove(&issi) {
                    for gssi in existing {
                        self.dec_group_listener(gssi);
                        self.drop_group_calls_if_unlistened(queue, gssi);
                    }
                }
                tracing::info!("CMCE: subscriber deregister issi={}", issi);
            }
            BrewSubscriberAction::Affiliate => {
                let mut new_groups = Vec::new();
                {
                    let entry = self.subscriber_groups.entry(issi).or_insert_with(HashSet::new);
                    for gssi in groups {
                        if entry.insert(gssi) {
                            new_groups.push(gssi);
                        }
                    }
                }
                for gssi in &new_groups {
                    self.inc_group_listener(*gssi);
                }
                self.activate_pending_remote_swmi_calls(queue, &new_groups);

                if new_groups.is_empty() {
                    tracing::debug!("CMCE: affiliate ignored (no new groups) issi={}", issi);
                } else {
                    tracing::info!("CMCE: subscriber affiliate issi={} groups={:?}", issi, new_groups);
                }
            }
            BrewSubscriberAction::Deaffiliate => {
                let mut removed_groups = Vec::new();
                let mut known_issi = false;
                if let Some(entry) = self.subscriber_groups.get_mut(&issi) {
                    known_issi = true;
                    for gssi in groups {
                        if entry.remove(&gssi) {
                            removed_groups.push(gssi);
                        }
                    }
                } else {
                    removed_groups = groups;
                }
                if known_issi {
                    for gssi in &removed_groups {
                        self.dec_group_listener(*gssi);
                    }
                }

                if removed_groups.is_empty() {
                    tracing::debug!("CMCE: deaffiliate ignored (no matching groups) issi={}", issi);
                } else {
                    tracing::info!("CMCE: subscriber deaffiliate issi={} groups={:?}", issi, removed_groups);
                    for gssi in &removed_groups {
                        self.drop_group_calls_if_unlistened(queue, *gssi);
                    }
                }
            }
        }
    }

    fn send_d_call_proceeding(&mut self, queue: &mut MessageQueue, message: &SapMsg, pdu_request: &USetup, call_id: u16) {
        tracing::trace!("send_d_call_proceeding");

        let SapMsgInner::LcmcMleUnitdataInd(prim) = &message.msg else {
            panic!()
        };

        let pdu_response = DCallProceeding {
            call_identifier: call_id,
            call_time_out_set_up_phase: CallTimeoutSetupPhase::T10s,
            hook_method_selection: pdu_request.hook_method_selection,
            simplex_duplex_selection: pdu_request.simplex_duplex_selection,
            basic_service_information: None, // Only needed if different from requested
            call_status: None,
            notification_indicator: None,
            facility: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(25);
        pdu_response.to_bitbuf(&mut sdu).expect("Failed to serialize DCallProceeding");
        sdu.seek(0);
        tracing::info!("-> {:?} sdu {}", pdu_response, sdu.dump_bin());

        let msg = SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: prim.handle,
                endpoint_id: prim.endpoint_id,
                link_id: prim.link_id,
                layer2service: Layer2Service::Acknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,

                chan_alloc: None,
                main_address: prim.received_tetra_address,
                tx_reporter: None,
            }),
        };
        queue.push_back(msg);
    }

    /// Complete a U-SETUP for a circuit that is already active locally.
    ///
    /// A terminal may join a group call after the central SwMI call has
    /// already created the local radio circuit.  In that case the terminal
    /// needs an individually addressed D-CALL-PROCEEDING/D-CONNECT, but it
    /// must not cause another CMCE circuit or another D-SETUP to be created.
    fn connect_u_setup_to_existing_call(
        &mut self,
        queue: &mut MessageQueue,
        message: &SapMsg,
        pdu: &USetup,
        calling_party: TetraAddress,
        call_id: u16,
        ts: u8,
        usage: u8,
        transmission_grant: TransmissionGrant,
        call_ownership: bool,
    ) {
        self.send_d_call_proceeding(queue, message, pdu, call_id);

        let SapMsgInner::LcmcMleUnitdataInd(prim) = &message.msg else {
            panic!()
        };

        let mut timeslots = [false; 4];
        timeslots[ts as usize - 1] = true;

        let d_connect = DConnect {
            call_identifier: call_id,
            call_time_out: CallTimeout::T5m,
            hook_method_selection: pdu.hook_method_selection,
            simplex_duplex_selection: pdu.simplex_duplex_selection,
            transmission_grant,
            transmission_request_permission: false,
            call_ownership,
            call_priority: None,
            basic_service_information: None,
            temporary_address: None,
            notification_indicator: None,
            facility: None,
            proprietary: None,
        };

        let mut connect_sdu = BitBuffer::new_autoexpand(30);
        d_connect.to_bitbuf(&mut connect_sdu).expect("Failed to serialize DConnect");
        connect_sdu.seek(0);
        tracing::info!(
            ?d_connect,
            itsi = calling_party.ssi,
            ts,
            usage,
            "connecting U-SETUP to existing group call"
        );

        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu: connect_sdu,
                handle: prim.handle,
                endpoint_id: prim.endpoint_id,
                link_id: prim.link_id,
                layer2service: Layer2Service::Unacknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: Some(CmceChanAllocReq {
                    usage: Some(usage),
                    alloc_type: ChanAllocType::Replace,
                    carrier: None,
                    timeslots,
                    ul_dl_assigned: UlDlAssignment::Both,
                }),
                main_address: calling_party,
                tx_reporter: None,
            }),
        });
    }

    fn next_swmi_command_id(&mut self) -> u64 {
        let value = self.next_swmi_command;
        self.next_swmi_command = self.next_swmi_command.wrapping_add(1).max(1);
        value
    }

    /// A rejected U-SETUP has no assigned call identifier yet, so the
    /// standardized dummy all-zero call identifier is used in D-RELEASE.
    fn send_d_release_for_setup_reject(&mut self, queue: &mut MessageQueue, message: &SapMsg, cause: DisconnectCause) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &message.msg else {
            panic!()
        };
        let pdu = DRelease {
            call_identifier: 0,
            disconnect_cause: cause,
            notification_indicator: None,
            facility: None,
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut sdu).expect("serialize setup rejection D-RELEASE");
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: prim.handle,
                endpoint_id: prim.endpoint_id,
                link_id: prim.link_id,
                layer2service: Layer2Service::Unacknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None,
                main_address: prim.received_tetra_address,
                tx_reporter: None,
            }),
        });
        tracing::info!(issi = prim.received_tetra_address.ssi, ?cause, "rejected U-SETUP sent as D-RELEASE");
    }

    /// D-TX WAIT is the explicit response to a floor request while another
    /// user transmits.  Dropping U-TX DEMAND makes the PTT appear dead.
    fn send_d_tx_wait(&mut self, queue: &mut MessageQueue, message: &SapMsg, call_id: u16) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &message.msg else {
            panic!()
        };
        let pdu = DTxWait {
            call_identifier: call_id,
            transmission_request_permission: true,
            notification_indicator: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut sdu).expect("serialize D-TX WAIT");
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: prim.handle,
                endpoint_id: prim.endpoint_id,
                link_id: prim.link_id,
                layer2service: Layer2Service::Unacknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None,
                main_address: prim.received_tetra_address,
                tx_reporter: None,
            }),
        });
        tracing::info!(
            issi = prim.received_tetra_address.ssi,
            call_id,
            "U-TX DEMAND deferred with D-TX WAIT"
        );
    }

    fn signal_umac_circuit_open(queue: &mut MessageQueue, call: &CmceCircuit) {
        let circuit = Circuit {
            direction: call.direction,
            ts: call.ts,
            usage: call.usage,
            circuit_mode: call.circuit_mode,
            speech_service: call.speech_service,
            etee_encrypted: call.etee_encrypted,
        };
        let cmd = SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::Open(circuit)),
        };
        queue.push_back(cmd);
    }

    fn signal_umac_circuit_close(queue: &mut MessageQueue, circuit: CmceCircuit) {
        let cmd = SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::Close(circuit.direction, circuit.ts)),
        };
        queue.push_back(cmd);
    }

    fn rx_u_setup(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_u_setup: {:?}", message);
        // `USetup::from_bitbuf` consumes the PDU cursor.  In network mode the
        // request is resumed only after the SwMI allocated a call id, so retain
        // an untouched copy for that asynchronous continuation.
        let original_message = message.clone();
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let calling_party = prim.received_tetra_address;

        let pdu = match USetup::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing U-SETUP: {:?} {}", e, prim.sdu.dump_bin());
                return;
            }
        };

        // Individual calls are always SwMI-authoritative in network mode.
        // Handle this before the legacy group feature checks, which correctly
        // reject hook/duplex only for the current P2MP implementation.
        if pdu.basic_service_information.communication_type == CommunicationType::P2p {
            self.rx_private_u_setup(queue, original_message, calling_party, pdu);
            return;
        }

        // Check if we can satisfy this request
        if !Self::feature_check_u_setup(&pdu) {
            tracing::error!("Unsupported critical features in USetup");
            return;
        }

        // Get destination GSSI (called party)
        let Some(dest_gssi) = pdu.called_party_ssi else {
            tracing::warn!("U-SETUP without called_party_ssi, ignoring");
            return;
        };
        let dest_gssi = dest_gssi as u32;
        let dest_addr = TetraAddress::new(dest_gssi, SsiType::Gssi);

        if !self.has_listener(dest_gssi) {
            tracing::info!(
                "CMCE: rejecting U-SETUP from issi={} to gssi={} (no listeners)",
                calling_party.ssi,
                dest_gssi
            );
            // TS 100 392-2 §14.5.1.3.2: do not leave a caller waiting for a
            // setup timer when the requested group cannot be served.
            self.send_d_release_for_setup_reject(queue, &message, DisconnectCause::RequestedServiceNotAvailable);
            return;
        }

        let setup_key = (calling_party.ssi, dest_gssi);
        let central_call_id = self.central_setup_call_ids.remove(&setup_key);
        let central_floor_itsi = self.central_setup_call_floors.remove(&setup_key);
        // A new central call grants its initial floor to the setup caller. A
        // setup resumed for an existing call uses the floor state carried by
        // the SwMI; the joining MS must not transmit while another MS owns it.
        let caller_has_central_floor = central_call_id.is_none() || central_floor_itsi == Some(calling_party.ssi);
        let another_central_speaker = central_floor_itsi.is_some_and(|floor_itsi| floor_itsi != 0 && floor_itsi != calling_party.ssi);

        // The SwMI may accept this request while this BS already has the
        // group's central circuit open.  The first implementation allocated
        // a second circuit here, then overwrote active_calls[call_id] while
        // leaving the original circuit (and its timeslot) in CircuitMgr.
        // Reuse the existing circuit instead.
        let existing_call = self
            .active_calls
            .iter()
            .find(|(_, call)| call.dest_gssi == dest_gssi)
            .map(|(&call_id, call)| (call_id, call.clone()));
        if let Some((existing_call_id, existing_call)) = existing_call {
            let central_call_matches = central_call_id.is_none_or(|call_id| call_id == existing_call_id);
            if central_call_matches && (central_call_id.is_some() || self.swmi.as_ref().is_none_or(|swmi| !swmi.is_online())) {
                let floor_itsi = central_floor_itsi.unwrap_or_else(|| if existing_call.tx_active { existing_call.source_issi } else { 0 });
                let caller_has_floor = floor_itsi == 0 || floor_itsi == calling_party.ssi;
                let grant = if caller_has_floor {
                    TransmissionGrant::Granted
                } else {
                    TransmissionGrant::GrantedToOtherUser
                };
                self.connect_u_setup_to_existing_call(
                    queue,
                    &message,
                    &pdu,
                    calling_party,
                    existing_call_id,
                    existing_call.ts,
                    existing_call.usage,
                    grant,
                    caller_has_floor,
                );
                return;
            }
        }

        if self.swmi.as_ref().is_some_and(SwmiCmceEndpoint::is_online) && central_call_id.is_none() {
            let command_id = self.next_swmi_command_id();
            let submitted = self.swmi.as_ref().expect("checked above").submit(SwmiMessage::GroupCallRequest {
                command_id,
                itsi: calling_party.ssi as u64,
                gssi: dest_gssi,
                priority: pdu.call_priority,
            });
            if submitted.is_ok() {
                // The SwMI allocates the one shared 14-bit call id.  Retain
                // the original RF request so D-CALL-PROCEEDING/D-CONNECT can
                // be emitted only after that decision returns.
                self.pending_swmi_setups.insert(setup_key, original_message);
                tracing::info!(
                    itsi = calling_party.ssi,
                    gssi = dest_gssi,
                    command_id,
                    "group call request forwarded to SwMI"
                );
                return;
            }
            tracing::warn!(
                itsi = calling_party.ssi,
                gssi = dest_gssi,
                "SwMI request queue unavailable; retaining local-site trunking"
            );
        }

        // Allocate circuit (DL+UL for group call)
        let circuit = match {
            let mut state = self.config.state_write();
            match central_call_id {
                Some(call_id) => self.circuits.allocate_circuit_with_allocator_and_call_id(
                    Direction::Both,
                    pdu.basic_service_information.communication_type,
                    &mut state.timeslot_alloc,
                    TimeslotOwner::Cmce,
                    call_id,
                ),
                None => self.circuits.allocate_circuit_with_allocator(
                    Direction::Both,
                    pdu.basic_service_information.communication_type,
                    &mut state.timeslot_alloc,
                    TimeslotOwner::Cmce,
                ),
            }
        } {
            Ok(circuit) => circuit.clone(),
            Err(e) => {
                tracing::error!("Failed to allocate circuit for U-SETUP: {:?}", e);
                return;
            }
        };

        tracing::info!(
            "rx_u_setup: call from ISSI {} to GSSI {} → ts={} call_id={} usage={}",
            calling_party.ssi,
            dest_gssi,
            circuit.ts,
            circuit.call_id,
            circuit.usage
        );

        // Signal UMAC to open DL+UL circuits
        Self::signal_umac_circuit_open(queue, &circuit);

        // === 1) Send D-CALL-PROCEEDING and D-CONNECT to the calling MS ===
        // This acknowledges the U-SETUP and keeps the radio on the existing
        // call before the group D-SETUP is sent.
        self.connect_u_setup_to_existing_call(
            queue,
            &message,
            &pdu,
            calling_party,
            circuit.call_id,
            circuit.ts,
            circuit.usage,
            if caller_has_central_floor {
                TransmissionGrant::Granted
            } else if another_central_speaker {
                TransmissionGrant::GrantedToOtherUser
            } else {
                TransmissionGrant::NotGranted
            },
            caller_has_central_floor,
        );

        // === 3) Send D-SETUP to group (broadcast on MCCH with channel allocation) ===
        // GrantedToOtherUser tells other group members that someone else has the floor.
        let d_setup = DSetup {
            call_identifier: circuit.call_id,
            call_time_out: CallTimeout::T5m,
            hook_method_selection: pdu.hook_method_selection,
            simplex_duplex_selection: pdu.simplex_duplex_selection,
            basic_service_information: pdu.basic_service_information.clone(),
            transmission_grant: TransmissionGrant::GrantedToOtherUser,
            transmission_request_permission: false,
            call_priority: pdu.call_priority,
            notification_indicator: None,
            temporary_address: None,
            calling_party_address_ssi: Some(calling_party.ssi),
            calling_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };

        // Cache for late-entry re-sends. Receipt starts as None so the CircuitMgr-triggered
        // backup send (within D_SETUP_REPEATS frames) is not throttled by this initial send.
        // The first re-send via tick_start will create a tracked receipt.
        self.cached_setups.insert(circuit.call_id, (d_setup, dest_addr, None));
        let (d_setup_ref, _, _) = self.cached_setups.get(&circuit.call_id).unwrap();

        let (setup_sdu, setup_chan_alloc) = Self::build_d_setup_prim(d_setup_ref, circuit.usage, circuit.ts, UlDlAssignment::Both);
        let setup_msg = Self::build_sapmsg(setup_sdu, Some(setup_chan_alloc), dest_addr, Layer2Service::Unacknowledged, None);
        queue.push_back(setup_msg);

        // Track the active local call — caller is granted the floor, so tx_active = true
        self.active_calls.insert(
            circuit.call_id,
            ActiveCall {
                origin: if central_call_id.is_some() {
                    CallOrigin::Swmi
                } else {
                    CallOrigin::Local {
                        caller_addr: calling_party,
                    }
                },
                dest_gssi,
                source_issi: calling_party.ssi,
                ts: circuit.ts,
                usage: circuit.usage,
                tx_active: caller_has_central_floor || another_central_speaker,
                hangtime_start: None,
                brew_uuid: None,
            },
        );

        // Notify Brew entity about this local call if Brew is loaded and the SSI is cleared for Brew
        // It can then forward to TetraPack if the group is subscribed
        if net_brew::is_brew_gssi_routable(&self.config, dest_gssi) {
            let msg = SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                    call_id: circuit.call_id,
                    source_issi: calling_party.ssi,
                    dest_gssi,
                    ts: circuit.ts,
                }),
            };
            queue.push_back(msg);
        }

        if central_call_id.is_some() && caller_has_central_floor {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Swmi,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                    call_id: circuit.call_id,
                    source_issi: calling_party.ssi,
                    dest_gssi,
                    ts: circuit.ts,
                }),
            });
        }
    }

    pub fn route_xx_deliver(&mut self, _queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("route_xx_deliver");

        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!();
        };
        let Some(bits) = prim.sdu.peek_bits(5) else {
            tracing::warn!("insufficient bits: {}", prim.sdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = CmcePduTypeUl::try_from(bits) else {
            tracing::warn!("invalid pdu type: {} in {}", bits, prim.sdu.dump_bin());
            return;
        };

        // TODO FIXME: Besides these PDUs, we can also receive several signals (BUSY ind, CLOSE ind, etc)
        match pdu_type {
            CmcePduTypeUl::USetup => self.rx_u_setup(_queue, message),
            CmcePduTypeUl::UTxCeased => self.rx_u_tx_ceased(_queue, message),
            CmcePduTypeUl::UTxDemand => self.rx_u_tx_demand(_queue, message),
            CmcePduTypeUl::URelease => self.rx_u_release(_queue, message),
            CmcePduTypeUl::UDisconnect => self.rx_u_disconnect(_queue, message),
            CmcePduTypeUl::UAlert => self.rx_private_u_alert(message),
            CmcePduTypeUl::UConnect => self.rx_private_u_connect(message),
            CmcePduTypeUl::UInfo | CmcePduTypeUl::UStatus | CmcePduTypeUl::UCallRestore => {
                unimplemented_log!("{}", pdu_type);
            }
            _ => {
                panic!();
            }
        }
    }

    pub fn tick_start(&mut self, queue: &mut MessageQueue, dltime: TdmaTime) {
        self.dltime = dltime;

        // Central decisions are applied on the radio/router thread, never on
        // the WSS worker.  Drain all pending control actions before TDMA work.
        let mut swmi_actions = Vec::new();
        if let Some(endpoint) = &self.swmi {
            while let Some(action) = endpoint.try_recv() {
                swmi_actions.push(action);
            }
        }
        for action in swmi_actions {
            self.handle_swmi_action(queue, action);
        }

        // Check hangtime expiry for active local calls
        self.check_hangtime_expiry(queue);

        // Drive deferred D-RELEASE teardown
        self.process_releasing_calls(queue);

        if let Some(tasks) = self.circuits.tick_start(dltime) {
            for task in tasks {
                match task {
                    CircuitMgrCmd::SendDSetup(call_id, usage, ts) => {
                        // P2P D-SETUP is individually addressed before RF
                        // resource reservation; it must never be emitted by
                        // the group-call late-entry scheduler.
                        if self.is_private_circuit(call_id, ts) {
                            continue;
                        }
                        // Skip late-entry D-SETUP during hangtime. The traffic channel is still
                        // allocated and sending D-SETUP with NotGranted can prevent floor requests.
                        if let Some(active) = self.active_calls.get(&call_id) {
                            if active.hangtime_start.is_some() {
                                continue;
                            }
                        }

                        // Get our cached D-SETUP, build a prim and send it down the stack
                        let Some((pdu, dest_addr, receipt)) = self.cached_setups.get_mut(&call_id) else {
                            tracing::error!("No cached D-SETUP for call id {}", call_id);
                            continue;
                        };

                        // Throttle: if the previous D-SETUP hasn't reached a final state yet
                        // (still queued in UMAC), skip this re-send to avoid flooding the MCCH.
                        if let Some(r) = receipt.as_ref() {
                            if !r.is_in_final_state() {
                                tracing::trace!(
                                    "Suppressing D-SETUP re-send for call_id={} (previous still {:?})",
                                    call_id,
                                    r.get_state()
                                );
                                continue;
                            }
                            if r.get_state() == TxState::Discarded {
                                tracing::debug!("Previous D-SETUP for call_id={} was discarded by UMAC, retrying", call_id);
                            }
                        }

                        // Update transmission_grant based on current call state:
                        // During hangtime (nobody transmitting), use NotGranted;
                        // during active TX, use GrantedToOtherUser.
                        if let Some(active) = self.active_calls.get(&call_id) {
                            pdu.transmission_grant = if active.tx_active {
                                TransmissionGrant::GrantedToOtherUser
                            } else {
                                TransmissionGrant::NotGranted
                            };
                        }
                        let dest_addr = *dest_addr;
                        let (sdu, chan_alloc) = Self::build_d_setup_prim(pdu, usage, ts, UlDlAssignment::Both);

                        // Create a fresh txreporter for this re-send
                        let reporter = TxReporter::new_unacked();

                        // Cache the setup in cached_setups with the reporter so we can check its state on the next tick and throttle if it's still pending in UMAC
                        *receipt = Some(reporter.clone());

                        let prim = Self::build_sapmsg(sdu, Some(chan_alloc), dest_addr, Layer2Service::Unacknowledged, Some(reporter));
                        queue.push_back(prim);
                    }

                    CircuitMgrCmd::SendClose(call_id, circuit) => {
                        // P2P calls have no group D-SETUP cache.  Their
                        // release path is individually addressed and the
                        // saved private circuit is closed after its stolen
                        // D-RELEASE has drained.  Never run the group-call
                        // late-entry cleanup for such a circuit.
                        if self.is_private_circuit(call_id, circuit.ts) {
                            tracing::debug!(call_id, ts = circuit.ts, "ignoring group circuit-manager close for private call");
                            continue;
                        }
                        tracing::warn!("need to send CLOSE for call id {}", call_id);
                        let ts = circuit.ts;
                        // Get our cached D-SETUP, build D-RELEASE and send
                        if let Some((pdu, dest_addr, _)) = self.cached_setups.get(&call_id) {
                            let dest_addr = *dest_addr;
                            let sdu = Self::build_d_release_from_d_setup(pdu, DisconnectCause::ExpiryOfTimer);
                            let prim = Self::build_sapmsg(sdu, None, dest_addr, Layer2Service::Unacknowledged, None);
                            queue.push_back(prim);
                        } else {
                            tracing::error!("No cached D-SETUP for call id {}", call_id);
                        }

                        // Clean up call state
                        self.cached_setups.remove(&call_id);
                        self.active_calls.remove(&call_id);

                        // Signal UMAC to release the circuit
                        Self::signal_umac_circuit_close(queue, circuit);
                        self.release_timeslot(ts);
                    }
                }
            }
        }
    }

    /// Check if any active calls in hangtime have expired, and if so, release them
    fn check_hangtime_expiry(&mut self, queue: &mut MessageQueue) {
        // Hangtime: 5 multiframes = ~5 seconds
        const HANGTIME_FRAMES: i32 = 5 * 18 * 4;

        let central_online = self.swmi.as_ref().is_some_and(SwmiCmceEndpoint::is_online);
        let expired: Vec<u16> = self
            .active_calls
            .iter()
            .filter_map(|(&call_id, call)| {
                // While the SwMI link is alive, only the SwMI's configured
                // hangtime can end a central call.  LST recovery falls back
                // to this local timeout after the link disappears.
                if central_online && matches!(call.origin, CallOrigin::Swmi) {
                    return None;
                }
                if let Some(hangtime_start) = call.hangtime_start {
                    if hangtime_start.age(self.dltime) > HANGTIME_FRAMES {
                        return Some(call_id);
                    }
                }
                None
            })
            .collect();

        for call_id in expired {
            tracing::info!("Hangtime expired for call_id={}, releasing", call_id);
            self.release_call(queue, call_id, DisconnectCause::ExpiryOfTimer);
        }
    }

    /// Apply a central call/floor decision received over the SwMI WSS link.
    fn handle_swmi_action(&mut self, queue: &mut MessageQueue, action: SwmiMessage) {
        match action {
            SwmiMessage::GroupCallStart {
                call_id,
                owner_itsi,
                gssi,
                floor_itsi,
                ..
            } => {
                let Ok(call_id) = u16::try_from(call_id) else {
                    tracing::warn!(call_id, "SwMI supplied call id outside TETRA range");
                    return;
                };
                // For a join, GroupCallStart carries the actual central
                // owner, while the pending U-SETUP belongs to the joining
                // terminal. Match that pending setup by GSSI as a fallback.
                let key = (owner_itsi as u32, gssi);
                let pending_key = self.pending_swmi_setups.contains_key(&key).then_some(key).or_else(|| {
                    self.pending_swmi_setups
                        .keys()
                        .find(|(_, pending_gssi)| *pending_gssi == gssi)
                        .copied()
                });
                if let Some(pending_key) = pending_key {
                    let request = self
                        .pending_swmi_setups
                        .remove(&pending_key)
                        .expect("pending setup key found immediately above");
                    self.central_setup_call_ids.insert(pending_key, call_id);
                    self.central_setup_call_floors.insert(pending_key, floor_itsi as u32);
                    self.rx_u_setup(queue, request);
                } else if !self.has_listener(gssi) {
                    self.pending_remote_swmi_calls
                        .insert(call_id, (owner_itsi as u32, gssi, floor_itsi as u32));
                    tracing::debug!(
                        call_id,
                        owner_itsi,
                        gssi,
                        "deferring SwMI group call until local attachment is active"
                    );
                } else {
                    self.start_remote_swmi_call(queue, call_id, owner_itsi as u32, gssi, floor_itsi as u32);
                }
            }
            SwmiMessage::FloorGranted { call_id, itsi } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let (dest_gssi, ts) = {
                    let Some(call) = self.active_calls.get_mut(&call_id) else { return };
                    call.source_issi = itsi as u32;
                    call.tx_active = true;
                    call.hangtime_start = None;
                    (call.dest_gssi, call.ts)
                };
                // The group indication is intentionally "granted to other
                // user".  The granted MS itself additionally requires the
                // individual "granted" indication; without it its PTT UI
                // remains rejected even while listeners show its ISSI.
                self.send_d_tx_granted_individual_facch(queue, call_id, itsi as u32, ts);
                self.send_d_tx_granted_facch(queue, call_id, itsi as u32, dest_gssi, ts);
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Umac,
                    msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                        call_id,
                        source_issi: itsi as u32,
                        dest_gssi,
                        ts,
                    }),
                });
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Swmi,
                    msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                        call_id,
                        source_issi: itsi as u32,
                        dest_gssi,
                        ts,
                    }),
                });
            }
            SwmiMessage::FloorReleased { call_id, .. } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                if let Some(call) = self.active_calls.get_mut(&call_id) {
                    call.tx_active = false;
                    call.hangtime_start = Some(self.dltime);
                    let ts = call.ts;
                    queue.push_back(SapMsg {
                        sap: Sap::Control,
                        src: TetraEntity::Cmce,
                        dest: TetraEntity::Umac,
                        msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
                    });
                    queue.push_back(SapMsg {
                        sap: Sap::Control,
                        src: TetraEntity::Cmce,
                        dest: TetraEntity::Swmi,
                        msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
                    });
                }
            }
            SwmiMessage::CallRelease { call_id, cause } => {
                self.pending_remote_swmi_calls.remove(&(call_id as u16));
                if let Ok(call_id) = u16::try_from(call_id) {
                    let cause = DisconnectCause::try_from(cause as u64).unwrap_or(DisconnectCause::SwmiRequestedDisconnection);
                    self.release_call(queue, call_id, cause);
                }
            }
            // Compatibility with an older SwMI that emitted CallDisconnect.
            // ETSI TS 100 392-2 clause 14.5.2.3 requires D-RELEASE for a
            // group-call disconnect, so treat it exactly like CallRelease.
            SwmiMessage::CallDisconnect { call_id, cause } => {
                self.pending_remote_swmi_calls.remove(&(call_id as u16));
                if let Ok(call_id) = u16::try_from(call_id) {
                    let cause = DisconnectCause::try_from(cause as u64).unwrap_or(DisconnectCause::SwmiRequestedDisconnection);
                    self.release_call(queue, call_id, cause);
                }
            }
            SwmiMessage::PrivateCallProceeding {
                call_id,
                caller_itsi,
                callee_itsi,
                hook,
                duplex,
                request_to_transmit,
                priority,
            } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let Some(mut request) = self.pending_private_setups.remove(&(caller_itsi as u32)) else {
                    return;
                };
                let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut request.msg else {
                    return;
                };
                let Ok(pdu) = USetup::from_bitbuf(&mut prim.sdu) else { return };
                self.private_calls.insert(
                    call_id,
                    PrivateCallLocal {
                        caller_itsi: caller_itsi as u32,
                        callee_itsi: callee_itsi as u32,
                        hook,
                        duplex,
                        request_to_transmit,
                        priority,
                        connected: false,
                        local_mask: 0x01,
                    },
                );
                self.send_d_call_proceeding(queue, &request, &pdu, call_id);
            }
            SwmiMessage::PrivateCallOffer {
                call_id,
                caller_itsi,
                callee_itsi,
                hook,
                duplex,
                request_to_transmit,
                priority,
            } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let call = PrivateCallLocal {
                    caller_itsi: caller_itsi as u32,
                    callee_itsi: callee_itsi as u32,
                    hook,
                    duplex,
                    request_to_transmit,
                    priority,
                    connected: false,
                    local_mask: 0x02,
                };
                self.private_calls
                    .entry(call_id)
                    .and_modify(|existing| existing.local_mask |= 0x02)
                    .or_insert_with(|| call.clone());
                self.send_private_d_setup(queue, call_id, &call);
                tracing::info!(call_id, caller_itsi, callee_itsi, "private D-SETUP sent to called terminal");
            }
            SwmiMessage::PrivateCallAlert { call_id, callee_itsi: _ } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let Some(call) = self.private_calls.get(&call_id) else { return };
                let pdu = DAlert {
                    call_identifier: call_id,
                    call_time_out_set_up_phase: 1,
                    reserved: true,
                    simplex_duplex_selection: call.duplex,
                    call_queued: false,
                    basic_service_information: None,
                    notification_indicator: None,
                    facility: None,
                    proprietary: None,
                };
                let mut sdu = BitBuffer::new_autoexpand(32);
                pdu.to_bitbuf(&mut sdu).expect("serialize private D-ALERT");
                sdu.seek(0);
                queue.push_back(Self::build_sapmsg(
                    sdu,
                    None,
                    TetraAddress::new(call.caller_itsi, SsiType::Issi),
                    Layer2Service::Acknowledged,
                    None,
                ));
            }
            SwmiMessage::PrivateCallReserve {
                call_id,
                caller_itsi,
                callee_itsi,
                endpoint_mask,
                duplex,
                ..
            } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let Some(call) = self.private_calls.get(&call_id).cloned() else {
                    return;
                };
                let mut allocated = Vec::new();
                if let Some(local) = self.private_calls.get_mut(&call_id) {
                    local.local_mask |= endpoint_mask;
                }
                // A simplex P2P call with both endpoints at this cell uses
                // one bidirectional traffic channel, just like a two-member
                // private P2MP call.  Allocating a TCH per ISSI wastes a
                // carrier slot and is only required for duplex P2P.
                let shared_simplex = !duplex && endpoint_mask & 0x03 == 0x03;
                let mut shared_circuit = if shared_simplex {
                    [caller_itsi as u32, callee_itsi as u32]
                        .into_iter()
                        .find_map(|itsi| self.private_circuits.get(&(call_id, itsi)).cloned())
                } else {
                    None
                };
                if shared_simplex {
                    tracing::info!(
                        call_id,
                        caller_itsi,
                        callee_itsi,
                        "reserving one shared radio circuit for same-cell simplex private call"
                    );
                }
                for (mask, itsi) in [(0x01, caller_itsi as u32), (0x02, callee_itsi as u32)] {
                    if endpoint_mask & mask == 0 || self.private_circuits.contains_key(&(call_id, itsi)) {
                        continue;
                    }
                    if let Some(circuit) = shared_circuit.as_ref() {
                        self.private_circuits.insert((call_id, itsi), circuit.clone());
                        continue;
                    }
                    let result = {
                        let mut state = self.config.state_write();
                        self.circuits
                            .allocate_circuit_with_allocator_and_call_id_and_mode(
                                Direction::Both,
                                CommunicationType::P2p,
                                &mut state.timeslot_alloc,
                                TimeslotOwner::Cmce,
                                call_id,
                                duplex,
                            )
                            .map(Clone::clone)
                    };
                    match result {
                        Ok(circuit) => {
                            Self::signal_umac_circuit_open(queue, &circuit);
                            self.private_circuits.insert((call_id, itsi), circuit.clone());
                            allocated.push((itsi, circuit));
                            if shared_simplex {
                                shared_circuit = allocated.last().map(|(_, circuit)| circuit.clone());
                            }
                        }
                        Err(error) => {
                            tracing::warn!(call_id, itsi, ?error, "private call resource allocation failed");
                            for (allocated_itsi, circuit) in allocated {
                                self.private_circuits.remove(&(call_id, allocated_itsi));
                                let _ = self.circuits.close_circuit(Direction::Both, circuit.ts);
                                Self::signal_umac_circuit_close(queue, circuit.clone());
                                self.release_timeslot(circuit.ts);
                            }
                            if let Some(swmi) = self.swmi.as_ref() {
                                let _ = swmi.submit(SwmiMessage::PrivateCallResourceResult {
                                    call_id: call_id as u64,
                                    endpoint_mask,
                                    accepted: false,
                                });
                            }
                            return;
                        }
                    }
                }
                if let Some(swmi) = self.swmi.as_ref() {
                    let _ = swmi.submit(SwmiMessage::PrivateCallResourceResult {
                        call_id: call_id as u64,
                        endpoint_mask,
                        accepted: true,
                    });
                }
                let _ = call;
            }
            SwmiMessage::PrivateCallConnected {
                call_id,
                initial_floor_itsi,
                ..
            } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let Some(call) = self.private_calls.get_mut(&call_id) else { return };
                call.connected = true;
                let call = call.clone();
                let shared_simplex = !call.duplex
                    && call.local_mask & 0x03 == 0x03
                    && self
                        .private_circuits
                        .get(&(call_id, call.caller_itsi))
                        .zip(self.private_circuits.get(&(call_id, call.callee_itsi)))
                        .is_some_and(|(caller, callee)| caller.ts == callee.ts);
                for itsi in [call.caller_itsi, call.callee_itsi] {
                    let Some(circuit) = self.private_circuits.get(&(call_id, itsi)).cloned() else {
                        continue;
                    };
                    self.send_private_connect(queue, call_id, &call, itsi, &circuit, initial_floor_itsi as u32);
                    let peer = if itsi == call.caller_itsi {
                        call.callee_itsi
                    } else {
                        call.caller_itsi
                    };
                    if !shared_simplex {
                        queue.push_back(SapMsg {
                            sap: Sap::Control,
                            src: TetraEntity::Cmce,
                            dest: TetraEntity::Swmi,
                            msg: SapMsgInner::CmceCallControl(CallControl::PrivateMediaStart {
                                call_id,
                                source_issi: itsi,
                                destination_issi: peer,
                                ts: circuit.ts,
                            }),
                        });
                        // UMAC must suppress its group-call same-timeslot
                        // loopback for P2P.  The media entity above routes
                        // this circuit to the peer timeslot (locally or via
                        // the SwMI).
                        queue.push_back(SapMsg {
                            sap: Sap::Control,
                            src: TetraEntity::Cmce,
                            dest: TetraEntity::Umac,
                            msg: SapMsgInner::CmceCallControl(CallControl::PrivateMediaStart {
                                call_id,
                                source_issi: itsi,
                                destination_issi: peer,
                                ts: circuit.ts,
                            }),
                        });
                    }
                }
                tracing::info!(
                    call_id,
                    caller_itsi = call.caller_itsi,
                    callee_itsi = call.callee_itsi,
                    duplex = call.duplex,
                    shared_simplex,
                    "private call connected on local RF resources"
                );
            }
            SwmiMessage::PrivateCallRelease { call_id, itsi: _, cause } => {
                if let Ok(call_id) = u16::try_from(call_id) {
                    let cause = DisconnectCause::try_from(cause as u64).unwrap_or(DisconnectCause::SwmiRequestedDisconnection);
                    self.release_private_call_local(queue, call_id, cause);
                }
            }
            SwmiMessage::PrivateFloorGranted { call_id, itsi } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let Some(call) = self.private_calls.get(&call_id).cloned() else {
                    return;
                };
                let mut resumed_timeslots = HashSet::new();
                for recipient in [call.caller_itsi, call.callee_itsi] {
                    if let Some(circuit) = self.private_circuits.get(&(call_id, recipient)) {
                        self.send_private_d_tx_granted(queue, call_id, itsi as u32, recipient, circuit.ts);
                        // A private call has one RF circuit per endpoint.
                        // Both must leave hangtime: the selected terminal
                        // needs an UL traffic channel and its peer needs the
                        // DL traffic channel that receives the routed TMD
                        // frames.  Leaving either slot in signalling mode
                        // makes a subsequent simplex PTT appear dead.
                        if resumed_timeslots.insert(circuit.ts) {
                            queue.push_back(SapMsg {
                                sap: Sap::Control,
                                src: TetraEntity::Cmce,
                                dest: TetraEntity::Umac,
                                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                                    call_id,
                                    source_issi: itsi as u32,
                                    dest_gssi: 0,
                                    ts: circuit.ts,
                                }),
                            });
                        }
                    }
                }
            }
            SwmiMessage::PrivateFloorReleased { call_id, .. } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                if let Some(call) = self.private_calls.get(&call_id).cloned() {
                    let mut hangtime_timeslots = HashSet::new();
                    for itsi in [call.caller_itsi, call.callee_itsi] {
                        if let Some(circuit) = self.private_circuits.get(&(call_id, itsi)) {
                            let pdu = DTxCeased {
                                call_identifier: call_id,
                                transmission_request_permission: false,
                                notification_indicator: None,
                                facility: None,
                                dm_ms_address: None,
                                proprietary: None,
                            };
                            let mut sdu = BitBuffer::new_autoexpand(24);
                            pdu.to_bitbuf(&mut sdu).expect("serialize private D-TX CEASED");
                            sdu.seek(0);
                            queue.push_back(Self::build_sapmsg_stealing(sdu, TetraAddress::new(itsi, SsiType::Issi), circuit.ts));
                            // D-TX CEASED alone only produces the terminal's
                            // end-of-transmission tone.  The scheduler must
                            // also advertise AssignedControl during P2P
                            // hangtime or the MS cannot send its next
                            // U-TX DEMAND.
                            if hangtime_timeslots.insert(circuit.ts) {
                                queue.push_back(SapMsg {
                                    sap: Sap::Control,
                                    src: TetraEntity::Cmce,
                                    dest: TetraEntity::Umac,
                                    msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts: circuit.ts }),
                                });
                            }
                        }
                    }
                }
            }
            SwmiMessage::PrivateCallKeepalive {
                call_id,
                itsi,
                sequence: _,
            } => {
                let Ok(call_id) = u16::try_from(call_id) else { return };
                let Some(circuit) = self.private_circuits.get(&(call_id, itsi as u32)) else {
                    return;
                };
                let pdu = DInfo {
                    call_identifier: call_id,
                    reset_call_time_out_timer_t310_: true,
                    poll_request: false,
                    new_call_identifier: None,
                    call_time_out: None,
                    call_time_out_set_up_phase_t301_t302_: None,
                    call_ownership: None,
                    modify: None,
                    call_status: None,
                    temporary_address: None,
                    notification_indicator: None,
                    poll_response_percentage: None,
                    poll_response_number: None,
                    dtmf: None,
                    facility: None,
                    poll_response_addresses: None,
                    proprietary: None,
                };
                let mut sdu = BitBuffer::new_autoexpand(32);
                pdu.to_bitbuf(&mut sdu).expect("serialize private D-INFO");
                sdu.seek(0);
                // The LLC implementation cannot send acknowledged BL-DATA
                // through FACCH/STCH. P2P D-INFO has no valid poll-response
                // procedure, so this is deliberately normal FACCH: it only
                // refreshes T310 at the called terminal.
                queue.push_back(Self::build_sapmsg_stealing(
                    sdu,
                    TetraAddress::new(itsi as u32, SsiType::Issi),
                    circuit.ts,
                ));
            }
            SwmiMessage::CallReject { call_id, itsi, cause, .. } => {
                if call_id == 0 {
                    if let Some(request) = self.pending_private_setups.remove(&(itsi as u32)) {
                        let cause = DisconnectCause::try_from(cause as u64).unwrap_or(DisconnectCause::RequestedServiceNotAvailable);
                        self.send_d_release_for_setup_reject(queue, &request, cause);
                        return;
                    }
                    let request_key = self
                        .pending_swmi_setups
                        .keys()
                        .find(|(pending_itsi, _)| *pending_itsi == itsi as u32)
                        .copied();
                    if let Some(request) = request_key.and_then(|key| self.pending_swmi_setups.remove(&key)) {
                        self.send_d_release_for_setup_reject(queue, &request, DisconnectCause::RequestedServiceNotAvailable);
                    }
                }
            }
            _ => {}
        }
    }

    /// Allocate the local radio circuit for a centrally-started group call at
    /// a non-originating BS.  Its call identifier is *not* locally generated.
    fn start_remote_swmi_call(&mut self, queue: &mut MessageQueue, call_id: u16, owner_itsi: u32, gssi: u32, floor_itsi: u32) {
        if !self.has_listener(gssi) || self.active_calls.contains_key(&call_id) {
            return;
        }
        let circuit = match {
            let mut state = self.config.state_write();
            self.circuits.allocate_circuit_with_allocator_and_call_id(
                Direction::Both,
                CommunicationType::P2Mp,
                &mut state.timeslot_alloc,
                TimeslotOwner::Cmce,
                call_id,
            )
        } {
            Ok(circuit) => circuit.clone(),
            Err(error) => {
                tracing::warn!(call_id, gssi, ?error, "unable to allocate local circuit for SwMI call");
                return;
            }
        };
        Self::signal_umac_circuit_open(queue, &circuit);
        let d_setup = DSetup {
            call_identifier: call_id,
            call_time_out: CallTimeout::T5m,
            hook_method_selection: false,
            simplex_duplex_selection: false,
            basic_service_information: BasicServiceInformation {
                circuit_mode_type: CircuitModeType::TchS,
                encryption_flag: false,
                communication_type: CommunicationType::P2Mp,
                slots_per_frame: None,
                speech_service: Some(0),
            },
            transmission_grant: if floor_itsi == 0 {
                TransmissionGrant::NotGranted
            } else {
                TransmissionGrant::GrantedToOtherUser
            },
            transmission_request_permission: false,
            call_priority: 0,
            notification_indicator: None,
            temporary_address: None,
            calling_party_address_ssi: Some(owner_itsi),
            calling_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let dest_addr = TetraAddress::new(gssi, SsiType::Gssi);
        self.cached_setups.insert(call_id, (d_setup, dest_addr, None));
        let (pdu, _, _) = self.cached_setups.get(&call_id).expect("inserted above");
        let (sdu, allocation) = Self::build_d_setup_prim(pdu, circuit.usage, circuit.ts, UlDlAssignment::Both);
        queue.push_back(Self::build_sapmsg(
            sdu,
            Some(allocation),
            dest_addr,
            Layer2Service::Unacknowledged,
            None,
        ));
        self.active_calls.insert(
            call_id,
            ActiveCall {
                origin: CallOrigin::Swmi,
                dest_gssi: gssi,
                source_issi: floor_itsi,
                ts: circuit.ts,
                usage: circuit.usage,
                tx_active: floor_itsi != 0,
                hangtime_start: None,
                brew_uuid: None,
            },
        );
        if floor_itsi != 0 {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Swmi,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                    call_id,
                    source_issi: floor_itsi,
                    dest_gssi: gssi,
                    ts: circuit.ts,
                }),
            });
        }
        tracing::info!(call_id, gssi, ts = circuit.ts, "central SwMI group call activated at serving BS");
    }

    fn release_timeslot(&mut self, ts: u8) {
        let mut state = self.config.state_write();
        if let Err(err) = state.timeslot_alloc.release(TimeslotOwner::Cmce, ts) {
            tracing::warn!("CcBsSubentity: failed to release timeslot ts={} err={:?}", ts, err);
        }
    }

    /// Release a call. Removes it from active state immediately so it cannot be re-keyed
    /// or reused, steals one D-RELEASE onto the traffic channel, and parks the teardown in
    /// releasing_calls. The circuit and timeslot stay allocated until process_releasing_calls
    /// tears them down, which lets the stolen D-RELEASE transmit before the slot leaves
    /// traffic mode. With no cached D-SETUP there is no D-RELEASE to send, so it tears down
    /// at once.
    fn release_call(&mut self, queue: &mut MessageQueue, call_id: u16, disconnect_cause: DisconnectCause) {
        let Some(call) = self.active_calls.remove(&call_id) else {
            return;
        };
        let ts = call.ts;
        let dest_gssi = call.dest_gssi;
        let is_local = matches!(call.origin, CallOrigin::Local { .. });
        // Prefer the live brew_uuid (current network speaker). Fall back to the origin uuid
        // for a Network call in hangtime, where rx_network_call_end cleared the field.
        let brew_uuid = call.brew_uuid.or(match call.origin {
            CallOrigin::Network { brew_uuid } => Some(brew_uuid),
            CallOrigin::Local { .. } | CallOrigin::Swmi => None,
        });

        match self.cached_setups.remove(&call_id) {
            Some((d_setup, dest_addr, _)) => {
                let sdu = Self::build_d_release_from_d_setup(&d_setup, disconnect_cause);
                queue.push_back(Self::build_sapmsg_stealing(sdu, dest_addr, ts));
                self.releasing_calls.push(ReleasingCall {
                    call_id,
                    ts,
                    dest_gssi,
                    is_local,
                    brew_uuid,
                    sent_at: self.dltime,
                });
            }
            None => {
                tracing::warn!("No cached D-SETUP for call_id={}, cleaning up without D-RELEASE", call_id);
                self.finalize_release(queue, call_id, ts, dest_gssi, is_local, brew_uuid);
            }
        }
    }

    /// Close a releasing call's circuit once enough frames have passed since the D-RELEASE
    /// was stolen for it to transmit. Driven once per tick.
    fn process_releasing_calls(&mut self, queue: &mut MessageQueue) {
        // Two TDMA frames: the stolen D-RELEASE drains over the next frame while the slot
        // is still in traffic mode, then teardown one frame later.
        const CLOSE_AFTER_SEND_TS: i32 = 8;

        let now = self.dltime;
        let mut i = 0;
        while i < self.releasing_calls.len() {
            if self.releasing_calls[i].sent_at.age(now) >= CLOSE_AFTER_SEND_TS {
                let rc = self.releasing_calls.remove(i);
                self.finalize_release(queue, rc.call_id, rc.ts, rc.dest_gssi, rc.is_local, rc.brew_uuid);
            } else {
                i += 1;
            }
        }

        let mut i = 0;
        while i < self.releasing_private_circuits.len() {
            if self.releasing_private_circuits[i].sent_at.age(now) >= CLOSE_AFTER_SEND_TS {
                let rc = self.releasing_private_circuits.remove(i);
                // The circuit may have been removed already by a stale
                // CircuitMgr timeout task; the saved circuit still carries
                // the exact UMAC/timeslot teardown information we need.
                let _ = self.circuits.close_circuit(Direction::Both, rc.circuit.ts);
                Self::signal_umac_circuit_close(queue, rc.circuit.clone());
                self.release_timeslot(rc.circuit.ts);
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Swmi,
                    msg: SapMsgInner::CmceCallControl(CallControl::PrivateMediaStop {
                        call_id: rc.call_id,
                        ts: rc.circuit.ts,
                    }),
                });
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Umac,
                    msg: SapMsgInner::CmceCallControl(CallControl::PrivateMediaStop {
                        call_id: rc.call_id,
                        ts: rc.circuit.ts,
                    }),
                });
                tracing::debug!(
                    call_id = rc.call_id,
                    itsi = rc.itsi,
                    ts = rc.circuit.ts,
                    "private RF circuit released after D-RELEASE transmission"
                );
            } else {
                i += 1;
            }
        }
    }

    fn is_private_circuit(&self, call_id: u16, ts: u8) -> bool {
        self.private_calls.contains_key(&call_id)
            || self
                .private_circuits
                .iter()
                .any(|((private_call_id, _), circuit)| *private_call_id == call_id && circuit.ts == ts)
            || self
                .releasing_private_circuits
                .iter()
                .any(|circuit| circuit.call_id == call_id && circuit.circuit.ts == ts)
    }

    /// Tear down a released call: close the circuit, free the timeslot, notify Brew.
    /// The active_calls and cached_setups entries were already removed in release_call.
    fn finalize_release(
        &mut self,
        queue: &mut MessageQueue,
        call_id: u16,
        ts: u8,
        dest_gssi: u32,
        is_local: bool,
        brew_uuid: Option<uuid::Uuid>,
    ) {
        if let Ok(circuit) = self.circuits.close_circuit(Direction::Both, ts) {
            Self::signal_umac_circuit_close(queue, circuit);
        }

        // Ensure UMAC clears hangtime even if the CMCE circuit was already closed above.
        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::CallEnded { call_id, ts }),
        });

        // Clear the native SwMI user-plane mapping as well.  Without this a
        // later, recycled radio timeslot could be incorrectly associated with
        // the released central call.
        if self.swmi.is_some() {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Swmi,
                msg: SapMsgInner::CmceCallControl(CallControl::CallEnded { call_id, ts }),
            });
        }

        self.release_timeslot(ts);

        // Tell Brew the call is gone. Local-origin calls get CallEnded so Brew clears
        // ul_forwarded[ts] from any earlier UL forwarding. If a network speaker was
        // ever involved (active or in hangtime), also send NetworkCallEnd so Brew
        // tears down the upstream session. Without the latter, hangtime expiry leaves
        // Brew thinking the circuit is still reusable and the backend keeps streaming.
        if net_brew::is_brew_gssi_routable(&self.config, dest_gssi) {
            if is_local {
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Brew,
                    msg: SapMsgInner::CmceCallControl(CallControl::CallEnded { call_id, ts }),
                });
            }
            if let Some(brew_uuid) = brew_uuid {
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Brew,
                    msg: SapMsgInner::CmceCallControl(CallControl::NetworkCallEnd { brew_uuid }),
                });
            }
        }
    }

    fn rx_private_u_setup(&mut self, queue: &mut MessageQueue, original: SapMsg, caller: TetraAddress, pdu: USetup) {
        let Some(callee_itsi) = pdu.called_party_ssi.map(|value| value as u32) else {
            self.send_d_release_for_setup_reject(queue, &original, DisconnectCause::RequestedServiceNotAvailable);
            return;
        };
        if pdu.called_party_type_identifier != PartyTypeIdentifier::Ssi || pdu.called_party_extension.is_some() {
            self.send_d_release_for_setup_reject(queue, &original, DisconnectCause::RequestedServiceNotAvailable);
            return;
        }
        if !self.swmi.as_ref().is_some_and(|endpoint| endpoint.is_online()) {
            self.send_d_release_for_setup_reject(queue, &original, DisconnectCause::RequestedServiceNotAvailable);
            return;
        }
        let command_id = self.next_swmi_command_id();
        let request = SwmiMessage::PrivateCallRequest {
            command_id,
            caller_itsi: caller.ssi as u64,
            callee_itsi: callee_itsi as u64,
            hook: pdu.hook_method_selection,
            duplex: pdu.simplex_duplex_selection,
            request_to_transmit: pdu.request_to_transmit_send_data,
            priority: pdu.call_priority,
        };
        let submitted = self.swmi.as_ref().is_some_and(|swmi| swmi.submit(request).is_ok());
        if submitted {
            self.pending_private_setups.insert(caller.ssi, original);
            tracing::info!(
                caller_itsi = caller.ssi,
                callee_itsi,
                command_id,
                "private U-SETUP forwarded to central SwMI"
            );
        } else {
            let rejected_request = self.pending_private_setups.remove(&caller.ssi).unwrap_or(original);
            self.send_d_release_for_setup_reject(queue, &rejected_request, DisconnectCause::RequestedServiceNotAvailable);
        }
    }

    fn send_private_d_setup(&self, queue: &mut MessageQueue, call_id: u16, call: &PrivateCallLocal) {
        let pdu = DSetup {
            call_identifier: call_id,
            call_time_out: CallTimeout::T30s,
            hook_method_selection: call.hook,
            simplex_duplex_selection: call.duplex,
            basic_service_information: BasicServiceInformation {
                circuit_mode_type: CircuitModeType::TchS,
                encryption_flag: false,
                communication_type: CommunicationType::P2p,
                slots_per_frame: None,
                speech_service: Some(0),
            },
            transmission_grant: TransmissionGrant::NotGranted,
            transmission_request_permission: !call.duplex,
            call_priority: call.priority,
            notification_indicator: None,
            temporary_address: None,
            calling_party_address_ssi: Some(call.caller_itsi),
            calling_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(80);
        pdu.to_bitbuf(&mut sdu).expect("serialize private D-SETUP");
        sdu.seek(0);
        queue.push_back(Self::build_sapmsg(
            sdu,
            None,
            TetraAddress::new(call.callee_itsi, SsiType::Issi),
            Layer2Service::Acknowledged,
            None,
        ));
    }

    fn rx_private_u_alert(&mut self, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            return;
        };
        let itsi = prim.received_tetra_address.ssi;
        let Ok(pdu) = UAlert::from_bitbuf(&mut prim.sdu) else { return };
        if self
            .private_calls
            .get(&pdu.call_identifier)
            .is_some_and(|call| call.callee_itsi == itsi)
        {
            if let Some(swmi) = self.swmi.as_ref().filter(|endpoint| endpoint.is_online()) {
                let _ = swmi.submit(SwmiMessage::PrivateCallAlert {
                    call_id: pdu.call_identifier as u64,
                    callee_itsi: itsi as u64,
                });
            }
        }
    }

    fn rx_private_u_connect(&mut self, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            return;
        };
        let itsi = prim.received_tetra_address.ssi;
        let Ok(pdu) = UConnect::from_bitbuf(&mut prim.sdu) else { return };
        if self
            .private_calls
            .get(&pdu.call_identifier)
            .is_some_and(|call| call.callee_itsi == itsi)
        {
            if self.swmi.as_ref().is_some_and(|endpoint| endpoint.is_online()) {
                let command_id = self.next_swmi_command_id();
                let _ = self
                    .swmi
                    .as_ref()
                    .expect("checked above")
                    .submit(SwmiMessage::PrivateCallConnectRequest {
                        command_id,
                        call_id: pdu.call_identifier as u64,
                        itsi: itsi as u64,
                    });
                tracing::info!(
                    call_id = pdu.call_identifier,
                    itsi,
                    command_id,
                    "private U-CONNECT forwarded to SwMI"
                );
            }
        }
    }

    fn send_private_connect(
        &self,
        queue: &mut MessageQueue,
        call_id: u16,
        call: &PrivateCallLocal,
        itsi: u32,
        circuit: &CmceCircuit,
        initial_floor_itsi: u32,
    ) {
        let mut timeslots = [false; 4];
        timeslots[circuit.ts as usize - 1] = true;
        let grant = if call.duplex || initial_floor_itsi == itsi {
            TransmissionGrant::Granted
        } else {
            TransmissionGrant::GrantedToOtherUser
        };
        let allocation = CmceChanAllocReq {
            usage: Some(circuit.usage),
            alloc_type: ChanAllocType::Replace,
            carrier: None,
            timeslots,
            ul_dl_assigned: UlDlAssignment::Both,
        };
        let mut sdu = BitBuffer::new_autoexpand(48);
        if itsi == call.caller_itsi {
            let pdu = DConnect {
                call_identifier: call_id,
                call_time_out: CallTimeout::T5m,
                hook_method_selection: call.hook,
                simplex_duplex_selection: call.duplex,
                transmission_grant: grant,
                transmission_request_permission: !call.duplex,
                call_ownership: true,
                call_priority: Some(call.priority as u64),
                basic_service_information: None,
                temporary_address: None,
                notification_indicator: None,
                facility: None,
                proprietary: None,
            };
            pdu.to_bitbuf(&mut sdu).expect("serialize private D-CONNECT");
        } else {
            let pdu = DConnectAcknowledge {
                call_identifier: call_id,
                call_time_out: CallTimeout::T5m as u8,
                transmission_grant: grant as u8,
                transmission_request_permission: !call.duplex,
                notification_indicator: None,
                facility: None,
                proprietary: None,
            };
            pdu.to_bitbuf(&mut sdu).expect("serialize private D-CONNECT ACKNOWLEDGE");
        }
        sdu.seek(0);
        queue.push_back(Self::build_sapmsg(
            sdu,
            Some(allocation),
            TetraAddress::new(itsi, SsiType::Issi),
            Layer2Service::Acknowledged,
            None,
        ));
    }

    fn release_private_call_local(&mut self, queue: &mut MessageQueue, call_id: u16, cause: DisconnectCause) {
        let Some(call) = self.private_calls.remove(&call_id) else { return };
        let mut teardown_timeslots = HashSet::new();
        for (mask, itsi) in [(0x01, call.caller_itsi), (0x02, call.callee_itsi)] {
            if call.local_mask & mask == 0 {
                continue;
            }
            if let Some(circuit) = self.private_circuits.remove(&(call_id, itsi)) {
                let pdu = DRelease {
                    call_identifier: call_id,
                    disconnect_cause: cause,
                    notification_indicator: None,
                    facility: None,
                    proprietary: None,
                };
                let mut sdu = BitBuffer::new_autoexpand(32);
                pdu.to_bitbuf(&mut sdu).expect("serialize private D-RELEASE");
                sdu.seek(0);
                queue.push_back(Self::build_sapmsg_stealing(sdu, TetraAddress::new(itsi, SsiType::Issi), circuit.ts));
                // FACCH stealing only works while the traffic circuit still
                // exists.  Closing it here drops D-RELEASE, after which the
                // terminal reports its own setup timeout ("Geen antwoord").
                // Keep the circuit for a few TDMA frames, then tear it down
                // from process_releasing_calls.
                if teardown_timeslots.insert(circuit.ts) {
                    self.releasing_private_circuits.push(ReleasingPrivateCircuit {
                        call_id,
                        itsi,
                        circuit,
                        sent_at: self.dltime,
                    });
                }
            } else {
                // An offer has no traffic circuit yet.  Still answer its
                // central release immediately, notably when the called MS
                // did not respond, so the calling MS sees the reject cause.
                let pdu = DRelease {
                    call_identifier: call_id,
                    disconnect_cause: cause,
                    notification_indicator: None,
                    facility: None,
                    proprietary: None,
                };
                let mut sdu = BitBuffer::new_autoexpand(32);
                pdu.to_bitbuf(&mut sdu).expect("serialize pre-connect private D-RELEASE");
                sdu.seek(0);
                queue.push_back(Self::build_sapmsg(
                    sdu,
                    None,
                    TetraAddress::new(itsi, SsiType::Issi),
                    Layer2Service::Acknowledged,
                    None,
                ));
            }
        }
    }

    fn feature_check_u_setup(pdu: &USetup) -> bool {
        let mut supported = true;

        if !(pdu.area_selection == 0 || pdu.area_selection == 1) {
            unimplemented_log!("Area selection not supported: {}", pdu.area_selection);
            supported = false;
        };
        if pdu.hook_method_selection == true {
            unimplemented_log!("Hook method selection not supported: {}", pdu.hook_method_selection);
            supported = false;
        };
        if pdu.simplex_duplex_selection != false {
            unimplemented_log!("Only simplex calls supported: {}", pdu.simplex_duplex_selection);
            supported = false;
        };
        // if pdu.basic_service_information != 0xFC {
        //     // TODO FIXME implement parsing
        //     tracing::error!("Basic service information not supported: {}", pdu.basic_service_information);
        //     return;
        // };
        // request_to_transmit_send_data can be false for speech group calls — the MS
        // implicitly requests to transmit by initiating the call. No action needed.
        if pdu.clir_control != 0 {
            unimplemented_log!("clir_control not supported: {}", pdu.clir_control);
        };
        if pdu.called_party_ssi.is_none() || pdu.called_party_short_number_address.is_some() || pdu.called_party_extension.is_some() {
            unimplemented_log!("we only support ssi-based calling");
        };
        // Then, we warn about some other unhandled/unsupported fields
        if let Some(v) = &pdu.external_subscriber_number {
            unimplemented_log!("external_subscriber_number not supported: {:?}", v);
        };
        if let Some(v) = &pdu.facility {
            unimplemented_log!("facility not supported: {:?}", v);
        };
        if let Some(v) = &pdu.dm_ms_address {
            unimplemented_log!("dm_ms_address not supported: {:?}", v);
        };
        if let Some(v) = &pdu.proprietary {
            unimplemented_log!("proprietary not supported: {:?}", v);
        };

        supported
    }

    /// Handle U-TX CEASED: radio released PTT
    /// Response: send D-TX CEASED via FACCH to all group members, enter hangtime
    fn rx_u_tx_ceased(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let pdu = match UTxCeased::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing U-TX CEASED: {:?}", e);
                return;
            }
        };

        let call_id = pdu.call_identifier;

        if let Some(call) = self.private_calls.get(&call_id) {
            if !call.connected || call.duplex {
                return;
            }
            if let Some(swmi) = self.swmi.as_ref().filter(|endpoint| endpoint.is_online()) {
                let _ = swmi.submit(SwmiMessage::PrivateFloorReleased {
                    call_id: call_id as u64,
                    itsi: prim.received_tetra_address.ssi as u64,
                });
            }
            return;
        }

        if self.swmi.as_ref().is_some_and(SwmiCmceEndpoint::is_online) {
            let itsi = prim.received_tetra_address.ssi;
            let command_id = self.next_swmi_command_id();
            if self
                .swmi
                .as_ref()
                .expect("checked above")
                .submit(SwmiMessage::FloorReleaseRequest {
                    command_id,
                    call_id: call_id as u64,
                    itsi: itsi as u64,
                })
                .is_ok()
            {
                tracing::info!(call_id, itsi, command_id, "U-TX CEASED forwarded to central SwMI");
                return;
            }
        }

        // Look up the active call
        let Some(call) = self.active_calls.get_mut(&call_id) else {
            tracing::warn!("U-TX CEASED for unknown call_id={}", call_id);
            return;
        };

        // Check if already in hangtime - ignore duplicate U-TX CEASED to avoid resetting timer
        if !call.tx_active && call.hangtime_start.is_some() {
            tracing::debug!("U-TX CEASED: already in hangtime for call_id={}, ignoring duplicate", call_id);
            return;
        }

        tracing::info!("U-TX CEASED: PTT released on call_id={}, entering hangtime", call_id);

        let ts = call.ts;
        let dest_ssi = call.dest_gssi;
        call.tx_active = false;
        call.hangtime_start = Some(self.dltime);

        // Get dest address from cached setup
        let Some((_, dest_addr, _)) = self.cached_setups.get(&call_id) else {
            tracing::error!("No cached D-SETUP for call_id={}", call_id);
            return;
        };
        let dest_addr = *dest_addr;

        // Send D-TX CEASED via FACCH (stealing) to all group members
        let d_tx_ceased = DTxCeased {
            call_identifier: call_id,
            transmission_request_permission: false, // ETSI 14.8.43: 0 = allowed to request transmission
            notification_indicator: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(25);
        d_tx_ceased.to_bitbuf(&mut sdu).expect("Failed to serialize DTxCeased");
        sdu.seek(0);
        tracing::info!("-> {:?} sdu {}", d_tx_ceased, sdu.dump_bin());

        // Send via FACCH (stealing channel) so radios on the traffic channel hear the beep
        let msg = Self::build_sapmsg_stealing(sdu, dest_addr, ts);
        queue.push_back(msg);

        // Notify UMAC to enter hangtime signalling mode on this traffic timeslot.
        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
        });

        // Notify Brew to stop forwarding audio, if this SSI is cleared for Br
        if net_brew::is_brew_gssi_routable(&self.config, dest_ssi) {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
            });
        }
    }

    /// Handle U-TX DEMAND: another radio requests floor during hangtime
    /// Response: send D-TX GRANTED via FACCH, resume voice path
    fn rx_u_tx_demand(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let requesting_party = prim.received_tetra_address;

        let pdu = match UTxDemand::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing U-TX DEMAND: {:?}", e);
                return;
            }
        };

        let call_id = pdu.call_identifier;

        if let Some(call) = self.private_calls.get(&call_id) {
            if !call.connected || call.duplex {
                return;
            }
            self.send_d_tx_wait(queue, &message, call_id);
            if let Some(swmi) = self.swmi.as_ref().filter(|endpoint| endpoint.is_online()) {
                let _ = swmi.submit(SwmiMessage::PrivateFloorGranted {
                    call_id: call_id as u64,
                    itsi: requesting_party.ssi as u64,
                });
            }
            return;
        }

        if self.swmi.as_ref().is_some_and(SwmiCmceEndpoint::is_online) {
            // The asynchronous central decision must not leave the MS with a
            // silent PTT press.  D-TX WAIT is the immediate ETSI response;
            // a later FloorGranted changes the floor network-wide.
            self.send_d_tx_wait(queue, &message, call_id);
            let command_id = self.next_swmi_command_id();
            if self
                .swmi
                .as_ref()
                .expect("checked above")
                .submit(SwmiMessage::FloorRequest {
                    command_id,
                    call_id: call_id as u64,
                    itsi: requesting_party.ssi as u64,
                })
                .is_ok()
            {
                tracing::info!(
                    call_id,
                    itsi = requesting_party.ssi,
                    command_id,
                    "U-TX DEMAND forwarded to central SwMI"
                );
                return;
            }
        }

        let Some(call) = self.active_calls.get_mut(&call_id) else {
            tracing::warn!("U-TX DEMAND for unknown call_id={}", call_id);
            return;
        };

        tracing::info!("U-TX DEMAND: ISSI {} requests floor on call_id={}", requesting_party.ssi, call_id);

        // ETSI 14.5.2.2.1 b): if another MS is already transmitting, the SwMI should
        // normally wait for that party to finish before granting. Reject the request.
        if call.tx_active {
            tracing::warn!(
                "U-TX DEMAND from ISSI {} rejected, ISSI {} already transmitting on call_id={}",
                requesting_party.ssi,
                call.source_issi,
                call_id
            );
            self.send_d_tx_wait(queue, &message, call_id);
            return;
        }

        // Grant the floor to the requesting MS
        let ts = call.ts;
        call.tx_active = true;
        call.hangtime_start = None;
        call.source_issi = requesting_party.ssi;

        // Update caller_addr for local calls
        if let CallOrigin::Local { caller_addr } = &mut call.origin {
            *caller_addr = requesting_party;
        }

        let Some((_, dest_addr, _)) = self.cached_setups.get(&call_id) else {
            tracing::error!("No cached D-SETUP for call_id={}", call_id);
            return;
        };
        let dest_addr = *dest_addr;

        // ETSI 14.5.2.2.1 b): Send individual D-TX GRANTED (Granted) to requesting MS FIRST
        let d_tx_granted_individual = DTxGranted {
            call_identifier: call_id,
            transmission_grant: TransmissionGrant::Granted.into_raw() as u8,
            transmission_request_permission: false,
            encryption_control: false,
            reserved: false,
            notification_indicator: None,
            transmitting_party_type_identifier: Some(1), // SSI
            transmitting_party_address_ssi: Some(requesting_party.ssi as u64),
            transmitting_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(50);
        d_tx_granted_individual.to_bitbuf(&mut sdu).expect("Failed to serialize DTxGranted");
        sdu.seek(0);
        tracing::info!("-> {:?} sdu {}", d_tx_granted_individual, sdu.dump_bin());

        let requesting_addr = TetraAddress::new(requesting_party.ssi, SsiType::Issi);
        let msg = Self::build_sapmsg_stealing(sdu, requesting_addr, ts);
        queue.push_back(msg);

        // ETSI 14.5.2.2.1 b): Send group D-TX GRANTED (GrantedToOtherUser) to GSSI
        self.send_d_tx_granted_facch(queue, call_id, requesting_party.ssi, dest_addr.ssi, ts);

        // Notify UMAC to resume traffic mode (exit hangtime) for this timeslot.
        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                call_id,
                source_issi: requesting_party.ssi,
                dest_gssi: dest_addr.ssi,
                ts,
            }),
        });

        // Notify Brew of speaker change (local MS taking floor)
        if net_brew::is_brew_gssi_routable(&self.config, dest_addr.ssi) {
            let Some(call) = self.active_calls.get(&call_id) else {
                return;
            };
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                    call_id,
                    source_issi: requesting_party.ssi,
                    dest_gssi: dest_addr.ssi,
                    ts: call.ts,
                }),
            });
        }
    }

    /// Handle U-RELEASE: radio explicitly releases the call
    fn rx_u_release(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let pdu = match URelease::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing U-RELEASE: {:?}", e);
                return;
            }
        };

        let call_id = pdu.call_identifier;
        tracing::info!("U-RELEASE: call_id={} cause={}", call_id, pdu.disconnect_cause);
        if self.private_calls.contains_key(&call_id) {
            if let Some(swmi) = self.swmi.as_ref().filter(|endpoint| endpoint.is_online()) {
                let _ = swmi.submit(SwmiMessage::PrivateCallRelease {
                    call_id: call_id as u64,
                    itsi: prim.received_tetra_address.ssi as u64,
                    cause: pdu.disconnect_cause as u8,
                });
                return;
            }
            self.release_private_call_local(queue, call_id, pdu.disconnect_cause);
            return;
        }
        self.release_call(queue, call_id, DisconnectCause::UserRequestedDisconnection);
    }

    /// Handle U-DISCONNECT: MS requests call disconnection (ETSI 14.5.2.3.1)
    /// Call owner → release entire group call with D-RELEASE (cause=1)
    /// Non-call owner → reject with D-RELEASE cause=8 individually addressed to sender
    fn rx_u_disconnect(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let sender = prim.received_tetra_address;
        let ul_handle = prim.handle;
        let ul_link_id = prim.link_id;
        let ul_endpoint_id = prim.endpoint_id;

        let pdu = match UDisconnect::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing U-DISCONNECT: {:?}", e);
                return;
            }
        };

        let call_id = pdu.call_identifier;
        let disconnect_cause = pdu.disconnect_cause;

        if self.private_calls.contains_key(&call_id) {
            if let Some(swmi) = self.swmi.as_ref().filter(|endpoint| endpoint.is_online()) {
                let _ = swmi.submit(SwmiMessage::PrivateCallRelease {
                    call_id: call_id as u64,
                    itsi: sender.ssi as u64,
                    cause: disconnect_cause as u8,
                });
                tracing::info!(call_id, itsi = sender.ssi, "private U-DISCONNECT forwarded to central SwMI");
                return;
            }
            self.release_private_call_local(queue, call_id, disconnect_cause);
            return;
        }

        if self.swmi.as_ref().is_some_and(SwmiCmceEndpoint::is_online) {
            let command_id = self.next_swmi_command_id();
            if self
                .swmi
                .as_ref()
                .expect("checked above")
                .submit(SwmiMessage::CallDisconnectRequest {
                    command_id,
                    call_id: call_id as u64,
                    itsi: sender.ssi as u64,
                })
                .is_ok()
            {
                tracing::info!(call_id, itsi = sender.ssi, command_id, "U-DISCONNECT forwarded to central SwMI");
                return;
            }
        }

        let Some(call) = self.active_calls.get(&call_id) else {
            tracing::debug!("U-DISCONNECT for unknown call_id={} (likely duplicate)", call_id);
            return;
        };

        let is_call_owner = matches!(&call.origin, CallOrigin::Local { caller_addr } if caller_addr.ssi == sender.ssi);

        if is_call_owner {
            // Call owner: tear down the entire group call
            tracing::info!("U-DISCONNECT: call owner ISSI {} disconnecting call_id={}", sender.ssi, call_id);
            self.release_call(queue, call_id, DisconnectCause::UserRequestedDisconnection);
        } else {
            // Non-call owner: reject with D-RELEASE cause=8 ("Requested service not available")
            // individually addressed back to the sender. The group call continues.
            tracing::info!(
                "U-DISCONNECT: non-call-owner ISSI {} rejected for call_id={} cause={}",
                sender.ssi,
                call_id,
                disconnect_cause
            );

            let d_release = DRelease {
                call_identifier: call_id,
                disconnect_cause: DisconnectCause::RequestedServiceNotAvailable,
                notification_indicator: None,
                facility: None,
                proprietary: None,
            };

            let mut sdu = BitBuffer::new_autoexpand(32);
            d_release.to_bitbuf(&mut sdu).expect("Failed to serialize DRelease");
            sdu.seek(0);
            tracing::info!("-> {:?} sdu {}", d_release, sdu.dump_bin());

            let sender_addr = TetraAddress::new(sender.ssi, SsiType::Issi);
            let msg = SapMsg {
                sap: Sap::LcmcSap,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Mle,
                msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                    sdu,
                    handle: ul_handle,
                    endpoint_id: ul_endpoint_id,
                    link_id: ul_link_id,
                    layer2service: Layer2Service::Unacknowledged,
                    pdu_prio: 0,
                    layer2_qos: 0,
                    stealing_permission: false,
                    stealing_repeats_flag: false,
                    chan_alloc: None,
                    main_address: sender_addr,
                    tx_reporter: None,
                }),
            };
            queue.push_back(msg);
        }
    }

    /// Handle incoming CallControl messages from Brew
    pub fn rx_call_control(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        let SapMsgInner::CmceCallControl(call_control) = message.msg else {
            panic!("Expected CmceCallControl message");
        };

        match call_control {
            CallControl::NetworkCallStart {
                brew_uuid,
                source_issi,
                dest_gssi,
                priority,
            } => {
                self.rx_network_call_start(queue, brew_uuid, source_issi, dest_gssi, priority);
            }
            CallControl::NetworkCallEnd { brew_uuid } => {
                self.rx_network_call_end(queue, brew_uuid);
            }
            CallControl::UlInactivityTimeout { ts } => {
                self.handle_ul_inactivity_timeout(queue, ts);
            }
            _ => {
                tracing::warn!("Unexpected CallControl message: {:?}", call_control);
            }
        }
    }

    /// Handle network-initiated group call start
    fn rx_network_call_start(&mut self, queue: &mut MessageQueue, brew_uuid: uuid::Uuid, source_issi: u32, dest_gssi: u32, _priority: u8) {
        assert!(net_brew::is_brew_gssi_routable(&self.config, dest_gssi));

        if !self.has_listener(dest_gssi) {
            tracing::info!(
                "CMCE: ignoring network call start uuid={} gssi={} (no listeners)",
                brew_uuid,
                dest_gssi
            );
            self.drop_group_calls_if_unlistened(queue, dest_gssi);

            // We already checked this is cleared for brew
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::NetworkCallEnd { brew_uuid }),
            });
            return;
        }

        // Check if there is an active call for this GSSI (speaker change scenario)
        if let Some((call_id, call)) = self.active_calls.iter_mut().find(|(_, c)| c.dest_gssi == dest_gssi) {
            // Reject speaker change if a local MS is already transmitting
            if call.tx_active {
                tracing::warn!(
                    "CMCE: network speaker change rejected, ISSI {} already transmitting on gssi={}",
                    call.source_issi,
                    dest_gssi
                );
                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Cmce,
                    dest: TetraEntity::Brew,
                    msg: SapMsgInner::CmceCallControl(CallControl::NetworkCallEnd { brew_uuid }),
                });
                return;
            }

            // Speaker change during hangtime
            tracing::info!(
                "CMCE: network call speaker change gssi={} new_speaker={} (was {})",
                dest_gssi,
                source_issi,
                call.source_issi
            );

            call.source_issi = source_issi;
            call.tx_active = true;
            call.hangtime_start = None;
            call.brew_uuid = Some(brew_uuid);

            if let CallOrigin::Network { brew_uuid: old_uuid } = call.origin {
                // Backend issues a fresh UUID for each speaker, so this fires every change.
                if old_uuid != brew_uuid {
                    tracing::debug!("CMCE: brew_uuid changed during speaker change ({} -> {})", old_uuid, brew_uuid);
                    call.origin = CallOrigin::Network { brew_uuid };
                }
            }

            // Extract values before mutable borrow ends
            let call_id_val = *call_id;
            let ts = call.ts;
            let usage = call.usage;

            // End the mutable borrow
            let _ = call;

            // Send D-TX GRANTED via FACCH to notify radios of new speaker
            self.send_d_tx_granted_facch(queue, call_id_val, source_issi, dest_gssi, ts);

            // Notify UMAC to resume traffic mode (exit hangtime) for this timeslot.
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorGranted {
                    call_id: call_id_val,
                    source_issi,
                    dest_gssi,
                    ts,
                }),
            });

            // Respond to Brew with existing call resources, we already ensured it is cleared for brew
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::NetworkCallReady {
                    brew_uuid,
                    call_id: call_id_val,
                    ts,
                    usage,
                }),
            });
            return;
        }

        // New network call - allocate circuit
        let circuit = match {
            let mut state = self.config.state_write();
            self.circuits.allocate_circuit_with_allocator(
                Direction::Both,
                CommunicationType::P2Mp,
                &mut state.timeslot_alloc,
                TimeslotOwner::Cmce,
            )
        } {
            Ok(c) => c.clone(),
            Err(err) => {
                tracing::warn!("CMCE: failed to allocate circuit for network call: {:?}", err);
                return;
            }
        };

        let call_id = circuit.call_id;
        let ts = circuit.ts;
        let usage = circuit.usage;

        tracing::info!(
            "CMCE: starting NEW network call brew_uuid={} gssi={} speaker={} ts={} call_id={}",
            brew_uuid,
            dest_gssi,
            source_issi,
            ts,
            call_id
        );

        // Signal UMAC to open DL and UL circuits
        Self::signal_umac_circuit_open(queue, &circuit);

        tracing::debug!(
            "CMCE: sending D-SETUP for NEW call call_id={} gssi={} (network-initiated)",
            call_id,
            dest_gssi
        );

        // Send D-SETUP to group (broadcast on MCCH)
        let dest_addr = TetraAddress::new(dest_gssi, SsiType::Gssi);
        let d_setup = DSetup {
            call_identifier: call_id,
            call_time_out: CallTimeout::T5m,
            hook_method_selection: false,
            simplex_duplex_selection: false, // Simplex
            basic_service_information: BasicServiceInformation {
                circuit_mode_type: CircuitModeType::TchS,
                encryption_flag: false,
                communication_type: CommunicationType::P2Mp,
                slots_per_frame: None,
                speech_service: Some(0),
            },
            transmission_grant: TransmissionGrant::GrantedToOtherUser,
            transmission_request_permission: false,
            call_priority: 0,
            notification_indicator: None,
            temporary_address: None,
            calling_party_address_ssi: Some(source_issi),
            calling_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };

        // Cache for late-entry re-sends. Receipt starts as None so the CircuitMgr-triggered
        // backup send (within D_SETUP_REPEATS frames) is not throttled by this initial send.
        // The first re-send via tick_start will create a tracked receipt.
        self.cached_setups.insert(call_id, (d_setup, dest_addr, None));
        let (d_setup_ref, _, _) = self.cached_setups.get(&call_id).unwrap();

        let (setup_sdu, setup_chan_alloc) = Self::build_d_setup_prim(d_setup_ref, usage, ts, UlDlAssignment::Both);
        let setup_msg = Self::build_sapmsg(setup_sdu, Some(setup_chan_alloc), dest_addr, Layer2Service::Unacknowledged, None);
        queue.push_back(setup_msg);

        // Send D-CONNECT to group
        let d_connect = DConnect {
            call_identifier: call_id,
            call_time_out: CallTimeout::T5m,
            hook_method_selection: false,
            simplex_duplex_selection: false, // Simplex
            transmission_grant: TransmissionGrant::GrantedToOtherUser,
            transmission_request_permission: false,
            call_ownership: false,
            call_priority: None,
            basic_service_information: None,
            temporary_address: None,
            notification_indicator: None,
            facility: None,
            proprietary: None,
        };

        let mut connect_sdu = BitBuffer::new_autoexpand(30);
        d_connect.to_bitbuf(&mut connect_sdu).expect("Failed to serialize DConnect");
        connect_sdu.seek(0);

        let connect_msg = SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu: connect_sdu,
                handle: 0, // Broadcast to group, no specific handle
                endpoint_id: 0,
                link_id: 0,
                layer2service: Layer2Service::Unacknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None, // Already sent in D-SETUP
                main_address: dest_addr,
                tx_reporter: None,
            }),
        };
        queue.push_back(connect_msg);

        // Track the active call
        self.active_calls.insert(
            call_id,
            ActiveCall {
                origin: CallOrigin::Network { brew_uuid },
                dest_gssi,
                source_issi,
                ts,
                usage,
                tx_active: true,
                hangtime_start: None,
                brew_uuid: Some(brew_uuid),
            },
        );

        // Respond to Brew with allocated resources, we already ensured it is cleared for brew
        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Brew,
            msg: SapMsgInner::CmceCallControl(CallControl::NetworkCallReady {
                brew_uuid,
                call_id,
                ts,
                usage,
            }),
        });
    }

    /// Handle network call end request
    fn rx_network_call_end(&mut self, queue: &mut MessageQueue, brew_uuid: uuid::Uuid) {
        // Find the call by brew_uuid field (works for both Local and Network origin calls)
        let Some((call_id, call)) = self
            .active_calls
            .iter()
            .find(|(_, c)| c.brew_uuid == Some(brew_uuid))
            .map(|(id, c)| (*id, c.clone()))
        else {
            tracing::debug!("CMCE: network call end for unknown brew_uuid={}", brew_uuid);
            return;
        };

        tracing::info!(
            "CMCE: network call ended brew_uuid={} call_id={} gssi={}",
            brew_uuid,
            call_id,
            call.dest_gssi
        );

        // If currently transmitting, enter hangtime instead of immediate release
        let tx_active = call.tx_active;
        let dest_gssi = call.dest_gssi;
        let ts = call.ts;

        if tx_active {
            if let Some(active_call) = self.active_calls.get_mut(&call_id) {
                active_call.tx_active = false;
                active_call.hangtime_start = Some(self.dltime);
                active_call.brew_uuid = None;
            }
            // Send D-TX CEASED via FACCH
            self.send_d_tx_ceased_facch(queue, call_id, dest_gssi, ts);

            // Notify UMAC to enter hangtime signalling mode on this traffic timeslot.
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Umac,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
            });
        } else {
            // Already in hangtime or idle, release immediately
            self.release_call(queue, call_id, DisconnectCause::SwmiRequestedDisconnection);
        }
    }

    /// Send D-TX GRANTED via FACCH stealing
    fn send_d_tx_granted_facch(&mut self, queue: &mut MessageQueue, call_id: u16, source_issi: u32, dest_gssi: u32, ts: u8) {
        let pdu = DTxGranted {
            call_identifier: call_id,
            transmission_grant: TransmissionGrant::GrantedToOtherUser.into_raw() as u8,
            transmission_request_permission: false,
            encryption_control: false,
            reserved: false,
            notification_indicator: None,
            transmitting_party_type_identifier: Some(1), // SSI
            transmitting_party_address_ssi: Some(source_issi as u64),
            transmitting_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(30);
        pdu.to_bitbuf(&mut sdu).expect("Failed to serialize DTxGranted");
        sdu.seek(0);
        tracing::info!("-> FACCH {:?} sdu {}", pdu, sdu.dump_bin());

        let dest_addr = TetraAddress::new(dest_gssi, SsiType::Gssi);
        let msg = Self::build_sapmsg_stealing(sdu, dest_addr, ts);
        queue.push_back(msg);
    }

    fn send_d_tx_granted_individual_facch(&mut self, queue: &mut MessageQueue, call_id: u16, source_issi: u32, ts: u8) {
        let pdu = DTxGranted {
            call_identifier: call_id,
            transmission_grant: TransmissionGrant::Granted.into_raw() as u8,
            transmission_request_permission: false,
            encryption_control: false,
            reserved: false,
            notification_indicator: None,
            transmitting_party_type_identifier: Some(1),
            transmitting_party_address_ssi: Some(source_issi as u64),
            transmitting_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(48);
        pdu.to_bitbuf(&mut sdu).expect("serialize individual D-TX GRANTED");
        sdu.seek(0);
        tracing::info!(issi = source_issi, call_id, "-> individual FACCH D-TX GRANTED");
        queue.push_back(Self::build_sapmsg_stealing(sdu, TetraAddress::new(source_issi, SsiType::Issi), ts));
    }

    fn send_private_d_tx_granted(&self, queue: &mut MessageQueue, call_id: u16, source_itsi: u32, recipient_itsi: u32, ts: u8) {
        let pdu = DTxGranted {
            call_identifier: call_id,
            transmission_grant: if source_itsi == recipient_itsi {
                TransmissionGrant::Granted
            } else {
                TransmissionGrant::GrantedToOtherUser
            }
            .into_raw() as u8,
            transmission_request_permission: false,
            encryption_control: false,
            reserved: false,
            notification_indicator: None,
            transmitting_party_type_identifier: Some(1),
            transmitting_party_address_ssi: Some(source_itsi as u64),
            transmitting_party_extension: None,
            external_subscriber_number: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(48);
        pdu.to_bitbuf(&mut sdu).expect("serialize private D-TX GRANTED");
        sdu.seek(0);
        queue.push_back(Self::build_sapmsg_stealing(
            sdu,
            TetraAddress::new(recipient_itsi, SsiType::Issi),
            ts,
        ));
    }

    /// Handle UL inactivity timeout from UMAC: a radio disappeared mid-transmission.
    /// Treat identically to rx_u_tx_ceased — force TX ceased, enter hangtime.
    fn handle_ul_inactivity_timeout(&mut self, queue: &mut MessageQueue, ts: u8) {
        // Find the active call on this timeslot with tx_active == true
        let call_entry = self
            .active_calls
            .iter()
            .find(|(_, call)| call.ts == ts && call.tx_active)
            .map(|(id, _)| *id);

        let Some(call_id) = call_entry else {
            tracing::debug!("UL inactivity timeout on ts={} but no active transmitting call found", ts);
            return;
        };

        let call = self.active_calls.get_mut(&call_id).unwrap();
        tracing::warn!("UL inactivity timeout on ts={}, forcing TX ceased for call_id={}", ts, call_id);

        let dest_gssi = call.dest_gssi;
        call.tx_active = false;
        call.hangtime_start = Some(self.dltime);

        // Send D-TX CEASED via FACCH to all group members
        self.send_d_tx_ceased_facch(queue, call_id, dest_gssi, ts);

        // Notify UMAC to enter hangtime signalling mode
        queue.push_back(SapMsg {
            sap: Sap::Control,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Umac,
            msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
        });

        // Notify Brew to stop forwarding audio
        if net_brew::is_brew_gssi_routable(&self.config, dest_gssi) {
            queue.push_back(SapMsg {
                sap: Sap::Control,
                src: TetraEntity::Cmce,
                dest: TetraEntity::Brew,
                msg: SapMsgInner::CmceCallControl(CallControl::FloorReleased { call_id, ts }),
            });
        }
    }

    /// Send D-TX CEASED via FACCH stealing
    fn send_d_tx_ceased_facch(&mut self, queue: &mut MessageQueue, call_id: u16, dest_gssi: u32, ts: u8) {
        let pdu = DTxCeased {
            call_identifier: call_id,
            transmission_request_permission: false, // ETSI 14.8.43: 0 = allowed to request transmission
            notification_indicator: None,
            facility: None,
            dm_ms_address: None,
            proprietary: None,
        };

        let mut sdu = BitBuffer::new_autoexpand(30);
        pdu.to_bitbuf(&mut sdu).expect("Failed to serialize DTxCeased");
        sdu.seek(0);
        tracing::info!("-> FACCH {:?} sdu {}", pdu, sdu.dump_bin());

        let dest_addr = TetraAddress::new(dest_gssi, SsiType::Gssi);
        let msg = Self::build_sapmsg_stealing(sdu, dest_addr, ts);
        queue.push_back(msg);
    }
}
