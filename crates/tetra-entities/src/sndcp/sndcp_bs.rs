use std::collections::{HashMap, HashSet};

use tetra_config::bluestation::{SharedConfig, SubscriberDeliveryRoute};
use tetra_core::{
    AieRequest, AieScope, AieSubject, BitBuffer, EndpointId, Layer2Service, LinkId, Sap, SsiType, TdmaTime, TetraAddress, TimeslotOwner,
    TxReporter, TxState, tetra_entities::TetraEntity,
};
use tetra_pdus::mm::pdus::d_location_update_command::DLocationUpdateCommand;
use tetra_pdus::sndcp::tip::{
    SndcpAddressRequest, SndcpDownlink, SndcpResourceRequest, SndcpUplink, ready_timer_code, response_wait_timer_code, standby_timer_code,
};
use tetra_saps::{
    SapMsg, SapMsgInner,
    control::packet_data::PacketBearerControl,
    lcmc::{
        enums::{alloc_type::ChanAllocType, ul_dl_assignment::UlDlAssignment},
        fields::chan_alloc_req::CmceChanAllocReq,
    },
    lmm::LmmMleUnitdataReq,
    ltpd::{LtpdMleUnitdataInd, LtpdMleUnitdataReq},
    tma::{AssociatedChannel, TmaUnitdataReq},
};
use tetra_swmi_protocol::{
    ChapProof, PacketAccessResponse, PacketAddressRequest, PacketBearerAction, PacketBearerState, PacketDataMessage, PacketDeliveryStatus,
    PacketRejectCause, PacketResourceRequest, SwmiMessage, TerminalSecurityClass,
};

use crate::{MessageQueue, TetraEntityTrait, net_swmi::SwmiPacketEndpoint};

const DEFAULT_NSAPI: u8 = 1;
const PACKET_USAGE_BASE: u8 = 48;
// TxReporter is completed while the MAC block is prepared ahead of RF. Keep
// the old PDCH alive until that preparation horizon has passed, so the
// QuitAndGo allocation or the BL-ACK for an MS-originated immediate service
// change cannot be removed together with the bearer that still carries it.
const PDCH_RELEASE_RF_GUARD_TIMESLOTS: i32 = 8;
const DRAIN_GRACE_TIMESLOTS: i32 = PDCH_RELEASE_RF_GUARD_TIMESLOTS;
// TxReporter becomes Transmitted when the MAC block is built ahead of RF.
// Retain the old PDCH for a short guard after that point so the channel
// allocation reaches air before voice reuses the removed physical slot.
const PDCH_RESIZE_RF_GUARD_TIMESLOTS: i32 = 8;
const PDCH_RESIZE_TIMEOUT_TIMESLOTS: i32 = 2 * 18 * 4;

#[derive(Debug, Clone)]
struct RadioContext {
    issi: u32,
    endpoint_id: EndpointId,
    link_id: LinkId,
    nsapi: u8,
    snei: Option<u16>,
    session_id: Option<u64>,
    session_generation: Option<u64>,
    bearer_id: Option<u64>,
    bearer_generation: Option<u64>,
    timeslot_bitmap: u8,
    event_label: Option<u16>,
    chap_identifier: Option<u8>,
    dynamic_address: bool,
}

impl RadioContext {
    fn address(&self) -> TetraAddress {
        TetraAddress::issi(self.issi)
    }

    fn session(&self) -> Option<(u64, u64)> {
        Some((self.session_id?, self.session_generation?))
    }

    fn primary_timeslot(&self) -> Option<u8> {
        (2..=4).find(|timeslot| self.timeslot_bitmap & (1 << (timeslot - 1)) != 0)
    }
}

#[derive(Debug, Clone)]
struct Bearer {
    id: u64,
    generation: u64,
    timeslot_bitmap: u8,
    /// Slot set requested by the SwMI/MS. A temporarily unavailable slot is
    /// added later, after a circuit releases it, using the ETSI resize order.
    desired_timeslot_bitmap: u8,
    members: HashSet<u32>,
    draining: bool,
    release_at: Option<TdmaTime>,
    force_at: Option<TdmaTime>,
    command_id: u64,
    drain_reporters: Vec<TxReporter>,
    resize: Option<PendingBearerResize>,
    expand_not_before: Option<TdmaTime>,
}

#[derive(Debug, Clone)]
struct PendingBearerResize {
    from_bitmap: u8,
    to_bitmap: u8,
    /// Slots reserved in advance for an expansion. They are released again
    /// if the new channel allocation cannot be put on air.
    expansion_bitmap: u8,
    reporters: Vec<TxReporter>,
    deadline: TdmaTime,
    commit_at: Option<TdmaTime>,
}

#[derive(Debug, Clone)]
struct PendingDelivery {
    session_id: u64,
    session_generation: u64,
    packet_id: u64,
    reporter: TxReporter,
}

#[derive(Debug, Clone)]
struct PendingStandby {
    issi: u32,
    session_id: u64,
    session_generation: u64,
    /// Present for a network-originated SN-END OF DATA. An MS-originated
    /// immediate service change needs only enough time for LLC's BL-ACK to
    /// reach RF.
    reporter: Option<TxReporter>,
    release_at: Option<TdmaTime>,
}

#[derive(Debug, Clone)]
struct PendingMsDeactivation {
    issi: u32,
    deactivation_type: u8,
    nsapi: Option<u8>,
    snei: Option<u16>,
}

#[derive(Debug, Clone, Copy)]
struct PendingNetworkDeactivation {
    command_id: u64,
    session_id: u64,
    session_generation: u64,
}

pub struct Sndcp {
    config: SharedConfig,
    swmi: Option<SwmiPacketEndpoint>,
    dltime: TdmaTime,
    next_command_id: u64,
    next_packet_id: u64,
    contexts: HashMap<u32, RadioContext>,
    pending_commands: HashMap<u64, u32>,
    pending_ms_deactivations: HashMap<u64, PendingMsDeactivation>,
    pending_network_deactivations: HashMap<u32, PendingNetworkDeactivation>,
    bearers: HashMap<u64, Bearer>,
    pending_deliveries: Vec<PendingDelivery>,
    pending_standby: Vec<PendingStandby>,
}

impl Sndcp {
    pub fn new(config: SharedConfig, swmi: Option<SwmiPacketEndpoint>) -> Self {
        Self {
            config,
            swmi,
            dltime: TdmaTime::default(),
            next_command_id: 1,
            next_packet_id: 1,
            contexts: HashMap::new(),
            pending_commands: HashMap::new(),
            pending_ms_deactivations: HashMap::new(),
            pending_network_deactivations: HashMap::new(),
            bearers: HashMap::new(),
            pending_deliveries: Vec::new(),
            pending_standby: Vec::new(),
        }
    }

    fn next_command(&mut self) -> u64 {
        let value = self.next_command_id;
        self.next_command_id = self.next_command_id.saturating_add(1).max(1);
        value
    }

    fn next_packet(&mut self) -> u64 {
        let value = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.saturating_add(1).max(1);
        value
    }

    fn submit(&self, message: PacketDataMessage) -> bool {
        let Some(swmi) = &self.swmi else {
            return false;
        };
        match swmi.submit(SwmiMessage::PacketData(message)) {
            Ok(()) => true,
            Err(message) => {
                tracing::warn!(?message, "SwMI packet-data queue unavailable");
                false
            }
        }
    }

    fn registration_generation(&self, issi: u32) -> u64 {
        self.config
            .state_read()
            .subscribers
            .registration_generation(issi)
            .unwrap_or_default()
    }

    fn route_for(&self, context: &RadioContext) -> Option<AssociatedChannel> {
        let timeslot = context.primary_timeslot()?;
        Some(AssociatedChannel {
            call_id: context.bearer_id.unwrap_or_default() as u16,
            timeslot,
            usage: context
                .event_label
                .map(|label| PACKET_USAGE_BASE + (label as u8 & 0x0f))
                .unwrap_or(PACKET_USAGE_BASE),
            best_effort_key: None,
        })
    }

    fn publish_delivery_routes(&self, context: &RadioContext) {
        let Some(bearer_id) = context.bearer_id else {
            self.config.state_write().subscriber_packet_delivery_routes.remove(&context.issi);
            return;
        };
        let usage = context
            .event_label
            .map(|label| PACKET_USAGE_BASE + (label as u8 & 0x0f))
            .unwrap_or(PACKET_USAGE_BASE);
        let routes = (2..=4)
            .filter(|timeslot| context.timeslot_bitmap & (1 << (timeslot - 1)) != 0)
            .map(|timeslot| SubscriberDeliveryRoute {
                call_id: bearer_id as u16,
                timeslot,
                usage,
            })
            .collect::<Vec<_>>();
        let mut state = self.config.state_write();
        if routes.is_empty() {
            state.subscriber_packet_delivery_routes.remove(&context.issi);
        } else {
            state.subscriber_packet_delivery_routes.insert(context.issi, routes);
        }
    }

    fn insert_context(&mut self, context: RadioContext) {
        self.publish_delivery_routes(&context);
        self.contexts.insert(context.issi, context);
    }

    fn remove_context(&mut self, issi: u32) -> Option<RadioContext> {
        self.config.state_write().subscriber_packet_delivery_routes.remove(&issi);
        self.contexts.remove(&issi)
    }

    fn queue_registration_recovery(&self, queue: &mut MessageQueue, issi: u32, handle: EndpointId) {
        let mut sdu = BitBuffer::new_autoexpand(16);
        DLocationUpdateCommand {
            group_identity_report: true,
            cipher_control: false,
            ciphering_parameters: None,
            address_extension: None,
            cell_type_control: None,
            proprietary: None,
        }
        .to_bitbuf(&mut sdu)
        .expect("fixed D-LOCATION UPDATE COMMAND must encode");
        sdu.seek(0);
        queue.push_back(SapMsg::new(
            Sap::LmmSap,
            TetraEntity::Sndcp,
            TetraEntity::Mle,
            SapMsgInner::LmmMleUnitdataReq(LmmMleUnitdataReq {
                sdu,
                handle,
                address: TetraAddress::issi(issi),
                layer2service: Layer2Service::Acknowledged,
                stealing_permission: false,
                stealing_repeats_flag: false,
                encryption_flag: false,
                // After a BS restart no usable terminal AIE context exists;
                // the MM registration procedure establishes a fresh one.
                aie_request: AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource),
                is_null_pdu: false,
                tx_reporter: None,
                seamless_handover: None,
            }),
        ));
        tracing::info!(issi, "requested registration recovery after SNDCP access from unknown terminal");
    }

    /// Move one activated PDP context off its current PDCH while retaining
    /// the context for a later SN-DATA TRANSMIT REQUEST.  A shared packet
    /// bearer remains open for its other members; the final member releases
    /// the timeslots back to voice/control service.
    fn detach_packet_bearer(&mut self, queue: &mut MessageQueue, issi: u32) {
        self.config.state_write().subscriber_packet_delivery_routes.remove(&issi);
        let association = self.contexts.get_mut(&issi).and_then(|context| {
            let value = context
                .bearer_id
                .zip(context.bearer_generation)
                .zip(context.event_label)
                .map(|((id, generation), event_label)| (id, generation, event_label));
            context.bearer_id = None;
            context.bearer_generation = None;
            context.timeslot_bitmap = 0;
            context.event_label = None;
            value
        });
        let Some((bearer_id, generation, event_label)) = association else {
            return;
        };
        let bearer_state = self
            .bearers
            .get_mut(&bearer_id)
            .filter(|bearer| bearer.generation == generation)
            .map(|bearer| {
                bearer.members.remove(&issi);
                (
                    bearer.members.is_empty(),
                    bearer.draining,
                    bearer.command_id,
                    bearer.timeslot_bitmap,
                    bearer.members.len().min(u16::MAX as usize) as u16,
                )
            });
        let Some((empty, draining, command_id, timeslot_bitmap, member_count)) = bearer_state else {
            return;
        };
        queue.push_back(SapMsg::new(
            Sap::Control,
            TetraEntity::Sndcp,
            TetraEntity::Umac,
            SapMsgInner::PacketBearerControl(PacketBearerControl::Detach {
                bearer_id,
                generation,
                event_label,
            }),
        ));
        if empty {
            self.release_bearer(queue, bearer_id, generation, false);
        } else {
            self.submit(PacketDataMessage::BearerReport {
                command_id,
                bearer_id,
                bearer_generation: generation,
                state: if draining {
                    PacketBearerState::Draining
                } else {
                    PacketBearerState::Ready
                },
                timeslot_bitmap,
                member_count,
            });
        }
    }

    fn queue_downlink(
        &self,
        queue: &mut MessageQueue,
        context: &RadioContext,
        pdu: SndcpDownlink,
        layer2service: Layer2Service,
        chan_alloc: Option<CmceChanAllocReq>,
    ) -> bool {
        self.queue_downlink_with_reporter(queue, context, pdu, layer2service, chan_alloc, None)
    }

    fn queue_downlink_with_reporter(
        &self,
        queue: &mut MessageQueue,
        context: &RadioContext,
        pdu: SndcpDownlink,
        layer2service: Layer2Service,
        chan_alloc: Option<CmceChanAllocReq>,
        tx_reporter: Option<TxReporter>,
    ) -> bool {
        let mut sdu = BitBuffer::new_autoexpand(256);
        if let Err(error) = pdu.to_bitbuf(&mut sdu) {
            tracing::warn!(issi = context.issi, ?error, "cannot encode SNDCP downlink PDU");
            return false;
        }
        sdu.seek(0);
        // A Replace allocation is the CCCH-to-PDCH assignment and therefore
        // has to be sent on the current common channel.  QuitAndGo is the
        // inverse transition: the MS is still listening on its PDCH until it
        // receives this PDU, so route it over the existing bearer.  Sending a
        // QuitAndGo on the CCCH leaves the MS unaware of the release and the
        // acknowledged link reporter can never complete.
        let associated_channel = match chan_alloc.as_ref().map(|allocation| allocation.alloc_type) {
            Some(ChanAllocType::QuitAndGo) | None => self.route_for(context),
            Some(_) => None,
        };
        queue.push_back(SapMsg::new(
            Sap::TlpdSap,
            TetraEntity::Sndcp,
            TetraEntity::Mle,
            SapMsgInner::LtpdMleUnitdataReq(LtpdMleUnitdataReq {
                sdu,
                handle: 0,
                layer2service,
                unacked_bl_repetitions: 1,
                pdu_prio: 0,
                main_address: context.address(),
                endpoint_id: context.endpoint_id,
                link_id: context.link_id,
                stealing_permission: false,
                stealing_repeats_flag: false,
                channel_advice_flag: false,
                data_class_info: 0,
                data_prio: 0,
                mle_data_prio_flag: false,
                packet_data_flag: true,
                scheduled_data_status: 0,
                max_schedule_interval: 0,
                fcs_flag: true,
                chan_alloc,
                associated_channel,
                aie_override: None,
                tx_reporter,
            }),
        ));
        true
    }

    fn individual_downlink_aie(&self, issi: u32) -> AieRequest {
        let state = self.config.state_read();
        let subject = AieSubject::Individual { issi };
        if !state.aie.enabled || state.aie_sessions.terminal_allows_clear(issi) {
            return AieRequest::clear(subject, AieScope::MacResource);
        }
        match state.aie_sessions.terminal_class(issi) {
            TerminalSecurityClass::Sc1 => AieRequest::clear(subject, AieScope::MacResource),
            TerminalSecurityClass::Sc2 => AieRequest::sc2(subject, AieScope::MacResource),
            TerminalSecurityClass::Sc3 => AieRequest::sc3(subject, AieScope::MacResource),
            TerminalSecurityClass::Unknown if state.aie.sc3.is_some() => AieRequest::sc3(subject, AieScope::MacResource),
            TerminalSecurityClass::Unknown => AieRequest::sc2(subject, AieScope::MacResource),
        }
    }

    /// Put a MAC-only Replace allocation on the MS's current PDCH. TTR
    /// 001-05 section 7.11.1 defines PDCH width changes as a MAC procedure:
    /// for shrinking, the allocation is sent before the removed AACH changes;
    /// for expansion, the new AACH is enabled before this allocation.
    fn queue_standalone_channel_allocation(&self, queue: &mut MessageQueue, context: &RadioContext, timeslot_bitmap: u8) -> TxReporter {
        let reporter = TxReporter::new_unacked();
        let usage = context
            .event_label
            .map(|label| PACKET_USAGE_BASE + (label as u8 & 0x0f))
            .unwrap_or(PACKET_USAGE_BASE);
        queue.push_back(SapMsg::new(
            Sap::TmaSap,
            TetraEntity::Sndcp,
            TetraEntity::Umac,
            SapMsgInner::TmaUnitdataReq(TmaUnitdataReq {
                req_handle: 0,
                pdu: BitBuffer::new(0),
                main_address: context.address(),
                endpoint_id: context.endpoint_id,
                stealing_permission: false,
                subscriber_class: 0,
                air_interface_encryption: Some(self.individual_downlink_aie(context.issi)),
                stealing_repeats_flag: None,
                data_category: None,
                chan_alloc: Some(Self::channel_allocation(timeslot_bitmap, usage, ChanAllocType::Replace)),
                associated_channel: self.route_for(context),
                tx_reporter: Some(reporter.clone()),
            }),
        ));
        reporter
    }

    fn channel_allocation(bitmap: u8, usage: u8, alloc_type: ChanAllocType) -> CmceChanAllocReq {
        CmceChanAllocReq {
            usage: Some(usage & 0x3f),
            carrier: None,
            timeslots: [
                bitmap & 0b0001 != 0,
                bitmap & 0b0010 != 0,
                bitmap & 0b0100 != 0,
                bitmap & 0b1000 != 0,
            ],
            alloc_type,
            cell_change_flag: false,
            ul_dl_assigned: UlDlAssignment::Both,
        }
    }

    /// TTR 001-05 sections 6.7 and 7.6 require the READY-to-STANDBY response
    /// to use `Quit current channel and go to specified channel`. Bitmap 0000
    /// selects the MCCH/common SCCH and the usage marker is absent for this
    /// allocation type.
    fn quit_to_common_channel() -> CmceChanAllocReq {
        CmceChanAllocReq {
            usage: None,
            carrier: None,
            timeslots: [false; 4],
            alloc_type: ChanAllocType::QuitAndGo,
            cell_change_flag: false,
            ul_dl_assigned: UlDlAssignment::Both,
        }
    }

    fn activation_reject_cause(cause: Option<PacketRejectCause>) -> u8 {
        match cause.unwrap_or(PacketRejectCause::ProtocolError) {
            PacketRejectCause::AuthenticationFailed => 20,
            // The only context validation delegated to the SwMI is its
            // configured APN index.
            PacketRejectCause::ContextUnsupported => 22,
            PacketRejectCause::ServiceTemporarilyUnavailable => 34,
            PacketRejectCause::SystemResourcesUnavailable => 7,
            PacketRejectCause::InvalidAddress => 8,
            PacketRejectCause::ProtocolError => 0,
        }
    }

    fn transmit_reject_cause(cause: Option<PacketRejectCause>) -> u8 {
        match cause.unwrap_or(PacketRejectCause::ProtocolError) {
            PacketRejectCause::SystemResourcesUnavailable => 1,
            PacketRejectCause::ContextUnsupported => 2,
            PacketRejectCause::ServiceTemporarilyUnavailable => 34,
            PacketRejectCause::AuthenticationFailed | PacketRejectCause::InvalidAddress | PacketRejectCause::ProtocolError => 0,
        }
    }

    fn unsupported_address_reject_cause(address_type: u8) -> u8 {
        match address_type {
            2 => 3,
            3 => 17,
            4 => 18,
            5 => 27,
            _ => 0,
        }
    }

    fn resource(resource: Option<SndcpResourceRequest>) -> Option<PacketResourceRequest> {
        resource.map(|resource| PacketResourceRequest {
            symmetric: resource.symmetric,
            requested_uplink_slots: resource.uplink_slots,
            requested_downlink_slots: resource.downlink_slots,
            full_phase_slots: resource.full_phase_slots,
            throughput: resource.throughput,
        })
    }

    fn handle_uplink(&mut self, queue: &mut MessageQueue, mut prim: LtpdMleUnitdataInd) {
        if prim.received_tetra_address.ssi_type != SsiType::Issi && prim.received_tetra_address.ssi_type != SsiType::Ssi {
            tracing::warn!(address = ?prim.received_tetra_address, "dropping non-individual SNDCP uplink");
            return;
        }
        let issi = prim.received_tetra_address.ssi;
        let pdu = match SndcpUplink::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(issi, ?error, bits = %prim.sdu.dump_bin(), "invalid SNDCP uplink PDU");
                return;
            }
        };
        tracing::info!(issi, ?pdu, "received SNDCP uplink");
        let registered = self.config.state_read().subscribers.is_registered(issi);
        let online = self.swmi.as_ref().is_some_and(SwmiPacketEndpoint::is_online);

        match pdu {
            SndcpUplink::ActivateDemand {
                version,
                nsapi,
                address,
                ms_type,
                apn_index,
                chap,
            } => {
                let dynamic_address = matches!(&address, SndcpAddressRequest::Dynamic);
                let context = RadioContext {
                    issi,
                    endpoint_id: prim.endpoint_id,
                    link_id: prim.link_id,
                    nsapi,
                    snei: None,
                    session_id: None,
                    session_generation: None,
                    bearer_id: None,
                    bearer_generation: None,
                    timeslot_bitmap: 0,
                    event_label: None,
                    chap_identifier: chap.as_ref().map(|proof| proof.identifier),
                    dynamic_address,
                };
                self.insert_context(context.clone());
                let local_reject = if version != 1 {
                    Some(16)
                } else if nsapi != DEFAULT_NSAPI {
                    Some(19)
                } else if !matches!(ms_type, 1 | 2) {
                    Some(15)
                } else if !registered {
                    Some(1)
                } else if !online {
                    Some(34)
                } else {
                    None
                };
                if let Some(cause) = local_reject {
                    self.queue_downlink(
                        queue,
                        &context,
                        SndcpDownlink::ActivateReject {
                            nsapi,
                            cause,
                            chap_failure: None,
                        },
                        Layer2Service::Acknowledged,
                        None,
                    );
                    if cause == 1 {
                        self.queue_registration_recovery(queue, issi, prim.endpoint_id);
                    }
                    self.remove_context(issi);
                    return;
                }
                let command_id = self.next_command();
                self.pending_commands.insert(command_id, issi);
                let packet_address = match address {
                    SndcpAddressRequest::Dynamic => PacketAddressRequest::Dynamic,
                    SndcpAddressRequest::Static(ipv4) => PacketAddressRequest::Static(ipv4),
                    SndcpAddressRequest::Unsupported(address_type) => {
                        self.pending_commands.remove(&command_id);
                        self.queue_downlink(
                            queue,
                            &context,
                            SndcpDownlink::ActivateReject {
                                nsapi,
                                cause: Self::unsupported_address_reject_cause(address_type),
                                chap_failure: None,
                            },
                            Layer2Service::Acknowledged,
                            None,
                        );
                        self.remove_context(issi);
                        return;
                    }
                };
                if !self.submit(PacketDataMessage::Activate {
                    command_id,
                    itsi: u64::from(issi),
                    air_handle: prim.endpoint_id,
                    registration_generation: self.registration_generation(issi),
                    nsapi,
                    ms_type,
                    apn_index,
                    address: packet_address,
                    chap: chap.map(|proof| ChapProof {
                        identifier: proof.identifier,
                        challenge: proof.challenge,
                        response: proof.response.to_vec(),
                        username: proof.username,
                    }),
                }) {
                    self.pending_commands.remove(&command_id);
                    self.queue_downlink(
                        queue,
                        &context,
                        SndcpDownlink::ActivateReject {
                            nsapi,
                            cause: 34,
                            chap_failure: None,
                        },
                        Layer2Service::Acknowledged,
                        None,
                    );
                    self.remove_context(issi);
                }
            }
            SndcpUplink::DeactivateDemand {
                deactivation_type,
                nsapi,
                snei,
            } => {
                let context = self.contexts.get(&issi).cloned().unwrap_or(RadioContext {
                    issi,
                    endpoint_id: prim.endpoint_id,
                    link_id: prim.link_id,
                    nsapi: nsapi.unwrap_or(DEFAULT_NSAPI),
                    snei,
                    session_id: None,
                    session_generation: None,
                    bearer_id: None,
                    bearer_generation: None,
                    timeslot_bitmap: 0,
                    event_label: None,
                    chap_identifier: None,
                    dynamic_address: true,
                });
                let identifies_context =
                    deactivation_type == 0 || (nsapi == Some(context.nsapi) && snei.is_none_or(|value| context.snei == Some(value)));
                if let Some((session_id, session_generation)) = context.session().filter(|_| identifies_context) {
                    let command_id = self.next_command();
                    self.pending_ms_deactivations.insert(
                        command_id,
                        PendingMsDeactivation {
                            issi,
                            deactivation_type,
                            nsapi,
                            snei,
                        },
                    );
                    if self.submit(PacketDataMessage::Deactivate {
                        command_id,
                        itsi: u64::from(issi),
                        session_id,
                        session_generation,
                        network_initiated: false,
                    }) {
                        return;
                    }
                    self.pending_ms_deactivations.remove(&command_id);
                }
                self.queue_downlink(
                    queue,
                    &context,
                    SndcpDownlink::DeactivateAccept {
                        deactivation_type,
                        nsapi,
                        snei,
                    },
                    Layer2Service::Acknowledged,
                    None,
                );
                if identifies_context {
                    self.remove_context(issi);
                }
            }
            SndcpUplink::DeactivateAccept {
                deactivation_type,
                nsapi,
                snei,
            } => {
                let Some(pending) = self.pending_network_deactivations.remove(&issi) else {
                    tracing::warn!(issi, "unexpected SNDCP deactivation accept");
                    return;
                };
                let context_matches = self.contexts.get(&issi).is_some_and(|context| {
                    deactivation_type == 1
                        && nsapi == Some(context.nsapi)
                        && snei.is_none_or(|value| context.snei == Some(value))
                        && context.session() == Some((pending.session_id, pending.session_generation))
                });
                self.submit(PacketDataMessage::DeactivateResult {
                    command_id: pending.command_id,
                    itsi: u64::from(issi),
                    session_id: pending.session_id,
                    session_generation: pending.session_generation,
                    accepted: context_matches,
                });
                if context_matches {
                    self.remove_context(issi);
                }
            }
            SndcpUplink::Data { nsapi, payload } => {
                let Some(context) = self.contexts.get(&issi).cloned() else {
                    return;
                };
                let Some((session_id, session_generation)) = context.session() else {
                    return;
                };
                if nsapi != context.nsapi || payload.len() < 20 || payload.first().map(|value| value >> 4) != Some(4) {
                    tracing::warn!(issi, nsapi, "dropping invalid IPv4 SN-DATA");
                    return;
                }
                let packet_id = self.next_packet();
                self.submit(PacketDataMessage::Ipv4 {
                    session_id,
                    session_generation,
                    packet_id,
                    payload,
                });
            }
            SndcpUplink::TransmitRequest {
                nsapi,
                logical_link_connected,
                snei,
                resource,
            } => {
                let recovering = !self.contexts.contains_key(&issi);
                if recovering {
                    let Some(snei) = snei else {
                        tracing::warn!(
                            issi,
                            nsapi,
                            logical_link_connected,
                            "cannot recover SNDCP transmit request without SNEI"
                        );
                        return;
                    };
                    tracing::info!(
                        issi,
                        nsapi,
                        snei,
                        logical_link_connected,
                        "recovering retained SNDCP context from transmit request"
                    );
                    self.insert_context(RadioContext {
                        issi,
                        endpoint_id: prim.endpoint_id,
                        link_id: prim.link_id,
                        nsapi,
                        snei: Some(snei),
                        session_id: None,
                        session_generation: None,
                        bearer_id: None,
                        bearer_generation: None,
                        timeslot_bitmap: 0,
                        event_label: None,
                        chap_identifier: None,
                        dynamic_address: true,
                    });
                } else if !self
                    .contexts
                    .get(&issi)
                    .is_some_and(|context| context.nsapi == nsapi && snei.is_none_or(|value| context.snei == Some(value)))
                {
                    tracing::warn!(issi, nsapi, ?snei, "ignoring SNDCP transmit request for another context");
                    return;
                }
                self.request_access(issi, prim.endpoint_id, prim.link_id, resource, recovering, true);
            }
            SndcpUplink::Reconnect {
                data_to_send,
                nsapi,
                snei,
                resource,
            } => {
                if !self.contexts.contains_key(&issi) {
                    let Some(snei) = snei else {
                        tracing::warn!(issi, "cannot recover roaming SNDCP context without SNEI");
                        return;
                    };
                    self.insert_context(RadioContext {
                        issi,
                        endpoint_id: prim.endpoint_id,
                        link_id: prim.link_id,
                        nsapi: nsapi.unwrap_or(DEFAULT_NSAPI),
                        snei: Some(snei),
                        session_id: None,
                        session_generation: None,
                        bearer_id: None,
                        bearer_generation: None,
                        timeslot_bitmap: 0,
                        event_label: None,
                        chap_identifier: None,
                        dynamic_address: true,
                    });
                }
                self.request_access(issi, prim.endpoint_id, prim.link_id, resource, true, data_to_send);
            }
            SndcpUplink::EndOfData { immediate_service_change } => {
                let Some(context) = self.contexts.get(&issi).cloned() else {
                    return;
                };
                let Some((session_id, session_generation)) = context.session() else {
                    return;
                };
                let command_id = self.next_command();
                self.submit(PacketDataMessage::EndOfData {
                    command_id,
                    itsi: u64::from(issi),
                    session_id,
                    session_generation,
                    immediate_service_change,
                });
            }
            SndcpUplink::PageResponse {
                nsapi,
                available,
                logical_link_status: _,
                snei,
                resource,
            } => {
                let Some(context) = self.contexts.get_mut(&issi) else {
                    return;
                };
                if nsapi != context.nsapi || snei.is_some_and(|value| context.snei != Some(value)) {
                    tracing::warn!(issi, nsapi, ?snei, "ignoring SNDCP page response for another context");
                    return;
                }
                context.endpoint_id = prim.endpoint_id;
                context.link_id = prim.link_id;
                let context = context.clone();
                let Some((session_id, session_generation)) = context.session() else {
                    return;
                };
                let command_id = self.next_command();
                self.pending_commands.insert(command_id, issi);
                self.submit(PacketDataMessage::PageResponse {
                    command_id,
                    itsi: u64::from(issi),
                    air_handle: prim.endpoint_id,
                    registration_generation: self.registration_generation(issi),
                    session_id,
                    session_generation,
                    available,
                    resource: Self::resource(resource),
                });
            }
        }
    }

    fn request_access(
        &mut self,
        issi: u32,
        endpoint_id: EndpointId,
        link_id: LinkId,
        resource: Option<SndcpResourceRequest>,
        reconnect: bool,
        data_to_send: bool,
    ) {
        let Some(context) = self.contexts.get_mut(&issi) else {
            return;
        };
        context.endpoint_id = endpoint_id;
        context.link_id = link_id;
        let context = context.clone();
        let (session_id, session_generation) = context.session().unwrap_or((0, 0));
        if session_id == 0 && (!reconnect || context.snei.is_none()) {
            return;
        }
        let command_id = self.next_command();
        self.pending_commands.insert(command_id, issi);
        self.submit(PacketDataMessage::Access {
            command_id,
            itsi: u64::from(issi),
            air_handle: endpoint_id,
            registration_generation: self.registration_generation(issi),
            session_id,
            session_generation,
            data_to_send,
            reconnect,
            snei: context.snei,
            resource: Self::resource(resource),
        });
    }

    fn reserve_bearer(&mut self, queue: &mut MessageQueue, command_id: u64, id: u64, generation: u64, requested: u8) {
        if let Some(existing) = self.bearers.get(&id) {
            let state = if existing.generation == generation {
                PacketBearerState::Ready
            } else {
                PacketBearerState::Failed
            };
            self.submit(PacketDataMessage::BearerReport {
                command_id,
                bearer_id: id,
                bearer_generation: generation,
                state,
                timeslot_bitmap: (existing.generation == generation)
                    .then_some(existing.timeslot_bitmap)
                    .unwrap_or_default(),
                member_count: (existing.generation == generation)
                    .then_some(existing.members.len().min(u16::MAX as usize) as u16)
                    .unwrap_or_default(),
            });
            return;
        }
        let mut allocated = 0u8;
        {
            let mut state = self.config.state_write();
            for timeslot in 2..=4 {
                let bit = 1 << (timeslot - 1);
                if requested & bit != 0 && state.timeslot_alloc.reserve(TimeslotOwner::PacketData, timeslot).is_ok() {
                    allocated |= bit;
                }
            }
        }
        if allocated == 0 {
            self.submit(PacketDataMessage::BearerReport {
                command_id,
                bearer_id: id,
                bearer_generation: generation,
                state: PacketBearerState::Failed,
                timeslot_bitmap: 0,
                member_count: 0,
            });
            return;
        }
        self.bearers.insert(
            id,
            Bearer {
                id,
                generation,
                timeslot_bitmap: allocated,
                desired_timeslot_bitmap: requested & 0b1110,
                members: HashSet::new(),
                draining: false,
                release_at: None,
                force_at: None,
                command_id,
                drain_reporters: Vec::new(),
                resize: None,
                expand_not_before: None,
            },
        );
        queue.push_back(SapMsg::new(
            Sap::Control,
            TetraEntity::Sndcp,
            TetraEntity::Umac,
            SapMsgInner::PacketBearerControl(PacketBearerControl::Open {
                bearer_id: id,
                generation,
                timeslot_bitmap: allocated,
            }),
        ));
        self.submit(PacketDataMessage::BearerReport {
            command_id,
            bearer_id: id,
            bearer_generation: generation,
            state: PacketBearerState::Ready,
            timeslot_bitmap: allocated,
            member_count: 0,
        });
    }

    fn start_bearer_resize(&mut self, queue: &mut MessageQueue, id: u64, generation: u64, to_bitmap: u8, expansion_bitmap: u8) -> bool {
        let Some((from_bitmap, mut members)) = self
            .bearers
            .get(&id)
            .filter(|bearer| bearer.generation == generation && !bearer.draining && bearer.resize.is_none())
            .map(|bearer| (bearer.timeslot_bitmap, bearer.members.clone()))
        else {
            return false;
        };
        if to_bitmap == 0 || to_bitmap == from_bitmap {
            return false;
        }

        // Bearer reservation and radio access are separate SwMI messages. A
        // BS restart or a delayed AccessResult can therefore leave the local
        // bearer member set temporarily behind a recovered radio context.
        // Include every context that already names this bearer so an attached
        // MS always receives the Replace allocation before its AACH changes.
        members.extend(self.contexts.iter().filter_map(|(&issi, context)| {
            (context.bearer_id == Some(id) && context.bearer_generation == Some(generation)).then_some(issi)
        }));
        let members = members.into_iter().collect::<Vec<_>>();
        let member_count = members.len();

        // For an expansion, UMAC must advertise Uma on the added slots before
        // the MS receives the larger Replace allocation (TTR 001-05 7.11.1).
        if expansion_bitmap != 0 {
            queue.push_back(SapMsg::new(
                Sap::Control,
                TetraEntity::Sndcp,
                TetraEntity::Umac,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Resize {
                    bearer_id: id,
                    generation,
                    timeslot_bitmap: to_bitmap,
                }),
            ));
        }

        let reporters = members
            .iter()
            .filter_map(|issi| self.contexts.get(issi))
            .filter(|context| context.bearer_id == Some(id) && context.bearer_generation == Some(generation))
            .map(|context| self.queue_standalone_channel_allocation(queue, context, to_bitmap))
            .collect::<Vec<_>>();
        self.bearers.get_mut(&id).expect("validated bearer").resize = Some(PendingBearerResize {
            from_bitmap,
            to_bitmap,
            expansion_bitmap,
            reporters,
            deadline: self.dltime.add_timeslots(PDCH_RESIZE_TIMEOUT_TIMESLOTS),
            // A reserved bearer can legitimately have no attached MS yet. In
            // that case there is nobody to notify over RF and the resize may
            // commit immediately instead of blocking a higher-priority call.
            commit_at: (member_count == 0).then_some(self.dltime),
        });
        tracing::info!(
            bearer_id = id,
            generation,
            from_bitmap,
            to_bitmap,
            member_count,
            "packet bearer resize announced to attached terminals"
        );
        true
    }

    fn commit_bearer_resize(&mut self, queue: &mut MessageQueue, id: u64, generation: u64) {
        let Some((resize, members, command_id)) =
            self.bearers
                .get_mut(&id)
                .filter(|bearer| bearer.generation == generation)
                .and_then(|bearer| {
                    let resize = bearer.resize.take()?;
                    bearer.timeslot_bitmap = resize.to_bitmap;
                    bearer.expand_not_before = (resize.expansion_bitmap == 0).then(|| self.dltime.add_timeslots(18 * 4));
                    Some((resize, bearer.members.iter().copied().collect::<Vec<_>>(), bearer.command_id))
                })
        else {
            return;
        };

        // On shrink the old AACH remains Uma until this point, after the
        // Replace allocation reached RF. Only now may voice take that slot.
        if resize.expansion_bitmap == 0 {
            queue.push_back(SapMsg::new(
                Sap::Control,
                TetraEntity::Sndcp,
                TetraEntity::Umac,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Resize {
                    bearer_id: id,
                    generation,
                    timeslot_bitmap: resize.to_bitmap,
                }),
            ));
            let removed = resize.from_bitmap & !resize.to_bitmap;
            let mut state = self.config.state_write();
            for timeslot in 2..=4 {
                if removed & (1 << (timeslot - 1)) != 0 {
                    let _ = state.timeslot_alloc.release(TimeslotOwner::PacketData, timeslot);
                }
            }
        }

        for issi in members {
            if let Some(context) = self.contexts.get_mut(&issi) {
                context.timeslot_bitmap = resize.to_bitmap;
                let context = context.clone();
                self.publish_delivery_routes(&context);
            }
        }
        self.submit(PacketDataMessage::BearerReport {
            command_id,
            bearer_id: id,
            bearer_generation: generation,
            state: PacketBearerState::Ready,
            timeslot_bitmap: resize.to_bitmap,
            member_count: self.bearers[&id].members.len().min(u16::MAX as usize) as u16,
        });
        tracing::info!(
            bearer_id = id,
            generation,
            from_bitmap = resize.from_bitmap,
            to_bitmap = resize.to_bitmap,
            "packet bearer resize committed after over-air notification"
        );
    }

    fn rollback_bearer_resize(&mut self, queue: &mut MessageQueue, id: u64, generation: u64) {
        let Some(resize) = self
            .bearers
            .get_mut(&id)
            .filter(|bearer| bearer.generation == generation)
            .and_then(|bearer| bearer.resize.take())
        else {
            return;
        };
        if resize.expansion_bitmap != 0 {
            queue.push_back(SapMsg::new(
                Sap::Control,
                TetraEntity::Sndcp,
                TetraEntity::Umac,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Resize {
                    bearer_id: id,
                    generation,
                    timeslot_bitmap: resize.from_bitmap,
                }),
            ));
            let mut state = self.config.state_write();
            for timeslot in 2..=4 {
                if resize.expansion_bitmap & (1 << (timeslot - 1)) != 0 {
                    let _ = state.timeslot_alloc.release(TimeslotOwner::PacketData, timeslot);
                }
            }
        }
        tracing::warn!(
            bearer_id = id,
            generation,
            "packet bearer resize did not reach every attached terminal; retaining old slot set"
        );
    }

    fn process_bearer_resizes(&mut self, queue: &mut MessageQueue) {
        let pending = self
            .bearers
            .iter_mut()
            .filter_map(|(&id, bearer)| {
                let resize = bearer.resize.as_mut()?;
                if resize
                    .reporters
                    .iter()
                    .any(|reporter| matches!(reporter.get_state(), TxState::Discarded | TxState::Lost))
                    || resize.deadline.age(self.dltime) >= 0
                {
                    return Some((id, bearer.generation, false));
                }
                if resize.reporters.iter().all(TxReporter::is_in_final_state) {
                    let commit_at = *resize
                        .commit_at
                        .get_or_insert_with(|| self.dltime.add_timeslots(PDCH_RESIZE_RF_GUARD_TIMESLOTS));
                    if commit_at.age(self.dltime) >= 0 {
                        return Some((id, bearer.generation, true));
                    }
                }
                None
            })
            .collect::<Vec<_>>();
        for (id, generation, commit) in pending {
            if commit {
                self.commit_bearer_resize(queue, id, generation);
            } else {
                self.rollback_bearer_resize(queue, id, generation);
            }
        }
    }

    fn process_bearer_expansions(&mut self, queue: &mut MessageQueue) {
        let candidates = self
            .bearers
            .iter()
            .filter(|(_, bearer)| {
                !bearer.draining && bearer.resize.is_none() && bearer.expand_not_before.is_none_or(|due| due.age(self.dltime) >= 0)
            })
            .filter_map(|(&id, bearer)| {
                let missing = bearer.desired_timeslot_bitmap & !bearer.timeslot_bitmap;
                (missing != 0).then_some((id, bearer.generation, bearer.timeslot_bitmap, missing))
            })
            .collect::<Vec<_>>();
        for (id, generation, current, missing) in candidates {
            let mut added = 0u8;
            {
                let mut state = self.config.state_write();
                for timeslot in 2..=4 {
                    let bit = 1 << (timeslot - 1);
                    if missing & bit != 0 && state.timeslot_alloc.reserve(TimeslotOwner::PacketData, timeslot).is_ok() {
                        added |= bit;
                    }
                }
            }
            if added != 0 {
                let _ = self.start_bearer_resize(queue, id, generation, current | added, added);
            }
        }
    }

    fn begin_drain(&mut self, queue: &mut MessageQueue, command_id: u64, id: u64, generation: u64, force_after_ms: u32) {
        if self
            .bearers
            .get(&id)
            .is_some_and(|bearer| bearer.generation == generation && bearer.resize.is_some())
        {
            self.rollback_bearer_resize(queue, id, generation);
        }
        let member_ids = self
            .bearers
            .get(&id)
            .filter(|bearer| bearer.generation == generation)
            .map(|bearer| bearer.members.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for issi in member_ids {
            if let Some(context) = self.contexts.get(&issi).cloned() {
                let reporter = TxReporter::new_unacked();
                if self.queue_downlink_with_reporter(
                    queue,
                    &context,
                    SndcpDownlink::EndOfData {
                        immediate_service_change: true,
                    },
                    Layer2Service::Unacknowledged,
                    Some(Self::quit_to_common_channel()),
                    Some(reporter.clone()),
                ) && let Some(bearer) = self.bearers.get_mut(&id)
                {
                    bearer.drain_reporters.push(reporter);
                }
            }
        }
        let Some(bearer) = self.bearers.get_mut(&id).filter(|bearer| bearer.generation == generation) else {
            return;
        };
        bearer.draining = true;
        bearer.command_id = command_id;
        bearer.release_at = Some(self.dltime.add_timeslots(DRAIN_GRACE_TIMESLOTS));
        let force_slots = ((force_after_ms as u64 * 18 * 4 + 999) / 1_000).min(i32::MAX as u64) as i32;
        bearer.force_at = Some(self.dltime.add_timeslots(force_slots.max(DRAIN_GRACE_TIMESLOTS)));
        let bitmap = bearer.timeslot_bitmap;
        let member_count = bearer.members.len().min(u16::MAX as usize) as u16;
        queue.push_back(SapMsg::new(
            Sap::Control,
            TetraEntity::Sndcp,
            TetraEntity::Umac,
            SapMsgInner::PacketBearerControl(PacketBearerControl::Drain { bearer_id: id, generation }),
        ));
        self.submit(PacketDataMessage::BearerReport {
            command_id,
            bearer_id: id,
            bearer_generation: generation,
            state: PacketBearerState::Draining,
            timeslot_bitmap: bitmap,
            member_count,
        });
    }

    fn release_bearer(&mut self, queue: &mut MessageQueue, id: u64, generation: u64, forced: bool) {
        if self.bearers.get(&id).map(|bearer| bearer.generation) != Some(generation) {
            tracing::warn!(bearer_id = id, generation, forced, "ignoring stale packet bearer release");
            return;
        }
        let Some(bearer) = self.bearers.remove(&id) else {
            return;
        };
        let reserved_bitmap = bearer.timeslot_bitmap | bearer.resize.as_ref().map(|resize| resize.expansion_bitmap).unwrap_or_default();
        {
            let mut state = self.config.state_write();
            for issi in &bearer.members {
                state.subscriber_packet_delivery_routes.remove(issi);
            }
            for timeslot in 2..=4 {
                if reserved_bitmap & (1 << (timeslot - 1)) != 0 {
                    let _ = state.timeslot_alloc.release(TimeslotOwner::PacketData, timeslot);
                }
            }
        }
        for issi in &bearer.members {
            if let Some(context) = self.contexts.get_mut(issi) {
                if let Some(event_label) = context.event_label {
                    queue.push_back(SapMsg::new(
                        Sap::Control,
                        TetraEntity::Sndcp,
                        TetraEntity::Umac,
                        SapMsgInner::PacketBearerControl(PacketBearerControl::Detach {
                            bearer_id: bearer.id,
                            generation: bearer.generation,
                            event_label,
                        }),
                    ));
                }
                context.bearer_id = None;
                context.bearer_generation = None;
                context.timeslot_bitmap = 0;
                context.event_label = None;
            }
        }
        queue.push_back(SapMsg::new(
            Sap::Control,
            TetraEntity::Sndcp,
            TetraEntity::Umac,
            SapMsgInner::PacketBearerControl(PacketBearerControl::Close {
                bearer_id: bearer.id,
                generation: bearer.generation,
                forced,
            }),
        ));
        self.submit(PacketDataMessage::BearerReport {
            command_id: bearer.command_id,
            bearer_id: bearer.id,
            bearer_generation: bearer.generation,
            state: if forced {
                PacketBearerState::ForcedReuse
            } else {
                PacketBearerState::Released
            },
            timeslot_bitmap: bearer.timeslot_bitmap,
            member_count: bearer.members.len().min(u16::MAX as usize) as u16,
        });
    }

    fn handle_swmi(&mut self, queue: &mut MessageQueue, message: PacketDataMessage) {
        match message {
            PacketDataMessage::ActivateResult {
                command_id,
                itsi,
                air_handle,
                accepted,
                cause,
                session_id,
                session_generation,
                ipv4,
                snei,
                timers,
                ..
            } => {
                let issi = itsi as u32;
                if self.pending_commands.remove(&command_id) != Some(issi) {
                    tracing::warn!(command_id, itsi, "stale SNDCP activation result");
                    return;
                }
                let Some(context) = self.contexts.get_mut(&issi) else {
                    return;
                };
                if context.endpoint_id != air_handle {
                    tracing::warn!(
                        command_id,
                        itsi,
                        air_handle,
                        "stale SNDCP activation result for replaced air endpoint"
                    );
                    return;
                }
                if accepted {
                    context.session_id = Some(session_id);
                    context.session_generation = Some(session_generation);
                    context.snei = snei;
                }
                let context = context.clone();
                let pdu = if accepted {
                    SndcpDownlink::ActivateAccept {
                        nsapi: context.nsapi,
                        ipv4: ipv4.unwrap_or_default(),
                        dynamic_address: context.dynamic_address,
                        // PacketTimers is validated by the SwMI. Retain the
                        // network's conventional 60-second READY value if a
                        // future peer nevertheless supplies an invalid value.
                        ready_timer: ready_timer_code(timers.ready_ms).unwrap_or(11),
                        standby_timer: standby_timer_code(timers.standby_seconds).unwrap_or(6),
                        response_wait_timer: response_wait_timer_code(timers.response_wait_ms).unwrap_or(7),
                        snei,
                        // The MS completes CHAP towards the TE itself.  The
                        // success PCO is optional on the air interface and is
                        // not relayed to the TE (TTR 001-05, 7.1.4).  Omitting
                        // it also keeps this time-critical response well below
                        // the capacity of one SCH/F MAC block.
                        chap_success: None,
                    }
                } else {
                    SndcpDownlink::ActivateReject {
                        nsapi: context.nsapi,
                        cause: Self::activation_reject_cause(cause),
                        chap_failure: (cause == Some(PacketRejectCause::AuthenticationFailed))
                            .then(|| context.chap_identifier.map(|id| (id, "authentication failed".into())))
                            .flatten(),
                    }
                };
                self.queue_downlink(queue, &context, pdu, Layer2Service::Acknowledged, None);
                if !accepted {
                    self.remove_context(issi);
                }
            }
            PacketDataMessage::DeactivateResult {
                command_id,
                itsi,
                accepted,
                ..
            } => {
                let issi = itsi as u32;
                let Some(pending) = self.pending_ms_deactivations.remove(&command_id) else {
                    return;
                };
                if pending.issi != issi {
                    return;
                }
                if let Some(context) = self.contexts.get(&issi).cloned() {
                    self.queue_downlink(
                        queue,
                        &context,
                        SndcpDownlink::DeactivateAccept {
                            deactivation_type: pending.deactivation_type,
                            nsapi: pending.nsapi,
                            snei: pending.snei,
                        },
                        Layer2Service::Acknowledged,
                        None,
                    );
                    if !accepted {
                        tracing::warn!(
                            issi,
                            command_id,
                            "SwMI did not recognize MS deactivation; closing radio context to converge"
                        );
                    }
                    self.remove_context(issi);
                }
            }
            PacketDataMessage::AccessResult {
                command_id,
                itsi,
                session_id,
                accepted,
                cause,
                response,
                bearer_id,
                timeslot_bitmap,
                event_label,
                session_generation,
                ..
            } => {
                let issi = itsi as u32;
                if self.pending_commands.remove(&command_id) != Some(issi) {
                    return;
                }
                let Some(context) = self.contexts.get_mut(&issi) else {
                    return;
                };
                let recovering = context.session_id.is_none() && context.session_generation.is_none();
                if !recovering && context.session_generation != Some(session_generation) {
                    return;
                }
                let bearer_unchanged = accepted
                    && response != PacketAccessResponse::None
                    && context.bearer_id == Some(bearer_id)
                    && context.timeslot_bitmap == timeslot_bitmap
                    && context.event_label == Some(event_label);
                if accepted {
                    // A new access decision supersedes a READY-to-STANDBY
                    // release that may still be inside its RF guard. Do not
                    // detach the freshly resumed bearer when that old guard
                    // expires.
                    self.pending_standby.retain(|pending| pending.issi != issi);
                    context.session_id = Some(session_id);
                    context.session_generation = Some(session_generation);
                    if response != PacketAccessResponse::None {
                        context.bearer_id = Some(bearer_id);
                        context.bearer_generation = self.bearers.get(&bearer_id).map(|bearer| bearer.generation);
                        context.timeslot_bitmap = timeslot_bitmap;
                        context.event_label = Some(event_label);
                        if let Some(bearer) = self.bearers.get_mut(&bearer_id) {
                            bearer.members.insert(issi);
                        }
                        if !bearer_unchanged && let Some(generation) = context.bearer_generation {
                            queue.push_back(SapMsg::new(
                                Sap::Control,
                                TetraEntity::Sndcp,
                                TetraEntity::Umac,
                                SapMsgInner::PacketBearerControl(PacketBearerControl::Attach {
                                    bearer_id,
                                    generation,
                                    issi,
                                    event_label,
                                }),
                            ));
                        }
                    }
                }
                let detach_for_standby = accepted && response == PacketAccessResponse::None && context.bearer_id.is_some();
                let mut context = context.clone();
                if detach_for_standby {
                    // After radio downlink failure, SN-RECONNECT with "no
                    // data to send" arrives on the CCCH (TTR 001-05 6.17).
                    // A null AccessResult deliberately has no air PDU, but it
                    // must detach the stale PDCH association so signalling and
                    // the next packet transfer start from the common channel.
                    self.detach_packet_bearer(queue, issi);
                    if let Some(updated) = self.contexts.get(&issi) {
                        context = updated.clone();
                    }
                    tracing::info!(
                        issi,
                        session_id,
                        session_generation,
                        "packet terminal returned to standby after reconnect without data"
                    );
                }
                self.publish_delivery_routes(&context);
                // A repeated READY-state access on the same bearer is answered
                // on that PDCH. Repeating the Replace allocation forces LLC
                // back to CCCH after the MS has already changed channel and
                // leaves the MS retransmitting SN-RECONNECT indefinitely.
                let chan_alloc = (accepted && response != PacketAccessResponse::None && !bearer_unchanged).then(|| {
                    let usage = PACKET_USAGE_BASE + (event_label as u8 & 0x0f);
                    Self::channel_allocation(timeslot_bitmap, usage, ChanAllocType::Replace)
                });
                match response {
                    PacketAccessResponse::TransmitResponse => {
                        self.queue_downlink(
                            queue,
                            &context,
                            SndcpDownlink::TransmitResponse {
                                nsapi: context.nsapi,
                                accepted,
                                cause: (!accepted).then_some(Self::transmit_reject_cause(cause)),
                                snei: context.snei,
                            },
                            Layer2Service::Acknowledged,
                            chan_alloc,
                        );
                    }
                    PacketAccessResponse::TransmitRequest if accepted => {
                        self.queue_downlink(
                            queue,
                            &context,
                            SndcpDownlink::TransmitRequest {
                                nsapi: context.nsapi,
                                snei: context.snei,
                            },
                            Layer2Service::Acknowledged,
                            chan_alloc,
                        );
                    }
                    PacketAccessResponse::TransmitRequest | PacketAccessResponse::None => {}
                }
                if !accepted && recovering {
                    self.remove_context(issi);
                }
            }
            PacketDataMessage::Page {
                command_id: _,
                itsi,
                session_id,
                session_generation,
                nsapi,
                snei,
            } => {
                let issi = itsi as u32;
                let context = self
                    .contexts
                    .get(&issi)
                    .cloned()
                    .filter(|context| context.session() == Some((session_id, session_generation)))
                    .unwrap_or_else(|| RadioContext {
                        issi,
                        endpoint_id: 0,
                        link_id: 0,
                        nsapi,
                        snei,
                        session_id: Some(session_id),
                        session_generation: Some(session_generation),
                        bearer_id: None,
                        bearer_generation: None,
                        timeslot_bitmap: 0,
                        event_label: None,
                        chap_identifier: None,
                        dynamic_address: true,
                    });
                self.insert_context(context.clone());
                self.queue_downlink(
                    queue,
                    &context,
                    SndcpDownlink::PageRequest {
                        nsapi: context.nsapi,
                        reply_requested: true,
                        snei: context.snei,
                    },
                    Layer2Service::Acknowledged,
                    None,
                );
            }
            PacketDataMessage::Ipv4 {
                session_id,
                session_generation,
                packet_id,
                payload,
            } => {
                let Some(context) = self
                    .contexts
                    .values()
                    .find(|context| context.session() == Some((session_id, session_generation)))
                    .cloned()
                else {
                    self.submit(PacketDataMessage::Delivery {
                        session_id,
                        session_generation,
                        packet_id,
                        status: PacketDeliveryStatus::StaleGeneration,
                    });
                    return;
                };
                let reporter = TxReporter::new();
                let sent = self.queue_downlink_with_reporter(
                    queue,
                    &context,
                    SndcpDownlink::Data {
                        nsapi: context.nsapi,
                        payload,
                    },
                    Layer2Service::Acknowledged,
                    None,
                    Some(reporter.clone()),
                );
                if sent {
                    self.pending_deliveries.push(PendingDelivery {
                        session_id,
                        session_generation,
                        packet_id,
                        reporter,
                    });
                } else {
                    self.submit(PacketDataMessage::Delivery {
                        session_id,
                        session_generation,
                        packet_id,
                        status: PacketDeliveryStatus::LinkFailed,
                    });
                }
            }
            PacketDataMessage::EndOfData {
                itsi,
                session_id,
                session_generation,
                immediate_service_change,
                ..
            } => {
                let issi = itsi as u32;
                let Some(context) = self
                    .contexts
                    .get(&issi)
                    .cloned()
                    .filter(|context| context.session() == Some((session_id, session_generation)))
                else {
                    return;
                };
                if immediate_service_change {
                    // TTR 001-12 sections 6.7.4 and 6.8.4 require the MS to
                    // wait for the basic-link ACK before leaving the PDCH.
                    // LLC generates that ACK automatically, but it is still
                    // queued behind this indication. Preserve the bearer for
                    // one RF preparation horizon before detaching it.
                    self.pending_standby.retain(|pending| pending.issi != issi);
                    self.pending_standby.push(PendingStandby {
                        issi,
                        session_id,
                        session_generation,
                        reporter: None,
                        release_at: Some(self.dltime.add_timeslots(PDCH_RELEASE_RF_GUARD_TIMESLOTS)),
                    });
                    return;
                }
                if self.pending_standby.iter().any(|pending| {
                    pending.issi == issi && pending.session_id == session_id && pending.session_generation == session_generation
                }) {
                    return;
                }
                // SN-END OF DATA is SNDCP control over the unacknowledged
                // basic link. The channel allocation itself moves the MS to
                // common control; no advanced-link teardown is part of this
                // procedure (TTR 001-05 section 6.7).
                let reporter = TxReporter::new_unacked();
                if self.queue_downlink_with_reporter(
                    queue,
                    &context,
                    SndcpDownlink::EndOfData {
                        immediate_service_change: false,
                    },
                    Layer2Service::Unacknowledged,
                    Some(Self::quit_to_common_channel()),
                    Some(reporter.clone()),
                ) {
                    self.pending_standby.push(PendingStandby {
                        issi,
                        session_id,
                        session_generation,
                        reporter: Some(reporter),
                        release_at: None,
                    });
                } else {
                    self.detach_packet_bearer(queue, issi);
                }
            }
            PacketDataMessage::Deactivate {
                command_id,
                itsi,
                session_id,
                session_generation,
                ..
            } => {
                let issi = itsi as u32;
                if let Some(context) = self
                    .contexts
                    .get(&issi)
                    .cloned()
                    .filter(|context| context.session() == Some((session_id, session_generation)))
                {
                    self.pending_network_deactivations.insert(
                        issi,
                        PendingNetworkDeactivation {
                            command_id,
                            session_id,
                            session_generation,
                        },
                    );
                    if !self.queue_downlink(
                        queue,
                        &context,
                        SndcpDownlink::DeactivateDemand {
                            deactivation_type: 1,
                            nsapi: Some(context.nsapi),
                            snei: context.snei,
                        },
                        Layer2Service::Acknowledged,
                        None,
                    ) {
                        self.pending_network_deactivations.remove(&issi);
                        self.submit(PacketDataMessage::DeactivateResult {
                            command_id,
                            itsi,
                            session_id,
                            session_generation,
                            accepted: false,
                        });
                    }
                } else {
                    self.submit(PacketDataMessage::DeactivateResult {
                        command_id,
                        itsi,
                        session_id,
                        session_generation,
                        accepted: false,
                    });
                }
            }
            PacketDataMessage::ContextRelease {
                itsi,
                session_id,
                session_generation,
            } => {
                let issi = itsi as u32;
                let Some(context) = self
                    .contexts
                    .get(&issi)
                    .filter(|context| context.session() == Some((session_id, session_generation)))
                    .cloned()
                else {
                    return;
                };
                self.remove_context(issi);
                self.pending_commands.retain(|_, pending_issi| *pending_issi != issi);
                self.pending_ms_deactivations.retain(|_, pending| pending.issi != issi);
                self.pending_network_deactivations.remove(&issi);
                self.pending_deliveries
                    .retain(|pending| pending.session_id != session_id || pending.session_generation != session_generation);

                let Some((bearer_id, bearer_generation, event_label)) = context
                    .bearer_id
                    .zip(context.bearer_generation)
                    .zip(context.event_label)
                    .map(|((bearer_id, generation), event_label)| (bearer_id, generation, event_label))
                else {
                    return;
                };
                let bearer_state = self
                    .bearers
                    .get_mut(&bearer_id)
                    .filter(|bearer| bearer.generation == bearer_generation)
                    .map(|bearer| {
                        bearer.members.remove(&issi);
                        (
                            bearer.members.is_empty(),
                            bearer.draining,
                            bearer.command_id,
                            bearer.timeslot_bitmap,
                            bearer.members.len().min(u16::MAX as usize) as u16,
                        )
                    });
                let Some((empty, draining, command_id, timeslot_bitmap, member_count)) = bearer_state else {
                    return;
                };
                queue.push_back(SapMsg::new(
                    Sap::Control,
                    TetraEntity::Sndcp,
                    TetraEntity::Umac,
                    SapMsgInner::PacketBearerControl(PacketBearerControl::Detach {
                        bearer_id,
                        generation: bearer_generation,
                        event_label,
                    }),
                ));
                if empty {
                    self.release_bearer(queue, bearer_id, bearer_generation, false);
                } else {
                    self.submit(PacketDataMessage::BearerReport {
                        command_id,
                        bearer_id,
                        bearer_generation,
                        state: if draining {
                            PacketBearerState::Draining
                        } else {
                            PacketBearerState::Ready
                        },
                        timeslot_bitmap,
                        member_count,
                    });
                }
            }
            PacketDataMessage::BearerControl {
                command_id,
                bearer_id,
                bearer_generation,
                action,
                timeslot_bitmap,
                force_after_ms,
            } => match action {
                PacketBearerAction::Reserve => self.reserve_bearer(queue, command_id, bearer_id, bearer_generation, timeslot_bitmap),
                PacketBearerAction::Resize | PacketBearerAction::Drain => {
                    self.begin_drain(queue, command_id, bearer_id, bearer_generation, force_after_ms)
                }
                PacketBearerAction::Release => self.release_bearer(queue, bearer_id, bearer_generation, false),
                PacketBearerAction::ForceRelease => self.release_bearer(queue, bearer_id, bearer_generation, true),
            },
            PacketDataMessage::Delivery { .. }
            | PacketDataMessage::Capability { .. }
            | PacketDataMessage::Activate { .. }
            | PacketDataMessage::Access { .. }
            | PacketDataMessage::PageResponse { .. }
            | PacketDataMessage::BearerReport { .. } => {}
        }
    }

    fn process_preemption(&mut self, queue: &mut MessageQueue) {
        let requested = self.config.state_write().timeslot_alloc.take_packet_preemption_request();
        if !requested {
            return;
        }
        let active = self.bearers.values().find(|bearer| !bearer.draining).map(|bearer| {
            (
                bearer.command_id,
                bearer.id,
                bearer.generation,
                bearer.timeslot_bitmap,
                bearer.resize.is_some(),
            )
        });
        if let Some((command_id, id, generation, bitmap, resizing)) = active {
            if resizing {
                // The capacity queue repeats its request. Let the in-progress
                // atomic resize finish before attempting another one.
                return;
            }
            let slots = (2..=4).filter(|timeslot| bitmap & (1 << (timeslot - 1)) != 0).collect::<Vec<_>>();
            if slots.len() > 1 {
                let released = *slots.last().expect("multislot bearer");
                let reduced = bitmap & !(1 << (released - 1));
                let _ = self.start_bearer_resize(queue, id, generation, reduced, 0);
            } else {
                tracing::info!(bearer_id = id, "voice capacity requested; draining final packet-data slot");
                self.begin_drain(queue, command_id, id, generation, 2_500);
            }
        }
    }

    fn process_drains(&mut self, queue: &mut MessageQueue) {
        let due = self
            .bearers
            .values()
            .filter(|bearer| bearer.draining)
            .filter_map(|bearer| {
                let forced = bearer.force_at.is_some_and(|deadline| deadline.age(self.dltime) >= 0);
                let notification_complete = bearer.members.is_empty()
                    || (!bearer.drain_reporters.is_empty() && bearer.drain_reporters.iter().all(TxReporter::is_in_final_state));
                let graceful = notification_complete && bearer.release_at.is_some_and(|deadline| deadline.age(self.dltime) >= 0);
                (forced || graceful).then_some((bearer.id, bearer.generation, forced))
            })
            .collect::<Vec<_>>();
        for (id, generation, forced) in due {
            self.release_bearer(queue, id, generation, forced);
        }
    }

    fn process_delivery_reports(&mut self) {
        let mut completed = Vec::new();
        let mut index = 0;
        while index < self.pending_deliveries.len() {
            if self.pending_deliveries[index].reporter.is_in_final_state() {
                completed.push(self.pending_deliveries.remove(index));
            } else {
                index += 1;
            }
        }
        for delivery in completed {
            self.submit(PacketDataMessage::Delivery {
                session_id: delivery.session_id,
                session_generation: delivery.session_generation,
                packet_id: delivery.packet_id,
                status: if delivery.reporter.get_state() == TxState::Acknowledged {
                    PacketDeliveryStatus::Delivered
                } else {
                    PacketDeliveryStatus::LinkFailed
                },
            });
        }
    }

    fn process_standby_reports(&mut self, queue: &mut MessageQueue) {
        let mut completed = Vec::new();
        let mut index = 0;
        while index < self.pending_standby.len() {
            let retry = self.pending_standby[index]
                .reporter
                .as_ref()
                .is_some_and(TxReporter::is_discarded)
                .then(|| {
                    let pending = &self.pending_standby[index];
                    (pending.issi, pending.session_id, pending.session_generation)
                });
            if let Some((issi, session_id, session_generation)) = retry {
                let context = self
                    .contexts
                    .get(&issi)
                    .cloned()
                    .filter(|context| context.session() == Some((session_id, session_generation)));
                if let Some(context) = context {
                    let reporter = TxReporter::new_unacked();
                    if self.queue_downlink_with_reporter(
                        queue,
                        &context,
                        SndcpDownlink::EndOfData {
                            immediate_service_change: false,
                        },
                        Layer2Service::Unacknowledged,
                        Some(Self::quit_to_common_channel()),
                        Some(reporter.clone()),
                    ) {
                        self.pending_standby[index].reporter = Some(reporter);
                        self.pending_standby[index].release_at = None;
                        tracing::debug!(issi, "retrying discarded SN-END OF DATA on retained PDCH");
                        index += 1;
                        continue;
                    }
                }
            }
            let pending = &mut self.pending_standby[index];
            if pending.release_at.is_none() && pending.reporter.as_ref().is_some_and(TxReporter::is_transmitted) {
                pending.release_at = Some(self.dltime.add_timeslots(PDCH_RELEASE_RF_GUARD_TIMESLOTS));
            }
            let due = pending.release_at.is_some_and(|release_at| release_at.age(self.dltime) >= 0);
            if due || retry.is_some() {
                completed.push(self.pending_standby.remove(index));
            } else {
                index += 1;
            }
        }
        for pending in completed {
            let context_matches = self
                .contexts
                .get(&pending.issi)
                .is_some_and(|context| context.session() == Some((pending.session_id, pending.session_generation)));
            if context_matches {
                self.detach_packet_bearer(queue, pending.issi);
            }
        }
    }
}

impl TetraEntityTrait for Sndcp {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Sndcp
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        assert_eq!(message.sap, Sap::TlpdSap);
        match message.msg {
            SapMsgInner::LtpdMleUnitdataInd(prim) => self.handle_uplink(queue, prim),
            other => tracing::warn!(?other, "unexpected SNDCP primitive"),
        }
    }

    fn tick_start(&mut self, queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
        loop {
            let message = self.swmi.as_ref().and_then(SwmiPacketEndpoint::try_recv);
            let Some(SwmiMessage::PacketData(message)) = message else {
                break;
            };
            self.handle_swmi(queue, message);
        }
        self.process_preemption(queue);
        self.process_delivery_reports();
        self.process_standby_reports(queue);
        self.process_bearer_resizes(queue);
        self.process_drains(queue);
        self.process_bearer_expansions(queue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_pdus::mm::pdus::d_location_update_command::DLocationUpdateCommand;
    use tetra_pdus::sndcp::pdus::sn_activate_pdp_context::SnActivatePdpContextAccept;
    use tetra_pdus::sndcp::pdus::sn_control::{SnDeactivatePdpContextAccept, SnDeactivatePdpContextDemand, SnEndOfData, SnReconnect};
    use tetra_pdus::sndcp::pdus::sn_transmit::SnDataTransmitRequest;

    fn test_sndcp() -> Sndcp {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration");
        Sndcp::new(SharedConfig::from_parts(config, None), None)
    }

    fn insert_bearer(sndcp: &mut Sndcp, generation: u64, members: HashSet<u32>, reporters: Vec<TxReporter>) {
        sndcp
            .config
            .state_write()
            .timeslot_alloc
            .reserve(TimeslotOwner::PacketData, 2)
            .unwrap();
        sndcp.bearers.insert(
            17,
            Bearer {
                id: 17,
                generation,
                timeslot_bitmap: 0b0010,
                desired_timeslot_bitmap: 0b0010,
                members,
                draining: true,
                release_at: Some(sndcp.dltime),
                force_at: Some(sndcp.dltime.add_timeslots(100)),
                command_id: 9,
                drain_reporters: reporters,
                resize: None,
                expand_not_before: None,
            },
        );
    }

    fn insert_active_multislot_bearer(sndcp: &mut Sndcp) {
        let members = HashSet::from([77_468]);
        for timeslot in 2..=4 {
            sndcp
                .config
                .state_write()
                .timeslot_alloc
                .reserve(TimeslotOwner::PacketData, timeslot)
                .unwrap();
        }
        sndcp.bearers.insert(
            17,
            Bearer {
                id: 17,
                generation: 4,
                timeslot_bitmap: 0b1110,
                desired_timeslot_bitmap: 0b1110,
                members,
                draining: false,
                release_at: None,
                force_at: None,
                command_id: 9,
                drain_reporters: Vec::new(),
                resize: None,
                expand_not_before: None,
            },
        );
        sndcp.contexts.insert(
            77_468,
            RadioContext {
                issi: 77_468,
                endpoint_id: 7,
                link_id: 8,
                nsapi: 1,
                snei: Some(8),
                session_id: Some(8),
                session_generation: Some(1),
                bearer_id: Some(17),
                bearer_generation: Some(4),
                timeslot_bitmap: 0b1110,
                event_label: Some(23),
                chap_identifier: None,
                dynamic_address: true,
            },
        );
        let context = sndcp.contexts[&77_468].clone();
        sndcp.publish_delivery_routes(&context);
    }

    fn uplink(sdu: BitBuffer, issi: u32) -> LtpdMleUnitdataInd {
        LtpdMleUnitdataInd {
            sdu,
            endpoint_id: 7,
            link_id: 8,
            received_tetra_address: TetraAddress::issi(issi),
            chan_change_resp_req: false,
            chan_change_handle: None,
        }
    }

    #[test]
    fn reject_causes_match_etsi_sndcp_tables() {
        assert_eq!(Sndcp::activation_reject_cause(Some(PacketRejectCause::AuthenticationFailed)), 20);
        assert_eq!(
            Sndcp::activation_reject_cause(Some(PacketRejectCause::ServiceTemporarilyUnavailable)),
            34
        );
        assert_eq!(Sndcp::transmit_reject_cause(Some(PacketRejectCause::SystemResourcesUnavailable)), 1);
        assert_eq!(Sndcp::transmit_reject_cause(Some(PacketRejectCause::ContextUnsupported)), 2);
    }

    #[test]
    fn unknown_packet_terminal_is_told_to_register_again() {
        let sndcp = test_sndcp();
        let mut queue = MessageQueue::new();

        sndcp.queue_registration_recovery(&mut queue, 77_479, 7);

        let SapMsgInner::LmmMleUnitdataReq(mut request) = queue.pop_front().unwrap().msg else {
            panic!("expected D-LOCATION UPDATE COMMAND")
        };
        let command = DLocationUpdateCommand::from_bitbuf(&mut request.sdu).unwrap();
        assert!(command.group_identity_report);
        assert!(!command.cipher_control);
        assert_eq!(request.address.ssi, 77_479);
        assert_eq!(request.address.ssi_type, SsiType::Issi);
        assert_eq!(request.handle, 7);
    }

    #[test]
    fn successful_chap_activation_uses_compact_accept_without_pco() {
        let mut sndcp = test_sndcp();
        sndcp.contexts.insert(
            77_479,
            RadioContext {
                issi: 77_479,
                endpoint_id: 7,
                link_id: 0,
                nsapi: 1,
                snei: None,
                session_id: None,
                session_generation: None,
                bearer_id: None,
                bearer_generation: None,
                timeslot_bitmap: 0,
                event_label: None,
                chap_identifier: Some(4),
                dynamic_address: true,
            },
        );
        sndcp.pending_commands.insert(9, 77_479);
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::ActivateResult {
                command_id: 9,
                itsi: 77_479,
                air_handle: 7,
                accepted: true,
                cause: None,
                session_id: 4,
                session_generation: 1,
                ipv4: Some(u32::from_be_bytes([10, 45, 0, 164])),
                snei: Some(4),
                timers: tetra_swmi_protocol::PacketTimers {
                    ready_ms: 10_000,
                    standby_seconds: 1_800,
                    response_wait_ms: 5_000,
                },
            },
        );

        let SapMsgInner::LtpdMleUnitdataReq(mut primitive) = queue.pop_front().expect("activation accept").msg else {
            panic!("expected LTPD unitdata request");
        };
        assert_eq!(primitive.sdu.get_len_remaining(), 90);
        let accept = SnActivatePdpContextAccept::from_bitbuf(&mut primitive.sdu).unwrap();
        assert_eq!(accept.ipv4_address, Some(u32::from_be_bytes([10, 45, 0, 164])));
        assert_eq!(accept.sndcp_network_endpoint_identifier, Some(4));
        assert!(accept.type34_elements.is_empty());
    }

    #[test]
    fn unknown_ms_deactivation_is_acknowledged_without_leaving_state() {
        let mut sndcp = test_sndcp();
        let mut encoded = BitBuffer::new_autoexpand(64);
        SnDeactivatePdpContextDemand {
            deactivation_type: 0,
            nsapi: None,
            sndcp_network_endpoint_identifier: None,
        }
        .to_bitbuf(&mut encoded)
        .unwrap();
        encoded.seek(0);
        let mut queue = MessageQueue::new();

        sndcp.handle_uplink(&mut queue, uplink(encoded, 77_468));

        let message = queue.pop_front().expect("deactivation accept");
        let SapMsgInner::LtpdMleUnitdataReq(mut primitive) = message.msg else {
            panic!("expected LTPD unitdata request");
        };
        let accept = SnDeactivatePdpContextAccept::from_bitbuf(&mut primitive.sdu).unwrap();
        assert_eq!(accept.deactivation_type, 0);
        assert_eq!(accept.nsapi, None);
        assert!(!sndcp.contexts.contains_key(&77_468));
    }

    #[test]
    fn reconnect_recovers_a_missing_local_radio_context_from_snei() {
        let mut sndcp = test_sndcp();
        let mut encoded = BitBuffer::new_autoexpand(64);
        SnReconnect {
            data_to_send: true,
            nsapi: Some(1),
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: Some(8),
            nsapi_for_reconnection: Vec::new(),
        }
        .to_bitbuf(&mut encoded)
        .unwrap();
        encoded.seek(0);

        sndcp.handle_uplink(&mut MessageQueue::new(), uplink(encoded, 77_468));

        let context = sndcp.contexts.get(&77_468).expect("recovered radio context");
        assert_eq!(context.endpoint_id, 7);
        assert_eq!(context.link_id, 8);
        assert_eq!(context.nsapi, 1);
        assert_eq!(context.snei, Some(8));
        assert_eq!(context.session(), None);
    }

    #[test]
    fn transmit_request_recovers_retained_context_after_bs_restart() {
        let mut sndcp = test_sndcp();
        let mut encoded = BitBuffer::new_autoexpand(64);
        SnDataTransmitRequest {
            nsapi: 1,
            logical_link_status: false,
            enhanced_pi_4_dqpsk_service: true,
            resource_request: Some(tetra_pdus::sndcp::pdus::resource_request::SndcpResourceRequest {
                asymmetric_connection: false,
                data_transfer_throughput: 7,
                uplink_or_symmetric_timeslots: 2,
                downlink_timeslots: None,
                full_phase_modulation_capability: 3,
                reserved: 3,
            }),
            sndcp_network_endpoint_identifier: Some(8),
            nsapi_additional: Vec::new(),
        }
        .to_bitbuf(&mut encoded)
        .unwrap();
        encoded.seek(0);

        sndcp.handle_uplink(&mut MessageQueue::new(), uplink(encoded, 77_468));

        let context = sndcp.contexts.get(&77_468).expect("recovered radio context");
        assert_eq!(context.endpoint_id, 7);
        assert_eq!(context.link_id, 8);
        assert_eq!(context.nsapi, 1);
        assert_eq!(context.snei, Some(8));
        assert_eq!(context.session(), None);
        assert_eq!(sndcp.pending_commands.get(&1), Some(&77_468));
    }

    #[test]
    fn repeated_access_response_stays_on_existing_pdch() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), Vec::new());
        let bearer = sndcp.bearers.get_mut(&17).unwrap();
        bearer.draining = false;
        bearer.timeslot_bitmap = 0b0010;
        sndcp.contexts.insert(
            77_468,
            RadioContext {
                issi: 77_468,
                endpoint_id: 7,
                link_id: 8,
                nsapi: 1,
                snei: Some(8),
                session_id: Some(8),
                session_generation: Some(2),
                bearer_id: Some(17),
                bearer_generation: Some(4),
                timeslot_bitmap: 0b0010,
                event_label: Some(23),
                chap_identifier: None,
                dynamic_address: true,
            },
        );
        sndcp.pending_commands.insert(9, 77_468);
        sndcp.pending_standby.push(PendingStandby {
            issi: 77_468,
            session_id: 8,
            session_generation: 2,
            reporter: None,
            release_at: Some(sndcp.dltime.add_timeslots(PDCH_RELEASE_RF_GUARD_TIMESLOTS)),
        });
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::AccessResult {
                command_id: 9,
                itsi: 77_468,
                session_id: 8,
                session_generation: 2,
                accepted: true,
                cause: None,
                response: PacketAccessResponse::TransmitResponse,
                bearer_id: 17,
                timeslot_bitmap: 0b0010,
                event_label: 23,
            },
        );

        let SapMsgInner::LtpdMleUnitdataReq(request) = queue.pop_front().expect("transmit response").msg else {
            panic!("expected LTPD unitdata request");
        };
        assert!(request.chan_alloc.is_none());
        assert_eq!(request.associated_channel.as_ref().map(|route| route.timeslot), Some(2));
        assert!(
            sndcp.pending_standby.is_empty(),
            "resumed access must cancel the old standby release guard"
        );
        assert!(queue.pop_front().is_none(), "existing bearer must not be attached twice");
    }

    #[test]
    fn null_access_response_detaches_terminal_that_returned_to_ccch() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), Vec::new());
        sndcp.bearers.get_mut(&17).unwrap().draining = false;
        sndcp.contexts.insert(
            77_468,
            RadioContext {
                issi: 77_468,
                endpoint_id: 7,
                link_id: 8,
                nsapi: 1,
                snei: Some(8),
                session_id: Some(8),
                session_generation: Some(2),
                bearer_id: Some(17),
                bearer_generation: Some(4),
                timeslot_bitmap: 0b0010,
                event_label: Some(23),
                chap_identifier: None,
                dynamic_address: true,
            },
        );
        let context = sndcp.contexts[&77_468].clone();
        sndcp.publish_delivery_routes(&context);
        sndcp.pending_commands.insert(9, 77_468);
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::AccessResult {
                command_id: 9,
                itsi: 77_468,
                session_id: 8,
                session_generation: 2,
                accepted: true,
                cause: None,
                response: PacketAccessResponse::None,
                bearer_id: 0,
                timeslot_bitmap: 0,
                event_label: 0,
            },
        );

        let context = &sndcp.contexts[&77_468];
        assert_eq!(context.bearer_id, None);
        assert_eq!(context.timeslot_bitmap, 0);
        assert!(!sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(2));
        assert!(!sndcp.config.state_read().subscriber_packet_delivery_routes.contains_key(&77_468));
        let mut saw_detach = false;
        let mut saw_close = false;
        while let Some(message) = queue.pop_front() {
            match message.msg {
                SapMsgInner::PacketBearerControl(PacketBearerControl::Detach {
                    bearer_id: 17,
                    generation: 4,
                    event_label: 23,
                }) => saw_detach = true,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Close {
                    bearer_id: 17,
                    generation: 4,
                    forced: false,
                }) => saw_close = true,
                SapMsgInner::LtpdMleUnitdataReq(_) => {
                    panic!("null access response must not transmit an SNDCP PDU")
                }
                _ => {}
            }
        }
        assert!(saw_detach);
        assert!(saw_close);
    }

    #[test]
    fn roaming_release_removes_old_context_and_empty_bearer() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), Vec::new());
        sndcp.contexts.insert(
            77_468,
            RadioContext {
                issi: 77_468,
                endpoint_id: 7,
                link_id: 8,
                nsapi: 1,
                snei: Some(8),
                session_id: Some(8),
                session_generation: Some(1),
                bearer_id: Some(17),
                bearer_generation: Some(4),
                timeslot_bitmap: 0b0010,
                event_label: Some(23),
                chap_identifier: None,
                dynamic_address: true,
            },
        );
        let context = sndcp.contexts.get(&77_468).unwrap().clone();
        sndcp.publish_delivery_routes(&context);
        assert_eq!(sndcp.config.state_read().subscriber_packet_delivery_routes[&77_468].len(), 1);
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::ContextRelease {
                itsi: 77_468,
                session_id: 8,
                session_generation: 1,
            },
        );

        assert!(!sndcp.contexts.contains_key(&77_468));
        assert!(!sndcp.config.state_read().subscriber_packet_delivery_routes.contains_key(&77_468));
        assert!(!sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(2));
        assert!(queue.iter_mut().any(|message| {
            matches!(
                message.msg,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Detach {
                    bearer_id: 17,
                    generation: 4,
                    event_label: 23,
                })
            )
        }));
    }

    #[test]
    fn end_of_data_response_uses_basic_link_and_releases_after_rf_guard() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), Vec::new());
        sndcp.contexts.insert(
            77_468,
            RadioContext {
                issi: 77_468,
                endpoint_id: 7,
                link_id: 8,
                nsapi: 1,
                snei: Some(8),
                session_id: Some(8),
                session_generation: Some(1),
                bearer_id: Some(17),
                bearer_generation: Some(4),
                timeslot_bitmap: 0b0010,
                event_label: Some(23),
                chap_identifier: None,
                dynamic_address: true,
            },
        );
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::EndOfData {
                command_id: 51,
                itsi: 77_468,
                session_id: 8,
                session_generation: 1,
                immediate_service_change: false,
            },
        );

        let SapMsgInner::LtpdMleUnitdataReq(mut response) = queue.pop_front().unwrap().msg else {
            panic!("expected SN-END OF DATA response")
        };
        assert!(!SnEndOfData::from_bitbuf(&mut response.sdu).unwrap().immediate_service_change);
        assert_eq!(response.layer2service, Layer2Service::Unacknowledged);
        let allocation = response.chan_alloc.expect("READY expiry must return the MS to common control");
        assert_eq!(allocation.alloc_type, ChanAllocType::QuitAndGo);
        assert_eq!(allocation.usage, None);
        assert_eq!(allocation.timeslots, [false; 4]);
        assert_eq!(
            response.associated_channel,
            Some(AssociatedChannel {
                call_id: 17,
                timeslot: 2,
                usage: PACKET_USAGE_BASE + (23 & 0x0f),
                best_effort_key: None,
            })
        );
        assert!(sndcp.bearers.contains_key(&17));
        assert_eq!(sndcp.pending_standby.len(), 1);

        sndcp.pending_standby[0]
            .reporter
            .as_ref()
            .expect("network response has a reporter")
            .mark_transmitted();
        sndcp.process_standby_reports(&mut queue);
        assert!(sndcp.bearers.contains_key(&17), "MAC preparation is earlier than RF transmission");
        sndcp.dltime = sndcp.dltime.add_timeslots(PDCH_RELEASE_RF_GUARD_TIMESLOTS - 1);
        sndcp.process_standby_reports(&mut queue);
        assert!(sndcp.bearers.contains_key(&17));
        sndcp.dltime = sndcp.dltime.add_timeslots(1);
        sndcp.process_standby_reports(&mut queue);

        assert!(!sndcp.bearers.contains_key(&17));
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(2), None);
        let context = sndcp.contexts.get(&77_468).unwrap();
        assert_eq!(context.session(), Some((8, 1)));
        assert_eq!(context.bearer_id, None);
    }

    #[test]
    fn immediate_end_of_data_keeps_pdch_until_automatic_bl_ack_can_reach_rf() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), Vec::new());
        sndcp.insert_context(RadioContext {
            issi: 77_468,
            endpoint_id: 7,
            link_id: 8,
            nsapi: 1,
            snei: Some(8),
            session_id: Some(8),
            session_generation: Some(1),
            bearer_id: Some(17),
            bearer_generation: Some(4),
            timeslot_bitmap: 0b0010,
            event_label: Some(23),
            chap_identifier: None,
            dynamic_address: true,
        });
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::EndOfData {
                command_id: 52,
                itsi: 77_468,
                session_id: 8,
                session_generation: 1,
                immediate_service_change: true,
            },
        );

        assert!(
            queue.pop_front().is_none(),
            "LLC already generated the required BL-ACK for the uplink"
        );
        assert!(sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().subscriber_packet_delivery_routes.contains_key(&77_468));
        sndcp.dltime = sndcp.dltime.add_timeslots(PDCH_RELEASE_RF_GUARD_TIMESLOTS - 1);
        sndcp.process_standby_reports(&mut queue);
        assert!(sndcp.bearers.contains_key(&17));
        sndcp.dltime = sndcp.dltime.add_timeslots(1);
        sndcp.process_standby_reports(&mut queue);

        assert!(!sndcp.bearers.contains_key(&17));
        assert!(!sndcp.config.state_read().subscriber_packet_delivery_routes.contains_key(&77_468));
    }

    #[test]
    fn discarded_end_of_data_is_retried_without_releasing_pdch() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), Vec::new());
        sndcp.insert_context(RadioContext {
            issi: 77_468,
            endpoint_id: 7,
            link_id: 8,
            nsapi: 1,
            snei: Some(8),
            session_id: Some(8),
            session_generation: Some(1),
            bearer_id: Some(17),
            bearer_generation: Some(4),
            timeslot_bitmap: 0b0010,
            event_label: Some(23),
            chap_identifier: None,
            dynamic_address: true,
        });
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::EndOfData {
                command_id: 52,
                itsi: 77_468,
                session_id: 8,
                session_generation: 1,
                immediate_service_change: false,
            },
        );
        let original = sndcp.pending_standby[0].reporter.as_ref().unwrap().clone();
        original.mark_discarded();
        while queue.pop_front().is_some() {}

        sndcp.process_standby_reports(&mut queue);

        assert!(sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().subscriber_packet_delivery_routes.contains_key(&77_468));
        assert_eq!(sndcp.pending_standby.len(), 1);
        assert_eq!(sndcp.pending_standby[0].reporter.as_ref().unwrap().get_state(), TxState::Pending);
        let SapMsgInner::LtpdMleUnitdataReq(mut retried) = queue.pop_front().expect("SN-END OF DATA retry").msg else {
            panic!("retry must use the SNDCP basic link")
        };
        assert_eq!(retried.layer2service, Layer2Service::Unacknowledged);
        assert!(!SnEndOfData::from_bitbuf(&mut retried.sdu).unwrap().immediate_service_change);
        assert_eq!(retried.chan_alloc.unwrap().alloc_type, ChanAllocType::QuitAndGo);
    }

    #[test]
    fn active_multislot_bearer_publishes_every_sds_delivery_route() {
        let mut sndcp = test_sndcp();
        let context = RadioContext {
            issi: 77_479,
            endpoint_id: 7,
            link_id: 8,
            nsapi: 1,
            snei: Some(3),
            session_id: Some(8),
            session_generation: Some(1),
            bearer_id: Some(11),
            bearer_generation: Some(4),
            timeslot_bitmap: 0b1110,
            event_label: Some(4),
            chap_identifier: None,
            dynamic_address: true,
        };

        sndcp.insert_context(context);

        let state = sndcp.config.state_read();
        let routes = &state.subscriber_packet_delivery_routes[&77_479];
        assert_eq!(routes.iter().map(|route| route.timeslot).collect::<Vec<_>>(), vec![2, 3, 4]);
        assert!(routes.iter().all(|route| route.call_id == 11 && route.usage == 52));
    }

    #[test]
    fn network_page_restores_context_lost_during_bs_restart() {
        let mut sndcp = test_sndcp();
        let mut queue = MessageQueue::new();

        sndcp.handle_swmi(
            &mut queue,
            PacketDataMessage::Page {
                command_id: 18,
                itsi: 77_468,
                session_id: 8,
                session_generation: 3,
                nsapi: 1,
                snei: Some(8),
            },
        );

        let context = sndcp.contexts.get(&77_468).expect("restored context");
        assert_eq!(context.nsapi, 1);
        assert_eq!(context.snei, Some(8));
        assert_eq!(context.session(), Some((8, 3)));
        assert!(
            !sndcp.pending_commands.contains_key(&18),
            "a page command completes through the MS response and must not leak into the BS command map"
        );
        assert!(matches!(
            queue.pop_front().map(|message| message.msg),
            Some(SapMsgInner::LtpdMleUnitdataReq(_))
        ));
    }

    #[test]
    fn stale_release_cannot_remove_a_recycled_bearer() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::new(), Vec::new());

        sndcp.handle_swmi(
            &mut MessageQueue::new(),
            PacketDataMessage::BearerControl {
                command_id: 10,
                bearer_id: 17,
                bearer_generation: 3,
                action: PacketBearerAction::Release,
                timeslot_bitmap: 0,
                force_after_ms: 0,
            },
        );

        assert_eq!(sndcp.bearers.get(&17).map(|bearer| bearer.generation), Some(4));
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(2), Some(TimeslotOwner::PacketData));
    }

    #[test]
    fn voice_preemption_shrinks_multislot_bearer_then_restores_released_slot() {
        let mut sndcp = test_sndcp();
        insert_active_multislot_bearer(&mut sndcp);
        let mut queue = MessageQueue::new();
        assert!(sndcp.config.state_write().timeslot_alloc.request_packet_preemption());

        sndcp.process_preemption(&mut queue);

        let resize = sndcp.bearers[&17].resize.as_ref().expect("shrink pending");
        assert_eq!((resize.from_bitmap, resize.to_bitmap, resize.expansion_bitmap), (0b1110, 0b0110, 0));
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(4), Some(TimeslotOwner::PacketData));
        assert!(queue.iter_mut().any(|message| {
            matches!(
                &message.msg,
                SapMsgInner::TmaUnitdataReq(request)
                    if request.chan_alloc.as_ref().is_some_and(|allocation| allocation.timeslots == [false, true, true, false])
            )
        }));

        for reporter in &resize.reporters {
            reporter.mark_transmitted();
        }
        sndcp.process_bearer_resizes(&mut queue);
        assert!(sndcp.bearers[&17].resize.is_some(), "RF guard must retain TS4");
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(4), Some(TimeslotOwner::PacketData));
        sndcp.dltime = sndcp.dltime.add_timeslots(PDCH_RESIZE_RF_GUARD_TIMESLOTS - 1);
        sndcp.process_bearer_resizes(&mut queue);
        assert!(sndcp.bearers[&17].resize.is_some());

        sndcp.dltime = sndcp.dltime.add_timeslots(1);
        sndcp.process_bearer_resizes(&mut queue);

        assert_eq!(sndcp.bearers[&17].timeslot_bitmap, 0b0110);
        assert_eq!(sndcp.contexts[&77_468].timeslot_bitmap, 0b0110);
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(4));
        assert_eq!(
            sndcp.config.state_read().subscriber_packet_delivery_routes[&77_468]
                .iter()
                .map(|route| route.timeslot)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );

        sndcp.config.state_write().timeslot_alloc.reserve(TimeslotOwner::Cmce, 4).unwrap();
        sndcp.dltime = sndcp.dltime.add_timeslots(18 * 4);
        sndcp.process_bearer_expansions(&mut queue);
        assert!(sndcp.bearers[&17].resize.is_none(), "active voice must keep TS4");
        sndcp.config.state_write().timeslot_alloc.release(TimeslotOwner::Cmce, 4).unwrap();

        sndcp.process_bearer_expansions(&mut queue);

        let expansion = sndcp.bearers[&17].resize.as_ref().expect("expansion pending");
        assert_eq!(
            (expansion.from_bitmap, expansion.to_bitmap, expansion.expansion_bitmap),
            (0b0110, 0b1110, 0b1000)
        );
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(4), Some(TimeslotOwner::PacketData));
        for reporter in &expansion.reporters {
            reporter.mark_transmitted();
        }
        sndcp.process_bearer_resizes(&mut queue);
        sndcp.dltime = sndcp.dltime.add_timeslots(PDCH_RESIZE_RF_GUARD_TIMESLOTS);
        sndcp.process_bearer_resizes(&mut queue);

        assert_eq!(sndcp.bearers[&17].timeslot_bitmap, 0b1110);
        assert_eq!(sndcp.contexts[&77_468].timeslot_bitmap, 0b1110);
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(4), Some(TimeslotOwner::PacketData));
        assert_eq!(
            sndcp.config.state_read().subscriber_packet_delivery_routes[&77_468]
                .iter()
                .map(|route| route.timeslot)
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn voice_preemption_immediately_shrinks_reserved_bearer_without_members() {
        let mut sndcp = test_sndcp();
        insert_active_multislot_bearer(&mut sndcp);
        sndcp.bearers.get_mut(&17).unwrap().members.clear();
        sndcp.contexts.clear();
        sndcp.config.state_write().subscriber_packet_delivery_routes.clear();
        let mut queue = MessageQueue::new();
        assert!(sndcp.config.state_write().timeslot_alloc.request_packet_preemption());

        sndcp.process_preemption(&mut queue);
        assert_eq!(sndcp.bearers[&17].resize.as_ref().unwrap().reporters.len(), 0);
        sndcp.process_bearer_resizes(&mut queue);

        assert_eq!(sndcp.bearers[&17].timeslot_bitmap, 0b0110);
        assert!(sndcp.bearers[&17].resize.is_none());
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(4));
        assert!(queue.iter_mut().any(|message| {
            matches!(
                message.msg,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Resize {
                    bearer_id: 17,
                    generation: 4,
                    timeslot_bitmap: 0b0110,
                })
            )
        }));
    }

    #[test]
    fn bearer_resize_recovers_member_from_matching_radio_context() {
        let mut sndcp = test_sndcp();
        insert_active_multislot_bearer(&mut sndcp);
        sndcp.bearers.get_mut(&17).unwrap().members.clear();
        let mut queue = MessageQueue::new();

        assert!(sndcp.start_bearer_resize(&mut queue, 17, 4, 0b0110, 0));

        let resize = sndcp.bearers[&17].resize.as_ref().unwrap();
        assert_eq!(resize.reporters.len(), 1);
        assert!(resize.commit_at.is_none());
        assert!(queue.iter_mut().any(|message| {
            matches!(
                &message.msg,
                SapMsgInner::TmaUnitdataReq(request)
                    if request.main_address.ssi == 77_468
                        && request.chan_alloc.as_ref().is_some_and(|allocation| allocation.timeslots == [false, true, true, false])
            )
        }));
    }

    #[test]
    fn failed_multislot_expansion_restores_aach_and_allocator() {
        let mut sndcp = test_sndcp();
        insert_active_multislot_bearer(&mut sndcp);
        sndcp.bearers.get_mut(&17).unwrap().timeslot_bitmap = 0b0110;
        sndcp.contexts.get_mut(&77_468).unwrap().timeslot_bitmap = 0b0110;
        sndcp
            .config
            .state_write()
            .timeslot_alloc
            .release(TimeslotOwner::PacketData, 4)
            .unwrap();
        let mut queue = MessageQueue::new();

        sndcp.process_bearer_expansions(&mut queue);

        let reporter = sndcp.bearers[&17].resize.as_ref().unwrap().reporters[0].clone();
        assert_eq!(sndcp.config.state_read().timeslot_alloc.owner(4), Some(TimeslotOwner::PacketData));
        reporter.mark_discarded();
        sndcp.process_bearer_resizes(&mut queue);

        assert!(sndcp.bearers[&17].resize.is_none());
        assert_eq!(sndcp.bearers[&17].timeslot_bitmap, 0b0110);
        assert_eq!(sndcp.contexts[&77_468].timeslot_bitmap, 0b0110);
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(4));
        assert!(queue.iter_mut().any(|message| {
            matches!(
                message.msg,
                SapMsgInner::PacketBearerControl(PacketBearerControl::Resize {
                    bearer_id: 17,
                    generation: 4,
                    timeslot_bitmap: 0b0110,
                })
            )
        }));
    }

    #[test]
    fn drain_waits_for_terminal_notification_before_graceful_release() {
        let mut sndcp = test_sndcp();
        let reporter = TxReporter::new();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), vec![reporter.clone()]);
        let mut queue = MessageQueue::new();

        sndcp.process_drains(&mut queue);
        assert!(sndcp.bearers.contains_key(&17));

        reporter.mark_transmitted();
        reporter.mark_acknowledged();
        sndcp.process_drains(&mut queue);
        assert!(!sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(2));
    }

    #[test]
    fn drain_force_deadline_releases_when_terminal_does_not_acknowledge() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::from([77_468]), vec![TxReporter::new()]);
        sndcp.bearers.get_mut(&17).unwrap().force_at = Some(sndcp.dltime);

        sndcp.process_drains(&mut MessageQueue::new());

        assert!(!sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(2));
    }

    #[test]
    fn empty_bearer_releases_after_grace_without_waiting_for_force() {
        let mut sndcp = test_sndcp();
        insert_bearer(&mut sndcp, 4, HashSet::new(), Vec::new());

        sndcp.process_drains(&mut MessageQueue::new());

        assert!(!sndcp.bearers.contains_key(&17));
        assert!(sndcp.config.state_read().timeslot_alloc.is_free(2));
    }
}
