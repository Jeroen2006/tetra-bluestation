use std::collections::{HashMap, HashSet};

use tetra_config::bluestation::SharedConfig;
use tetra_core::{
    BitBuffer, EndpointId, Layer2Service, LinkId, Sap, SsiType, TdmaTime, TetraAddress, TimeslotOwner, TxReporter, TxState,
    tetra_entities::TetraEntity,
};
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
    ltpd::{LtpdMleUnitdataInd, LtpdMleUnitdataReq},
    tma::AssociatedChannel,
};
use tetra_swmi_protocol::{
    ChapProof, PacketAddressRequest, PacketBearerAction, PacketBearerState, PacketDataMessage, PacketDeliveryStatus, PacketRejectCause,
    PacketResourceRequest, SwmiMessage,
};

use crate::{MessageQueue, TetraEntityTrait, net_swmi::SwmiPacketEndpoint};

const DEFAULT_NSAPI: u8 = 1;
const PACKET_USAGE_BASE: u8 = 48;
const DRAIN_GRACE_TIMESLOTS: i32 = 2 * 18 * 4;

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
    members: HashSet<u32>,
    draining: bool,
    release_at: Option<TdmaTime>,
    force_at: Option<TdmaTime>,
    command_id: u64,
    drain_reporters: Vec<TxReporter>,
}

#[derive(Debug, Clone)]
struct PendingDelivery {
    session_id: u64,
    session_generation: u64,
    packet_id: u64,
    reporter: TxReporter,
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
        let associated_channel = if chan_alloc.is_some() { None } else { self.route_for(context) };
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
                self.contexts.insert(issi, context.clone());
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
                    self.contexts.remove(&issi);
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
                        self.contexts.remove(&issi);
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
                    self.contexts.remove(&issi);
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
                    self.contexts.remove(&issi);
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
                    self.contexts.remove(&issi);
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
            SndcpUplink::TransmitRequest { resource, .. } => {
                self.request_access(issi, prim.endpoint_id, prim.link_id, resource, false);
            }
            SndcpUplink::Reconnect { resource, .. } => {
                self.request_access(issi, prim.endpoint_id, prim.link_id, resource, true);
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
            SndcpUplink::PageResponse { available, resource, .. } => {
                let Some(context) = self.contexts.get_mut(&issi) else {
                    return;
                };
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
    ) {
        let Some(context) = self.contexts.get_mut(&issi) else {
            return;
        };
        context.endpoint_id = endpoint_id;
        context.link_id = link_id;
        let context = context.clone();
        let Some((session_id, session_generation)) = context.session() else {
            return;
        };
        let command_id = self.next_command();
        self.pending_commands.insert(command_id, issi);
        self.submit(PacketDataMessage::Access {
            command_id,
            itsi: u64::from(issi),
            air_handle: endpoint_id,
            registration_generation: self.registration_generation(issi),
            session_id,
            session_generation,
            data_to_send: true,
            reconnect,
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
                members: HashSet::new(),
                draining: false,
                release_at: None,
                force_at: None,
                command_id,
                drain_reporters: Vec::new(),
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

    fn begin_drain(&mut self, queue: &mut MessageQueue, command_id: u64, id: u64, generation: u64, force_after_ms: u32) {
        let member_ids = self
            .bearers
            .get(&id)
            .filter(|bearer| bearer.generation == generation)
            .map(|bearer| bearer.members.iter().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        for issi in member_ids {
            if let Some(context) = self.contexts.get(&issi).cloned() {
                let reporter = TxReporter::new();
                if self.queue_downlink_with_reporter(
                    queue,
                    &context,
                    SndcpDownlink::EndOfData {
                        immediate_service_change: true,
                    },
                    Layer2Service::Acknowledged,
                    Some(Self::channel_allocation(0, 0, ChanAllocType::QuitAndGo)),
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
        {
            let mut state = self.config.state_write();
            for timeslot in 2..=4 {
                if bearer.timeslot_bitmap & (1 << (timeslot - 1)) != 0 {
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
                        ready_timer: ready_timer_code(timers.ready_ms).unwrap_or(8),
                        standby_timer: standby_timer_code(timers.standby_seconds).unwrap_or(6),
                        response_wait_timer: response_wait_timer_code(timers.response_wait_ms).unwrap_or(7),
                        snei,
                        chap_success: context.chap_identifier.map(|id| (id, "OK".into())),
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
                    self.contexts.remove(&issi);
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
                    self.contexts.remove(&issi);
                }
            }
            PacketDataMessage::AccessResult {
                command_id,
                itsi,
                accepted,
                cause,
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
                if context.session_generation != Some(session_generation) {
                    return;
                }
                if accepted {
                    context.bearer_id = Some(bearer_id);
                    context.bearer_generation = self.bearers.get(&bearer_id).map(|bearer| bearer.generation);
                    context.timeslot_bitmap = timeslot_bitmap;
                    context.event_label = Some(event_label);
                    if let Some(bearer) = self.bearers.get_mut(&bearer_id) {
                        bearer.members.insert(issi);
                    }
                    if let Some(generation) = context.bearer_generation {
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
                let context = context.clone();
                let usage = PACKET_USAGE_BASE + (event_label as u8 & 0x0f);
                let chan_alloc = accepted.then(|| Self::channel_allocation(timeslot_bitmap, usage, ChanAllocType::Replace));
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
            PacketDataMessage::Page {
                command_id,
                itsi,
                session_id,
                session_generation,
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
                self.pending_commands.insert(command_id, issi);
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
            | PacketDataMessage::EndOfData { .. }
            | PacketDataMessage::BearerReport { .. } => {}
        }
    }

    fn process_preemption(&mut self, queue: &mut MessageQueue) {
        let requested = self.config.state_write().timeslot_alloc.take_packet_preemption_request();
        if !requested {
            return;
        }
        let active = self
            .bearers
            .values()
            .find(|bearer| !bearer.draining)
            .map(|bearer| (bearer.command_id, bearer.id, bearer.generation));
        if let Some((command_id, id, generation)) = active {
            tracing::info!(bearer_id = id, "voice capacity requested; draining lower-priority packet bearer");
            self.begin_drain(queue, command_id, id, generation, 2_500);
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
        self.process_drains(queue);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_pdus::sndcp::pdus::sn_control::{SnDeactivatePdpContextAccept, SnDeactivatePdpContextDemand};

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
                members,
                draining: true,
                release_at: Some(sndcp.dltime),
                force_at: Some(sndcp.dltime.add_timeslots(100)),
                command_id: 9,
                drain_reporters: reporters,
            },
        );
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
