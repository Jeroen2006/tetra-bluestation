use std::collections::HashMap;

use crate::mle::components::{broadcast::MleBroadcast, network_time};
use tetra_config::bluestation::RuntimeSc2RolloverEvent;
use crate::net_control::{ControlCommand, ControlEndpoint, ControlResponse};
use crate::net_swmi::SwmiMleEndpoint;
use crate::{MessageQueue, TetraEntityTrait};
use tetra_config::bluestation::SharedConfig;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{
    AieRequest, AieScope, AieSubject, BitBuffer, EndpointId, Layer2Service, LinkId, Sap, SsiType, TdmaTime, TetraAddress, unimplemented_log,
};
use tetra_saps::lcmc::{LcmcMleUnitdataInd, fields::chan_alloc_req::CmceChanAllocReq};
use tetra_saps::lmm::{LmmMleSeamlessHandover, LmmMleUnitdataInd};
use tetra_saps::ltpd::LtpdMleUnitdataInd;
use tetra_saps::tla::{TlaTlDataReqBl, TlaTlUnitdataIndBl, TlaTlUnitdataReqBl};
use tetra_saps::{SapMsg, SapMsgInner};

use tetra_pdus::mle::enums::mle_pdu_type_ul::MlePduTypeUl;
use tetra_pdus::mle::enums::mle_protocol_discriminator::MleProtocolDiscriminator;
use tetra_pdus::mle::pdus::{
    d_new_cell::DNewCell, d_prepare_fail::DPrepareFail, d_restore_ack::DRestoreAck, d_restore_fail::DRestoreFail, u_prepare::UPrepare,
    u_restore::URestore,
};
use tetra_pdus::mm::enums::location_update_type::LocationUpdateType;
use tetra_pdus::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use tetra_pdus::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use tetra_pdus::mm::pdus::u_location_update_demand::ULocationUpdateDemand;

pub struct MleBs {
    config: SharedConfig,
    broadcast: MleBroadcast,
    swmi: Option<SwmiMleEndpoint>,
    control: Option<ControlEndpoint>,
    // Keep the AIE policy of the incoming roaming procedure until its
    // asynchronous MM/CMCE result returns.  AieRequest is key-free protocol
    // metadata; the key itself remains solely in the BS AIE provider.
    forward_registrations: HashMap<u32, ForwardRegistration>,
    forward_registration_deadlines: HashMap<u32, TdmaTime>,
    pending_restores: HashMap<u32, Option<AieRequest>>,
    current_time: TdmaTime,
    /// First physical downlink slot at which the next CA broadcast may be
    /// queued.  The message is handed to UMAC one slot ahead, so this tracks
    /// the on-air timestamp rather than the current router timestamp.
    next_network_broadcast: Option<TdmaTime>,
}

#[derive(Clone, Copy)]
struct ForwardRegistration {
    incoming_aie: Option<AieRequest>,
}

/// CA broadcasts are offered once per five TETRA multiframes (about 5.1 s).
/// This keeps the MCCH usable for ordinary signalling instead of sending the
/// same serving-cell advertisement on nearly every second.
const MLE_BROADCAST_INTERVAL_MULTIFRAMES: i32 = 5;
const MLE_BROADCAST_INTERVAL_FRAMES: i32 = MLE_BROADCAST_INTERVAL_MULTIFRAMES * 18;
const MLE_BROADCAST_INTERVAL_TIMESLOTS: i32 = MLE_BROADCAST_INTERVAL_FRAMES * 4;
/// UMAC constructs the physical downlink one timeslot ahead of the router's
/// current time.  Queue the message in TS4 so that it is transmitted on MCCH
/// TS1 of the following frame.
const MLE_BROADCAST_TX_AHEAD_TIMESLOTS: i32 = 1;
/// ETSI T370 = 5 seconds. There are 18 TDMA frames of four slots per second.
const T370_TIMESLOTS: i32 = 5 * 18 * 4;

fn network_broadcast_due(transmission_time: TdmaTime, next_broadcast: Option<TdmaTime>) -> bool {
    transmission_time.t == 1
        && match next_broadcast {
            // `age(now)` is `now - self`, so `next` is the deadline and the
            // physical transmission timestamp is the current time.
            Some(next) => next.age(transmission_time) >= 0,
            None => true,
        }
}

impl MleBs {
    pub fn new(config: SharedConfig, swmi: Option<SwmiMleEndpoint>, control: Option<ControlEndpoint>) -> Self {
        let broadcast = MleBroadcast::new(config.clone());
        Self {
            config,
            broadcast,
            swmi,
            control,
            forward_registrations: HashMap::new(),
            forward_registration_deadlines: HashMap::new(),
            pending_restores: HashMap::new(),
            current_time: TdmaTime::default(),
            next_network_broadcast: None,
        }
    }

    /// Select the MAC AIE policy for CMCE downlink signalling at the last
    /// common point before LLC. MM bootstrap PDUs use LMM-SAP and therefore
    /// deliberately do not pass here. That keeps the narrowly permitted clear
    /// registration/OTAR bootstrap separate from normal CMCE traffic.
    ///
    /// An encrypted SC2 MAC-RESOURCE carries an ESI. For a group PDU this is
    /// a GESI: TA61 is applied to the GSSI by UMAC at the exact TX time. This
    /// lets every group member select and decrypt the resource using the SCK.
    /// Individual PDU handling remains fail-closed in an SC2-only cell.
    fn cmce_downlink_aie(&self, address: TetraAddress) -> Option<AieRequest> {
        let state = self.config.state_read();
        if !state.aie.enabled {
            return None;
        }

        match address.ssi_type {
            // In an SC2-only cell CMCE has no permitted clear fallback for a
            // registered ISSI.  Keep the request encrypted even while the
            // terminal binding is not ready: the provider then rejects it at
            // TX time rather than silently emitting (for example) D-STATUS
            // in clear.  MM bootstrap traffic does not use this path.
            SsiType::Issi
                if state.aie_sessions.terminal(address.ssi).is_some()
                    || (!state.aie.sc1_allowed && state.subscribers.is_registered(address.ssi)) =>
            {
                Some(AieRequest::sc2(AieSubject::Individual { issi: address.ssi }, AieScope::MacResource))
            }
            SsiType::Gssi => Some(AieRequest::sc2(AieSubject::Group { gssi: address.ssi }, AieScope::MacResource)),
            _ => None,
        }
    }

    /// MLE roaming procedure replies use SC2 only when the corresponding
    /// uplink procedure was protected and the MS has a local SC2 binding.
    /// This preserves a clear bootstrap transaction as clear, while ensuring
    /// that a protected U-PREPARE/U-RESTORE does not silently fall back to
    /// clear merely because MLE crosses an asynchronous SAP boundary.
    fn mle_reply_aie(&self, address: TetraAddress, incoming_aie: Option<AieRequest>) -> Option<AieRequest> {
        let state = self.config.state_read();
        if state.aie.enabled && state.aie_sessions.terminal(address.ssi).is_some() && matches!(incoming_aie, Some(AieRequest::Sc2 { .. })) {
            Some(AieRequest::sc2(AieSubject::Individual { issi: address.ssi }, AieScope::MacResource))
        } else {
            None
        }
    }

    fn rx_tla_mle_pdu(
        &mut self,
        queue: &mut MessageQueue,
        sdu: BitBuffer,
        address: TetraAddress,
        endpoint_id: EndpointId,
        link_id: LinkId,
        incoming_aie: Option<AieRequest>,
    ) {
        // The MLE protocol discriminator has already been removed. Uplink
        // and downlink MLE PDU values overlap, so this must use the UL enum.
        let Some(bits) = sdu.peek_bits(3) else {
            tracing::warn!("insufficient bits: {}", sdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = MlePduTypeUl::try_from(bits) else {
            tracing::warn!("invalid uplink MLE PDU type: {} in {}", bits, sdu.dump_bin());
            return;
        };
        match pdu_type {
            MlePduTypeUl::UPrepare => self.rx_u_prepare(queue, sdu, address, incoming_aie),
            MlePduTypeUl::URestore => self.rx_u_restore(queue, sdu, address, endpoint_id, link_id, incoming_aie),
            MlePduTypeUl::UPrepareDa => tracing::debug!(issi = address.ssi, "U-PREPARE-DA is outside CA roaming scope"),
            other => tracing::debug!(?other, issi = address.ssi, "unsupported uplink MLE PDU"),
        }
    }

    fn rx_u_prepare(&mut self, queue: &mut MessageQueue, sdu: BitBuffer, address: TetraAddress, incoming_aie: Option<AieRequest>) {
        let mut input = sdu;
        let pdu = match UPrepare::from_bitbuf(&mut input) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(issi = address.ssi, ?error, "invalid U-PREPARE");
                self.send_prepare_fail(queue, address, 1, None, self.mle_reply_aie(address, incoming_aie));
                return;
            }
        };
        let Some(cell_identifier_ca) = pdu.cell_identifier_ca else {
            // Type 3 has no preferred cell and no embedded forward-registration SDU.
            self.send_new_cell(queue, address, 1, None, None, self.mle_reply_aie(address, incoming_aie));
            return;
        };
        let Some(target_station_id) = self.broadcast.neighbour_station_id(cell_identifier_ca).map(str::to_owned) else {
            tracing::warn!(
                issi = address.ssi,
                cell_identifier_ca,
                "U-PREPARE refers to a non-advertised CA neighbour"
            );
            self.send_prepare_fail(queue, address, 1, None, self.mle_reply_aie(address, incoming_aie));
            return;
        };
        let Some(mut embedded_mm) = pdu.sdu else {
            // Announced type 2 without forward registration.
            self.send_new_cell(queue, address, 1, None, None, self.mle_reply_aie(address, incoming_aie));
            return;
        };
        let Some(raw_type) = embedded_mm.peek_bits(4) else {
            self.send_prepare_fail(queue, address, 1, None, self.mle_reply_aie(address, incoming_aie));
            return;
        };
        if MmPduTypeUl::try_from(raw_type) != Ok(MmPduTypeUl::ULocationUpdateDemand) {
            tracing::warn!(issi = address.ssi, "U-PREPARE did not contain U-LOCATION UPDATE DEMAND");
            self.send_prepare_fail(queue, address, 1, None, self.mle_reply_aie(address, incoming_aie));
            return;
        }
        let mut validation = embedded_mm.clone();
        let Ok(location_update) = ULocationUpdateDemand::from_bitbuf(&mut validation) else {
            self.send_prepare_fail(queue, address, 1, None, self.mle_reply_aie(address, incoming_aie));
            return;
        };
        if location_update.location_update_type != LocationUpdateType::ServiceRestorationRoamingLocationUpdating {
            tracing::warn!(issi = address.ssi, ?location_update.location_update_type, "rejecting non-forward-registration U-PREPARE SDU");
            self.send_prepare_fail(queue, address, 1, None, self.mle_reply_aie(address, incoming_aie));
            return;
        }
        embedded_mm.seek(0);
        self.forward_registrations.insert(address.ssi, ForwardRegistration { incoming_aie });
        self.forward_registration_deadlines
            .insert(address.ssi, self.current_time.add_timeslots(T370_TIMESLOTS));
        queue.push_back(SapMsg {
            sap: Sap::LmmSap,
            src: TetraEntity::Mle,
            dest: TetraEntity::Mm,
            msg: SapMsgInner::LmmMleUnitdataInd(LmmMleUnitdataInd {
                sdu: embedded_mm,
                handle: 0,
                received_address: address,
                air_interface_encryption: incoming_aie,
                forward_registration_target_station_id: Some(target_station_id),
            }),
        });
    }

    fn rx_u_restore(
        &mut self,
        queue: &mut MessageQueue,
        sdu: BitBuffer,
        address: TetraAddress,
        endpoint_id: EndpointId,
        link_id: LinkId,
        incoming_aie: Option<AieRequest>,
    ) {
        let mut input = sdu;
        let pdu = match URestore::from_bitbuf(&mut input) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(issi = address.ssi, ?error, "invalid U-RESTORE");
                self.send_restore_fail(queue, address, 1, self.mle_reply_aie(address, incoming_aie));
                return;
            }
        };
        let Some(mut embedded_cmce) = pdu.sdu else {
            self.send_restore_fail(queue, address, 1, self.mle_reply_aie(address, incoming_aie));
            return;
        };
        embedded_cmce.seek(0);
        self.pending_restores.insert(address.ssi, incoming_aie);
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Mle,
            dest: TetraEntity::Cmce,
            msg: SapMsgInner::LcmcMleUnitdataInd(LcmcMleUnitdataInd {
                sdu: embedded_cmce,
                handle: 0,
                endpoint_id,
                link_id,
                received_tetra_address: address,
                chan_change_resp_req: false,
                chan_change_handle: None,
            }),
        });
    }

    fn send_mle_downlink(
        &self,
        queue: &mut MessageQueue,
        address: TetraAddress,
        mut pdu: BitBuffer,
        chan_alloc: Option<CmceChanAllocReq>,
        air_interface_encryption: Option<AieRequest>,
    ) {
        let pdu_len = pdu.get_len_remaining();
        let mut tl_sdu = BitBuffer::new_autoexpand(3 + pdu_len);
        tl_sdu.write_bits(MleProtocolDiscriminator::Mle.into_raw(), 3);
        tl_sdu.copy_bits(&mut pdu, pdu_len);
        tl_sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::TlaSap,
            src: TetraEntity::Mle,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TlaTlDataReqBl(TlaTlDataReqBl {
                main_address: address,
                link_id: 0,
                endpoint_id: 0,
                tl_sdu,
                stealing_permission: false,
                subscriber_class: 0,
                fcs_flag: false,
                air_interface_encryption,
                stealing_repeats_flag: None,
                data_class_info: None,
                req_handle: 0,
                graceful_degradation: None,
                chan_alloc,
                associated_channel: None,
                tx_reporter: None,
            }),
        });
    }

    fn send_new_cell(
        &self,
        queue: &mut MessageQueue,
        address: TetraAddress,
        channel_command_valid: u8,
        sdu: Option<BitBuffer>,
        chan_alloc: Option<CmceChanAllocReq>,
        air_interface_encryption: Option<AieRequest>,
    ) {
        let mut bits = BitBuffer::new_autoexpand(64);
        if (DNewCell {
            channel_command_valid,
            sdu,
        })
        .to_bitbuf(&mut bits)
        .is_ok()
        {
            bits.seek(0);
            self.send_mle_downlink(queue, address, bits, chan_alloc, air_interface_encryption);
        }
    }

    fn seamless_handover_allocation(handover: LmmMleSeamlessHandover) -> CmceChanAllocReq {
        CmceChanAllocReq {
            usage: Some(handover.usage),
            alloc_type: tetra_saps::lcmc::enums::alloc_type::ChanAllocType::Replace,
            carrier: Some(handover.carrier),
            timeslots: handover.timeslots,
            cell_change_flag: true,
            ul_dl_assigned: tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment::Both,
        }
    }

    fn send_prepare_fail(
        &self,
        queue: &mut MessageQueue,
        address: TetraAddress,
        fail_cause: u8,
        sdu: Option<BitBuffer>,
        air_interface_encryption: Option<AieRequest>,
    ) {
        let mut bits = BitBuffer::new_autoexpand(64);
        if (DPrepareFail { fail_cause, sdu }).to_bitbuf(&mut bits).is_ok() {
            bits.seek(0);
            self.send_mle_downlink(queue, address, bits, None, air_interface_encryption);
        }
    }

    fn send_restore_fail(
        &self,
        queue: &mut MessageQueue,
        address: TetraAddress,
        fail_cause: u8,
        air_interface_encryption: Option<AieRequest>,
    ) {
        let mut bits = BitBuffer::new_autoexpand(16);
        if (DRestoreFail { fail_cause }).to_bitbuf(&mut bits).is_ok() {
            bits.seek(0);
            self.send_mle_downlink(queue, address, bits, None, air_interface_encryption);
        }
    }

    fn rx_tla_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tla_prim");
        match message.msg {
            SapMsgInner::TlaTlDataIndBl(_) => {
                self.rx_tla_data_ind_bl(queue, message);
            }
            SapMsgInner::TlaTlUnitdataIndBl(_) => {
                self.rx_tla_unitdata_ind_bl(queue, message);
            }
            _ => {
                panic!();
            }
        }
    }

    /// TL-UNITDATA is the unacknowledged basic-link service.  It is valid on
    /// a BS for MM/OTAR and key-change traffic (not only for MS-side SNDCP).
    /// Treat its MLE protocol payload identically to TL-DATA while preserving
    /// the fact that LLC did not provide a reliable-link acknowledgement.
    fn rx_tla_unitdata_ind_bl(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::TlaTlUnitdataIndBl(prim) = &mut message.msg else {
            panic!()
        };
        let Some(mut sdu) = prim.tl_sdu.take() else {
            tracing::warn!("dropping TL-UNITDATA without an SDU");
            return;
        };
        if sdu.get_pos() != 0 {
            tracing::warn!(position = sdu.get_pos(), "dropping TL-UNITDATA with a nonzero SDU position");
            return;
        }
        let Some(bits) = sdu.read_bits(3) else {
            tracing::warn!("dropping short TL-UNITDATA: {}", sdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = MleProtocolDiscriminator::try_from(bits) else {
            tracing::warn!(bits, "dropping TL-UNITDATA with an invalid MLE protocol discriminator");
            return;
        };
        let main_address = prim.main_address;
        let endpoint_id = prim.endpoint_id;
        let link_id = prim.link_id;
        let air_interface_encryption = prim.air_interface_encryption;

        let is_clear_from_bound_sc2_terminal = matches!(air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled && !state.aie.sc1_allowed && state.aie_sessions.terminal(main_address.ssi).is_some()
        };
        if is_clear_from_bound_sc2_terminal && pdu_type != MleProtocolDiscriminator::Mm {
            tracing::warn!(
                issi = main_address.ssi,
                ?pdu_type,
                "rejecting unexpected clear unacknowledged post-SC2 uplink outside MM bootstrap allow-list"
            );
            return;
        }
        if matches!(
            air_interface_encryption,
            Some(AieRequest::Sc2 {
                subject: AieSubject::System,
                ..
            })
        ) && main_address.ssi_type == SsiType::Esi
            && pdu_type != MleProtocolDiscriminator::Mm
        {
            tracing::warn!(?pdu_type, "rejecting unbound encrypted unacknowledged bootstrap outside MM location update");
            return;
        }

        match pdu_type {
            MleProtocolDiscriminator::Mm => queue.push_back(SapMsg {
                sap: Sap::LmmSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Mm,
                msg: SapMsgInner::LmmMleUnitdataInd(LmmMleUnitdataInd {
                    sdu,
                    handle: 0,
                    received_address: main_address,
                    air_interface_encryption,
                    forward_registration_target_station_id: None,
                }),
            }),
            MleProtocolDiscriminator::Cmce => queue.push_back(SapMsg {
                sap: Sap::LcmcSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::LcmcMleUnitdataInd(LcmcMleUnitdataInd {
                    sdu,
                    handle: 0,
                    received_tetra_address: main_address,
                    endpoint_id,
                    link_id,
                    chan_change_resp_req: false,
                    chan_change_handle: None,
                }),
            }),
            MleProtocolDiscriminator::Sndcp => queue.push_back(SapMsg {
                sap: Sap::LcmcSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Cmce,
                msg: SapMsgInner::LtpdMleUnitdataInd(LtpdMleUnitdataInd {
                    sdu,
                    endpoint_id,
                    link_id,
                    received_tetra_address: main_address,
                    chan_change_resp_req: false,
                    chan_change_handle: None,
                }),
            }),
            MleProtocolDiscriminator::Mle => {
                self.rx_tla_mle_pdu(queue, sdu, main_address, endpoint_id, link_id, air_interface_encryption)
            }
            MleProtocolDiscriminator::TetraManagementEntity => {
                tracing::warn!("dropping unsupported TME TL-UNITDATA");
            }
        }
    }

    fn rx_tla_data_ind_bl(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        // Take ownership of bitbuf and read protocol discriminator
        let SapMsgInner::TlaTlDataIndBl(prim) = &mut message.msg else {
            panic!()
        };
        let Some(mut sdu) = prim.tl_sdu.take() else { panic!("no tl_sdu") };
        assert!(sdu.get_pos() == 0); // We should be at the start of the MAC PDU
        let Some(bits) = sdu.read_bits(3) else {
            tracing::warn!("insufficient bits: {}", sdu.dump_bin());
            return;
        };
        let Ok(pdu_type) = MleProtocolDiscriminator::try_from(bits) else {
            tracing::warn!("invalid pdu type: {} in {}", bits, sdu.dump_bin());
            return;
        };
        let main_address = prim.main_address;
        let endpoint_id = prim.endpoint_id;
        let link_id = prim.link_id;
        let air_interface_encryption = prim.air_interface_encryption;

        // With SC1 disabled, post-registration clear traffic is only
        // meaningful for the MM bootstrap/transition allow-list. Do not let
        // clear CMCE/SNDCP/MLE traffic of a bound SC2 terminal reach a
        // higher-layer fallback path. LLC handles the one matching clear
        // BL-ACK before it reaches MLE.
        let is_clear_from_bound_sc2_terminal = matches!(air_interface_encryption, Some(AieRequest::Clear { .. }) | None) && {
            let state = self.config.state_read();
            state.aie.enabled && !state.aie.sc1_allowed && state.aie_sessions.terminal(main_address.ssi).is_some()
        };
        if is_clear_from_bound_sc2_terminal && pdu_type != MleProtocolDiscriminator::Mm {
            tracing::warn!(
                issi = main_address.ssi,
                ?pdu_type,
                "rejecting unexpected clear post-SC2 uplink outside MM bootstrap allow-list"
            );
            return;
        }
        if matches!(
            air_interface_encryption,
            Some(AieRequest::Sc2 {
                subject: AieSubject::System,
                ..
            })
        ) && main_address.ssi_type == SsiType::Esi
            && pdu_type != MleProtocolDiscriminator::Mm
        {
            tracing::warn!(?pdu_type, "rejecting unbound encrypted bootstrap outside MM location update");
            return;
        }

        // Dispatch to appropriate component (or to self if for MLE)
        match pdu_type {
            MleProtocolDiscriminator::Mm => {
                let m = LmmMleUnitdataInd {
                    sdu,
                    handle: 0,
                    received_address: main_address,
                    air_interface_encryption,
                    forward_registration_target_station_id: None,
                };
                let msg = SapMsg {
                    sap: Sap::LmmSap,
                    src: TetraEntity::Mle,
                    dest: TetraEntity::Mm,
                    msg: SapMsgInner::LmmMleUnitdataInd(m),
                };
                queue.push_back(msg);
            }
            MleProtocolDiscriminator::Cmce => {
                let m = LcmcMleUnitdataInd {
                    sdu,
                    handle: 0,
                    received_tetra_address: main_address,
                    endpoint_id,
                    link_id,
                    chan_change_resp_req: false, // TODO FIXME
                    chan_change_handle: None,    // TODO FIXME
                };
                let msg = SapMsg {
                    sap: Sap::LcmcSap,
                    src: TetraEntity::Mle,
                    dest: TetraEntity::Cmce,
                    msg: SapMsgInner::LcmcMleUnitdataInd(m),
                };
                queue.push_back(msg);
            }
            MleProtocolDiscriminator::Sndcp => {
                let m = LtpdMleUnitdataInd {
                    sdu,
                    endpoint_id: prim.endpoint_id,
                    link_id: prim.link_id,
                    received_tetra_address: prim.main_address,
                    chan_change_resp_req: false, // TODO FIXME
                    chan_change_handle: None,    // TODO FIXME
                };
                let msg = SapMsg {
                    sap: Sap::LcmcSap,
                    src: TetraEntity::Mle,
                    dest: TetraEntity::Cmce,
                    msg: SapMsgInner::LtpdMleUnitdataInd(m),
                };
                queue.push_back(msg);
            }
            MleProtocolDiscriminator::Mle => self.rx_tla_mle_pdu(queue, sdu, main_address, endpoint_id, link_id, air_interface_encryption),
            MleProtocolDiscriminator::TetraManagementEntity => {
                unimplemented_log!("MleProtocolDiscriminator::TetraManagementEntity");
            }
        }
    }

    fn rx_tlmc_prim(&mut self, _queue: &mut MessageQueue, _message: SapMsg) {
        tracing::trace!("rx_tlmc_prim");
        unimplemented!("rx_tlmc_prim");
    }

    fn rx_lmm_mle_unitdata_req(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_lmm_mle_unitdata_req");
        let SapMsgInner::LmmMleUnitdataReq(prim) = &mut message.msg else {
            panic!()
        };

        if let Some(forward_registration) = self.forward_registrations.get(&prim.address.ssi).copied() {
            let pdu_type = prim.sdu.peek_bits(4).and_then(|raw| MmPduTypeDl::try_from(raw).ok());
            match pdu_type {
                Some(MmPduTypeDl::DLocationUpdateAccept) => {
                    self.forward_registrations.remove(&prim.address.ssi);
                    self.forward_registration_deadlines.remove(&prim.address.ssi);
                    let chan_alloc = prim.seamless_handover.map(Self::seamless_handover_allocation);
                    let command = if chan_alloc.is_some() { 0 } else { 1 };
                    self.send_new_cell(
                        queue,
                        prim.address,
                        command,
                        Some(prim.sdu.clone()),
                        chan_alloc,
                        self.mle_reply_aie(prim.address, forward_registration.incoming_aie),
                    );
                    return;
                }
                Some(MmPduTypeDl::DLocationUpdateReject) => {
                    self.forward_registrations.remove(&prim.address.ssi);
                    self.forward_registration_deadlines.remove(&prim.address.ssi);
                    self.send_prepare_fail(
                        queue,
                        prim.address,
                        1,
                        Some(prim.sdu.clone()),
                        self.mle_reply_aie(prim.address, forward_registration.incoming_aie),
                    );
                    return;
                }
                _ => {}
            }
        }

        let mle_prot_discriminator = MleProtocolDiscriminator::Mm;
        let sdu_len = prim.sdu.get_len();
        let mut pdu = BitBuffer::new(3 + sdu_len);
        pdu.write_bits(mle_prot_discriminator.into_raw(), 3);
        pdu.copy_bits(&mut prim.sdu, sdu_len);
        pdu.seek(0);

        // let (addr, link, endpoint) = self.router.use_handle(prim.handle, message.dltime);
        // assert_eq!(addr.ssi, prim.address.ssi);
        let sapmsg = if prim.layer2service == Layer2Service::Unacknowledged {
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Llc,
                msg: SapMsgInner::TlaTlUnitdataReqBl(TlaTlUnitdataReqBl {
                    main_address: prim.address,
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: pdu,
                    stealing_permission: false,
                    subscriber_class: 0,
                    fcs_flag: false,
                    air_interface_encryption: Some(prim.aie_request),
                    packet_data_flag: false,
                    n_tlsdu_repeats: 0,
                    data_class_info: None,
                    req_handle: 0,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: prim.tx_reporter.take(),
                }),
            }
        } else {
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Llc,
                msg: SapMsgInner::TlaTlDataReqBl(TlaTlDataReqBl {
                    main_address: prim.address,
                    link_id: 0,
                    endpoint_id: 0,
                    tl_sdu: pdu,
                    stealing_permission: false,
                    subscriber_class: 0, // TODO fixme
                    fcs_flag: false,
                    air_interface_encryption: Some(prim.aie_request),
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0, // TODO FIXME; should we pass the same handle here?
                    graceful_degradation: None,
                    chan_alloc: None,
                    associated_channel: None,
                    tx_reporter: prim.tx_reporter.take(),
                }),
            }
        };
        queue.push_back(sapmsg);
    }

    fn rx_lmm_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_lmm_prim");
        match &message.msg {
            SapMsgInner::LmmMleUnitdataReq(_prim) => {
                self.rx_lmm_mle_unitdata_req(queue, message);
            }
            _ => panic!(),
        }
    }

    fn rx_tlpd_prim(&mut self, _queue: &mut MessageQueue, _message: SapMsg) {
        tracing::trace!("rx_tlpd_prim");
        unimplemented!("rx_tlpd_prim");
        // match &message.msg {
        //     _ => {
        //         panic!();
        //     }
        // }
    }

    fn rx_lcmc_mle_unitdata_req(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_lcmc_mle_unitdata_req");
        let SapMsgInner::LcmcMleUnitdataReq(prim) = &mut message.msg else {
            panic!()
        };

        if let Some(incoming_aie) = self.pending_restores.remove(&prim.main_address.ssi) {
            if prim.sdu.get_len_remaining() == 0 {
                self.send_restore_fail(queue, prim.main_address, 1, self.mle_reply_aie(prim.main_address, incoming_aie));
            } else {
                let mut bits = BitBuffer::new_autoexpand(64);
                if (DRestoreAck { sdu: prim.sdu.clone() }).to_bitbuf(&mut bits).is_ok() {
                    bits.seek(0);
                    self.send_mle_downlink(
                        queue,
                        prim.main_address,
                        bits,
                        prim.chan_alloc.take(),
                        self.mle_reply_aie(prim.main_address, incoming_aie),
                    );
                }
            }
            return;
        }

        let mle_prot_discriminator = MleProtocolDiscriminator::Cmce;
        let sdu_len = prim.sdu.get_len();
        let mut pdu = BitBuffer::new(3 + sdu_len);
        pdu.write_bits(mle_prot_discriminator.into_raw(), 3);
        pdu.copy_bits(&mut prim.sdu, sdu_len);
        pdu.seek(0);

        // let (_addr, link, endpoint) = self.router.use_handle(prim.handle, message.dltime);
        // assert_eq!(link, prim.link_id);
        // assert_eq!(endpoint, prim.endpoint_id);
        // Take Channel Allocation Request if any
        let chan_alloc = prim.chan_alloc.take();
        // Preserve CMCE's likely-listening-channel decision through LLC.
        let associated_channel = prim.associated_channel.take();
        // Resolve once before moving the address into the outgoing primitive.
        // LLC/UMAC retain this request across fragmentation and bind the key at
        // the exact transmission time.
        let air_interface_encryption = self.cmce_downlink_aie(prim.main_address);

        let sapmsg = if prim.layer2service == Layer2Service::Unacknowledged {
            // Unacknowledged service, send a TlUnitdataReqBl
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Llc,
                msg: SapMsgInner::TlaTlUnitdataReqBl(TlaTlUnitdataReqBl {
                    main_address: prim.main_address,
                    link_id: prim.link_id,
                    endpoint_id: prim.endpoint_id,
                    tl_sdu: pdu,
                    stealing_permission: prim.stealing_permission,
                    subscriber_class: 0, // TODO fixme
                    fcs_flag: false,
                    air_interface_encryption,
                    packet_data_flag: false,
                    n_tlsdu_repeats: 0,
                    data_class_info: None,
                    req_handle: 0,

                    chan_alloc,
                    associated_channel,
                    tx_reporter: prim.tx_reporter.take(),
                }),
            }
        } else {
            // Acknowledged service, send a TlDataReqBl
            SapMsg {
                sap: Sap::TlaSap,
                src: TetraEntity::Mle,
                dest: TetraEntity::Llc,
                msg: SapMsgInner::TlaTlDataReqBl(TlaTlDataReqBl {
                    main_address: prim.main_address,
                    link_id: prim.link_id,
                    endpoint_id: prim.endpoint_id,
                    tl_sdu: pdu,
                    stealing_permission: prim.stealing_permission,
                    subscriber_class: 0, // TODO fixme
                    fcs_flag: false,
                    air_interface_encryption,
                    stealing_repeats_flag: None,
                    data_class_info: None,
                    req_handle: 0, // TODO FIXME
                    graceful_degradation: None,
                    chan_alloc,
                    associated_channel,
                    tx_reporter: prim.tx_reporter.take(),
                }),
            }
        };

        queue.push_back(sapmsg);
    }

    fn rx_lcmc_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_lcmc_prim");
        match &message.msg {
            SapMsgInner::LcmcMleUnitdataReq(_) => {
                self.rx_lcmc_mle_unitdata_req(queue, message);
            }
            _ => panic!(),
        }
    }
}

impl TetraEntityTrait for MleBs {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Mle
    }

    fn tick_start(&mut self, queue: &mut MessageQueue, ts: TdmaTime) {
        self.current_time = ts;
        // The Network Time value is the common rollover target, but this BS
        // is authoritative for its local TDMA slot. Activation therefore
        // happens here at a real downlink tick rather than in the WSS worker.
        let network_time = {
            let state = self.config.state_read();
            state
                .network_broadcast
                .broadcast
                .time_enabled
                .then(|| state.network_broadcast.broadcast.timezone.as_deref().and_then(network_time::encode_tetra_network_time))
                .flatten()
        };
        if let Some(network_time) = network_time {
            let mut state = self.config.state_write();
            let (scheduled, rollover_id) = {
                let tetra_config::bluestation::StackState {
                    aie,
                    aie_sessions: sessions,
                    ..
                } = &mut *state;
                (
                    aie.schedule_rollover_absolute_iv(network_time, ts),
                    aie.activate_rollover_if_due(ts, sessions),
                )
            };
            if let Some((rollover_id, absolute_iv)) = scheduled {
                tracing::debug!(rollover_id, absolute_iv = %absolute_iv, "SC2 rollover uses serving-cell Absolute IV");
            }
            if let Some(rollover_id) = rollover_id {
                state.sc2_rollover_events.push_back(RuntimeSc2RolloverEvent {
                    rollover_id,
                    activated: true,
                    local_network_time: network_time,
                });
                tracing::info!(rollover_id, network_time, tdma_time = %ts, "SC2 rollover activated at local downlink slot");
            }
        }
        let timed_out: Vec<u32> = self
            .forward_registration_deadlines
            .iter()
            .filter_map(|(&issi, deadline)| (deadline.age(ts) >= 0).then_some(issi))
            .collect();
        for issi in timed_out {
            self.forward_registration_deadlines.remove(&issi);
            if let Some(forward_registration) = self.forward_registrations.remove(&issi) {
                tracing::warn!(issi, "U-PREPARE timed out at T370");
                let address = TetraAddress::issi(issi);
                self.send_prepare_fail(
                    queue,
                    address,
                    1,
                    None,
                    self.mle_reply_aie(address, forward_registration.incoming_aie),
                );
            }
        }
        while let Some(snapshot) = self.swmi.as_ref().and_then(SwmiMleEndpoint::try_recv) {
            self.broadcast.replace_neighbours(snapshot);
        }
        if let Some(control) = &self.control {
            while let Some(command) = control.try_recv() {
                match command {
                    ControlCommand::UpdateCellAdvertisement {
                        handle,
                        neighbour_ids,
                        cell_reselect_parameters,
                        cell_load_ca,
                        time_enabled,
                        timezone,
                    } => {
                        let update = tetra_config::bluestation::CfgNetworkBroadcast {
                            cell_reselect_parameters,
                            cell_load_ca,
                            time_enabled,
                            timezone,
                        };
                        match self.broadcast.apply_runtime_update(neighbour_ids, update) {
                            Ok(version) => control.respond(ControlResponse::UpdateCellAdvertisementResponse {
                                handle,
                                success: true,
                                version,
                                error: None,
                            }),
                            Err(error) => control.respond(ControlResponse::UpdateCellAdvertisementResponse {
                                handle,
                                success: false,
                                version: self.config.state_read().network_broadcast.version,
                                error: Some(error.to_owned()),
                            }),
                        }
                    }
                    command => tracing::warn!(?command, "unsupported MLE control command"),
                }
            }
        }
        // Offer D-NWRK-BROADCAST every five multiframes.  The UMAC scheduler packs
        // this into free MCCH capacity and defers it to a subsequent TS1 if
        // the selected block has no room.  Looking one slot ahead is required
        // to put the actual air-interface message on TS1, rather than merely
        // enqueueing it while the router happens to be at TS1.
        let transmission_time = ts.add_timeslots(MLE_BROADCAST_TX_AHEAD_TIMESLOTS);
        if network_broadcast_due(transmission_time, self.next_network_broadcast) {
            self.broadcast.send_broadcast(queue);
            self.next_network_broadcast = Some(transmission_time.add_timeslots(MLE_BROADCAST_INTERVAL_TIMESLOTS));
        }
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::TlaSap => {
                self.rx_tla_prim(queue, message);
            }
            Sap::TlmbSap => {
                panic!("MleBs can't accept broadcast messages");
            }
            Sap::TlmcSap => {
                self.rx_tlmc_prim(queue, message);
            }
            Sap::LmmSap => {
                self.rx_lmm_prim(queue, message);
            }
            Sap::TlpdSap => {
                self.rx_tlpd_prim(queue, message);
            }
            Sap::LcmcSap => {
                self.rx_lcmc_prim(queue, message);
            }
            _ => {
                panic!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_broadcast_repeats_every_five_multiframes_on_ts1() {
        let mut next_broadcast = None;
        let mut broadcasts = Vec::new();

        // The MLE runs at the preceding TS4; UMAC then emits the PDU at the
        // corresponding TS1. Cover multiple five-multiframe periods.
        for offset in 0..(18 * 4 * 16 + 4) {
            let now = TdmaTime::default().add_timeslots(offset);
            let transmission_time = now.add_timeslots(MLE_BROADCAST_TX_AHEAD_TIMESLOTS);
            if network_broadcast_due(transmission_time, next_broadcast) {
                broadcasts.push(transmission_time);
                next_broadcast = Some(transmission_time.add_timeslots(MLE_BROADCAST_INTERVAL_TIMESLOTS));
            }
        }

        assert!(broadcasts.len() >= 4);
        assert!(broadcasts.iter().all(|time| time.t == 1));
        for pair in broadcasts.windows(2) {
            assert_eq!(pair[1].age(pair[0]), MLE_BROADCAST_INTERVAL_TIMESLOTS);
        }
        assert_eq!(broadcasts[0].f, 2);
        assert_eq!(broadcasts[1].m, 6);
        assert_eq!(broadcasts[2].m, 11);
    }
}
