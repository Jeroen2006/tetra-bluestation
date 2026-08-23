use std::collections::HashMap;

use tetra_config::bluestation::SharedConfig;
use tetra_core::{
    BitBuffer, Layer2Service, Sap, SsiType, TetraAddress, TxReporter, TxState, tetra_entities::TetraEntity, unimplemented_log,
};
use tetra_pdus::cmce::enums::party_type_identifier::PartyTypeIdentifier;
use tetra_pdus::cmce::enums::pre_coded_status::PreCodedStatus;
use tetra_pdus::cmce::pdus::d_sds_data::DSdsData;
use tetra_pdus::cmce::pdus::d_status::DStatus;
use tetra_pdus::cmce::pdus::u_sds_data::USdsData;
use tetra_pdus::cmce::pdus::u_status::UStatus;
use tetra_saps::control::enums::sds_user_data::SdsUserData;
use tetra_saps::lcmc::LcmcMleUnitdataReq;
use tetra_saps::{SapMsg, SapMsgInner};
use tetra_swmi_protocol::SwmiMessage;

use crate::MessageQueue;
use crate::net_control::ControlCommand;
use crate::net_swmi::SwmiCmceEndpoint;

/// ETSI TTR 001-01 table 11: SwMI-generated status/error reports use this SSI.
const SWMI_ISSI: u32 = 0x00ff_fffd;
const STATUS_GENERAL_NEGATIVE_ACK: u16 = 0xfe01;
const STATUS_NOT_AUTHORISED: u16 = 0xfe02;
const STATUS_DESTINATION_DOES_NOT_EXIST: u16 = 0xfe04;
const STATUS_DESTINATION_NOT_REACHABLE: u16 = 0xfe05;
const STATUS_DESTINATION_NOT_AUTHORISED: u16 = 0xfe06;
const SDS_FAILURE_SOURCE_NOT_AUTHORISED: u8 = 0x2b;
const SDS_FAILURE_DESTINATION_NOT_AUTHORISED: u8 = 0x2c;
const SDS_FAILURE_UNKNOWN_DESTINATION: u8 = 0x2d;
const SDS_FAILURE_DELIVERY_FAILED: u8 = 0x32;
const SDS_FAILURE_DESTINATION_NOT_REGISTERED: u8 = 0x33;
const SDS_FAILURE_DESTINATION_NOT_REACHABLE: u8 = 0x3d;

struct PendingSdsDelivery {
    transaction_id: Option<u64>,
    originator_issi: u32,
    destination_issi: u32,
    sds_tl_protocol_id: Option<u8>,
    message_reference: Option<u8>,
    reporter: TxReporter,
}

/// Online, the SwMI owns every SDS route; this subentity is only the radio
/// adapter and reports the terminal's LLC delivery result. LST retains a
/// deliberately local-only route.
pub struct SdsBsSubentity {
    config: SharedConfig,
    swmi: Option<SwmiCmceEndpoint>,
    next_command_id: u64,
    next_local_delivery_id: u64,
    pending_deliveries: HashMap<(bool, u64), PendingSdsDelivery>,
}

impl SdsBsSubentity {
    pub fn new(config: SharedConfig, swmi: Option<SwmiCmceEndpoint>) -> Self {
        Self {
            config,
            swmi,
            next_command_id: 1,
            next_local_delivery_id: 1,
            pending_deliveries: HashMap::new(),
        }
    }

    fn swmi_online(&self) -> bool {
        self.swmi.as_ref().is_some_and(SwmiCmceEndpoint::is_online)
    }

    fn next_command_id(&mut self) -> u64 {
        let id = self.next_command_id;
        self.next_command_id = self.next_command_id.wrapping_add(1).max(1);
        id
    }

    pub fn tick_start(&mut self, queue: &mut MessageQueue) {
        let done: Vec<_> = self
            .pending_deliveries
            .iter()
            .filter_map(|(id, pending)| pending.reporter.is_in_final_state().then_some((*id, pending.reporter.get_state())))
            .collect();
        for (delivery_id, state) in done {
            let Some(pending) = self.pending_deliveries.remove(&delivery_id) else {
                continue;
            };
            let delivered = state == TxState::Acknowledged;
            if let Some(transaction_id) = pending.transaction_id {
                self.report_delivery(
                    transaction_id,
                    pending.destination_issi,
                    delivered,
                    if delivered { 0 } else { SDS_FAILURE_DELIVERY_FAILED },
                );
            } else if !delivered {
                self.send_swmi_failure(
                    queue,
                    pending.originator_issi,
                    pending.destination_issi,
                    SDS_FAILURE_DELIVERY_FAILED,
                    pending.sds_tl_protocol_id,
                    pending.message_reference,
                );
            }
        }
    }

    /// CMCE has a single SwMI receiver. Call control owns the drain and
    /// delegates the SDS/status variants here, preventing cloned receivers
    /// from competing for (and dropping) each other's messages.
    pub fn is_swmi_action(message: &SwmiMessage) -> bool {
        matches!(
            message,
            SwmiMessage::SdsDeliver { .. } | SwmiMessage::SdsFailure { .. } | SwmiMessage::StatusDeliver { .. }
        )
    }

    pub fn handle_swmi_action(&mut self, queue: &mut MessageQueue, message: SwmiMessage) {
        match message {
            SwmiMessage::SdsDeliver {
                transaction_id,
                source_issi,
                destination_ssi,
                destination_is_group,
                data_type,
                length_bits,
                data,
            } => {
                tracing::info!(transaction_id, source_issi, destination_ssi, "SwMI SDS delivery received by BS");
                self.deliver_from_swmi(
                    queue,
                    transaction_id,
                    source_issi as u32,
                    destination_ssi,
                    destination_is_group,
                    data_type,
                    length_bits,
                    data,
                );
            }
            SwmiMessage::SdsFailure {
                originator_issi,
                destination_ssi,
                cause,
                sds_tl_protocol_id,
                message_reference,
            } => {
                tracing::info!(originator_issi, destination_ssi, cause, "SwMI SDS/status failure received by BS");
                self.send_swmi_failure(
                    queue,
                    originator_issi as u32,
                    destination_ssi,
                    cause,
                    sds_tl_protocol_id,
                    message_reference,
                );
            }
            SwmiMessage::StatusDeliver {
                source_issi,
                destination_ssi,
                status,
            } => {
                tracing::info!(source_issi, destination_ssi, status, "SwMI status delivery received by BS");
                let destination_type = if self.config.state_read().subscribers.is_registered(destination_ssi) {
                    SsiType::Issi
                } else {
                    SsiType::Gssi
                };
                self.send_d_status(
                    queue,
                    source_issi as u32,
                    destination_ssi,
                    destination_type,
                    PreCodedStatus::from(status),
                );
            }
            _ => unreachable!("non-SDS SwMI action was delegated to SDS"),
        }
    }

    /// Submit every online U-SDS-DATA to the SwMI before considering local state.
    pub fn route_rf_deliver(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let source_issi = prim.received_tetra_address.ssi;
        let pdu = match USdsData::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(?error, "failed parsing U-SDS-DATA");
                return;
            }
        };
        if !Self::feature_check_u_sds_data(&pdu) {
            return;
        }
        let destination_ssi = pdu.called_party_ssi.expect("checked") as u32;
        let destination_is_group = !self.config.state_read().subscribers.is_registered(destination_ssi)
            && self.config.state_read().subscribers.has_group_members(destination_ssi);
        if self.swmi_online() {
            let command_id = self.next_command_id();
            let submitted = self
                .swmi
                .as_ref()
                .expect("online endpoint")
                .submit(SwmiMessage::SdsSubmit {
                    command_id,
                    source_issi: source_issi as u64,
                    destination_ssi,
                    destination_is_group,
                    data_type: pdu.user_defined_data.type_identifier(),
                    length_bits: pdu.user_defined_data.length_bits(),
                    data: pdu.user_defined_data.to_arr(),
                })
                .is_ok();
            if !submitted {
                self.send_swmi_failure(queue, source_issi, destination_ssi, SDS_FAILURE_DELIVERY_FAILED, None, None);
            }
        } else {
            self.route_lstr_sds(queue, source_issi, destination_ssi, destination_is_group, pdu.user_defined_data);
        }
    }

    /// U-STATUS carries normal pre-coded status and SDS-SHORT REPORT. It has
    /// its own SwMI message so the recipient receives D-STATUS, never SDS data.
    pub fn route_status_deliver(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        let source_issi = prim.received_tetra_address.ssi;
        let pdu = match UStatus::from_bitbuf(&mut prim.sdu) {
            Ok(pdu) => pdu,
            Err(error) => {
                tracing::warn!(?error, "failed parsing U-STATUS");
                return;
            }
        };
        if !Self::feature_check_u_status(&pdu) {
            return;
        }
        let destination_ssi = pdu.called_party_ssi.expect("checked") as u32;
        if self.swmi_online() {
            let command_id = self.next_command_id();
            let submitted = self
                .swmi
                .as_ref()
                .expect("online endpoint")
                .submit(SwmiMessage::StatusSubmit {
                    command_id,
                    source_issi: source_issi as u64,
                    destination_ssi,
                    status: pdu.pre_coded_status.into_raw(),
                })
                .is_ok();
            if !submitted {
                self.send_d_status(
                    queue,
                    SWMI_ISSI,
                    source_issi,
                    SsiType::Issi,
                    PreCodedStatus::NetworkUserSpecific(STATUS_GENERAL_NEGATIVE_ACK),
                );
            }
        } else if self.config.state_read().subscribers.is_registered(destination_ssi) {
            self.send_d_status(queue, source_issi, destination_ssi, SsiType::Issi, pdu.pre_coded_status);
        } else {
            self.send_d_status(
                queue,
                SWMI_ISSI,
                source_issi,
                SsiType::Issi,
                PreCodedStatus::NetworkUserSpecific(STATUS_DESTINATION_NOT_REACHABLE),
            );
        }
    }

    pub fn rx_sds_from_brew(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        let SapMsgInner::CmceSdsData(sds) = message.msg else {
            panic!("Expected CmceSdsData")
        };
        if self.swmi_online() {
            let destination_is_group = !self.config.state_read().subscribers.is_registered(sds.dest_issi)
                && self.config.state_read().subscribers.has_group_members(sds.dest_issi);
            let sds_tl_context = Self::sds_tl_context(&sds.user_defined_data);
            let command_id = self.next_command_id();
            let submitted = self
                .swmi
                .as_ref()
                .expect("online endpoint")
                .submit(SwmiMessage::SdsSubmit {
                    command_id,
                    source_issi: sds.source_issi as u64,
                    destination_ssi: sds.dest_issi,
                    destination_is_group,
                    data_type: sds.user_defined_data.type_identifier(),
                    length_bits: sds.user_defined_data.length_bits(),
                    data: sds.user_defined_data.to_arr(),
                })
                .is_ok();
            if !submitted {
                self.send_swmi_failure(
                    queue,
                    sds.source_issi,
                    sds.dest_issi,
                    SDS_FAILURE_DELIVERY_FAILED,
                    sds_tl_context.0,
                    sds_tl_context.1,
                );
            }
            return;
        }
        if self.config.state_read().subscribers.is_registered(sds.dest_issi) {
            let _ = self.send_d_sds_data(queue, sds.source_issi, sds.dest_issi, SsiType::Issi, sds.user_defined_data, None);
        }
    }

    pub fn rx_sds_from_control(&mut self, queue: &mut MessageQueue, message: ControlCommand) -> bool {
        let ControlCommand::SendSds {
            source_ssi,
            dest_ssi,
            dest_is_group,
            len_bits,
            payload,
            ..
        } = message
        else {
            panic!("Expected SendSds")
        };
        if self.swmi_online() {
            let command_id = self.next_command_id();
            return self
                .swmi
                .as_ref()
                .expect("online endpoint")
                .submit(SwmiMessage::SdsSubmit {
                    command_id,
                    source_issi: source_ssi as u64,
                    destination_ssi: dest_ssi,
                    destination_is_group: dest_is_group,
                    data_type: 3,
                    length_bits: len_bits,
                    data: payload,
                })
                .is_ok();
        }
        let destination_type = if dest_is_group { SsiType::Gssi } else { SsiType::Issi };
        let local = if dest_is_group {
            self.config.state_read().subscribers.has_group_members(dest_ssi)
        } else {
            self.config.state_read().subscribers.is_registered(dest_ssi)
        };
        local
            && self.send_d_sds_data(
                queue,
                source_ssi,
                dest_ssi,
                destination_type,
                SdsUserData::Type4(len_bits, payload),
                None,
            )
    }

    fn route_lstr_sds(
        &mut self,
        queue: &mut MessageQueue,
        source_issi: u32,
        destination_ssi: u32,
        destination_is_group: bool,
        data: SdsUserData,
    ) {
        let destination_type = if destination_is_group { SsiType::Gssi } else { SsiType::Issi };
        let local = if destination_is_group {
            self.config.state_read().subscribers.has_group_members(destination_ssi)
        } else {
            self.config.state_read().subscribers.is_registered(destination_ssi)
        };
        if local {
            let reporter = (!destination_is_group).then(TxReporter::new);
            let sds_tl_context = Self::sds_tl_context(&data);
            if !self.send_d_sds_data(queue, source_issi, destination_ssi, destination_type, data, reporter.clone()) {
                self.send_swmi_failure(
                    queue,
                    source_issi,
                    destination_ssi,
                    SDS_FAILURE_DELIVERY_FAILED,
                    sds_tl_context.0,
                    sds_tl_context.1,
                );
            } else if let Some(reporter) = reporter {
                self.track_delivery(None, source_issi, destination_ssi, sds_tl_context, reporter);
            }
        } else {
            self.send_swmi_failure(
                queue,
                source_issi,
                destination_ssi,
                SDS_FAILURE_DESTINATION_NOT_REACHABLE,
                None,
                None,
            );
        }
    }

    fn deliver_from_swmi(
        &mut self,
        queue: &mut MessageQueue,
        transaction_id: u64,
        source_issi: u32,
        destination_ssi: u32,
        destination_is_group: bool,
        data_type: u8,
        length_bits: u16,
        data: Vec<u8>,
    ) {
        let destination_type = if destination_is_group { SsiType::Gssi } else { SsiType::Issi };
        let local = if destination_is_group {
            self.config.state_read().subscribers.has_group_members(destination_ssi)
        } else {
            self.config.state_read().subscribers.is_registered(destination_ssi)
        };
        let Some(user_data) = Self::user_data_from_wire(data_type, length_bits, data) else {
            self.report_delivery(transaction_id, destination_ssi, false, SDS_FAILURE_DELIVERY_FAILED);
            return;
        };
        if !local {
            self.report_delivery(transaction_id, destination_ssi, false, SDS_FAILURE_DESTINATION_NOT_REACHABLE);
            return;
        }
        let reporter = (!destination_is_group && transaction_id != 0).then(TxReporter::new);
        if !self.send_d_sds_data(queue, source_issi, destination_ssi, destination_type, user_data, reporter.clone()) {
            self.report_delivery(transaction_id, destination_ssi, false, SDS_FAILURE_DELIVERY_FAILED);
        } else if let Some(reporter) = reporter {
            self.track_delivery(Some(transaction_id), source_issi, destination_ssi, (None, None), reporter);
        }
    }

    fn track_delivery(
        &mut self,
        transaction_id: Option<u64>,
        originator_issi: u32,
        destination_issi: u32,
        sds_tl_context: (Option<u8>, Option<u8>),
        reporter: TxReporter,
    ) {
        let key = if let Some(transaction_id) = transaction_id {
            (true, transaction_id)
        } else {
            let local_id = self.next_local_delivery_id;
            self.next_local_delivery_id = self.next_local_delivery_id.wrapping_add(1).max(1);
            (false, local_id)
        };
        self.pending_deliveries.insert(
            key,
            PendingSdsDelivery {
                transaction_id,
                originator_issi,
                destination_issi,
                sds_tl_protocol_id: sds_tl_context.0,
                message_reference: sds_tl_context.1,
                reporter,
            },
        );
    }

    fn report_delivery(&self, transaction_id: u64, destination_issi: u32, delivered: bool, cause: u8) {
        if transaction_id == 0 {
            return;
        }
        if let Some(swmi) = &self.swmi {
            if swmi
                .submit(SwmiMessage::SdsDeliveryResult {
                    transaction_id,
                    destination_issi: destination_issi as u64,
                    delivered,
                    cause,
                })
                .is_err()
            {
                tracing::warn!(transaction_id, "SwMI unavailable while reporting SDS delivery result");
            }
        }
    }

    fn send_swmi_failure(
        &self,
        queue: &mut MessageQueue,
        originator_issi: u32,
        destination_ssi: u32,
        cause: u8,
        protocol_id: Option<u8>,
        message_reference: Option<u8>,
    ) {
        if let (Some(protocol_id), Some(message_reference)) = (protocol_id, message_reference) {
            let report = SdsUserData::Type4(32, vec![protocol_id, 0x10, cause, message_reference]);
            let _ = self.send_d_sds_data(queue, SWMI_ISSI, originator_issi, SsiType::Issi, report, None);
            return;
        }
        let status = match cause {
            SDS_FAILURE_SOURCE_NOT_AUTHORISED => STATUS_NOT_AUTHORISED,
            SDS_FAILURE_DESTINATION_NOT_AUTHORISED => STATUS_DESTINATION_NOT_AUTHORISED,
            SDS_FAILURE_UNKNOWN_DESTINATION => STATUS_DESTINATION_DOES_NOT_EXIST,
            SDS_FAILURE_DESTINATION_NOT_REGISTERED | SDS_FAILURE_DESTINATION_NOT_REACHABLE => STATUS_DESTINATION_NOT_REACHABLE,
            SDS_FAILURE_DELIVERY_FAILED => STATUS_GENERAL_NEGATIVE_ACK,
            _ => STATUS_GENERAL_NEGATIVE_ACK,
        };
        tracing::info!(originator_issi, destination_ssi, cause, status, "sending SwMI SDS failure status");
        self.send_d_status(
            queue,
            SWMI_ISSI,
            originator_issi,
            SsiType::Issi,
            PreCodedStatus::NetworkUserSpecific(status),
        );
    }

    fn send_d_status(
        &self,
        queue: &mut MessageQueue,
        source_issi: u32,
        destination_ssi: u32,
        destination_type: SsiType,
        pre_coded_status: PreCodedStatus,
    ) {
        let pdu = DStatus {
            calling_party_type_identifier: PartyTypeIdentifier::Ssi,
            calling_party_address_ssi: Some(source_issi as u64),
            calling_party_extension: None,
            pre_coded_status,
            external_subscriber_number: None,
            dm_ms_address: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(64);
        if pdu.to_bitbuf(&mut sdu).is_err() {
            return;
        }
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: 0,
                endpoint_id: 0,
                link_id: 0,
                layer2service: if destination_type == SsiType::Issi {
                    Layer2Service::Acknowledged
                } else {
                    Layer2Service::Unacknowledged
                },
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None,
                associated_channel: None,
                main_address: TetraAddress::new(destination_ssi, destination_type),
                tx_reporter: None,
            }),
        });
    }

    fn send_d_sds_data(
        &self,
        queue: &mut MessageQueue,
        source_issi: u32,
        destination_ssi: u32,
        destination_type: SsiType,
        user_defined_data: SdsUserData,
        tx_reporter: Option<TxReporter>,
    ) -> bool {
        let pdu = DSdsData {
            calling_party_type_identifier: PartyTypeIdentifier::Ssi,
            calling_party_address_ssi: Some(source_issi as u64),
            calling_party_extension: None,
            user_defined_data,
            external_subscriber_number: None,
            dm_ms_address: None,
        };
        let mut sdu = BitBuffer::new_autoexpand(128);
        if let Err(error) = pdu.to_bitbuf(&mut sdu) {
            tracing::error!(?error, "failed serializing D-SDS-DATA");
            return false;
        }
        sdu.seek(0);
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: 0,
                endpoint_id: 0,
                link_id: 0,
                layer2service: if destination_type == SsiType::Issi {
                    Layer2Service::Acknowledged
                } else {
                    Layer2Service::Unacknowledged
                },
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None,
                associated_channel: None,
                main_address: TetraAddress::new(destination_ssi, destination_type),
                tx_reporter,
            }),
        });
        true
    }

    fn user_data_from_wire(data_type: u8, length_bits: u16, data: Vec<u8>) -> Option<SdsUserData> {
        match data_type {
            0 if length_bits == 16 && data.len() == 2 => Some(SdsUserData::Type1(u16::from_be_bytes(data.try_into().ok()?))),
            1 if length_bits == 32 && data.len() == 4 => Some(SdsUserData::Type2(u32::from_be_bytes(data.try_into().ok()?))),
            2 if length_bits == 64 && data.len() == 8 => Some(SdsUserData::Type3(u64::from_be_bytes(data.try_into().ok()?))),
            3 if data.len() == usize::from(length_bits.div_ceil(8)) => Some(SdsUserData::Type4(length_bits, data)),
            _ => None,
        }
    }

    fn sds_tl_context(data: &SdsUserData) -> (Option<u8>, Option<u8>) {
        match data {
            SdsUserData::Type4(_, bytes) if bytes.len() >= 3 && bytes[0] >= 0x80 => (Some(bytes[0]), Some(bytes[2])),
            _ => (None, None),
        }
    }

    fn feature_check_u_sds_data(pdu: &USdsData) -> bool {
        if pdu.called_party_ssi.is_none() {
            tracing::warn!("SDS destination SSI missing or unsupported");
            return false;
        }
        if pdu.called_party_extension.is_some() {
            unimplemented_log!("SDS TSI addressing not supported");
            return false;
        }
        if pdu.external_subscriber_number.is_some() || pdu.dm_ms_address.is_some() {
            unimplemented_log!("SDS external/DM addressing not supported");
            return false;
        }
        true
    }

    fn feature_check_u_status(pdu: &UStatus) -> bool {
        if pdu.called_party_ssi.is_none() {
            tracing::warn!("status destination SSI missing or unsupported");
            return false;
        }
        if pdu.called_party_extension.is_some() {
            unimplemented_log!("status TSI addressing not supported");
            return false;
        }
        if pdu.external_subscriber_number.is_some() || pdu.dm_ms_address.is_some() {
            unimplemented_log!("status external/DM addressing not supported");
            return false;
        }
        true
    }
}
