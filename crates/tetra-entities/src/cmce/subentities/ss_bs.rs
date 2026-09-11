use std::collections::HashMap;

use crate::{MessageQueue, net_swmi::SwmiCmceEndpoint};
use tetra_config::bluestation::SharedConfig;
use tetra_core::{BitBuffer, Layer2Service, Sap, SsiType, TetraAddress, tetra_entities::TetraEntity, typed_pdu_fields::Type3FieldGeneric};
use tetra_pdus::cmce::enums::type3_elem_id::CmceType3ElemId;
use tetra_pdus::cmce::pdus::{d_facility::DFacility, u_facility::UFacility};
use tetra_saps::{SapMsg, SapMsgInner, lcmc::LcmcMleUnitdataReq, tma::AssociatedChannel};
use tetra_swmi_protocol::{DgnaObservedGroup, SwmiMessage};

/// Clause 12 Supplementary Services CMCE sub-entity.
///
/// This implements the individual, call-unrelated SS-DGNA flows. The
/// interoperability profile requires exactly one SS-DGNA PDU in each
/// D-/U-FACILITY PDU.
pub struct SsBsSubentity {
    config: SharedConfig,
    swmi: Option<SwmiCmceEndpoint>,
    pending: HashMap<(u32, u8, Option<u32>), PendingDgna>,
    /// The SwMI accepts a registration before the BS has placed the matching
    /// D-LOCATION UPDATE ACCEPT on the air interface.  Do not let an
    /// asynchronous DGNA command overtake that response: especially an EE MS
    /// can otherwise miss the FACILITY while it is still completing access.
    deferred_until_registered: HashMap<u64, SwmiMessage>,
    next_command_id: u64,
}

struct PendingDgna {
    job_id: u64,
    groups: Vec<DgnaObservedGroup>,
    next_sequence: Option<u8>,
}

impl SsBsSubentity {
    pub fn new(config: SharedConfig, swmi: Option<SwmiCmceEndpoint>) -> Self {
        Self {
            config,
            swmi,
            pending: HashMap::new(),
            deferred_until_registered: HashMap::new(),
            next_command_id: 1,
        }
    }

    pub fn is_swmi_action(message: &SwmiMessage) -> bool {
        matches!(message, SwmiMessage::DgnaCommand { .. }) || matches!(message, SwmiMessage::CallWaitingResponse { call_id: 0, .. })
    }

    pub fn handle_swmi_action(&mut self, queue: &mut MessageQueue, message: SwmiMessage) {
        if let SwmiMessage::CallWaitingResponse {
            itsi,
            operation,
            accepted,
            active,
            cause,
            waiting_calls,
            ..
        } = message
        {
            let Ok(issi) = u32::try_from(itsi) else {
                return;
            };
            let Some((ss_pdu, ss_pdu_bits)) = encode_call_waiting_response(operation, accepted, active, cause, waiting_calls) else {
                return;
            };
            self.queue_facility(queue, issi, ss_pdu, ss_pdu_bits);
            return;
        }
        // Retain the complete command for the registration gate below.  The
        // individual fields are consumed while serializing the PDU.
        let deferred_message = message.clone();
        let SwmiMessage::DgnaCommand {
            job_id,
            itsi,
            action,
            gssi,
            name,
            ..
        } = message
        else {
            return;
        };
        let issi = match u32::try_from(itsi) {
            Ok(value) if value <= 0x00ff_ffff => value,
            _ => return,
        };
        if !self.terminal_ready_for_dgna(issi) {
            tracing::info!(
                job_id,
                issi,
                action,
                gssi = ?gssi,
                "deferring DGNA command until registration response is queued"
            );
            self.deferred_until_registered.insert(job_id, deferred_message);
            return;
        }
        let gck_select_number = gssi.and_then(|gssi| {
            self.config.state_read().aie.sc3.as_ref().and_then(|sc3| {
                sc3.linked_gck_crypto_periods()
                    .then(|| sc3.gckn_for_gssi(gssi).map(u64::from))
                    .flatten()
            })
        });
        let Some((ss_pdu, ss_pdu_bits)) = encode_dgna(action, gssi, name.as_deref(), gck_select_number) else {
            self.send_result(job_id, issi, action, false, 0, Vec::new());
            return;
        };
        let facility = DFacility { ss_pdu, ss_pdu_bits };
        let mut sdu = BitBuffer::new_autoexpand(128);
        if facility.to_bitbuf(&mut sdu).is_err() {
            self.send_result(job_id, issi, action, false, 0, Vec::new());
            return;
        }
        sdu.seek(0);
        self.pending.insert(
            (issi, action, gssi),
            PendingDgna {
                job_id,
                groups: Vec::new(),
                next_sequence: None,
            },
        );
        tracing::info!(
            job_id,
            issi,
            action,
            gssi = ?gssi,
            ss_pdu_bits,
            "queueing individual D-FACILITY SS-DGNA command"
        );
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: 0,
                endpoint_id: 0,
                link_id: 0,
                layer2service: Layer2Service::Acknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None,
                associated_channel: None,
                main_address: TetraAddress::new(issi, SsiType::Issi),
                aie_override: None,
                tx_reporter: None,
            }),
        });
    }

    /// Release commands only after MM has admitted the corresponding
    /// D-LOCATION UPDATE ACCEPT to MLE.  Queue order then guarantees that the
    /// terminal sees its registration response before an individual
    /// D-FACILITY, while UMAC still applies its normal EE monitoring policy.
    pub fn tick_start(&mut self, queue: &mut MessageQueue) {
        let ready = self
            .deferred_until_registered
            .iter()
            .filter_map(|(job_id, message)| {
                let SwmiMessage::DgnaCommand { itsi, .. } = message else {
                    return Some(*job_id);
                };
                u32::try_from(*itsi)
                    .ok()
                    .filter(|issi| self.terminal_ready_for_dgna(*issi))
                    .map(|_| *job_id)
            })
            .collect::<Vec<_>>();
        for job_id in ready {
            if let Some(message) = self.deferred_until_registered.remove(&job_id) {
                self.handle_swmi_action(queue, message);
            }
        }
    }

    fn terminal_ready_for_dgna(&self, issi: u32) -> bool {
        let state = self.config.state_read();
        state.subscribers.is_active(issi) && !state.subscribers.is_registration_pending(issi)
    }

    pub fn route_re_deliver(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            return;
        };
        let issi = prim.received_tetra_address.ssi;
        let Ok(facility) = UFacility::from_bitbuf(&mut prim.sdu) else {
            tracing::warn!(issi, "invalid U-FACILITY");
            return;
        };
        if let Some(decoded) = decode_call_waiting(&facility.ss_pdu, facility.ss_pdu_bits) {
            let expected_routing = match decoded.operation {
                CW_ACTIVATE | CW_DEACTIVATE => 1, // sending MS's home SwMI
                CW_LOCATION_CHANGE => 0,          // current/new serving SwMI
                _ => return,
            };
            if facility.routing != expected_routing {
                tracing::warn!(
                    issi,
                    operation = decoded.operation,
                    routing = facility.routing,
                    expected_routing,
                    "SS-CW request has invalid U-FACILITY routing"
                );
                return;
            }
            let command_id = self.next_command_id;
            self.next_command_id = self.next_command_id.wrapping_add(1).max(1);
            if let Some(swmi) = &self.swmi {
                let _ = swmi.submit(SwmiMessage::CallWaitingRequest {
                    command_id,
                    itsi: u64::from(issi),
                    operation: decoded.operation,
                    waiting_calls: decoded.waiting_calls,
                });
            }
            return;
        }
        if let Some((ss_type, operation)) = decode_ss_header(&facility.ss_pdu, facility.ss_pdu_bits)
            && ss_type != SS_DGNA as u8
        {
            // EN 300 392-9's generic response is 6-bit SS type followed by
            // PDU type 00000. The supplied terminal emits SS-CF (000100)
            // action 10011 while refreshing its service profile. This stack
            // does not implement call forwarding, so answer explicitly
            // instead of misclassifying it as DGNA and leaving the MS to
            // retry until its local service timer expires.
            if operation > SS_LAST_GENERIC_PDU_TYPE {
                let (response, response_bits) = encode_ss_not_supported(ss_type);
                self.queue_facility(queue, issi, response, response_bits);
                tracing::info!(
                    issi,
                    ss_type,
                    operation,
                    "responding that requested supplementary service is not supported"
                );
            } else {
                tracing::debug!(issi, ss_type, operation, "received generic supplementary-service result");
            }
            return;
        }
        let Some(decoded) = decode_dgna(&facility.ss_pdu, facility.ss_pdu_bits) else {
            tracing::warn!(
                issi,
                ss_pdu_bits = facility.ss_pdu_bits,
                ss_pdu = ?facility.ss_pdu,
                "unsupported SS-DGNA action in U-FACILITY"
            );
            // The tested MS explicitly responds to INTERROGATE MS GROUPS with
            // a short, vendor-specific SS-DGNA rejection PDU rather than the
            // standard INTERROGATE MS GROUPS ACK.  It has already confirmed
            // link delivery, so do not retry this optional operation forever.
            // ETSI TS 100 392-12-22 table 70 reserves cause 110 for an
            // unsupported interrogation type.
            self.reject_pending_interrogation(issi);
            return;
        };

        tracing::info!(
            issi,
            action = decoded.action,
            gssi = ?decoded.gssi,
            success = decoded.success,
            cause = decoded.cause,
            complete = decoded.complete,
            groups = decoded.groups.len(),
            "received terminal SS-DGNA result"
        );

        let key = (issi, decoded.action, decoded.gssi);
        let Some(pending) = self.pending.get_mut(&key) else {
            tracing::debug!(issi, action = decoded.action, "unsolicited DGNA result ignored");
            return;
        };

        if decoded.action == ACTION_INTERROGATE {
            if let Some(sequence) = decoded.sequence {
                let expected = pending.next_sequence.unwrap_or(1);
                if sequence != expected {
                    let job_id = pending.job_id;
                    self.pending.remove(&key);
                    self.send_result(job_id, issi, decoded.action, false, 0, Vec::new());
                    return;
                }
                pending.next_sequence = Some(expected.saturating_add(1));
            } else if pending.next_sequence.is_some() {
                let job_id = pending.job_id;
                self.pending.remove(&key);
                self.send_result(job_id, issi, decoded.action, false, 0, Vec::new());
                return;
            }
            pending.groups.extend(decoded.groups);
            if !decoded.complete {
                return;
            }
            let pending = self.pending.remove(&key).expect("pending DGNA query exists");
            self.send_result(pending.job_id, issi, decoded.action, decoded.success, decoded.cause, pending.groups);
            return;
        }

        let pending = self.pending.remove(&key);
        if let Some(pending) = pending {
            self.send_result(pending.job_id, issi, decoded.action, decoded.success, decoded.cause, decoded.groups);
        }
    }

    fn send_result(&self, job_id: u64, itsi: u32, action: u8, success: bool, cause: u8, groups: Vec<DgnaObservedGroup>) {
        if let Some(swmi) = &self.swmi {
            if swmi
                .submit(SwmiMessage::DgnaResult {
                    job_id,
                    itsi: itsi as u64,
                    action,
                    success,
                    cause,
                    groups,
                })
                .is_err()
            {
                tracing::warn!(job_id, itsi, "SwMI unavailable while reporting DGNA result");
            }
        }
    }

    fn reject_pending_interrogation(&mut self, issi: u32) {
        let key = (issi, ACTION_INTERROGATE, None);
        let Some(pending) = self.pending.remove(&key) else {
            return;
        };
        tracing::info!(
            job_id = pending.job_id,
            issi,
            "terminal does not support DGNA MS-group interrogation"
        );
        self.send_result(
            pending.job_id,
            issi,
            ACTION_INTERROGATE,
            false,
            INTERROGATION_TYPE_NOT_SUPPORTED,
            Vec::new(),
        );
    }

    fn queue_facility(&self, queue: &mut MessageQueue, issi: u32, ss_pdu: Vec<u8>, ss_pdu_bits: u16) {
        let facility = DFacility { ss_pdu, ss_pdu_bits };
        let mut sdu = BitBuffer::new_autoexpand(64);
        if facility.to_bitbuf(&mut sdu).is_err() {
            return;
        }
        sdu.seek(0);
        let associated_channel = self
            .config
            .state_read()
            .subscriber_packet_delivery_routes
            .get(&issi)
            .and_then(|routes| routes.first())
            .copied()
            .map(|route| AssociatedChannel {
                call_id: route.call_id,
                timeslot: route.timeslot,
                usage: route.usage,
                best_effort_key: None,
            });
        queue.push_back(SapMsg {
            sap: Sap::LcmcSap,
            src: TetraEntity::Cmce,
            dest: TetraEntity::Mle,
            msg: SapMsgInner::LcmcMleUnitdataReq(LcmcMleUnitdataReq {
                sdu,
                handle: 0,
                endpoint_id: 0,
                link_id: 0,
                layer2service: Layer2Service::Acknowledged,
                pdu_prio: 0,
                layer2_qos: 0,
                stealing_permission: false,
                stealing_repeats_flag: false,
                chan_alloc: None,
                associated_channel,
                main_address: TetraAddress::new(issi, SsiType::Issi),
                aie_override: None,
                tx_reporter: None,
            }),
        });
    }

    pub(super) fn is_call_waiting_invoke(facility: &Type3FieldGeneric) -> bool {
        let (raw, bits) = type3_payload(facility);
        decode_call_waiting(&raw, bits).is_some_and(|decoded| decoded.operation == CW_INVOKE)
    }

    pub(super) fn call_waiting_invocation_failure_facility(cause: u8) -> Option<Type3FieldGeneric> {
        let (raw, bits) = encode_call_waiting_invocation_failure(cause)?;
        Some(type3_facility(raw, bits))
    }
}

const SS_DGNA: u64 = 0b010110;
const SS_CALL_WAITING: u64 = 0b001011;
const SS_LAST_GENERIC_PDU_TYPE: u8 = 0b00100;
const CW_ACTIVATE: u8 = 0b00101;
const CW_ACTIVATE_ACK: u8 = 0b00110;
const CW_DEACTIVATE: u8 = 0b00111;
const CW_DEACTIVATE_ACK: u8 = 0b01000;
const CW_INVOCATION_FAILURE: u8 = 0b01001;
const CW_INVOKE: u8 = 0b01010;
const CW_LOCATION_CHANGE: u8 = 0b01100;
const CW_LOCATION_CHANGE_ACK: u8 = 0b01101;
const ASSIGN: u64 = 0b00111;
const ASSIGN_ACK: u64 = 0b01000;
const DEASSIGN: u64 = 0b01001;
const DEASSIGN_ACK: u64 = 0b01010;
const INTERROGATE_MS_GROUPS: u64 = 0b10001;
const INTERROGATE_MS_GROUPS_ACK: u64 = 0b10010;

const ACTION_ASSIGN: u8 = 1;
const ACTION_DEASSIGN: u8 = 2;
const ACTION_INTERROGATE: u8 = 3;
const INTERROGATION_TYPE_NOT_SUPPORTED: u8 = 0b110;

struct DecodedDgna {
    action: u8,
    success: bool,
    cause: u8,
    gssi: Option<u32>,
    groups: Vec<DgnaObservedGroup>,
    complete: bool,
    sequence: Option<u8>,
}

struct DecodedCallWaiting {
    operation: u8,
    waiting_calls: u8,
}

fn decode_ss_header(raw: &[u8], bits: u16) -> Option<(u8, u8)> {
    if raw.len() < usize::from(bits).div_ceil(8) || bits < 11 {
        return None;
    }
    let mut buffer = BitBuffer::from_vec(raw.to_vec());
    Some((buffer.read_bits(6)? as u8, buffer.read_bits(5)? as u8))
}

fn encode_ss_not_supported(ss_type: u8) -> (Vec<u8>, u16) {
    let mut buffer = BitBuffer::new_autoexpand(11);
    buffer.write_bits(u64::from(ss_type & 0x3f), 6);
    buffer.write_bits(0, 5);
    bitbuffer_bytes(buffer).expect("fixed generic SS response must encode")
}

fn decode_call_waiting(raw: &[u8], bits: u16) -> Option<DecodedCallWaiting> {
    if raw.len() < usize::from(bits).div_ceil(8) || bits < 11 {
        return None;
    }
    let mut buffer = BitBuffer::from_vec(raw.to_vec());
    if buffer.read_bits(6)? != SS_CALL_WAITING {
        return None;
    }
    let operation = buffer.read_bits(5)? as u8;
    let waiting_calls = match operation {
        CW_ACTIVATE | CW_DEACTIVATE | CW_INVOKE => 0,
        CW_LOCATION_CHANGE => {
            let count = buffer.read_bits(3)? as u8;
            if count == 0 {
                return None;
            }
            count
        }
        _ => return None,
    };
    (buffer.get_pos() == usize::from(bits)).then_some(DecodedCallWaiting { operation, waiting_calls })
}

fn encode_call_waiting_response(operation: u8, accepted: bool, active: bool, cause: u8, _waiting_calls: u8) -> Option<(Vec<u8>, u16)> {
    let mut buffer = BitBuffer::new_autoexpand(32);
    buffer.write_bits(SS_CALL_WAITING, 6);
    buffer.write_bits(u64::from(operation), 5);
    match operation {
        CW_ACTIVATE_ACK | CW_DEACTIVATE_ACK => {
            buffer.write_bit(u8::from(accepted));
            buffer.write_bit(if accepted { u8::from(active) } else { u8::from(cause != 0) });
        }
        CW_LOCATION_CHANGE_ACK => {
            // Intra-SwMI relocation preserves central call identifiers. The
            // mandatory bitmap therefore reports neither changed nor lost.
            buffer.write_bits(0, 2);
        }
        _ => return None,
    }
    bitbuffer_bytes(buffer)
}

fn encode_call_waiting_invocation_failure(cause: u8) -> Option<(Vec<u8>, u16)> {
    if cause > 3 {
        return None;
    }
    let mut buffer = BitBuffer::new_autoexpand(16);
    buffer.write_bits(SS_CALL_WAITING, 6);
    buffer.write_bits(u64::from(CW_INVOCATION_FAILURE), 5);
    buffer.write_bits(u64::from(cause), 2);
    bitbuffer_bytes(buffer)
}

fn bitbuffer_bytes(mut buffer: BitBuffer) -> Option<(Vec<u8>, u16)> {
    let bits = buffer.get_len();
    let mut raw = vec![0; bits.div_ceil(8)];
    buffer.seek(0);
    buffer.read_bits_into_slice(bits, &mut raw)?;
    Some((raw, u16::try_from(bits).ok()?))
}

fn type3_payload(facility: &Type3FieldGeneric) -> (Vec<u8>, u16) {
    let bits = u16::try_from(facility.len).unwrap_or(u16::MAX);
    if !facility.raw.is_empty() {
        return (facility.raw.clone(), bits);
    }
    let mut buffer = BitBuffer::new_autoexpand(facility.len.max(1));
    buffer.write_bits(facility.data, facility.len);
    bitbuffer_bytes(buffer).unwrap_or_default()
}

fn type3_facility(raw: Vec<u8>, bits: u16) -> Type3FieldGeneric {
    let len = usize::from(bits);
    let first_bits = len.min(64);
    let data = raw
        .iter()
        .take(first_bits.div_ceil(8))
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
        >> (first_bits.div_ceil(8) * 8 - first_bits);
    Type3FieldGeneric {
        field_id: CmceType3ElemId::Facility.into_raw(),
        len,
        data,
        raw: (len > 64).then_some(raw).unwrap_or_default(),
    }
}

fn encode_dgna(action: u8, gssi: Option<u32>, name: Option<&str>, gck_select_number: Option<u64>) -> Option<(Vec<u8>, u16)> {
    let mut buffer = BitBuffer::new_autoexpand(256);
    buffer.write_bits(SS_DGNA, 6);
    match action {
        ACTION_ASSIGN => {
            let gssi = gssi?;
            let name = match name {
                Some(name) => Some(encode_mnemonic_name(name)?),
                None => None,
            };
            buffer.write_bits(ASSIGN, 5);
            buffer.write_bits(1, 5); // Number of groups
            buffer.write_bits(gssi as u64, 24);
            buffer.write_bits(0, 1); // no group extension
            // Attach the newly assigned group immediately as a normal group.
            // TTR 001-03 table 14 prescribes the exact pairing `001` + class
            // `000` for this case.  Mode `000` is the permanently attached,
            // always-scanned profile from table 13 and requires class `111`;
            // combining it with class `000` makes interoperable terminals
            // silently discard the complete ASSIGN PDU.
            buffer.write_bits(0b001, 3); // attached; re-attach at next ITSI attach
            buffer.write_bit(1); // group-assignment O-bit: class of usage present
            buffer.write_bit(1); // class of usage present
            buffer.write_bits(0b000, 3); // class of usage 1
            buffer.write_bit(u8::from(name.is_some())); // mnemonic name present
            if let Some(name) = name {
                buffer.write_bits(1, 7); // ISO/IEC 8859-1
                buffer.write_bits((name.len() * 8) as u64, 8);
                for byte in name {
                    buffer.write_bits(u64::from(byte), 8);
                }
            }
            buffer.write_bit(u8::from(gck_select_number.is_some()));
            if let Some(gck_select_number) = gck_select_number {
                // EN 300 392-12-22 table 59 encodes this length as N - 1:
                // 000000 means one bit and 111111 means 64 bits. TTR 001-11
                // tables 12/13 define a 19-bit payload here, so the on-air
                // value must be 18. Writing 19 makes the MS consume the next
                // Type-2 P-bit as a twentieth security bit and shifts every
                // remaining field, causing the complete ASSIGN to be ignored.
                buffer.write_bits(19 - 1, 6);
                buffer.write_bit(1);
                buffer.write_bits(gck_select_number, 17);
                buffer.write_bit(0);
            }
            buffer.write_bit(0); // additional group information absent
            buffer.write_bit(0); // V-GSSI absent
            buffer.write_bit(1); // acknowledgement requested
            buffer.write_bit(0); // no optional PDU fields
        }
        ACTION_DEASSIGN => {
            buffer.write_bits(DEASSIGN, 5);
            buffer.write_bits(1, 5); // Number of groups in deassign request
            buffer.write_bits(gssi? as u64, 24);
            buffer.write_bit(0); // no group extension
            buffer.write_bit(1); // acknowledgement requested
            buffer.write_bit(0); // no optional PDU fields
        }
        ACTION_INTERROGATE => {
            buffer.write_bits(INTERROGATE_MS_GROUPS, 5);
            buffer.write_bits(0b001, 3); // DGNA groups only
            // ETSI encodes this field in tens: value 10 requests the maximum
            // 100 groups, so fragmented replies can provide the full inventory.
            buffer.write_bits(10, 7);
            buffer.write_bit(0); // affected-user identity absent
        }
        _ => return None,
    }
    let bits = buffer.get_len();
    let mut raw = vec![0; bits.div_ceil(8)];
    buffer.seek(0);
    buffer.read_bits_into_slice(bits, &mut raw)?;
    Some((raw, u16::try_from(bits).ok()?))
}

fn encode_mnemonic_name(name: &str) -> Option<Vec<u8>> {
    if name.is_empty() || name.chars().count() > 15 {
        return None;
    }
    let bytes = name
        .chars()
        .map(|character| u8::try_from(character as u32).ok())
        .collect::<Option<Vec<_>>>()?;
    (!bytes.is_empty() && bytes.len() <= 15).then_some(bytes)
}

fn decode_dgna(raw: &[u8], bits: u16) -> Option<DecodedDgna> {
    if raw.len() < usize::from(bits).div_ceil(8) || usize::from(bits) < 12 {
        return None;
    }
    let mut buffer = BitBuffer::from_vec(raw.to_vec());
    if buffer.read_bits(6)? != SS_DGNA {
        return None;
    }
    match buffer.read_bits(5)? {
        ASSIGN_ACK => decode_assign_ack(&mut buffer, bits),
        DEASSIGN_ACK => decode_deassign_ack(&mut buffer, bits),
        INTERROGATE_MS_GROUPS_ACK => decode_interrogate_ack(&mut buffer, bits),
        _ => None,
    }
}

fn decode_assign_ack(buffer: &mut BitBuffer, bits: u16) -> Option<DecodedDgna> {
    let count = buffer.read_bits(5)?;
    if count != 1 {
        return None;
    }
    let gssi = buffer.read_bits(24)? as u32;
    if buffer.read_bits(1)? != 0 {
        return None;
    }
    let result = buffer.read_bits(2)? as u8;
    let _attachment = buffer.read_bits(1)?;
    if buffer.read_bits(1)? != 0 || buffer.get_pos() != usize::from(bits) {
        return None;
    }
    Some(DecodedDgna {
        action: ACTION_ASSIGN,
        success: result == 1,
        cause: result,
        gssi: Some(gssi),
        groups: Vec::new(),
        complete: true,
        sequence: None,
    })
}

fn decode_deassign_ack(buffer: &mut BitBuffer, bits: u16) -> Option<DecodedDgna> {
    let count = buffer.read_bits(5)?;
    if count != 1 {
        return None;
    }
    let gssi = buffer.read_bits(24)? as u32;
    if buffer.read_bits(1)? != 0 {
        return None;
    }
    let result = buffer.read_bits(2)? as u8;
    let complete = buffer.read_bits(1)? != 0;
    if buffer.read_bits(1)? != 0 || buffer.get_pos() != usize::from(bits) {
        return None;
    }
    Some(DecodedDgna {
        action: ACTION_DEASSIGN,
        success: result == 1 && complete,
        cause: result,
        gssi: Some(gssi),
        groups: Vec::new(),
        complete,
        sequence: None,
    })
}

fn decode_interrogate_ack(buffer: &mut BitBuffer, bits: u16) -> Option<DecodedDgna> {
    if buffer.read_bits(3)? != 0b001 {
        return None;
    }
    let result = buffer.read_bits(3)? as u8;
    let complete = buffer.read_bits(1)? != 0;
    let has_optional = buffer.read_bits(1)? != 0;
    let mut groups = Vec::new();
    let mut sequence = None;
    if has_optional {
        let has_count = buffer.read_bits(1)? != 0;
        if has_count {
            let count = buffer.read_bits(5)? as usize;
            for _ in 0..count {
                let gssi = buffer.read_bits(24)? as u32;
                if buffer.read_bits(1)? != 0 {
                    return None;
                }
                let status = buffer.read_bits(3)? as u8;
                groups.push(DgnaObservedGroup { gssi, status, name: None });
            }
        }
        let has_sequence = buffer.read_bits(1)? != 0;
        if has_sequence {
            sequence = Some(buffer.read_bits(6)? as u8);
        }
        if buffer.read_bits(1)? != 0 {
            // An affected-user identity is legal only when it differs from the
            // receiving ITSI; this individual query does not need it.
            return None;
        }
        if buffer.read_bits(1)? != 0 {
            return None;
        }
    }
    if buffer.get_pos() != usize::from(bits) {
        return None;
    }
    Some(DecodedDgna {
        action: ACTION_INTERROGATE,
        success: result == 1,
        cause: result,
        gssi: None,
        groups,
        complete,
        sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_waiting_requests_use_exact_stage_3_type_1_lengths() {
        for (operation, bits) in [(CW_ACTIVATE, 11), (CW_DEACTIVATE, 11), (CW_INVOKE, 11), (CW_LOCATION_CHANGE, 14)] {
            let mut encoded = BitBuffer::new_autoexpand(bits);
            encoded.write_bits(SS_CALL_WAITING, 6);
            encoded.write_bits(u64::from(operation), 5);
            if operation == CW_LOCATION_CHANGE {
                encoded.write_bits(2, 3);
            }
            let (raw, encoded_bits) = bitbuffer_bytes(encoded).expect("encode SS-CW request");
            let decoded = decode_call_waiting(&raw, encoded_bits).expect("decode SS-CW request");
            assert_eq!(decoded.operation, operation);
            assert_eq!(decoded.waiting_calls, u8::from(operation == CW_LOCATION_CHANGE) * 2);

            let mut malformed = BitBuffer::from_vec(raw);
            malformed.seek(usize::from(encoded_bits));
            malformed.write_bit(0);
            let (raw, malformed_bits) = bitbuffer_bytes(malformed).expect("encode malformed request");
            assert!(
                decode_call_waiting(&raw, malformed_bits).is_none(),
                "type-1-only SS-CW PDU must reject a trailing bit"
            );
        }
    }

    #[test]
    fn unsupported_call_forwarding_request_gets_generic_ss_response() {
        let request = [0x12, 0x64, 0x00, 0x00];
        assert_eq!(decode_ss_header(&request, 31), Some((0b000100, 0b10011)));

        let (response, bits) = encode_ss_not_supported(0b000100);
        assert_eq!(bits, 11);
        let mut encoded = BitBuffer::from_vec(response);
        assert_eq!(encoded.read_bits(6), Some(0b000100));
        assert_eq!(encoded.read_bits(5), Some(0));
    }

    #[test]
    fn call_waiting_responses_match_stage_3_tables() {
        for (operation, accepted, active, cause, expected_tail) in [
            (CW_ACTIVATE_ACK, true, true, 0, 0b11),
            (CW_DEACTIVATE_ACK, true, false, 0, 0b10),
            (CW_ACTIVATE_ACK, false, false, 1, 0b01),
            (CW_LOCATION_CHANGE_ACK, true, true, 0, 0b00),
        ] {
            let (raw, bits) = encode_call_waiting_response(operation, accepted, active, cause, 0).expect("encode SS-CW response");
            assert_eq!(bits, 13);
            let mut encoded = BitBuffer::from_vec(raw);
            assert_eq!(encoded.read_bits(6), Some(SS_CALL_WAITING));
            assert_eq!(encoded.read_bits(5), Some(u64::from(operation)));
            assert_eq!(encoded.read_bits(2), Some(expected_tail));
            assert_eq!(encoded.get_pos(), usize::from(bits));
        }

        for cause in 0..=3 {
            let (raw, bits) = encode_call_waiting_invocation_failure(cause).expect("encode SS-CW invocation failure");
            assert_eq!(bits, 13);
            let mut encoded = BitBuffer::from_vec(raw);
            assert_eq!(encoded.read_bits(6), Some(SS_CALL_WAITING));
            assert_eq!(encoded.read_bits(5), Some(u64::from(CW_INVOCATION_FAILURE)));
            assert_eq!(encoded.read_bits(2), Some(u64::from(cause)));
            assert_eq!(encoded.get_pos(), usize::from(bits));
        }
    }

    #[test]
    fn sc3g_assignment_encodes_security_length_before_gck_association() {
        let gssi = 1301;
        let gck_select_number = 2;
        let (raw, bits) = encode_dgna(ACTION_ASSIGN, Some(gssi), None, Some(gck_select_number)).expect("encode DGNA assignment");
        assert_eq!(bits, 80);

        let mut encoded = BitBuffer::from_vec(raw);
        assert_eq!(encoded.read_bits(6), Some(SS_DGNA));
        assert_eq!(encoded.read_bits(5), Some(ASSIGN));
        assert_eq!(encoded.read_bits(5), Some(1));
        assert_eq!(encoded.read_bits(24), Some(gssi as u64));
        assert_eq!(encoded.read_bits(1), Some(0)); // group extension
        assert_eq!(encoded.read_bits(3), Some(0b001)); // attached normal group
        assert_eq!(encoded.read_bits(1), Some(1)); // optional fields follow
        assert_eq!(encoded.read_bits(1), Some(1)); // class of usage present
        assert_eq!(encoded.read_bits(3), Some(0));
        assert_eq!(encoded.read_bits(1), Some(0)); // mnemonic absent
        assert_eq!(encoded.read_bits(1), Some(1)); // security length present
        assert_eq!(encoded.read_bits(6), Some(18)); // 19 payload bits, encoded N - 1
        assert_eq!(encoded.read_bits(1), Some(1)); // GCK association
        assert_eq!(encoded.read_bits(17), Some(gck_select_number));
        assert_eq!(encoded.read_bits(1), Some(0)); // SCK association absent
        assert_eq!(encoded.read_bits(1), Some(0)); // additional info absent
        assert_eq!(encoded.read_bits(1), Some(0)); // V-GSSI absent
        assert_eq!(encoded.read_bits(1), Some(1)); // ACK requested
        assert_eq!(encoded.read_bits(1), Some(0)); // no PDU optionals
        assert_eq!(encoded.get_pos(), usize::from(bits));
    }

    #[test]
    fn cck_assignment_omits_unsupported_gck_association() {
        let (raw, bits) = encode_dgna(ACTION_ASSIGN, Some(1302), None, None).expect("encode CCK DGNA assignment");
        assert_eq!(bits, 55);

        let mut encoded = BitBuffer::from_vec(raw);
        assert_eq!(encoded.read_bits(6), Some(SS_DGNA));
        assert_eq!(encoded.read_bits(5), Some(ASSIGN));
        assert_eq!(encoded.read_bits(5), Some(1));
        assert_eq!(encoded.read_bits(24), Some(1302));
        assert_eq!(encoded.read_bits(1), Some(0)); // group extension
        assert_eq!(encoded.read_bits(3), Some(0b001));
        assert_eq!(encoded.read_bits(1), Some(1)); // optional fields follow
        assert_eq!(encoded.read_bits(1), Some(1)); // class of usage present
        assert_eq!(encoded.read_bits(3), Some(0));
        assert_eq!(encoded.read_bits(1), Some(0)); // mnemonic absent
        assert_eq!(encoded.read_bits(1), Some(0)); // no GCK association: use CCK
        assert_eq!(encoded.read_bits(1), Some(0)); // additional info absent
        assert_eq!(encoded.read_bits(1), Some(0)); // V-GSSI absent
        assert_eq!(encoded.read_bits(1), Some(1)); // ACK requested
        assert_eq!(encoded.read_bits(1), Some(0)); // no PDU optionals
        assert_eq!(encoded.get_pos(), usize::from(bits));
    }

    #[test]
    fn live_named_sc3g_assignment_keeps_all_following_fields_aligned() {
        let (raw, bits) = encode_dgna(ACTION_ASSIGN, Some(1301), Some("Intern 1"), Some(3)).expect("encode named SC3G assignment");
        assert_eq!(bits, 159);

        let mut encoded = BitBuffer::from_vec(raw);
        assert_eq!(encoded.read_bits(6), Some(SS_DGNA));
        assert_eq!(encoded.read_bits(5), Some(ASSIGN));
        assert_eq!(encoded.read_bits(5), Some(1));
        assert_eq!(encoded.read_bits(24), Some(1301));
        assert_eq!(encoded.read_bits(1), Some(0));
        assert_eq!(encoded.read_bits(3), Some(0b001));
        assert_eq!(encoded.read_bits(1), Some(1));
        assert_eq!(encoded.read_bits(1), Some(1));
        assert_eq!(encoded.read_bits(3), Some(0));
        assert_eq!(encoded.read_bits(1), Some(1)); // mnemonic present
        assert_eq!(encoded.read_bits(7), Some(1));
        assert_eq!(encoded.read_bits(8), Some(64));
        for byte in b"Intern 1" {
            assert_eq!(encoded.read_bits(8), Some(u64::from(*byte)));
        }
        assert_eq!(encoded.read_bits(1), Some(1)); // security length present
        assert_eq!(encoded.read_bits(6), Some(18)); // 19-bit payload
        assert_eq!(encoded.read_bits(1), Some(1));
        assert_eq!(encoded.read_bits(17), Some(3));
        assert_eq!(encoded.read_bits(1), Some(0));
        assert_eq!(encoded.read_bits(1), Some(0)); // additional info absent
        assert_eq!(encoded.read_bits(1), Some(0)); // V-GSSI absent
        assert_eq!(encoded.read_bits(1), Some(1)); // ACK requested
        assert_eq!(encoded.read_bits(1), Some(0)); // no PDU optionals
        assert_eq!(encoded.get_pos(), usize::from(bits));
    }
}
