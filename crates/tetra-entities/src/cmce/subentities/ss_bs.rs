use std::collections::HashMap;

use crate::{MessageQueue, net_swmi::SwmiCmceEndpoint};
use tetra_config::bluestation::SharedConfig;
use tetra_core::{BitBuffer, Layer2Service, Sap, SsiType, TetraAddress, tetra_entities::TetraEntity};
use tetra_pdus::cmce::pdus::{d_facility::DFacility, u_facility::UFacility};
use tetra_saps::{SapMsg, SapMsgInner, lcmc::LcmcMleUnitdataReq};
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
        }
    }

    pub fn is_swmi_action(message: &SwmiMessage) -> bool {
        matches!(message, SwmiMessage::DgnaCommand { .. })
    }

    pub fn handle_swmi_action(&mut self, queue: &mut MessageQueue, message: SwmiMessage) {
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

    pub fn route_re_deliver(&mut self, _queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::LcmcMleUnitdataInd(prim) = &mut message.msg else {
            return;
        };
        let issi = prim.received_tetra_address.ssi;
        let Ok(facility) = UFacility::from_bitbuf(&mut prim.sdu) else {
            tracing::warn!(issi, "invalid U-FACILITY");
            return;
        };
        let Some(decoded) = decode_dgna(&facility.ss_pdu, facility.ss_pdu_bits) else {
            tracing::warn!(
                issi,
                ss_pdu_bits = facility.ss_pdu_bits,
                ss_pdu = ?facility.ss_pdu,
                "unsupported SS-DGNA PDU in U-FACILITY"
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
}

const SS_DGNA: u64 = 0b010110;
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
