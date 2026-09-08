use tetra_core::typed_pdu_fields::delimiters;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;

pub const MODIFY_REJECT_REQUESTED_QOS_NOT_AVAILABLE: u8 = 26;
pub const MODIFY_REJECT_PRIMARY_PDP_CONTEXT_DOES_NOT_EXIST: u8 = 28;
pub const MODIFY_REJECT_SNDCP_SERVICE_TEMPORARILY_NOT_AVAILABLE: u8 = 34;
pub const PDP_CONTEXT_AVAILABLE: u8 = 0;
pub const PDP_CONTEXT_SCHEDULE_SUSPENDED: u8 = 1;
pub const PDP_CONTEXT_USAGE_SCHEDULE_PAUSED: u8 = 0;
pub const PDP_CONTEXT_USAGE_CONTEXT_PAUSED: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnModifySubType {
    Request = 0,
    Response = 1,
    Availability = 3,
    Usage = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnModifyPdpContextRequest {
    pub nsapi: u8,
    pub qos_len_bits: usize,
    pub qos: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnModifyPdpContextResponse {
    pub nsapi: u8,
    pub modification_rejected: bool,
    pub modification_reject_cause: Option<u8>,
    pub pdu_priority_max: Option<u8>,
    pub qos_len_bits: usize,
    pub qos: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnModifyPdpContextAvailability {
    pub nsapi: u8,
    pub pdp_context_availability: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnModifyPdpContextUsage {
    pub nsapi: u8,
    pub pdp_context_usage: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnModify {
    Request(SnModifyPdpContextRequest),
    Response(SnModifyPdpContextResponse),
    Availability(SnModifyPdpContextAvailability),
    Usage(SnModifyPdpContextUsage),
}

impl TryFrom<u64> for SnModifySubType {
    type Error = PduParseErr;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SnModifySubType::Request),
            1 => Ok(SnModifySubType::Response),
            3 => Ok(SnModifySubType::Availability),
            4 => Ok(SnModifySubType::Usage),
            found => Err(PduParseErr::InvalidElemId { found }),
        }
    }
}

impl SnModifySubType {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

fn validate_nsapi(nsapi: u8) -> Result<(), PduParseErr> {
    if (1..=14).contains(&nsapi) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "nsapi",
            value: nsapi as u64,
        })
    }
}

fn validate_three_bit(field: &'static str, value: u8) -> Result<(), PduParseErr> {
    if value <= 7 {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field,
            value: value as u64,
        })
    }
}

fn read_raw_bits(buffer: &mut BitBuffer, field: &'static str) -> Result<(usize, Vec<u8>), PduParseErr> {
    let len_bits = buffer.get_len_remaining();
    let mut data = vec![0; len_bits.div_ceil(8)];
    buffer
        .read_bits_into_slice(len_bits, &mut data)
        .ok_or(PduParseErr::BufferEnded { field: Some(field) })?;
    Ok((len_bits, data))
}

fn write_raw_bits(buffer: &mut BitBuffer, len_bits: usize, data: &[u8]) -> Result<(), PduParseErr> {
    if data.len() * 8 < len_bits {
        return Err(PduParseErr::InconsistentLength {
            expected: len_bits.div_ceil(8),
            found: data.len(),
        });
    }

    let mut src = BitBuffer::from_bytes(data);
    buffer.copy_bits(&mut src, len_bits);
    Ok(())
}

fn skip_usage_reserved(buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    let obit = delimiters::read_obit(buffer)?;
    if !obit {
        return Ok(());
    }

    if delimiters::read_pbit(buffer)? {
        buffer.seek_rel(9);
    }
    if delimiters::read_mbit(buffer)? {
        return Err(PduParseErr::InvalidTrailingMbitValue);
    }
    Ok(())
}

impl SnModify {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Modify)?;

        let sub_type = SnModifySubType::try_from(buffer.read_field(4, "modify_sub_type")?)?;
        match sub_type {
            SnModifySubType::Request => Ok(SnModify::Request(SnModifyPdpContextRequest::from_body(buffer)?)),
            SnModifySubType::Response => Ok(SnModify::Response(SnModifyPdpContextResponse::from_body(buffer)?)),
            SnModifySubType::Availability => Ok(SnModify::Availability(SnModifyPdpContextAvailability::from_body(buffer)?)),
            SnModifySubType::Usage => Ok(SnModify::Usage(SnModifyPdpContextUsage::from_body(buffer)?)),
        }
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::Modify.into_raw(), 4);
        match self {
            SnModify::Request(pdu) => {
                buffer.write_bits(SnModifySubType::Request.into_raw(), 4);
                pdu.to_body_bitbuf(buffer)
            }
            SnModify::Response(pdu) => {
                buffer.write_bits(SnModifySubType::Response.into_raw(), 4);
                pdu.to_body_bitbuf(buffer)
            }
            SnModify::Availability(pdu) => {
                buffer.write_bits(SnModifySubType::Availability.into_raw(), 4);
                pdu.to_body_bitbuf(buffer)
            }
            SnModify::Usage(pdu) => {
                buffer.write_bits(SnModifySubType::Usage.into_raw(), 4);
                pdu.to_body_bitbuf(buffer)
            }
        }
    }
}

impl SnModifyPdpContextRequest {
    fn from_body(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        validate_nsapi(nsapi)?;
        let (qos_len_bits, qos) = read_raw_bits(buffer, "qos")?;
        Ok(SnModifyPdpContextRequest { nsapi, qos_len_bits, qos })
    }

    fn to_body_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        buffer.write_bits(self.nsapi as u64, 4);
        write_raw_bits(buffer, self.qos_len_bits, &self.qos)
    }
}

impl SnModifyPdpContextResponse {
    fn from_body(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        validate_nsapi(nsapi)?;
        let modification_rejected = buffer.read_field(1, "modification_result")? != 0;
        if modification_rejected {
            let modification_reject_cause = Some(buffer.read_field(8, "modification_reject_cause")? as u8);
            return Ok(SnModifyPdpContextResponse {
                nsapi,
                modification_rejected,
                modification_reject_cause,
                pdu_priority_max: None,
                qos_len_bits: 0,
                qos: Vec::new(),
            });
        }

        let pdu_priority_max = Some(buffer.read_field(3, "pdu_priority_max")? as u8);
        let (qos_len_bits, qos) = read_raw_bits(buffer, "qos")?;
        Ok(SnModifyPdpContextResponse {
            nsapi,
            modification_rejected,
            modification_reject_cause: None,
            pdu_priority_max,
            qos_len_bits,
            qos,
        })
    }

    fn to_body_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        if self.modification_rejected {
            let Some(cause) = self.modification_reject_cause else {
                return Err(PduParseErr::Inconsistency {
                    field: "modification_reject_cause",
                    reason: "reject cause is present only when modification result is rejected",
                });
            };
            if self.pdu_priority_max.is_some() || self.qos_len_bits != 0 || !self.qos.is_empty() {
                return Err(PduParseErr::Inconsistency {
                    field: "qos",
                    reason: "PDU priority and QoS are present only when modification result is applied",
                });
            }
            buffer.write_bits(self.nsapi as u64, 4);
            buffer.write_bit(1);
            buffer.write_bits(cause as u64, 8);
            return Ok(());
        }

        let Some(pdu_priority_max) = self.pdu_priority_max else {
            return Err(PduParseErr::Inconsistency {
                field: "pdu_priority_max",
                reason: "PDU priority max is present when modification result is applied",
            });
        };
        validate_three_bit("pdu_priority_max", pdu_priority_max)?;
        if self.modification_reject_cause.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "modification_reject_cause",
                reason: "reject cause is present only when modification result is rejected",
            });
        }

        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bit(0);
        buffer.write_bits(pdu_priority_max as u64, 3);
        write_raw_bits(buffer, self.qos_len_bits, &self.qos)
    }
}

impl SnModifyPdpContextAvailability {
    fn from_body(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        validate_nsapi(nsapi)?;
        let pdp_context_availability = buffer.read_field(3, "pdp_context_availability")? as u8;
        Ok(SnModifyPdpContextAvailability {
            nsapi,
            pdp_context_availability,
        })
    }

    fn to_body_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        validate_three_bit("pdp_context_availability", self.pdp_context_availability)?;
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.pdp_context_availability as u64, 3);
        Ok(())
    }
}

impl SnModifyPdpContextUsage {
    fn from_body(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        validate_nsapi(nsapi)?;
        let pdp_context_usage = buffer.read_field(3, "pdp_context_usage")? as u8;
        skip_usage_reserved(buffer)?;
        Ok(SnModifyPdpContextUsage { nsapi, pdp_context_usage })
    }

    fn to_body_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        validate_three_bit("pdp_context_usage", self.pdp_context_usage)?;
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.pdp_context_usage as u64, 3);
        delimiters::write_obit(buffer, 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modify_request_keeps_raw_qos_bits() {
        let pdu = SnModify::Request(SnModifyPdpContextRequest {
            nsapi: 1,
            qos_len_bits: 8,
            qos: vec![0xaa],
        });

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "11010000000110101010");

        encoded.seek(0);
        let decoded = SnModify::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn modify_response_reject_layout() {
        let pdu = SnModify::Response(SnModifyPdpContextResponse {
            nsapi: 1,
            modification_rejected: true,
            modification_reject_cause: Some(26),
            pdu_priority_max: None,
            qos_len_bits: 0,
            qos: Vec::new(),
        });

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "110100010001100011010");

        encoded.seek(0);
        let decoded = SnModify::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn modify_response_accept_keeps_raw_qos_bits() {
        let pdu = SnModify::Response(SnModifyPdpContextResponse {
            nsapi: 1,
            modification_rejected: false,
            modification_reject_cause: None,
            pdu_priority_max: Some(4),
            qos_len_bits: 8,
            qos: vec![0xee],
        });

        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "110100010001010011101110");

        encoded.seek(0);
        let decoded = SnModify::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn modify_availability_layout() {
        let pdu = SnModify::Availability(SnModifyPdpContextAvailability {
            nsapi: 1,
            pdp_context_availability: 0,
        });

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "110100110001000");

        encoded.seek(0);
        let decoded = SnModify::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn modify_usage_layout() {
        let pdu = SnModify::Usage(SnModifyPdpContextUsage {
            nsapi: 1,
            pdp_context_usage: 1,
        });

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "1101010000010010");

        encoded.seek(0);
        let decoded = SnModify::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
