use core::fmt;

use crate::cmce::enums::cmce_pdu_type_ul::CmcePduTypeUl;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

/// Representation of the U-FACILITY PDU (Clause 14.7.2.5).
/// This PDU shall be used to send call unrelated SS information.
/// Response expected: -
/// Response to: -

// note 1: Contents of this PDU shall be defined by SS protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UFacility {
    /// ETSI EN 300 392-9 routeing value. Zero addresses the current SwMI and
    /// one addresses the sending MS's home SwMI.
    pub routing: u8,
    pub ss_pdu: Vec<u8>,
    pub ss_pdu_bits: u16,
}

impl UFacility {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(5, "pdu_type")?;
        expect_pdu_type!(pdu_type, CmcePduTypeUl::UFacility)?;

        let routing = buffer.read_field(2, "routing")? as u8;
        if routing > 1 {
            return Err(PduParseErr::NotImplemented {
                field: Some("unsupported U-FACILITY routing"),
            });
        }
        let count = buffer.read_field(4, "number_ss_pdus")?;
        if count != 1 {
            return Err(PduParseErr::NotImplemented {
                field: Some("multiple SS PDUs"),
            });
        }
        let bits = buffer.read_field(11, "ss_pdu_length")? as usize;
        if bits == 0 {
            return Err(PduParseErr::InvalidValue {
                field: "ss_pdu_length",
                value: 0,
            });
        }
        let mut ss_pdu = vec![0; bits.div_ceil(8)];
        buffer
            .read_bits_into_slice(bits, &mut ss_pdu)
            .ok_or(PduParseErr::BufferEnded { field: Some("ss_pdu") })?;
        if buffer.read_field(1, "o_bit")? != 0 {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }
        Ok(Self {
            routing,
            ss_pdu,
            ss_pdu_bits: bits as u16,
        })
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.ss_pdu_bits == 0 || self.ss_pdu_bits > 0x07ff || self.ss_pdu.len() < usize::from(self.ss_pdu_bits).div_ceil(8) {
            return Err(PduParseErr::Inconsistency {
                field: "ss_pdu",
                reason: "invalid SS PDU length",
            });
        }
        buffer.write_bits(CmcePduTypeUl::UFacility.into_raw(), 5);
        if self.routing > 1 {
            return Err(PduParseErr::InvalidValue {
                field: "routing",
                value: u64::from(self.routing),
            });
        }
        buffer.write_bits(u64::from(self.routing), 2);
        buffer.write_bits(1, 4);
        buffer.write_bits(self.ss_pdu_bits as u64, 11);
        let mut source = BitBuffer::from_vec(self.ss_pdu.clone());
        buffer.copy_bits(&mut source, usize::from(self.ss_pdu_bits));
        buffer.write_bits(0, 1);
        Ok(())
    }
}

impl fmt::Display for UFacility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UFacility {{ routing: {}, ss_pdu_bits: {} }}", self.routing, self.ss_pdu_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_swmi_routing_roundtrips() {
        let facility = UFacility {
            routing: 1,
            ss_pdu: vec![0xab, 0xc0],
            ss_pdu_bits: 12,
        };
        let mut buffer = BitBuffer::new_autoexpand(64);
        facility.to_bitbuf(&mut buffer).expect("serialize U-FACILITY");
        buffer.seek(0);

        assert_eq!(UFacility::from_bitbuf(&mut buffer).expect("parse U-FACILITY"), facility);
    }

    #[test]
    fn unsupported_routing_is_rejected() {
        let facility = UFacility {
            routing: 2,
            ss_pdu: vec![0x80],
            ss_pdu_bits: 1,
        };
        assert!(facility.to_bitbuf(&mut BitBuffer::new_autoexpand(32)).is_err());
    }
}
