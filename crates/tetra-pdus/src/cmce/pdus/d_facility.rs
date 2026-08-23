use core::fmt;

use crate::cmce::enums::cmce_pdu_type_dl::CmcePduTypeDl;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

/// Representation of the D-FACILITY PDU (Clause 14.7.1.7).
/// This PDU shall be used to send call unrelated SS information.
/// Response expected: -
/// Response to: -

// note 1: Contents of this PDU shall be defined by SS protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DFacility {
    /// Raw SS PDU, packed most-significant-bit first. DGNA uses one SS PDU
    /// per D-FACILITY as required by ETSI TS 100 392-12-22.
    pub ss_pdu: Vec<u8>,
    pub ss_pdu_bits: u16,
}

impl DFacility {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(5, "pdu_type")?;
        expect_pdu_type!(pdu_type, CmcePduTypeDl::DFacility)?;

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
        buffer.write_bits(CmcePduTypeDl::DFacility.into_raw(), 5);
        buffer.write_bits(1, 4);
        buffer.write_bits(self.ss_pdu_bits as u64, 11);
        let mut source = BitBuffer::from_vec(self.ss_pdu.clone());
        buffer.copy_bits(&mut source, usize::from(self.ss_pdu_bits));
        buffer.write_bits(0, 1);
        Ok(())
    }
}

impl fmt::Display for DFacility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "DFacility {{ ss_pdu_bits: {} }}", self.ss_pdu_bits)
    }
}
