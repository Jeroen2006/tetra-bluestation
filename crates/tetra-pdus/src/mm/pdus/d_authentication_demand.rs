use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DAuthenticationDemand {
    pub rand_1: [u8; 10],
    pub random_seed: [u8; 10],
}

impl DAuthenticationDemand {
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeDl::DAuthentication.into_raw(), 4);
        // Authentication sub-type DEMAND (A.1.1).
        buffer.write_bits(0, 2);
        for byte in self.rand_1.iter() {
            buffer.write_bits(*byte as u64, 8);
        }
        // RS is the fixed 80-bit Type-1 field in A.1.1.  The Type-3
        // proprietary form is only the optional extension form; putting its
        // header here shifts RS by 16 bits and causes MS implementations to
        // ignore the demand.
        for byte in self.random_seed.iter() {
            buffer.write_bits(*byte as u64, 8);
        }
        // A.1.1 also defines an optional Type-3 proprietary element.  Per
        // EN 300 392-2 14.7.0 an O-bit therefore follows the final Type-1
        // field even when that element is absent.  Omitting this bit produces
        // a 166-bit PDU that compliant MS implementations discard; the valid
        // no-proprietary form is 167 bits with O=0.
        buffer.write_bit(0);
        Ok(())
    }
}
