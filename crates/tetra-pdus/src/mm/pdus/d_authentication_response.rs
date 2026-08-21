use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// D-AUTHENTICATION RESPONSE (ETSI EN 300 392-7 A.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DAuthenticationResponse {
    pub random_seed: [u8; 10],
    pub response_2: [u8; 4],
    pub mutual: bool,
    pub rand_1: Option<[u8; 10]>,
}

impl DAuthenticationResponse {
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeDl::DAuthentication.into_raw(), 4);
        // A.8.6: 01 = RESPONSE (10 is RESULT).
        buffer.write_bits(1, 2); // RESPONSE subtype
        for byte in self.random_seed {
            buffer.write_bits(byte as u64, 8);
        }
        for byte in self.response_2 {
            buffer.write_bits(byte as u64, 8);
        }
        buffer.write_bit(self.mutual as u8);
        if let Some(rand_1) = self.rand_1 {
            // RAND1 is the conditional fixed Type-1 field when mutual
            // authentication is requested.  The optional proprietary tail
            // follows it and is absent (O=0).
            for byte in rand_1 {
                buffer.write_bits(byte as u64, 8);
            }
            buffer.write_bit(0);
        } else {
            buffer.write_bit(0);
        }
        Ok(())
    }
}
