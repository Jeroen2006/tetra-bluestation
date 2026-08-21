use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DAuthenticationResult {
    pub success: bool,
    pub mutual: bool,
    pub response_2: Option<[u8; 4]>,
}

impl DAuthenticationResult {
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeDl::DAuthentication.into_raw(), 4);
        // Authentication sub-type RESULT (A.1.4), R1 and mutual flag.
        // A.8.6: 10 = RESULT (11 is REJECT).
        buffer.write_bits(2, 2);
        buffer.write_bits(self.success as u64, 1);
        buffer.write_bits(self.mutual as u64, 1);
        if let Some(response) = self.response_2 {
            // RES2 is the conditional fixed Type-1 field for mutual
            // authentication.  The optional proprietary tail follows it
            // and is absent (O=0).
            for byte in response {
                buffer.write_bits(byte as u64, 8);
            }
            buffer.write_bit(0);
        } else {
            buffer.write_bit(0);
        }
        Ok(())
    }
}
