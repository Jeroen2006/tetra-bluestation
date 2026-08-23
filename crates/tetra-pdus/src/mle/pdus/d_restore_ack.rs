use core::fmt;

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr, typed_pdu_fields::delimiters};

use crate::mle::enums::mle_pdu_type_dl::MlePduTypeDl;

/// D-RESTORE-ACK carrying the mandatory CMCE D-CALL-RESTORE SDU on a
/// successful restoration.
///
/// ETSI TS 100 392-2, table E.23 encodes the MLE O-bit as zero and places
/// the CMCE SDU immediately after it.  The embedded D-CALL-RESTORE PDU owns
/// its own terminating O-bit; D-RESTORE-ACK does not add an M-bit after it.
pub struct DRestoreAck {
    pub sdu: BitBuffer,
}

impl DRestoreAck {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeDl::DRestoreAck)?;
        // This is an O-bit for optional MLE elements, not a presence bit for
        // the mandatory CMCE restoration SDU.  Table E.23 fixes it to zero.
        if delimiters::read_obit(buffer)? {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }
        let bits = buffer.get_len_remaining();
        if bits == 0 {
            return Err(PduParseErr::BufferEnded {
                field: Some("D-RESTORE-ACK CMCE SDU"),
            });
        }
        let mut sdu = BitBuffer::new_autoexpand(bits);
        sdu.copy_bits(buffer, bits);
        sdu.seek(0);
        Ok(Self { sdu })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MlePduTypeDl::DRestoreAck.into_raw(), 3);
        // See table E.23: O-bit = 0, immediately followed by D-CALL RESTORE.
        delimiters::write_obit(buffer, 0);
        let mut sdu = self.sdu.clone();
        let bits = sdu.get_len_remaining();
        buffer.copy_bits(&mut sdu, bits);
        Ok(())
    }
}

impl fmt::Display for DRestoreAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DRestoreAck {{ sdu_bits: {:?} }}", self.sdu.get_len_remaining())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_embedded_cmce_sdu() {
        let mut sdu = BitBuffer::from_bitstr("101001011");
        sdu.seek(0);
        let pdu = DRestoreAck { sdu };
        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).expect("serialize D-RESTORE-ACK");
        assert_eq!(encoded.to_bitstr(), "1000101001011");
        encoded.seek(0);
        let decoded = DRestoreAck::from_bitbuf(&mut encoded).expect("parse D-RESTORE-ACK");
        assert_eq!(decoded.sdu.to_bitstr(), "101001011");
    }
}
