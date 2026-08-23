use core::fmt;

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr, typed_pdu_fields::delimiters};

use crate::mle::enums::mle_pdu_type_dl::MlePduTypeDl;

/// D-RESTORE-ACK carrying the mandatory CMCE D-CALL-RESTORE SDU on a
/// successful restoration.
pub struct DRestoreAck {
    pub sdu: Option<BitBuffer>,
}

impl DRestoreAck {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeDl::DRestoreAck)?;
        let has_sdu = delimiters::read_obit(buffer)?;
        let sdu = if has_sdu {
            let bits = buffer.get_len_remaining().checked_sub(1).ok_or(PduParseErr::BufferEnded {
                field: Some("D-RESTORE-ACK terminating M-bit"),
            })?;
            let mut result = BitBuffer::new_autoexpand(bits);
            result.copy_bits(buffer, bits);
            result.seek(0);
            Some(result)
        } else {
            None
        };
        if delimiters::read_mbit(buffer)? {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }
        Ok(Self { sdu })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MlePduTypeDl::DRestoreAck.into_raw(), 3);
        delimiters::write_obit(buffer, self.sdu.is_some() as u8);
        if let Some(sdu) = &self.sdu {
            let mut sdu = sdu.clone();
            let bits = sdu.get_len_remaining();
            buffer.copy_bits(&mut sdu, bits);
        }
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for DRestoreAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DRestoreAck {{ sdu_bits: {:?} }}",
            self.sdu.as_ref().map(BitBuffer::get_len_remaining)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_embedded_cmce_sdu() {
        let mut sdu = BitBuffer::from_bitstr("101001011");
        sdu.seek(0);
        let pdu = DRestoreAck { sdu: Some(sdu) };
        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).expect("serialize D-RESTORE-ACK");
        encoded.seek(0);
        let decoded = DRestoreAck::from_bitbuf(&mut encoded).expect("parse D-RESTORE-ACK");
        assert_eq!(decoded.sdu.expect("embedded CMCE SDU").to_bitstr(), "101001011");
    }
}
