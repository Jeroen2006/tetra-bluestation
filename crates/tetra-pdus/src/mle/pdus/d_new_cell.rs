use core::fmt;

use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr, typed_pdu_fields::delimiters};

use crate::mle::enums::mle_pdu_type_dl::MlePduTypeDl;

/// D-NEW-CELL. Its optional MM SDU is a variable bit-length payload and has
/// no P-bit of its own; the final M-bit terminates the MLE PDU.
pub struct DNewCell {
    pub channel_command_valid: u8,
    pub sdu: Option<BitBuffer>,
}

impl DNewCell {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeDl::DNewCell)?;
        let channel_command_valid = buffer.read_field(2, "channel_command_valid")? as u8;
        let has_sdu = delimiters::read_obit(buffer)?;
        let sdu = if has_sdu {
            let bits = buffer.get_len_remaining().checked_sub(1).ok_or(PduParseErr::BufferEnded {
                field: Some("D-NEW-CELL terminating M-bit"),
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
        Ok(Self {
            channel_command_valid,
            sdu,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.channel_command_valid > 2 {
            return Err(PduParseErr::InvalidValue {
                field: "channel_command_valid",
                value: self.channel_command_valid as u64,
            });
        }
        buffer.write_bits(MlePduTypeDl::DNewCell.into_raw(), 3);
        buffer.write_bits(self.channel_command_valid as u64, 2);
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

impl fmt::Display for DNewCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNewCell {{ channel_command_valid: {:?} sdu_bits: {:?} }}",
            self.channel_command_valid,
            self.sdu.as_ref().map(BitBuffer::get_len_remaining)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_embedded_mm_sdu() {
        let mut sdu = BitBuffer::from_bitstr("010100111");
        sdu.seek(0);
        let pdu = DNewCell {
            channel_command_valid: 1,
            sdu: Some(sdu),
        };
        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).expect("serialize D-NEW-CELL");
        encoded.seek(0);
        let decoded = DNewCell::from_bitbuf(&mut encoded).expect("parse D-NEW-CELL");
        assert_eq!(decoded.channel_command_valid, 1);
        assert_eq!(decoded.sdu.expect("embedded MM SDU").to_bitstr(), "010100111");
    }
}
