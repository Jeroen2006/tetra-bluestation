use core::fmt;

use tetra_core::{
    BitBuffer, expect_pdu_type,
    pdu_parse_error::PduParseErr,
    typed_pdu_fields::{delimiters, typed},
};

use crate::mle::enums::mle_pdu_type_ul::MlePduTypeUl;

/// U-PREPARE for announced CA reselection. The optional SDU is a raw MM
/// registration payload (without another protocol discriminator/P-bit).
pub struct UPrepare {
    pub cell_identifier_ca: Option<u8>,
    pub sdu: Option<BitBuffer>,
}

impl UPrepare {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeUl::UPrepare)?;
        let obit = delimiters::read_obit(buffer)?;
        let cell_identifier_ca = typed::parse_type2_generic(obit, buffer, 5, "cell_identifier_ca")?.map(|value| value as u8);
        let sdu = if cell_identifier_ca.is_some() && buffer.get_len_remaining() > 1 {
            let bits = buffer.get_len_remaining() - 1;
            let mut result = BitBuffer::new_autoexpand(bits);
            result.copy_bits(buffer, bits);
            result.seek(0);
            Some(result)
        } else {
            None
        };
        if obit && delimiters::read_mbit(buffer)? {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }
        Ok(Self { cell_identifier_ca, sdu })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.cell_identifier_ca.is_none() && self.sdu.is_some() {
            return Err(PduParseErr::InvalidValue {
                field: "U-PREPARE SDU requires cell_identifier_ca",
                value: 0,
            });
        }
        buffer.write_bits(MlePduTypeUl::UPrepare.into_raw(), 3);
        let obit = self.cell_identifier_ca.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }
        typed::write_type2_generic(obit, buffer, self.cell_identifier_ca.map(u64::from), 5);
        if let Some(sdu) = &self.sdu {
            let mut sdu = sdu.clone();
            let bits = sdu.get_len_remaining();
            buffer.copy_bits(&mut sdu, bits);
        }
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for UPrepare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UPrepare {{ cell_identifier_ca: {:?} sdu_bits: {:?} }}",
            self.cell_identifier_ca,
            self.sdu.as_ref().map(BitBuffer::get_len_remaining)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_target_and_embedded_mm_sdu() {
        let mut sdu = BitBuffer::from_bitstr("001011010");
        sdu.seek(0);
        let pdu = UPrepare {
            cell_identifier_ca: Some(7),
            sdu: Some(sdu),
        };
        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).expect("serialize U-PREPARE");
        encoded.seek(0);
        let decoded = UPrepare::from_bitbuf(&mut encoded).expect("parse U-PREPARE");
        assert_eq!(decoded.cell_identifier_ca, Some(7));
        assert_eq!(decoded.sdu.expect("embedded MM SDU").to_bitstr(), "001011010");
    }
}
