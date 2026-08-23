use core::fmt;

use tetra_core::{
    BitBuffer, expect_pdu_type,
    pdu_parse_error::PduParseErr,
    typed_pdu_fields::{delimiters, typed},
};

use crate::mle::enums::mle_pdu_type_ul::MlePduTypeUl;

/// U-RESTORE. MCC/MNC/LA, when present, identify the *old* cell; the raw
/// CMCE U-CALL-RESTORE SDU has no preceding P-bit.
pub struct URestore {
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
    pub la: Option<u16>,
    pub sdu: Option<BitBuffer>,
}

impl URestore {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeUl::URestore)?;
        let obit = delimiters::read_obit(buffer)?;
        let mcc = typed::parse_type2_generic(obit, buffer, 10, "mcc")?.map(|value| value as u16);
        let mnc = typed::parse_type2_generic(obit, buffer, 14, "mnc")?.map(|value| value as u16);
        let la = typed::parse_type2_generic(obit, buffer, 14, "la")?.map(|value| value as u16);
        let sdu = if obit && buffer.get_len_remaining() > 1 {
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
        Ok(Self { mcc, mnc, la, sdu })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MlePduTypeUl::URestore.into_raw(), 3);
        let obit = self.mcc.is_some() || self.mnc.is_some() || self.la.is_some() || self.sdu.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }
        typed::write_type2_generic(obit, buffer, self.mcc.map(u64::from), 10);
        typed::write_type2_generic(obit, buffer, self.mnc.map(u64::from), 14);
        typed::write_type2_generic(obit, buffer, self.la.map(u64::from), 14);
        if let Some(sdu) = &self.sdu {
            let mut sdu = sdu.clone();
            let bits = sdu.get_len_remaining();
            buffer.copy_bits(&mut sdu, bits);
        }
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for URestore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "URestore {{ mcc: {:?} mnc: {:?} la: {:?} sdu_bits: {:?} }}",
            self.mcc,
            self.mnc,
            self.la,
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
        let pdu = URestore {
            mcc: Some(204),
            mnc: Some(123),
            la: Some(100),
            sdu: Some(sdu),
        };
        let mut encoded = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut encoded).expect("serialize U-RESTORE");
        encoded.seek(0);
        let decoded = URestore::from_bitbuf(&mut encoded).expect("parse U-RESTORE");
        assert_eq!(decoded.mcc, Some(204));
        assert_eq!(decoded.mnc, Some(123));
        assert_eq!(decoded.la, Some(100));
        assert_eq!(decoded.sdu.expect("embedded CMCE SDU").to_bitstr(), "101001011");
    }
}
