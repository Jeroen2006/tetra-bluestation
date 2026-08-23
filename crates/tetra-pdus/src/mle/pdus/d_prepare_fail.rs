use core::fmt;

use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::mle::enums::mle_pdu_type_dl::MlePduTypeDl;

/// Representation of the D-PREPARE-FAIL PDU (Clause 18.4.1.4.3).
/// Upon receipt from the SwMI the message shall be used by the MS-MLE as a preparation failure, while announcing cell reselection to the old cell.
/// Response expected: -
/// Response to: U-PREPARE/U-PREPARE-DA

// note 1: The SDU may carry an MM registration PDU. The SDU is coded according to the MM protocol description. There shall be no P-bit in the PDU coding preceding the SDU information element.
#[derive(Debug, Clone)]
pub struct DPrepareFail {
    /// Type1, 2 bits, Fail cause
    pub fail_cause: u8,
    /// Conditional See note,
    pub sdu: Option<BitBuffer>,
}

impl DPrepareFail {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(3, "pdu_type")?;
        expect_pdu_type!(pdu_type, MlePduTypeDl::DPrepareFail)?;

        // Type1
        let fail_cause = buffer.read_field(2, "fail_cause")? as u8;
        let obit = delimiters::read_obit(buffer)?;
        let sdu = if obit {
            let bits = buffer.get_len_remaining().checked_sub(1).ok_or(PduParseErr::BufferEnded {
                field: Some("D-PREPARE-FAIL terminating M-bit"),
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

        Ok(DPrepareFail { fail_cause, sdu })
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        // PDU Type
        buffer.write_bits(MlePduTypeDl::DPrepareFail.into_raw(), 3);
        // Type1
        buffer.write_bits(self.fail_cause as u64, 2);
        delimiters::write_obit(buffer, self.sdu.is_some() as u8);
        if let Some(value) = &self.sdu {
            let mut value = value.clone();
            let bits = value.get_len_remaining();
            buffer.copy_bits(&mut value, bits);
        }
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for DPrepareFail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DPrepareFail {{ fail_cause: {:?} sdu: {:?} }}", self.fail_cause, self.sdu,)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_embedded_mm_sdu() {
        let mut sdu = BitBuffer::from_bitstr("010100111");
        sdu.seek(0);
        let pdu = DPrepareFail {
            fail_cause: 1,
            sdu: Some(sdu),
        };
        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).expect("serialize D-PREPARE-FAIL");
        encoded.seek(0);
        let decoded = DPrepareFail::from_bitbuf(&mut encoded).expect("parse D-PREPARE-FAIL");
        assert_eq!(decoded.fail_cause, 1);
        assert_eq!(decoded.sdu.expect("embedded MM SDU").to_bitstr(), "010100111");
    }
}
