use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnNotSupported {
    pub not_supported_sn_pdu_type: u8,
}

impl SnNotSupported {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::NotSupported)?;

        Ok(SnNotSupported {
            not_supported_sn_pdu_type: buffer.read_field(4, "not_supported_sn_pdu_type")? as u8,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.not_supported_sn_pdu_type > 15 {
            return Err(PduParseErr::InvalidValue {
                field: "not_supported_sn_pdu_type",
                value: self.not_supported_sn_pdu_type as u64,
            });
        }

        buffer.write_bits(SnPduType::NotSupported.into_raw(), 4);
        buffer.write_bits(self.not_supported_sn_pdu_type as u64, 4);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_supported_layout() {
        let pdu = SnNotSupported {
            not_supported_sn_pdu_type: SnPduType::Data.into_raw() as u8,
        };

        let mut encoded = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "10110101");

        encoded.seek(0);
        let decoded = SnNotSupported::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
