use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// ETSI EN 300 392-7 Annex A.7.3, Table A.35a.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityDownlink {
    pub authentication_result: bool,
    pub tei_requested: bool,
    pub model_requested: bool,
    pub hardware_software_requested: bool,
    pub ai_algorithms_requested: bool,
}

impl SecurityDownlink {
    pub fn terminal_information_request() -> Self {
        Self {
            // Table A.39: one also means no authentication is in progress.
            authentication_result: true,
            tei_requested: true,
            model_requested: true,
            hardware_software_requested: true,
            ..Self::default()
        }
    }

    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let value = buffer.read_field(6, "security_downlink")?;
        if value & 1 != 0 {
            return Err(PduParseErr::InvalidValue {
                field: "security_downlink_reserved",
                value: 1,
            });
        }
        Ok(Self {
            authentication_result: value & 0b100000 != 0,
            tei_requested: value & 0b010000 != 0,
            model_requested: value & 0b001000 != 0,
            hardware_software_requested: value & 0b000100 != 0,
            ai_algorithms_requested: value & 0b000010 != 0,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        let value = (u64::from(self.authentication_result) << 5)
            | (u64::from(self.tei_requested) << 4)
            | (u64::from(self.model_requested) << 3)
            | (u64::from(self.hardware_software_requested) << 2)
            | (u64::from(self.ai_algorithms_requested) << 1);
        buffer.write_bits(value, 6);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_information_request_is_exactly_six_bits() {
        let mut encoded = BitBuffer::new_autoexpand(6);
        SecurityDownlink::terminal_information_request().to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "111100");
        encoded.seek(0);
        assert_eq!(
            SecurityDownlink::from_bitbuf(&mut encoded).unwrap(),
            SecurityDownlink::terminal_information_request()
        );
    }
}
