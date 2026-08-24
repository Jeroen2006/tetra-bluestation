use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// ETSI TS 100 392-2, 16.10.8a.  BlueStation records this carrier for the
/// SwMI; it never retunes its TMO radio to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmoCarrier {
    pub carrier_number: u16,
    pub frequency_band: Option<u8>,
    pub offset: Option<u8>,
    pub duplex_spacing: Option<u8>,
    pub normal_reverse: Option<bool>,
    pub reserved: Option<u8>,
}

impl DmoCarrier {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let carrier_number = buffer.read_field(12, "dmo_carrier_number")? as u16;
        let extended = buffer.read_field(1, "dmo_extended_carrier_numbering")? != 0;
        if !extended {
            return Ok(Self {
                carrier_number,
                frequency_band: None,
                offset: None,
                duplex_spacing: None,
                normal_reverse: None,
                reserved: None,
            });
        }
        Ok(Self {
            carrier_number,
            frequency_band: Some(buffer.read_field(4, "dmo_frequency_band")? as u8),
            offset: Some(buffer.read_field(2, "dmo_offset")? as u8),
            duplex_spacing: Some(buffer.read_field(3, "dmo_duplex_spacing")? as u8),
            normal_reverse: Some(buffer.read_field(1, "dmo_normal_reverse")? != 0),
            reserved: Some(buffer.read_field(2, "dmo_reserved")? as u8),
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.carrier_number > 0x0fff {
            return Err(PduParseErr::InvalidValue {
                field: "dmo_carrier_number",
                value: self.carrier_number as u64,
            });
        }
        let extended = self.frequency_band.is_some()
            || self.offset.is_some()
            || self.duplex_spacing.is_some()
            || self.normal_reverse.is_some()
            || self.reserved.is_some();
        if extended
            && (self.frequency_band.is_none()
                || self.offset.is_none()
                || self.duplex_spacing.is_none()
                || self.normal_reverse.is_none()
                || self.reserved.is_none())
        {
            return Err(PduParseErr::FieldNotPresent {
                field: Some("extended_dmo_carrier"),
            });
        }
        buffer.write_bits(self.carrier_number as u64, 12);
        buffer.write_bits(extended as u64, 1);
        if extended {
            buffer.write_bits(self.frequency_band.unwrap() as u64, 4);
            buffer.write_bits(self.offset.unwrap() as u64, 2);
            buffer.write_bits(self.duplex_spacing.unwrap() as u64, 3);
            buffer.write_bits(self.normal_reverse.unwrap() as u64, 1);
            buffer.write_bits(self.reserved.unwrap() as u64, 2);
        }
        Ok(())
    }
}
