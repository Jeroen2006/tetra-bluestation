use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// ETSI EN 300 396-5, annex B.3.1 DM-MS address.
///
/// `mcc` and `mnc` are present only for a TSI.  Keeping the extension in the
/// wire type is important: an ISSI by itself is not globally unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DmMsAddress {
    pub ssi: u32,
    pub mcc: Option<u16>,
    pub mnc: Option<u16>,
}

impl DmMsAddress {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let is_tsi = buffer.read_field(1, "dm_ms_identity_address_type")? != 0;
        let ssi = buffer.read_field(24, "dm_ms_ssi")? as u32;
        let (mcc, mnc) = if is_tsi {
            (
                Some(buffer.read_field(10, "dm_ms_mcc")? as u16),
                Some(buffer.read_field(14, "dm_ms_mnc")? as u16),
            )
        } else {
            (None, None)
        };
        Ok(Self { ssi, mcc, mnc })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        let is_tsi = self.mcc.is_some() || self.mnc.is_some();
        if is_tsi && (self.mcc.is_none() || self.mnc.is_none()) {
            return Err(PduParseErr::FieldNotPresent {
                field: Some("dm_ms_address_extension"),
            });
        }
        if self.ssi > 0x00ff_ffff {
            return Err(PduParseErr::InvalidValue {
                field: "dm_ms_ssi",
                value: self.ssi as u64,
            });
        }
        buffer.write_bits(is_tsi as u64, 1);
        buffer.write_bits(self.ssi as u64, 24);
        if let (Some(mcc), Some(mnc)) = (self.mcc, self.mnc) {
            if mcc > 0x03ff || mnc > 0x3fff {
                return Err(PduParseErr::InvalidValue {
                    field: "dm_ms_address_extension",
                    value: ((mcc as u64) << 14) | mnc as u64,
                });
            }
            buffer.write_bits(mcc as u64, 10);
            buffer.write_bits(mnc as u64, 14);
        }
        Ok(())
    }
}
