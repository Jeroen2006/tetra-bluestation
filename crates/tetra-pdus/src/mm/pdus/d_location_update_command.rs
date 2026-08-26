use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::typed_pdu_fields::*;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;

/// Representation of the D-LOCATION UPDATE COMMAND PDU (Clause 16.9.2.8).
/// The infrastructure sends this message to the MS to initiate a location update demand in the MS.
/// Response expected: U-LOCATION UPDATE DEMAND
/// Response to: -

// note 1: Ciphering parameters element is not present if Cipher control is set to ‘0’ and is present if set to ‘1’.
#[derive(Debug)]
pub struct DLocationUpdateCommand {
    /// Type1, 1 bits, Group identity report
    pub group_identity_report: bool,
    /// Type1, 1 bits, Cipher control
    pub cipher_control: bool,
    /// Conditional 10 bits, Conditional: present only if Cipher control = 1 (on); absent if Cipher control = 0 (off),
    pub ciphering_parameters: Option<u64>,
    /// Type2, 24 bits, MNI of the MS,
    pub address_extension: Option<u64>,
    /// Conditional 3 bits, Cell type control
    pub cell_type_control: Option<u64>,
    /// Conditional 3 bits, Proprietary
    pub proprietary: Option<u64>,
}

impl DLocationUpdateCommand {
    /// Parse from BitBuffer
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeDl::DLocationUpdateCommand)?;

        // Type1
        let group_identity_report = buffer.read_field(1, "group_identity_report")? != 0;
        // Type1
        let cipher_control = buffer.read_field(1, "cipher_control")? != 0;
        // Conditional.  Ciphering parameters are present exactly when the
        // command requests ciphering on (EN 300 392-7, 16.9.2.8).
        let ciphering_parameters = cipher_control.then(|| buffer.read_field(10, "ciphering_parameters")).transpose()?;

        // obit designates presence of any further type2, type3 or type4 fields
        let mut obit = delimiters::read_obit(buffer)?;

        // Type2
        let address_extension = typed::parse_type2_generic(obit, buffer, 24, "address_extension")?;
        // Conditional Type-3 fields.  They appear in numerical order after
        // the Type-2 address extension and are followed by the terminating
        // M-bit when any optional element is present.
        let cell_type_control = typed::parse_type3_generic(obit, buffer, 13u64)?.map(|field| field.data);
        let proprietary = typed::parse_type3_generic(obit, buffer, 15u64)?.map(|field| field.data);

        // Read trailing obit (if not previously encountered)
        obit = if obit { buffer.read_field(1, "trailing_obit")? == 1 } else { obit };
        if obit {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }

        Ok(DLocationUpdateCommand {
            group_identity_report,
            cipher_control,
            ciphering_parameters,
            address_extension,
            cell_type_control,
            proprietary,
        })
    }

    /// Serialize this PDU into the given BitBuffer.
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.cipher_control != self.ciphering_parameters.is_some() {
            return Err(PduParseErr::InvalidValue {
                field: "ciphering_parameters",
                value: self.ciphering_parameters.unwrap_or_default(),
            });
        }
        // PDU Type
        buffer.write_bits(MmPduTypeDl::DLocationUpdateCommand.into_raw(), 4);
        // Type1
        buffer.write_bits(self.group_identity_report as u64, 1);
        // Type1
        buffer.write_bits(self.cipher_control as u64, 1);
        // Conditional
        if let Some(ref value) = self.ciphering_parameters {
            buffer.write_bits(*value, 10);
        }

        // Check if any optional field present and place o-bit
        let obit = self.address_extension.is_some() || self.cell_type_control.is_some() || self.proprietary.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if !obit {
            return Ok(());
        }

        // Type2
        typed::write_type2_generic(obit, buffer, self.address_extension, 24);

        // Conditional Type-3 fields.  Cell type control and proprietary are
        // three-bit payloads in this PDU, so construct their Type-3 headers
        // through the common writer rather than writing naked payload bits.
        let cell_type_control = self.cell_type_control.map(|data| Type3FieldGeneric {
            field_id: 13,
            len: 3,
            data,
            raw: Vec::new(),
        });
        typed::write_type3_generic(obit, buffer, &cell_type_control, 13u64)?;
        let proprietary = self.proprietary.map(|data| Type3FieldGeneric {
            field_id: 15,
            len: 3,
            data,
            raw: Vec::new(),
        });
        typed::write_type3_generic(obit, buffer, &proprietary, 15u64)?;
        // Write terminating m-bit
        delimiters::write_mbit(buffer, 0);
        Ok(())
    }
}

impl fmt::Display for DLocationUpdateCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DLocationUpdateCommand {{ group_identity_report: {:?} cipher_control: {:?} ciphering_parameters: {:?} address_extension: {:?} cell_type_control: {:?} proprietary: {:?} }}",
            self.group_identity_report,
            self.cipher_control,
            self.ciphering_parameters,
            self.address_extension,
            self.cell_type_control,
            self.proprietary,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphering_on_roundtrips() {
        let pdu = DLocationUpdateCommand {
            group_identity_report: false,
            cipher_control: true,
            ciphering_parameters: Some(0b10_0101_0110),
            address_extension: Some(0x12_3456),
            cell_type_control: Some(0b101),
            proprietary: Some(0b011),
        };
        let mut encoded = BitBuffer::new_autoexpand(96);
        pdu.to_bitbuf(&mut encoded).expect("serialize");
        encoded.seek(0);
        let decoded = DLocationUpdateCommand::from_bitbuf(&mut encoded).expect("parse");
        assert_eq!(decoded.group_identity_report, pdu.group_identity_report);
        assert_eq!(decoded.cipher_control, pdu.cipher_control);
        assert_eq!(decoded.ciphering_parameters, pdu.ciphering_parameters);
        assert_eq!(decoded.address_extension, pdu.address_extension);
        assert_eq!(decoded.cell_type_control, pdu.cell_type_control);
        assert_eq!(decoded.proprietary, pdu.proprietary);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn cipher_control_and_parameters_must_agree() {
        let pdu = DLocationUpdateCommand {
            group_identity_report: false,
            cipher_control: false,
            ciphering_parameters: Some(1),
            address_extension: None,
            cell_type_control: None,
            proprietary: None,
        };
        let mut encoded = BitBuffer::new_autoexpand(32);
        assert!(pdu.to_bitbuf(&mut encoded).is_err());
    }
}
