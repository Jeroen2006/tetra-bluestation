use tetra_core::typed_pdu_fields::{delimiters, typed};
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::type34_elem_id_ul::MmType34ElemIdUl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UTeiProvide {
    pub tei: String,
    pub ssi: u32,
    pub address_extension: Option<u32>,
}

fn read_tei(buffer: &mut BitBuffer) -> Result<String, PduParseErr> {
    let mut value = String::with_capacity(15);
    for _ in 0..15 {
        let digit = buffer.read_field(4, "tei_digit")? as u8;
        if digit > 9 {
            return Err(PduParseErr::InvalidValue {
                field: "tei_digit",
                value: u64::from(digit),
            });
        }
        value.push(char::from(b'0' + digit));
    }
    Ok(value)
}

impl UTeiProvide {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UTeiProvide)?;
        let tei = read_tei(buffer)?;
        let ssi = buffer.read_field(24, "ssi")? as u32;
        let mut obit = delimiters::read_obit(buffer)?;
        let address_extension = typed::parse_type2_generic(obit, buffer, 24, "address_extension")?.map(|value| value as u32);
        let _proprietary = typed::parse_type3_generic(obit, buffer, MmType34ElemIdUl::Proprietary)?;
        if obit {
            obit = buffer.read_field(1, "trailing_mbit")? != 0;
            if obit {
                return Err(PduParseErr::InvalidTrailingMbitValue);
            }
        }
        Ok(Self {
            tei,
            ssi,
            address_extension,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fifteen_bcd_digits() {
        let mut bits = String::from("1001");
        for digit in "000123456789012".bytes() {
            bits.push_str(&format!("{:04b}", digit - b'0'));
        }
        bits.push_str(&format!("{:024b}0", 77_492));
        let mut buffer = BitBuffer::from_bitstr(&bits);
        let pdu = UTeiProvide::from_bitbuf(&mut buffer).unwrap();
        assert_eq!(pdu.tei, "000123456789012");
        assert_eq!(pdu.ssi, 77_492);
    }

    #[test]
    fn parses_type_two_address_extension() {
        let mut bits = String::from("1001");
        for digit in "000123456789012".bytes() {
            bits.push_str(&format!("{:04b}", digit - b'0'));
        }
        bits.push_str(&format!("{:024b}", 77_492));
        bits.push_str("11"); // optional fields present; address extension present
        bits.push_str(&format!("{:024b}", 204_2671));
        bits.push_str("0"); // no proprietary element / terminating m-bit
        let mut buffer = BitBuffer::from_bitstr(&bits);
        let pdu = UTeiProvide::from_bitbuf(&mut buffer).unwrap();
        assert_eq!(pdu.address_extension, Some(204_2671));
        assert_eq!(buffer.get_len_remaining(), 0);
    }
}
