use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UInformationProvide {
    pub ssi: u32,
    pub address_extension: Option<u32>,
    pub tei: Option<String>,
    pub model: Option<String>,
    pub hardware_version: Option<String>,
    pub software_version: Option<String>,
    pub ai_algorithms: Vec<u8>,
    pub further_information_follows: bool,
}

fn read_ascii(buffer: &mut BitBuffer, field: &'static str) -> Result<String, PduParseErr> {
    let length = buffer.read_field(8, field)? as usize;
    if !(1..=63).contains(&length) {
        return Err(PduParseErr::InvalidValue {
            field,
            value: length as u64,
        });
    }
    let bytes = (0..length)
        .map(|_| buffer.read_field(8, field).map(|value| value as u8))
        .collect::<Result<Vec<_>, _>>()?;
    if !bytes.iter().all(u8::is_ascii) {
        return Err(PduParseErr::InvalidValue { field, value: 0 });
    }
    String::from_utf8(bytes).map_err(|_| PduParseErr::InvalidValue { field, value: 0 })
}

fn read_tei(buffer: &mut BitBuffer) -> Result<String, PduParseErr> {
    let mut tei = String::with_capacity(15);
    for _ in 0..15 {
        let digit = buffer.read_field(4, "tei_digit")? as u8;
        if digit > 9 {
            return Err(PduParseErr::InvalidValue {
                field: "tei_digit",
                value: u64::from(digit),
            });
        }
        tei.push(char::from(b'0' + digit));
    }
    Ok(tei)
}

impl UInformationProvide {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UInformationProvide)?;
        let subtype = buffer.read_field(4, "information_provide_subtype")?;
        if subtype != 0 {
            return Err(PduParseErr::InvalidValue {
                field: "information_provide_subtype",
                value: subtype,
            });
        }
        let ssi = buffer.read_field(24, "ssi")? as u32;
        let address_extension = (buffer.read_field(1, "address_extension_present")? != 0)
            .then(|| buffer.read_field(24, "address_extension").map(|value| value as u32))
            .transpose()?;
        let tei = (buffer.read_field(1, "tei_present")? != 0).then(|| read_tei(buffer)).transpose()?;
        let model = (buffer.read_field(1, "model_present")? != 0)
            .then(|| read_ascii(buffer, "model"))
            .transpose()?;
        let hardware_version = (buffer.read_field(1, "hardware_version_present")? != 0)
            .then(|| read_ascii(buffer, "hardware_version"))
            .transpose()?;
        let software_version = (buffer.read_field(1, "software_version_present")? != 0)
            .then(|| read_ascii(buffer, "software_version"))
            .transpose()?;
        let ai_algorithms = if buffer.read_field(1, "ai_algorithms_present")? != 0 {
            let count = buffer.read_field(4, "ai_algorithm_count")? as usize;
            (0..count)
                .map(|_| buffer.read_field(4, "ksg_number").map(|value| value as u8))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        if buffer.read_field(1, "additional_information_present")? != 0 {
            let length = buffer.read_field(8, "additional_information_length")? as usize;
            if !(1..=63).contains(&length) {
                return Err(PduParseErr::InvalidValue {
                    field: "additional_information_length",
                    value: length as u64,
                });
            }
            for _ in 0..length {
                buffer.read_field(8, "additional_information")?;
            }
        }
        let further_information_follows = buffer.read_field(1, "further_information_follows")? != 0;
        let future = buffer.read_field(1, "future_information_present")?;
        if future != 0 {
            return Err(PduParseErr::InvalidValue {
                field: "future_information_present",
                value: future,
            });
        }
        if buffer.get_len_remaining() > 0 {
            let proprietary = buffer.read_field(1, "proprietary_obit")?;
            if proprietary != 0 {
                return Err(PduParseErr::NotImplemented {
                    field: Some("proprietary"),
                });
            }
        }
        Ok(Self {
            ssi,
            address_extension,
            tei,
            model,
            hardware_version,
            software_version,
            ai_algorithms,
            further_information_follows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requested_terminal_information() {
        let mut buffer = BitBuffer::new_autoexpand(256);
        buffer.write_bits(MmPduTypeUl::UInformationProvide.into_raw(), 4);
        buffer.write_bits(0, 4);
        buffer.write_bits(77_492, 24);
        buffer.write_bits(0, 1);
        buffer.write_bits(0, 1);
        for value in ["MTP850", "R2", "MR2025.1"] {
            buffer.write_bits(1, 1);
            buffer.write_bits(value.len() as u64, 8);
            for byte in value.bytes() {
                buffer.write_bits(u64::from(byte), 8);
            }
        }
        buffer.write_bits(0, 1);
        buffer.write_bits(0, 1);
        buffer.write_bits(0, 1);
        buffer.write_bits(0, 1);
        buffer.seek(0);
        let pdu = UInformationProvide::from_bitbuf(&mut buffer).unwrap();
        assert_eq!(pdu.model.as_deref(), Some("MTP850"));
        assert_eq!(pdu.hardware_version.as_deref(), Some("R2"));
        assert_eq!(pdu.software_version.as_deref(), Some("MR2025.1"));
    }
}
