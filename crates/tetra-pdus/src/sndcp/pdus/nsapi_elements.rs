use tetra_core::typed_pdu_fields::delimiters;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

pub const TYPE34_ELEMENT_NSAPI_ADDITIONAL: u8 = 4;
pub const TYPE34_ELEMENT_NSAPI_FOR_RECONNECTION: u8 = 5;

const NSAPI_ADDITIONAL_BITS_PER_ELEMENT: usize = 6;
const NSAPI_FOR_RECONNECTION_BITS_PER_ELEMENT: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnNsapiForReconnection {
    pub nsapi: u8,
    pub data_to_send: bool,
}

pub fn validate_nsapi(nsapi: u8) -> Result<(), PduParseErr> {
    if (1..=14).contains(&nsapi) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "nsapi",
            value: nsapi as u64,
        })
    }
}

fn validate_type4_count(count: usize) -> Result<(), PduParseErr> {
    if (1..=63).contains(&count) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "type4_num_elems",
            value: count as u64,
        })
    }
}

fn skip_remaining_element_bits(buffer: &mut BitBuffer, element_id: u8, start_pos: usize, data_bits: usize) -> Result<(), PduParseErr> {
    let parsed_bits = buffer.get_pos().saturating_sub(start_pos);
    if parsed_bits > data_bits {
        return Err(PduParseErr::InconsistentLength {
            expected: data_bits,
            found: parsed_bits,
        });
    }
    if parsed_bits < data_bits {
        buffer.seek_rel((data_bits - parsed_bits) as isize);
        tracing::trace!(
            "SNDCP type4 element {} had {} trailing bit(s) after parsed sub-elements",
            element_id,
            data_bits - parsed_bits
        );
    }
    Ok(())
}

fn read_type4_header(buffer: &mut BitBuffer) -> Result<Option<(u8, usize, usize)>, PduParseErr> {
    if !delimiters::read_mbit(buffer)? {
        return Ok(None);
    }

    let element_id = buffer.read_field(4, "type4_element_id")? as u8;
    let len_bits = buffer.read_field(11, "type4_len_bits")? as usize;
    if len_bits < 6 {
        return Err(PduParseErr::InconsistentLength {
            expected: 6,
            found: len_bits,
        });
    }
    let num_elems = buffer.read_field(6, "type4_num_elems")? as usize;
    validate_type4_count(num_elems)?;
    Ok(Some((element_id, len_bits, num_elems)))
}

pub fn read_nsapi_type4_chain(buffer: &mut BitBuffer) -> Result<(Vec<u8>, Vec<SnNsapiForReconnection>), PduParseErr> {
    let mut additional = Vec::new();
    let mut reconnection = Vec::new();

    while let Some((element_id, len_bits, num_elems)) = read_type4_header(buffer)? {
        let data_bits = len_bits - 6;
        if buffer.get_len_remaining() < data_bits {
            return Err(PduParseErr::BufferEnded { field: Some("type4_data") });
        }
        let start_pos = buffer.get_pos();

        match element_id {
            TYPE34_ELEMENT_NSAPI_ADDITIONAL => {
                let expected = num_elems * NSAPI_ADDITIONAL_BITS_PER_ELEMENT;
                if data_bits != expected {
                    return Err(PduParseErr::InconsistentLength {
                        expected,
                        found: data_bits,
                    });
                }
                for _ in 0..num_elems {
                    let nsapi = buffer.read_field(4, "nsapi_additional")? as u8;
                    validate_nsapi(nsapi)?;
                    let reserved = buffer.read_field(2, "nsapi_additional_reserved")?;
                    if reserved != 0 {
                        return Err(PduParseErr::InvalidValue {
                            field: "nsapi_additional_reserved",
                            value: reserved,
                        });
                    }
                    additional.push(nsapi);
                }
            }
            TYPE34_ELEMENT_NSAPI_FOR_RECONNECTION => {
                let expected = num_elems * NSAPI_FOR_RECONNECTION_BITS_PER_ELEMENT;
                if data_bits != expected {
                    return Err(PduParseErr::InconsistentLength {
                        expected,
                        found: data_bits,
                    });
                }
                for _ in 0..num_elems {
                    let nsapi = buffer.read_field(4, "nsapi_for_reconnection")? as u8;
                    validate_nsapi(nsapi)?;
                    let data_to_send = buffer.read_field(1, "nsapi_for_reconnection_data_to_send")? != 0;
                    let reserved = buffer.read_field(1, "nsapi_for_reconnection_reserved")?;
                    if reserved != 0 {
                        return Err(PduParseErr::InvalidValue {
                            field: "nsapi_for_reconnection_reserved",
                            value: reserved,
                        });
                    }
                    reconnection.push(SnNsapiForReconnection { nsapi, data_to_send });
                }
            }
            _ => {
                buffer.seek_rel(data_bits as isize);
            }
        }

        skip_remaining_element_bits(buffer, element_id, start_pos, data_bits)?;
    }

    Ok((additional, reconnection))
}

pub fn write_nsapi_additional_type4(buffer: &mut BitBuffer, nsapis: &[u8]) -> Result<(), PduParseErr> {
    if nsapis.is_empty() {
        return Ok(());
    }
    validate_type4_count(nsapis.len())?;
    delimiters::write_mbit(buffer, 1);
    buffer.write_bits(TYPE34_ELEMENT_NSAPI_ADDITIONAL as u64, 4);
    buffer.write_bits((6 + nsapis.len() * NSAPI_ADDITIONAL_BITS_PER_ELEMENT) as u64, 11);
    buffer.write_bits(nsapis.len() as u64, 6);
    for nsapi in nsapis {
        validate_nsapi(*nsapi)?;
        buffer.write_bits(*nsapi as u64, 4);
        buffer.write_bits(0, 2);
    }
    Ok(())
}

pub fn write_nsapi_for_reconnection_type4(buffer: &mut BitBuffer, nsapis: &[SnNsapiForReconnection]) -> Result<(), PduParseErr> {
    if nsapis.is_empty() {
        return Ok(());
    }
    validate_type4_count(nsapis.len())?;
    delimiters::write_mbit(buffer, 1);
    buffer.write_bits(TYPE34_ELEMENT_NSAPI_FOR_RECONNECTION as u64, 4);
    buffer.write_bits((6 + nsapis.len() * NSAPI_FOR_RECONNECTION_BITS_PER_ELEMENT) as u64, 11);
    buffer.write_bits(nsapis.len() as u64, 6);
    for nsapi in nsapis {
        validate_nsapi(nsapi.nsapi)?;
        buffer.write_bits(nsapi.nsapi as u64, 4);
        buffer.write_bit(nsapi.data_to_send as u8);
        buffer.write_bit(0);
    }
    Ok(())
}
