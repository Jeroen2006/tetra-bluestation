use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnDataPrioritySubType {
    Acknowledgement = 0,
    Information = 1,
    Request = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataPriorityDetails {
    pub network_default_data_priority: u8,
    pub layer2_data_priority_lifetime: u8,
    pub layer2_data_priority_signalling_delay: u8,
    pub data_priority_random_access_delay_factor: u8,
    pub reserved: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataPriorityAcknowledgement {
    pub request_accepted: bool,
    pub details: SnDataPriorityDetails,
    pub ms_default_data_priority: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataPriorityInformation {
    pub details: SnDataPriorityDetails,
    pub ms_default_data_priority: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataPriorityRequest {
    pub request_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnDataPriority {
    Acknowledgement(SnDataPriorityAcknowledgement),
    Information(SnDataPriorityInformation),
    Request(SnDataPriorityRequest),
}

impl TryFrom<u64> for SnDataPrioritySubType {
    type Error = PduParseErr;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SnDataPrioritySubType::Acknowledgement),
            1 => Ok(SnDataPrioritySubType::Information),
            2 => Ok(SnDataPrioritySubType::Request),
            found => Err(PduParseErr::InvalidElemId { found }),
        }
    }
}

impl SnDataPrioritySubType {
    fn into_raw(self) -> u64 {
        self as u64
    }
}

impl SnDataPriorityDetails {
    fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        Ok(Self {
            network_default_data_priority: buffer.read_field(3, "network_default_data_priority")? as u8,
            layer2_data_priority_lifetime: buffer.read_field(6, "layer2_data_priority_lifetime")? as u8,
            layer2_data_priority_signalling_delay: buffer.read_field(3, "layer2_data_priority_signalling_delay")? as u8,
            data_priority_random_access_delay_factor: buffer.read_field(3, "data_priority_random_access_delay_factor")? as u8,
            reserved: buffer.read_field(9, "reserved")? as u16,
        })
    }

    fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.network_default_data_priority > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "network_default_data_priority",
                value: self.network_default_data_priority as u64,
            });
        }
        if self.layer2_data_priority_lifetime > 63 {
            return Err(PduParseErr::InvalidValue {
                field: "layer2_data_priority_lifetime",
                value: self.layer2_data_priority_lifetime as u64,
            });
        }
        if self.layer2_data_priority_signalling_delay > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "layer2_data_priority_signalling_delay",
                value: self.layer2_data_priority_signalling_delay as u64,
            });
        }
        if self.data_priority_random_access_delay_factor > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "data_priority_random_access_delay_factor",
                value: self.data_priority_random_access_delay_factor as u64,
            });
        }
        if self.reserved > 0x01ff {
            return Err(PduParseErr::InvalidValue {
                field: "reserved",
                value: self.reserved as u64,
            });
        }

        buffer.write_bits(self.network_default_data_priority as u64, 3);
        buffer.write_bits(self.layer2_data_priority_lifetime as u64, 6);
        buffer.write_bits(self.layer2_data_priority_signalling_delay as u64, 3);
        buffer.write_bits(self.data_priority_random_access_delay_factor as u64, 3);
        buffer.write_bits(self.reserved as u64, 9);
        Ok(())
    }
}

fn validate_ms_default_data_priority(value: u8) -> Result<(), PduParseErr> {
    if value <= 8 {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "ms_default_data_priority",
            value: value as u64,
        })
    }
}

impl SnDataPriority {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DataPriority)?;

        let sub_type = SnDataPrioritySubType::try_from(buffer.read_field(4, "data_priority_sub_type")?)?;
        match sub_type {
            SnDataPrioritySubType::Acknowledgement => {
                let request_accepted = buffer.read_field(1, "data_priority_request_result")? == 0;
                let details = SnDataPriorityDetails::from_bitbuf(buffer)?;
                let ms_default_data_priority = if request_accepted {
                    let value = buffer.read_field(4, "ms_default_data_priority")? as u8;
                    validate_ms_default_data_priority(value)?;
                    Some(value)
                } else {
                    None
                };
                Ok(SnDataPriority::Acknowledgement(SnDataPriorityAcknowledgement {
                    request_accepted,
                    details,
                    ms_default_data_priority,
                }))
            }
            SnDataPrioritySubType::Information => {
                let details = SnDataPriorityDetails::from_bitbuf(buffer)?;
                let ms_default_data_priority = if buffer.read_field(1, "ms_default_data_priority_flag")? != 0 {
                    let value = buffer.read_field(4, "ms_default_data_priority")? as u8;
                    validate_ms_default_data_priority(value)?;
                    Some(value)
                } else {
                    None
                };
                Ok(SnDataPriority::Information(SnDataPriorityInformation {
                    details,
                    ms_default_data_priority,
                }))
            }
            SnDataPrioritySubType::Request => Ok(SnDataPriority::Request(SnDataPriorityRequest {
                request_type: buffer.read_field(4, "data_priority_request_type")? as u8,
            })),
        }
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DataPriority.into_raw(), 4);
        match self {
            SnDataPriority::Acknowledgement(pdu) => {
                if pdu.request_accepted != pdu.ms_default_data_priority.is_some() {
                    return Err(PduParseErr::Inconsistency {
                        field: "ms_default_data_priority",
                        reason: "MS default data priority is present only when the request is accepted",
                    });
                }
                buffer.write_bits(SnDataPrioritySubType::Acknowledgement.into_raw(), 4);
                buffer.write_bit((!pdu.request_accepted) as u8);
                pdu.details.to_bitbuf(buffer)?;
                if let Some(value) = pdu.ms_default_data_priority {
                    validate_ms_default_data_priority(value)?;
                    buffer.write_bits(value as u64, 4);
                }
            }
            SnDataPriority::Information(pdu) => {
                buffer.write_bits(SnDataPrioritySubType::Information.into_raw(), 4);
                pdu.details.to_bitbuf(buffer)?;
                buffer.write_bit(pdu.ms_default_data_priority.is_some() as u8);
                if let Some(value) = pdu.ms_default_data_priority {
                    validate_ms_default_data_priority(value)?;
                    buffer.write_bits(value as u64, 4);
                }
            }
            SnDataPriority::Request(pdu) => {
                if pdu.request_type > 15 {
                    return Err(PduParseErr::InvalidValue {
                        field: "data_priority_request_type",
                        value: pdu.request_type as u64,
                    });
                }
                buffer.write_bits(SnDataPrioritySubType::Request.into_raw(), 4);
                buffer.write_bits(pdu.request_type as u64, 4);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details() -> SnDataPriorityDetails {
        SnDataPriorityDetails {
            network_default_data_priority: 2,
            layer2_data_priority_lifetime: 1,
            layer2_data_priority_signalling_delay: 0,
            data_priority_random_access_delay_factor: 0,
            reserved: 0,
        }
    }

    #[test]
    fn data_priority_request_layout() {
        let pdu = SnDataPriority::Request(SnDataPriorityRequest { request_type: 8 });
        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "110000101000");

        encoded.seek(0);
        let decoded = SnDataPriority::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_priority_ack_reject_layout() {
        let pdu = SnDataPriority::Acknowledgement(SnDataPriorityAcknowledgement {
            request_accepted: false,
            details: details(),
            ms_default_data_priority: None,
        });
        let mut encoded = BitBuffer::new_autoexpand(40);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "110000001010000001000000000000000");

        encoded.seek(0);
        let decoded = SnDataPriority::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_priority_information_with_ms_default_layout() {
        let pdu = SnDataPriority::Information(SnDataPriorityInformation {
            details: details(),
            ms_default_data_priority: Some(8),
        });
        let mut encoded = BitBuffer::new_autoexpand(40);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "1100000101000000100000000000000011000");

        encoded.seek(0);
        let decoded = SnDataPriority::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
