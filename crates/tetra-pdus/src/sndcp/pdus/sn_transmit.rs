use tetra_core::typed_pdu_fields::delimiters;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::pdus::nsapi_elements::{read_nsapi_type4_chain, validate_nsapi, write_nsapi_additional_type4};
use crate::sndcp::pdus::resource_request::SndcpResourceRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataTransmitRequest {
    pub nsapi: u8,
    pub logical_link_status: bool,
    pub enhanced_pi_4_dqpsk_service: bool,
    pub resource_request: Option<SndcpResourceRequest>,
    pub sndcp_network_endpoint_identifier: Option<u16>,
    pub nsapi_additional: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDataTransmitResponse {
    pub nsapi: u8,
    pub accept: bool,
    pub transmit_response_reject_cause: Option<u8>,
    pub sndcp_network_endpoint_identifier: Option<u16>,
    pub nsapi_additional: Vec<u8>,
}

impl SnDataTransmitRequest {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DataTransmitRequest)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let logical_link_status = buffer.read_field(1, "logical_link_status")? != 0;
        let enhanced_pi_4_dqpsk_service = buffer.read_field(1, "enhanced_pi_4_dqpsk_service")? != 0;
        let resource_request = if enhanced_pi_4_dqpsk_service {
            Some(SndcpResourceRequest::from_bitbuf(buffer)?)
        } else {
            None
        };

        let obit = delimiters::read_obit(buffer)?;
        let (sndcp_network_endpoint_identifier, nsapi_additional) = if obit {
            let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
            } else {
                None
            };
            let reserved_present = delimiters::read_pbit(buffer)?;
            if reserved_present {
                let _reserved = buffer.read_field(20, "reserved")?;
            }
            let (nsapi_additional, _) = read_nsapi_type4_chain(buffer)?;
            (sndcp_network_endpoint_identifier, nsapi_additional)
        } else {
            (None, Vec::new())
        };

        Ok(SnDataTransmitRequest {
            nsapi,
            logical_link_status,
            enhanced_pi_4_dqpsk_service,
            resource_request,
            sndcp_network_endpoint_identifier,
            nsapi_additional,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        if self.enhanced_pi_4_dqpsk_service != self.resource_request.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "resource_request",
                reason: "resource request presence must match enhanced pi/4-DQPSK service",
            });
        }

        buffer.write_bits(SnPduType::DataTransmitRequest.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bit(self.logical_link_status as u8);
        buffer.write_bit(self.enhanced_pi_4_dqpsk_service as u8);
        if let Some(resource_request) = &self.resource_request {
            resource_request.to_bitbuf(buffer)?;
        }

        for nsapi in &self.nsapi_additional {
            validate_nsapi(*nsapi)?;
        }

        let obit = self.sndcp_network_endpoint_identifier.is_some() || !self.nsapi_additional.is_empty();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.sndcp_network_endpoint_identifier.is_some() as u8);
            if let Some(value) = self.sndcp_network_endpoint_identifier {
                buffer.write_bits(value as u64, 16);
            }
            delimiters::write_pbit(buffer, 0);
            write_nsapi_additional_type4(buffer, &self.nsapi_additional)?;
            delimiters::write_mbit(buffer, 0);
        }
        Ok(())
    }
}

impl SnDataTransmitResponse {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DataTransmitResponse)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let accept = buffer.read_field(1, "accept")? != 0;
        let transmit_response_reject_cause = if accept {
            None
        } else {
            Some(buffer.read_field(8, "transmit_response_reject_cause")? as u8)
        };

        let obit = delimiters::read_obit(buffer)?;
        let (sndcp_network_endpoint_identifier, nsapi_additional) = if obit {
            let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
            } else {
                None
            };
            let (nsapi_additional, _) = read_nsapi_type4_chain(buffer)?;
            (sndcp_network_endpoint_identifier, nsapi_additional)
        } else {
            (None, Vec::new())
        };

        Ok(SnDataTransmitResponse {
            nsapi,
            accept,
            transmit_response_reject_cause,
            sndcp_network_endpoint_identifier,
            nsapi_additional,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        if self.accept != self.transmit_response_reject_cause.is_none() {
            return Err(PduParseErr::Inconsistency {
                field: "transmit_response_reject_cause",
                reason: "reject cause is present only when Accept/Reject is 0",
            });
        }

        buffer.write_bits(SnPduType::DataTransmitResponse.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bit(self.accept as u8);
        if let Some(cause) = self.transmit_response_reject_cause {
            buffer.write_bits(cause as u64, 8);
        }

        for nsapi in &self.nsapi_additional {
            validate_nsapi(*nsapi)?;
        }

        let obit = self.sndcp_network_endpoint_identifier.is_some() || !self.nsapi_additional.is_empty();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.sndcp_network_endpoint_identifier.is_some() as u8);
            if let Some(value) = self.sndcp_network_endpoint_identifier {
                buffer.write_bits(value as u64, 16);
            }
            write_nsapi_additional_type4(buffer, &self.nsapi_additional)?;
            delimiters::write_mbit(buffer, 0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_transmit_request_minimal_layout() {
        let pdu = SnDataTransmitRequest {
            nsapi: 1,
            logical_link_status: false,
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "01100001000");

        encoded.seek(0);
        let decoded = SnDataTransmitRequest::from_bitbuf(&mut encoded).unwrap();

        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_transmit_request_with_symmetric_resource_request_layout() {
        let pdu = SnDataTransmitRequest {
            nsapi: 1,
            logical_link_status: true,
            enhanced_pi_4_dqpsk_service: true,
            resource_request: Some(SndcpResourceRequest {
                asymmetric_connection: false,
                data_transfer_throughput: 0b110,
                uplink_or_symmetric_timeslots: 0,
                downlink_timeslots: None,
                full_phase_modulation_capability: 0,
                reserved: 0b11,
            }),
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "011000011101100000110");

        encoded.seek(0);
        let decoded = SnDataTransmitRequest::from_bitbuf(&mut encoded).unwrap();

        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_transmit_request_with_asymmetric_resource_request_layout() {
        let pdu = SnDataTransmitRequest {
            nsapi: 1,
            logical_link_status: true,
            enhanced_pi_4_dqpsk_service: true,
            resource_request: Some(SndcpResourceRequest {
                asymmetric_connection: true,
                data_transfer_throughput: 0b100,
                uplink_or_symmetric_timeslots: 0,
                downlink_timeslots: Some(1),
                full_phase_modulation_capability: 1,
                reserved: 0b11,
            }),
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "01100001111100000101110");

        encoded.seek(0);
        let decoded = SnDataTransmitRequest::from_bitbuf(&mut encoded).unwrap();

        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_transmit_response_accept_minimal_layout() {
        let pdu = SnDataTransmitResponse {
            nsapi: 1,
            accept: true,
            transmit_response_reject_cause: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "0111000110");

        encoded.seek(0);
        let decoded = SnDataTransmitResponse::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_transmit_response_reject_minimal_layout() {
        let pdu = SnDataTransmitResponse {
            nsapi: 1,
            accept: false,
            transmit_response_reject_cause: Some(1),
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "011100010000000010");

        encoded.seek(0);
        let decoded = SnDataTransmitResponse::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_transmit_request_with_nsapi_additional_layout() {
        let pdu = SnDataTransmitRequest {
            nsapi: 1,
            logical_link_status: false,
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: vec![2, 3],
        };

        let mut encoded = BitBuffer::new_autoexpand(48);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "011000010010010100000000100100000100010000011000");

        encoded.seek(0);
        let decoded = SnDataTransmitRequest::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn data_transmit_response_accept_with_nsapi_additional_layout() {
        let pdu = SnDataTransmitResponse {
            nsapi: 1,
            accept: true,
            transmit_response_reject_cause: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_additional: vec![2, 3],
        };

        let mut encoded = BitBuffer::new_autoexpand(48);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "0111000111010100000000100100000100010000011000");

        encoded.seek(0);
        let decoded = SnDataTransmitResponse::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
