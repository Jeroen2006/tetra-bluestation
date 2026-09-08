use tetra_core::typed_pdu_fields::delimiters;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::pdus::resource_request::SndcpResourceRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnPageRequest {
    pub nsapi: u8,
    pub reply_requested: bool,
    pub sndcp_network_endpoint_identifier: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnPageResponse {
    pub nsapi: u8,
    pub pd_service_available: bool,
    pub logical_link_status: bool,
    pub enhanced_pi_4_dqpsk_service: bool,
    pub resource_request: Option<SndcpResourceRequest>,
    pub sndcp_network_endpoint_identifier: Option<u16>,
}

fn validate_nsapi(nsapi: u8) -> Result<(), PduParseErr> {
    if (1..=14).contains(&nsapi) {
        Ok(())
    } else {
        Err(PduParseErr::InvalidValue {
            field: "nsapi",
            value: nsapi as u64,
        })
    }
}

fn skip_type4_chain(buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    loop {
        if !delimiters::read_mbit(buffer)? {
            break;
        }
        let _element_id = buffer.read_field(4, "type4_element_id")?;
        let len_bits = buffer.read_field(11, "type4_len_bits")? as usize;
        let _num_elems = buffer.read_field(6, "type4_num_elems")?;
        if buffer.get_len_remaining() < len_bits.saturating_sub(6) {
            return Err(PduParseErr::BufferEnded { field: Some("type4_data") });
        }
        buffer.seek_rel(len_bits.saturating_sub(6) as isize);
    }
    Ok(())
}

impl SnPageRequest {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Page)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        validate_nsapi(nsapi)?;
        let reply_requested = buffer.read_field(1, "reply_requested")? != 0;
        let obit = delimiters::read_obit(buffer)?;
        let sndcp_network_endpoint_identifier = if obit {
            let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
            } else {
                None
            };
            skip_type4_chain(buffer)?;
            sndcp_network_endpoint_identifier
        } else {
            None
        };

        Ok(SnPageRequest {
            nsapi,
            reply_requested,
            sndcp_network_endpoint_identifier,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;

        buffer.write_bits(SnPduType::Page.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bit(self.reply_requested as u8);
        let obit = self.sndcp_network_endpoint_identifier.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.sndcp_network_endpoint_identifier.is_some() as u8);
            if let Some(value) = self.sndcp_network_endpoint_identifier {
                buffer.write_bits(value as u64, 16);
            }
            delimiters::write_mbit(buffer, 0);
        }
        Ok(())
    }
}

impl SnPageResponse {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Page)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        validate_nsapi(nsapi)?;
        let pd_service_available = buffer.read_field(1, "pd_service_status")? != 0;
        let logical_link_status = buffer.read_field(1, "logical_link_status")? != 0;
        let enhanced_pi_4_dqpsk_service = buffer.read_field(1, "enhanced_pi_4_dqpsk_service")? != 0;
        let resource_request = if enhanced_pi_4_dqpsk_service {
            Some(SndcpResourceRequest::from_bitbuf(buffer)?)
        } else {
            None
        };

        let obit = delimiters::read_obit(buffer)?;
        let sndcp_network_endpoint_identifier = if obit {
            let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
            } else {
                None
            };
            let reserved_present = delimiters::read_pbit(buffer)?;
            if reserved_present {
                buffer.seek_rel(18);
            }
            skip_type4_chain(buffer)?;
            sndcp_network_endpoint_identifier
        } else {
            None
        };

        Ok(SnPageResponse {
            nsapi,
            pd_service_available,
            logical_link_status,
            enhanced_pi_4_dqpsk_service,
            resource_request,
            sndcp_network_endpoint_identifier,
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

        buffer.write_bits(SnPduType::Page.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bit(self.pd_service_available as u8);
        buffer.write_bit(self.logical_link_status as u8);
        buffer.write_bit(self.enhanced_pi_4_dqpsk_service as u8);
        if let Some(resource_request) = &self.resource_request {
            resource_request.to_bitbuf(buffer)?;
        }

        let obit = self.sndcp_network_endpoint_identifier.is_some();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.sndcp_network_endpoint_identifier.is_some() as u8);
            if let Some(value) = self.sndcp_network_endpoint_identifier {
                buffer.write_bits(value as u64, 16);
            }
            delimiters::write_pbit(buffer, 0);
            delimiters::write_mbit(buffer, 0);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_minimal_layout() {
        let pdu = SnPageRequest {
            nsapi: 1,
            reply_requested: false,
            sndcp_network_endpoint_identifier: None,
        };

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "1010000100");

        encoded.seek(0);
        let decoded = SnPageRequest::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn page_response_minimal_layout() {
        let pdu = SnPageResponse {
            nsapi: 1,
            pd_service_available: true,
            logical_link_status: true,
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: None,
        };

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "101000011100");

        encoded.seek(0);
        let decoded = SnPageResponse::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
