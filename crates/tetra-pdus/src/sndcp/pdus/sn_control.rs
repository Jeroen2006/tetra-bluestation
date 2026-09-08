use tetra_core::typed_pdu_fields::delimiters;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::pdus::nsapi_elements::{
    SnNsapiForReconnection, read_nsapi_type4_chain, validate_nsapi, write_nsapi_for_reconnection_type4,
};
use crate::sndcp::pdus::resource_request::SndcpResourceRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDeactivatePdpContextDemand {
    pub deactivation_type: u8,
    pub nsapi: Option<u8>,
    pub sndcp_network_endpoint_identifier: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnDeactivatePdpContextAccept {
    pub deactivation_type: u8,
    pub nsapi: Option<u8>,
    pub sndcp_network_endpoint_identifier: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnEndOfData {
    pub immediate_service_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnReconnect {
    pub data_to_send: bool,
    pub nsapi: Option<u8>,
    pub enhanced_pi_4_dqpsk_service: bool,
    pub resource_request: Option<SndcpResourceRequest>,
    pub sndcp_network_endpoint_identifier: Option<u16>,
    pub nsapi_for_reconnection: Vec<SnNsapiForReconnection>,
}

fn validate_deactivation_type(deactivation_type: u8, nsapi: Option<u8>) -> Result<(), PduParseErr> {
    if deactivation_type == 0 {
        if nsapi.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "nsapi",
                reason: "NSAPI shall be absent when deactivation type is 0",
            });
        }
    } else if nsapi.is_none() {
        return Err(PduParseErr::Inconsistency {
            field: "nsapi",
            reason: "NSAPI shall be present when deactivation type is not 0",
        });
    }

    if let Some(nsapi) = nsapi {
        validate_nsapi(nsapi)?;
    }
    Ok(())
}

fn parse_deactivate_tail(
    buffer: &mut BitBuffer,
    deactivation_type: u8,
    reserved_bits: usize,
) -> Result<(Option<u8>, Option<u16>), PduParseErr> {
    let nsapi = if deactivation_type == 0 {
        None
    } else {
        Some(buffer.read_field(4, "nsapi")? as u8)
    };
    validate_deactivation_type(deactivation_type, nsapi)?;

    let obit = delimiters::read_obit(buffer)?;
    let sndcp_network_endpoint_identifier = if obit {
        let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
            Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
        } else {
            None
        };
        let reserved_present = delimiters::read_pbit(buffer)?;
        if reserved_present {
            buffer.seek_rel(reserved_bits as isize);
        }
        if delimiters::read_mbit(buffer)? {
            return Err(PduParseErr::InvalidTrailingMbitValue);
        }
        sndcp_network_endpoint_identifier
    } else {
        None
    };

    Ok((nsapi, sndcp_network_endpoint_identifier))
}

fn write_deactivate_tail(
    buffer: &mut BitBuffer,
    deactivation_type: u8,
    nsapi: Option<u8>,
    sndcp_network_endpoint_identifier: Option<u16>,
    reserved_bits: usize,
) -> Result<(), PduParseErr> {
    validate_deactivation_type(deactivation_type, nsapi)?;

    if let Some(nsapi) = nsapi {
        buffer.write_bits(nsapi as u64, 4);
    }

    let obit = sndcp_network_endpoint_identifier.is_some();
    delimiters::write_obit(buffer, obit as u8);
    if obit {
        delimiters::write_pbit(buffer, sndcp_network_endpoint_identifier.is_some() as u8);
        if let Some(value) = sndcp_network_endpoint_identifier {
            buffer.write_bits(value as u64, 16);
        }
        delimiters::write_pbit(buffer, 0);
        let _ = reserved_bits;
        delimiters::write_mbit(buffer, 0);
    }

    Ok(())
}

impl SnDeactivatePdpContextDemand {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DeactivatePdpContextDemand)?;

        let deactivation_type = buffer.read_field(8, "deactivation_type")? as u8;
        let (nsapi, sndcp_network_endpoint_identifier) = parse_deactivate_tail(buffer, deactivation_type, 12)?;

        Ok(SnDeactivatePdpContextDemand {
            deactivation_type,
            nsapi,
            sndcp_network_endpoint_identifier,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DeactivatePdpContextDemand.into_raw(), 4);
        buffer.write_bits(self.deactivation_type as u64, 8);
        write_deactivate_tail(
            buffer,
            self.deactivation_type,
            self.nsapi,
            self.sndcp_network_endpoint_identifier,
            12,
        )
    }
}

impl SnDeactivatePdpContextAccept {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::DeactivatePdpContextAccept)?;

        let deactivation_type = buffer.read_field(8, "deactivation_type")? as u8;
        let (nsapi, sndcp_network_endpoint_identifier) = parse_deactivate_tail(buffer, deactivation_type, 11)?;

        Ok(SnDeactivatePdpContextAccept {
            deactivation_type,
            nsapi,
            sndcp_network_endpoint_identifier,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::DeactivatePdpContextAccept.into_raw(), 4);
        buffer.write_bits(self.deactivation_type as u64, 8);
        write_deactivate_tail(
            buffer,
            self.deactivation_type,
            self.nsapi,
            self.sndcp_network_endpoint_identifier,
            11,
        )
    }
}

impl SnEndOfData {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::EndOfData)?;

        let immediate_service_change = buffer.read_field(1, "immediate_service_change")? != 0;
        let obit = delimiters::read_obit(buffer)?;
        if obit {
            let reserved_present = delimiters::read_pbit(buffer)?;
            if reserved_present {
                buffer.seek_rel(41);
            }
            if delimiters::read_mbit(buffer)? {
                return Err(PduParseErr::InvalidTrailingMbitValue);
            }
        }

        Ok(SnEndOfData { immediate_service_change })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(SnPduType::EndOfData.into_raw(), 4);
        buffer.write_bit(self.immediate_service_change as u8);
        delimiters::write_obit(buffer, 0);
        Ok(())
    }
}

impl SnReconnect {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::Reconnect)?;

        let data_to_send = buffer.read_field(1, "data_to_send")? != 0;
        let nsapi = if data_to_send {
            Some(buffer.read_field(4, "nsapi")? as u8)
        } else {
            None
        };
        if let Some(nsapi) = nsapi {
            validate_nsapi(nsapi)?;
        }

        let enhanced_pi_4_dqpsk_service = buffer.read_field(1, "enhanced_pi_4_dqpsk_service")? != 0;
        let resource_request = if enhanced_pi_4_dqpsk_service {
            Some(SndcpResourceRequest::from_bitbuf(buffer)?)
        } else {
            None
        };

        let obit = delimiters::read_obit(buffer)?;
        let (sndcp_network_endpoint_identifier, nsapi_for_reconnection) = if obit {
            let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
            } else {
                None
            };
            let reserved_present = delimiters::read_pbit(buffer)?;
            if reserved_present {
                buffer.seek_rel(19);
            }
            let (_, nsapi_for_reconnection) = read_nsapi_type4_chain(buffer)?;
            (sndcp_network_endpoint_identifier, nsapi_for_reconnection)
        } else {
            (None, Vec::new())
        };

        Ok(SnReconnect {
            data_to_send,
            nsapi,
            enhanced_pi_4_dqpsk_service,
            resource_request,
            sndcp_network_endpoint_identifier,
            nsapi_for_reconnection,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        if self.data_to_send != self.nsapi.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "nsapi",
                reason: "NSAPI presence must match data to send",
            });
        }
        if let Some(nsapi) = self.nsapi {
            validate_nsapi(nsapi)?;
        }
        if self.enhanced_pi_4_dqpsk_service != self.resource_request.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "resource_request",
                reason: "resource request presence must match enhanced pi/4-DQPSK service",
            });
        }
        for nsapi in &self.nsapi_for_reconnection {
            validate_nsapi(nsapi.nsapi)?;
        }

        buffer.write_bits(SnPduType::Reconnect.into_raw(), 4);
        buffer.write_bit(self.data_to_send as u8);
        if let Some(nsapi) = self.nsapi {
            buffer.write_bits(nsapi as u64, 4);
        }
        buffer.write_bit(self.enhanced_pi_4_dqpsk_service as u8);
        if let Some(resource_request) = &self.resource_request {
            resource_request.to_bitbuf(buffer)?;
        }

        let obit = self.sndcp_network_endpoint_identifier.is_some() || !self.nsapi_for_reconnection.is_empty();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.sndcp_network_endpoint_identifier.is_some() as u8);
            if let Some(value) = self.sndcp_network_endpoint_identifier {
                buffer.write_bits(value as u64, 16);
            }
            delimiters::write_pbit(buffer, 0);
            write_nsapi_for_reconnection_type4(buffer, &self.nsapi_for_reconnection)?;
            delimiters::write_mbit(buffer, 0);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deactivate_demand_all_nsapis_minimal_layout() {
        let pdu = SnDeactivatePdpContextDemand {
            deactivation_type: 0,
            nsapi: None,
            sndcp_network_endpoint_identifier: None,
        };

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "0010000000000");

        encoded.seek(0);
        let decoded = SnDeactivatePdpContextDemand::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn deactivate_accept_one_nsapi_minimal_layout() {
        let pdu = SnDeactivatePdpContextAccept {
            deactivation_type: 1,
            nsapi: Some(1),
            sndcp_network_endpoint_identifier: None,
        };

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "00010000000100010");

        encoded.seek(0);
        let decoded = SnDeactivatePdpContextAccept::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn deactivate_accept_skips_table_28_33_reserved_length() {
        let mut encoded = BitBuffer::from_bitstr("000100000000101000000000000");
        let decoded = SnDeactivatePdpContextAccept::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(
            decoded,
            SnDeactivatePdpContextAccept {
                deactivation_type: 0,
                nsapi: None,
                sndcp_network_endpoint_identifier: None,
            }
        );
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn end_of_data_minimal_layout() {
        let pdu = SnEndOfData {
            immediate_service_change: false,
        };

        let mut encoded = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "100000");

        encoded.seek(0);
        let decoded = SnEndOfData::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn reconnect_no_data_minimal_layout() {
        let pdu = SnReconnect {
            data_to_send: false,
            nsapi: None,
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_for_reconnection: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(8);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "1001000");

        encoded.seek(0);
        let decoded = SnReconnect::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn reconnect_with_data_minimal_layout() {
        let pdu = SnReconnect {
            data_to_send: true,
            nsapi: Some(1),
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_for_reconnection: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(16);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "10011000100");

        encoded.seek(0);
        let decoded = SnReconnect::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn reconnect_with_resource_request_layout() {
        let pdu = SnReconnect {
            data_to_send: true,
            nsapi: Some(1),
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
            nsapi_for_reconnection: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "100110001101100000110");

        encoded.seek(0);
        let decoded = SnReconnect::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn reconnect_with_nsapi_for_reconnection_layout() {
        let pdu = SnReconnect {
            data_to_send: false,
            nsapi: None,
            enhanced_pi_4_dqpsk_service: false,
            resource_request: None,
            sndcp_network_endpoint_identifier: None,
            nsapi_for_reconnection: vec![
                SnNsapiForReconnection {
                    nsapi: 2,
                    data_to_send: true,
                },
                SnNsapiForReconnection {
                    nsapi: 3,
                    data_to_send: false,
                },
            ],
        };

        let mut encoded = BitBuffer::new_autoexpand(48);
        pdu.to_bitbuf(&mut encoded).unwrap();
        assert_eq!(encoded.to_bitstr(), "10010010010101000000100100000100010100011000");

        encoded.seek(0);
        let decoded = SnReconnect::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
