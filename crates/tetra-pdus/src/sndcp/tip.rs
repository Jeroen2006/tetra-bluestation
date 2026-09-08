//! Direction-aware façade for the interoperable TIP SNDCP profile.
//!
//! The individual PDU codecs in [`super::pdus`] follow the ETSI tables. This
//! module only selects the direction-dependent message behind PDU types 0 and
//! 10 and maps the raw phase-modulation fields to one-based slot counts.

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use super::{
    enums::{
        address_type_identifier_in_demand::AddressTypeIdentifierInDemand, sn_pdu_type::SnPduType,
        type_identifier_in_accept::TypeIdentifierInAccept,
    },
    pdus::{
        resource_request::SndcpResourceRequest as RawResourceRequest,
        sn_activate_pdp_context::{
            PCO_CONFIGURATION_PROTOCOL_PPP, PCO_PROTOCOL_CHAP, SnActivatePdpContextAccept, SnActivatePdpContextDemand,
            SnActivatePdpContextReject, SndcpProtocolConfigurationOptions, SndcpProtocolConfigurationUnit,
        },
        sn_control::{SnDeactivatePdpContextAccept, SnDeactivatePdpContextDemand, SnEndOfData, SnReconnect},
        sn_data::SnData,
        sn_page::{SnPageRequest, SnPageResponse},
        sn_transmit::{SnDataTransmitRequest, SnDataTransmitResponse},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SndcpAddressRequest {
    Dynamic,
    Static(u32),
    Unsupported(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SndcpResourceRequest {
    pub symmetric: bool,
    pub throughput: u8,
    pub uplink_slots: u8,
    pub downlink_slots: u8,
    pub full_phase_slots: u8,
}

impl TryFrom<RawResourceRequest> for SndcpResourceRequest {
    type Error = PduParseErr;

    fn try_from(value: RawResourceRequest) -> Result<Self, Self::Error> {
        if value.reserved != 3 {
            return Err(PduParseErr::InvalidValue {
                field: "resource_request_reserved",
                value: value.reserved.into(),
            });
        }
        let uplink_slots = value.uplink_or_symmetric_timeslots + 1;
        Ok(Self {
            symmetric: !value.asymmetric_connection,
            throughput: value.data_transfer_throughput,
            uplink_slots,
            downlink_slots: value.downlink_timeslots.map(|slots| slots + 1).unwrap_or(uplink_slots),
            full_phase_slots: value.full_phase_modulation_capability + 1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpChapProof {
    pub identifier: u8,
    pub challenge: Vec<u8>,
    pub response: [u8; 16],
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SndcpUplink {
    ActivateDemand {
        version: u8,
        nsapi: u8,
        address: SndcpAddressRequest,
        ms_type: u8,
        apn_index: Option<u16>,
        chap: Option<SndcpChapProof>,
    },
    DeactivateDemand,
    Data {
        nsapi: u8,
        payload: Vec<u8>,
    },
    TransmitRequest {
        resource: Option<SndcpResourceRequest>,
    },
    Reconnect {
        resource: Option<SndcpResourceRequest>,
    },
    EndOfData {
        immediate_service_change: bool,
    },
    PageResponse {
        available: bool,
        resource: Option<SndcpResourceRequest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SndcpDownlink {
    ActivateAccept {
        nsapi: u8,
        ipv4: u32,
        ready_timer: u8,
        standby_timer: u8,
        response_wait_timer: u8,
        snei: Option<u16>,
        chap_success: Option<(u8, String)>,
    },
    ActivateReject {
        nsapi: u8,
        cause: u8,
        chap_failure: Option<(u8, String)>,
    },
    DeactivateDemand {
        deactivation_type: u8,
        nsapi: Option<u8>,
        snei: Option<u16>,
    },
    DeactivateAccept {
        deactivation_type: u8,
        nsapi: Option<u8>,
        snei: Option<u16>,
    },
    Data {
        nsapi: u8,
        payload: Vec<u8>,
    },
    TransmitResponse {
        nsapi: u8,
        accepted: bool,
        cause: Option<u8>,
        snei: Option<u16>,
    },
    EndOfData {
        immediate_service_change: bool,
    },
    PageRequest {
        nsapi: u8,
        reply_requested: bool,
        snei: Option<u16>,
    },
}

impl SndcpUplink {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let mut header = buffer.clone();
        let raw_type = header.read_field(4, "sndcp_pdu_type")?;
        let pdu_type = SnPduType::try_from(raw_type)?;
        match pdu_type {
            SnPduType::ActivatePdpContext => {
                let pdu = SnActivatePdpContextDemand::from_bitbuf(buffer)?;
                let address = match pdu.address_type_identifier {
                    AddressTypeIdentifierInDemand::Ipv4Dynamic => SndcpAddressRequest::Dynamic,
                    AddressTypeIdentifierInDemand::Ipv4Static => SndcpAddressRequest::Static(pdu.ipv4_address.unwrap_or_default()),
                    value => SndcpAddressRequest::Unsupported(value.into_raw() as u8),
                };
                Ok(Self::ActivateDemand {
                    version: pdu.sndcp_version,
                    nsapi: pdu.nsapi,
                    address,
                    ms_type: pdu.packet_data_ms_type.into_raw() as u8,
                    apn_index: pdu.access_point_name_index,
                    chap: chap_proof(&pdu)?,
                })
            }
            SnPduType::DeactivatePdpContextDemand => {
                let _ = SnDeactivatePdpContextDemand::from_bitbuf(buffer)?;
                Ok(Self::DeactivateDemand)
            }
            SnPduType::Data => {
                let pdu = SnData::from_bitbuf(buffer)?;
                if pdu.pcomp != 0 || pdu.dcomp != 0 || pdu.n_pdu_len_bits % 8 != 0 {
                    return Err(PduParseErr::NotImplemented {
                        field: Some("compressed or non-octet SN-DATA"),
                    });
                }
                Ok(Self::Data {
                    nsapi: pdu.nsapi,
                    payload: pdu.n_pdu,
                })
            }
            SnPduType::DataTransmitRequest => {
                let pdu = SnDataTransmitRequest::from_bitbuf(buffer)?;
                Ok(Self::TransmitRequest {
                    resource: pdu.resource_request.map(TryInto::try_into).transpose()?,
                })
            }
            SnPduType::Reconnect => {
                let pdu = SnReconnect::from_bitbuf(buffer)?;
                Ok(Self::Reconnect {
                    resource: pdu.resource_request.map(TryInto::try_into).transpose()?,
                })
            }
            SnPduType::EndOfData => {
                let pdu = SnEndOfData::from_bitbuf(buffer)?;
                Ok(Self::EndOfData {
                    immediate_service_change: pdu.immediate_service_change,
                })
            }
            SnPduType::Page => {
                let pdu = SnPageResponse::from_bitbuf(buffer)?;
                Ok(Self::PageResponse {
                    available: pdu.pd_service_available,
                    resource: pdu.resource_request.map(TryInto::try_into).transpose()?,
                })
            }
            _ => Err(PduParseErr::InvalidPduType {
                expected: SnPduType::ActivatePdpContext.into_raw(),
                found: raw_type,
            }),
        }
    }
}

impl SndcpDownlink {
    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        match self {
            Self::ActivateAccept {
                nsapi,
                ipv4,
                ready_timer,
                standby_timer,
                response_wait_timer,
                snei,
                chap_success,
            } => SnActivatePdpContextAccept {
                nsapi: *nsapi,
                pdu_priority_max: 4,
                ready_timer: *ready_timer,
                standby_timer: *standby_timer,
                response_wait_timer: *response_wait_timer,
                type_identifier_in_accept: TypeIdentifierInAccept::Ipv4Dynamic,
                ipv4_address: Some(*ipv4),
                pcomp_negotiation: 0,
                vj_compression_state_slots: None,
                ip_header_compression_state_slots_tcp: None,
                ip_header_compression_state_slots_non_tcp: None,
                maximum_interval_between_full_headers: None,
                maximum_time_interval_between_full_headers: None,
                largest_header_size: None,
                maximum_transmission_unit: 4,
                sndcp_network_endpoint_identifier: *snei,
                swmi_ipv6_information: None,
                swmi_mobile_ipv4_information: None,
                type34_elements: chap_success
                    .as_ref()
                    .map(|(id, message)| chap_element(3, *id, message.as_bytes()))
                    .transpose()?
                    .into_iter()
                    .collect(),
            }
            .to_bitbuf(buffer),
            Self::ActivateReject {
                nsapi,
                cause,
                chap_failure,
            } => SnActivatePdpContextReject {
                nsapi: *nsapi,
                activation_reject_cause: *cause,
                type34_elements: chap_failure
                    .as_ref()
                    .map(|(id, message)| chap_element(4, *id, message.as_bytes()))
                    .transpose()?
                    .into_iter()
                    .collect(),
            }
            .to_bitbuf(buffer),
            Self::DeactivateDemand {
                deactivation_type,
                nsapi,
                snei,
            } => SnDeactivatePdpContextDemand {
                deactivation_type: *deactivation_type,
                nsapi: *nsapi,
                sndcp_network_endpoint_identifier: *snei,
            }
            .to_bitbuf(buffer),
            Self::DeactivateAccept {
                deactivation_type,
                nsapi,
                snei,
            } => SnDeactivatePdpContextAccept {
                deactivation_type: *deactivation_type,
                nsapi: *nsapi,
                sndcp_network_endpoint_identifier: *snei,
            }
            .to_bitbuf(buffer),
            Self::Data { nsapi, payload } => SnData {
                nsapi: *nsapi,
                pcomp: 0,
                dcomp: 0,
                n_pdu_len_bits: payload.len() * 8,
                n_pdu: payload.clone(),
            }
            .to_bitbuf(buffer),
            Self::TransmitResponse {
                nsapi,
                accepted,
                cause,
                snei,
            } => SnDataTransmitResponse {
                nsapi: *nsapi,
                accept: *accepted,
                transmit_response_reject_cause: *cause,
                sndcp_network_endpoint_identifier: *snei,
                nsapi_additional: Vec::new(),
            }
            .to_bitbuf(buffer),
            Self::EndOfData { immediate_service_change } => SnEndOfData {
                immediate_service_change: *immediate_service_change,
            }
            .to_bitbuf(buffer),
            Self::PageRequest {
                nsapi,
                reply_requested,
                snei,
            } => SnPageRequest {
                nsapi: *nsapi,
                reply_requested: *reply_requested,
                sndcp_network_endpoint_identifier: *snei,
            }
            .to_bitbuf(buffer),
        }
    }
}

fn chap_proof(pdu: &SnActivatePdpContextDemand) -> Result<Option<SndcpChapProof>, PduParseErr> {
    let mut challenge = None;
    let mut response = None;
    for element in &pdu.type34_elements {
        let Some(options) = SndcpProtocolConfigurationOptions::from_type34_element(element)? else {
            continue;
        };
        for unit in options.protocols.iter().filter(|unit| unit.protocol_identity == PCO_PROTOCOL_CHAP) {
            if unit.contents.len() < 5 {
                continue;
            }
            let declared = u16::from_be_bytes([unit.contents[2], unit.contents[3]]) as usize;
            if declared != unit.contents.len() {
                return Err(PduParseErr::InconsistentLength {
                    expected: declared,
                    found: unit.contents.len(),
                });
            }
            let id = unit.contents[1];
            let value_len = unit.contents[4] as usize;
            if 5 + value_len > unit.contents.len() {
                return Err(PduParseErr::BufferEnded { field: Some("CHAP value") });
            }
            match unit.contents[0] {
                1 if value_len > 0 => challenge = Some((id, unit.contents[5..5 + value_len].to_vec())),
                2 if value_len == 16 => {
                    let mut digest = [0; 16];
                    digest.copy_from_slice(&unit.contents[5..21]);
                    let username = String::from_utf8(unit.contents[21..].to_vec()).map_err(|_| PduParseErr::InvalidValue {
                        field: "CHAP username",
                        value: 0,
                    })?;
                    response = Some((id, digest, username));
                }
                _ => {}
            }
        }
    }
    Ok(match (challenge, response) {
        (Some((challenge_id, challenge)), Some((response_id, response, username)))
            if challenge_id == response_id && !username.is_empty() =>
        {
            Some(SndcpChapProof {
                identifier: challenge_id,
                challenge,
                response,
                username,
            })
        }
        _ => None,
    })
}

fn chap_element(
    code: u8,
    identifier: u8,
    message: &[u8],
) -> Result<super::pdus::sn_activate_pdp_context::SndcpRawType34Element, PduParseErr> {
    let mut contents = vec![code, identifier];
    contents.extend_from_slice(&((4 + message.len()) as u16).to_be_bytes());
    contents.extend_from_slice(message);
    SndcpProtocolConfigurationOptions {
        configuration_protocol: PCO_CONFIGURATION_PROTOCOL_PPP,
        protocols: vec![SndcpProtocolConfigurationUnit {
            protocol_identity: PCO_PROTOCOL_CHAP,
            contents,
        }],
    }
    .to_type34_element()
}

pub fn ready_timer_code(milliseconds: u32) -> Option<u8> {
    [
        0, 200, 500, 700, 1_000, 2_000, 3_000, 5_000, 10_000, 20_000, 30_000, 60_000, 120_000, 180_000, 300_000,
    ]
    .iter()
    .position(|value| *value == milliseconds)
    .map(|value| value as u8)
    .filter(|value| *value != 0)
}

pub fn standby_timer_code(seconds: u32) -> Option<u8> {
    [
        0, 10, 30, 60, 300, 600, 1_800, 3_600, 7_200, 10_800, 21_600, 43_200, 86_400, 172_800, 259_200,
    ]
    .iter()
    .position(|value| *value == seconds)
    .map(|value| value as u8)
    .filter(|value| *value != 0)
}

pub fn response_wait_timer_code(milliseconds: u32) -> Option<u8> {
    [
        400, 600, 800, 1_000, 2_000, 3_000, 4_000, 5_000, 10_000, 15_000, 20_000, 30_000, 40_000, 50_000, 60_000,
    ]
    .iter()
    .position(|value| *value == milliseconds)
    .map(|value| value as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_multislot_resource_request_to_one_based_counts() {
        let raw = RawResourceRequest {
            asymmetric_connection: true,
            data_transfer_throughput: 4,
            uplink_or_symmetric_timeslots: 1,
            downlink_timeslots: Some(2),
            full_phase_modulation_capability: 3,
            reserved: 3,
        };
        assert_eq!(
            SndcpResourceRequest::try_from(raw).unwrap(),
            SndcpResourceRequest {
                symmetric: false,
                throughput: 4,
                uplink_slots: 2,
                downlink_slots: 3,
                full_phase_slots: 4,
            }
        );
    }

    #[test]
    fn activation_accept_uses_tip_timer_codes_and_mtu() {
        let pdu = SndcpDownlink::ActivateAccept {
            nsapi: 1,
            ipv4: 0xc0a8_0102,
            ready_timer: ready_timer_code(10_000).unwrap(),
            standby_timer: standby_timer_code(1_800).unwrap(),
            response_wait_timer: response_wait_timer_code(5_000).unwrap(),
            snei: Some(7),
            chap_success: None,
        };
        let mut bits = BitBuffer::new_autoexpand(128);
        pdu.to_bitbuf(&mut bits).unwrap();
        bits.seek(0);
        let decoded = SnActivatePdpContextAccept::from_bitbuf(&mut bits).unwrap();
        assert_eq!(decoded.ready_timer, 8);
        assert_eq!(decoded.standby_timer, 6);
        assert_eq!(decoded.response_wait_timer, 7);
        assert_eq!(decoded.maximum_transmission_unit, 4);
        assert_eq!(decoded.ipv4_address, Some(0xc0a8_0102));
    }
}
