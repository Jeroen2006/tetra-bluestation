use tetra_core::typed_pdu_fields::delimiters;
use tetra_core::{BitBuffer, expect_pdu_type, pdu_parse_error::PduParseErr};

use crate::sndcp::enums::address_type_identifier_in_demand::AddressTypeIdentifierInDemand;
use crate::sndcp::enums::packet_data_ms_type::PacketDataMsType;
use crate::sndcp::enums::sn_pdu_type::SnPduType;
use crate::sndcp::enums::type_identifier_in_accept::TypeIdentifierInAccept;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpRawType2Element {
    pub len_bits: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpRawType34Element {
    pub element_id: u8,
    pub len_bits: usize,
    pub data: Vec<u8>,
}

pub const TYPE34_ELEMENT_PROTOCOL_CONFIGURATION_OPTIONS: u8 = 1;
pub const TYPE34_ELEMENT_QOS: u8 = 3;
pub const PCO_CONFIGURATION_PROTOCOL_PPP: u8 = 0;
pub const PCO_PROTOCOL_PAP: u16 = 0xC023;
pub const PCO_PROTOCOL_IPCP: u16 = 0x8021;
pub const PCO_PROTOCOL_CHAP: u16 = 0xC223;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpProtocolConfigurationOptions {
    pub configuration_protocol: u8,
    pub protocols: Vec<SndcpProtocolConfigurationUnit>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SndcpProtocolConfigurationUnit {
    pub protocol_identity: u16,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnActivatePdpContextDemand {
    pub sndcp_version: u8,
    pub nsapi: u8,
    pub address_type_identifier: AddressTypeIdentifierInDemand,
    pub ipv4_address: Option<u32>,
    pub primary_nsapi: Option<u8>,
    pub packet_data_ms_type: PacketDataMsType,
    pub pcomp_negotiation: u8,
    pub vj_compression_state_slots: Option<u8>,
    pub ip_header_compression_state_slots_tcp: Option<u8>,
    pub ip_header_compression_state_slots_non_tcp: Option<u16>,
    pub maximum_interval_between_full_headers: Option<u8>,
    pub maximum_time_interval_between_full_headers: Option<u8>,
    pub largest_header_size: Option<u8>,
    pub access_point_name_index: Option<u16>,
    pub type34_elements: Vec<SndcpRawType34Element>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnActivatePdpContextAccept {
    pub nsapi: u8,
    pub pdu_priority_max: u8,
    pub ready_timer: u8,
    pub standby_timer: u8,
    pub response_wait_timer: u8,
    pub type_identifier_in_accept: TypeIdentifierInAccept,
    pub ipv4_address: Option<u32>,
    pub pcomp_negotiation: u8,
    pub vj_compression_state_slots: Option<u8>,
    pub ip_header_compression_state_slots_tcp: Option<u8>,
    pub ip_header_compression_state_slots_non_tcp: Option<u16>,
    pub maximum_interval_between_full_headers: Option<u8>,
    pub maximum_time_interval_between_full_headers: Option<u8>,
    pub largest_header_size: Option<u8>,
    pub maximum_transmission_unit: u8,
    pub sndcp_network_endpoint_identifier: Option<u16>,
    pub swmi_ipv6_information: Option<SndcpRawType2Element>,
    pub swmi_mobile_ipv4_information: Option<SndcpRawType2Element>,
    pub type34_elements: Vec<SndcpRawType34Element>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnActivatePdpContextReject {
    pub nsapi: u8,
    pub activation_reject_cause: u8,
    pub type34_elements: Vec<SndcpRawType34Element>,
}

fn read_raw_bits(buffer: &mut BitBuffer, len_bits: usize, field: &'static str) -> Result<Vec<u8>, PduParseErr> {
    let mut data = vec![0; len_bits.div_ceil(8)];
    buffer
        .read_bits_into_slice(len_bits, &mut data)
        .ok_or(PduParseErr::BufferEnded { field: Some(field) })?;
    Ok(data)
}

fn write_raw_bits(buffer: &mut BitBuffer, data: &[u8], len_bits: usize) -> Result<(), PduParseErr> {
    if data.len() * 8 < len_bits {
        return Err(PduParseErr::InconsistentLength {
            expected: len_bits.div_ceil(8),
            found: data.len(),
        });
    }

    let mut src = BitBuffer::from_bytes(data);
    buffer.copy_bits(&mut src, len_bits);
    Ok(())
}

fn parse_type34_chain(buffer: &mut BitBuffer) -> Result<Vec<SndcpRawType34Element>, PduParseErr> {
    let mut elements = Vec::new();

    loop {
        if !delimiters::read_mbit(buffer)? {
            break;
        }

        let element_id = buffer.read_field(4, "type34_element_id")? as u8;
        let len_bits = buffer.read_field(11, "type34_len_bits")? as usize;
        let data = read_raw_bits(buffer, len_bits, "type34_data")?;
        elements.push(SndcpRawType34Element {
            element_id,
            len_bits,
            data,
        });
    }

    Ok(elements)
}

fn write_type34_chain(buffer: &mut BitBuffer, elements: &[SndcpRawType34Element]) -> Result<(), PduParseErr> {
    for element in elements {
        if element.element_id > 15 {
            return Err(PduParseErr::InvalidValue {
                field: "type34_element_id",
                value: element.element_id as u64,
            });
        }
        if element.len_bits > 2047 {
            return Err(PduParseErr::InvalidValue {
                field: "type34_len_bits",
                value: element.len_bits as u64,
            });
        }

        delimiters::write_mbit(buffer, 1);
        buffer.write_bits(element.element_id as u64, 4);
        buffer.write_bits(element.len_bits as u64, 11);
        write_raw_bits(buffer, &element.data, element.len_bits)?;
    }

    delimiters::write_mbit(buffer, 0);
    Ok(())
}

impl SndcpProtocolConfigurationOptions {
    pub fn from_type34_element(element: &SndcpRawType34Element) -> Result<Option<Self>, PduParseErr> {
        if element.element_id != TYPE34_ELEMENT_PROTOCOL_CONFIGURATION_OPTIONS {
            return Ok(None);
        }
        if element.len_bits > 1024 {
            return Err(PduParseErr::InvalidValue {
                field: "protocol_configuration_options_len_bits",
                value: element.len_bits as u64,
            });
        }
        if element.data.len() * 8 < element.len_bits {
            return Err(PduParseErr::InconsistentLength {
                expected: element.len_bits.div_ceil(8),
                found: element.data.len(),
            });
        }

        let mut buffer = BitBuffer::from_bytes(&element.data);
        buffer.set_raw_end(element.len_bits);

        let configuration_protocol = buffer.read_field(4, "pco_configuration_protocol")? as u8;
        let mut protocols = Vec::new();
        while buffer.get_len_remaining() > 0 {
            if buffer.get_len_remaining() < 24 {
                return Err(PduParseErr::BufferEnded {
                    field: Some("pco_protocol_unit"),
                });
            }

            let protocol_identity = buffer.read_field(16, "pco_protocol_identity")? as u16;
            let contents_len_octets = buffer.read_field(8, "pco_protocol_contents_len_octets")? as usize;
            let contents_len_bits = contents_len_octets * 8;
            let contents = read_raw_bits(&mut buffer, contents_len_bits, "pco_protocol_contents")?;
            protocols.push(SndcpProtocolConfigurationUnit {
                protocol_identity,
                contents,
            });
        }

        Ok(Some(Self {
            configuration_protocol,
            protocols,
        }))
    }

    pub fn to_type34_element(&self) -> Result<SndcpRawType34Element, PduParseErr> {
        if self.configuration_protocol > 15 {
            return Err(PduParseErr::InvalidValue {
                field: "pco_configuration_protocol",
                value: self.configuration_protocol as u64,
            });
        }

        let mut buffer = BitBuffer::new_autoexpand(128);
        buffer.write_bits(self.configuration_protocol as u64, 4);
        for protocol in &self.protocols {
            if protocol.contents.len() > u8::MAX as usize {
                return Err(PduParseErr::InvalidValue {
                    field: "pco_protocol_contents_len_octets",
                    value: protocol.contents.len() as u64,
                });
            }

            buffer.write_bits(protocol.protocol_identity as u64, 16);
            buffer.write_bits(protocol.contents.len() as u64, 8);
            write_raw_bits(&mut buffer, &protocol.contents, protocol.contents.len() * 8)?;
        }

        let len_bits = buffer.get_len_written();
        if len_bits > 1024 {
            return Err(PduParseErr::InvalidValue {
                field: "protocol_configuration_options_len_bits",
                value: len_bits as u64,
            });
        }

        Ok(SndcpRawType34Element {
            element_id: TYPE34_ELEMENT_PROTOCOL_CONFIGURATION_OPTIONS,
            len_bits,
            data: buffer.into_bytes(),
        })
    }
}

fn pcomp_vj_enabled(pcomp_negotiation: u8) -> bool {
    pcomp_negotiation & 0x01 != 0
}

fn pcomp_ip_enabled(pcomp_negotiation: u8) -> bool {
    pcomp_negotiation & 0x02 != 0
}

fn parse_pcomp_conditionals(
    buffer: &mut BitBuffer,
    pcomp_negotiation: u8,
) -> Result<(Option<u8>, Option<u8>, Option<u16>, Option<u8>, Option<u8>, Option<u8>), PduParseErr> {
    let vj_compression_state_slots = if pcomp_vj_enabled(pcomp_negotiation) {
        Some(buffer.read_field(8, "vj_compression_state_slots")? as u8)
    } else {
        None
    };

    let (
        ip_header_compression_state_slots_tcp,
        ip_header_compression_state_slots_non_tcp,
        maximum_interval_between_full_headers,
        maximum_time_interval_between_full_headers,
        largest_header_size,
    ) = if pcomp_ip_enabled(pcomp_negotiation) {
        (
            Some(buffer.read_field(8, "ip_header_compression_state_slots_tcp")? as u8),
            Some(buffer.read_field(16, "ip_header_compression_state_slots_non_tcp")? as u16),
            Some(buffer.read_field(8, "maximum_interval_between_full_headers")? as u8),
            Some(buffer.read_field(8, "maximum_time_interval_between_full_headers")? as u8),
            Some(buffer.read_field(8, "largest_header_size")? as u8),
        )
    } else {
        (None, None, None, None, None)
    };

    Ok((
        vj_compression_state_slots,
        ip_header_compression_state_slots_tcp,
        ip_header_compression_state_slots_non_tcp,
        maximum_interval_between_full_headers,
        maximum_time_interval_between_full_headers,
        largest_header_size,
    ))
}

fn validate_pcomp_conditionals(
    pcomp_negotiation: u8,
    vj_compression_state_slots: Option<u8>,
    ip_header_compression_state_slots_tcp: Option<u8>,
    ip_header_compression_state_slots_non_tcp: Option<u16>,
    maximum_interval_between_full_headers: Option<u8>,
    maximum_time_interval_between_full_headers: Option<u8>,
    largest_header_size: Option<u8>,
) -> Result<(), PduParseErr> {
    let has_vj = vj_compression_state_slots.is_some();
    if has_vj != pcomp_vj_enabled(pcomp_negotiation) {
        return Err(PduParseErr::Inconsistency {
            field: "vj_compression_state_slots",
            reason: "presence must match bit 1 (LSB) of PCOMP negotiation",
        });
    }

    let ip_fields_present = ip_header_compression_state_slots_tcp.is_some()
        || ip_header_compression_state_slots_non_tcp.is_some()
        || maximum_interval_between_full_headers.is_some()
        || maximum_time_interval_between_full_headers.is_some()
        || largest_header_size.is_some();
    if pcomp_ip_enabled(pcomp_negotiation) {
        if ip_header_compression_state_slots_tcp.is_none()
            || ip_header_compression_state_slots_non_tcp.is_none()
            || maximum_interval_between_full_headers.is_none()
            || maximum_time_interval_between_full_headers.is_none()
            || largest_header_size.is_none()
        {
            return Err(PduParseErr::Inconsistency {
                field: "pcomp_negotiation",
                reason: "all IP header compression conditional fields must be present when bit 2 is set",
            });
        }
    } else if ip_fields_present {
        return Err(PduParseErr::Inconsistency {
            field: "pcomp_negotiation",
            reason: "IP header compression conditional fields must be absent when bit 2 is clear",
        });
    }

    Ok(())
}

fn write_pcomp_conditionals(
    buffer: &mut BitBuffer,
    pcomp_negotiation: u8,
    vj_compression_state_slots: Option<u8>,
    ip_header_compression_state_slots_tcp: Option<u8>,
    ip_header_compression_state_slots_non_tcp: Option<u16>,
    maximum_interval_between_full_headers: Option<u8>,
    maximum_time_interval_between_full_headers: Option<u8>,
    largest_header_size: Option<u8>,
) -> Result<(), PduParseErr> {
    validate_pcomp_conditionals(
        pcomp_negotiation,
        vj_compression_state_slots,
        ip_header_compression_state_slots_tcp,
        ip_header_compression_state_slots_non_tcp,
        maximum_interval_between_full_headers,
        maximum_time_interval_between_full_headers,
        largest_header_size,
    )?;

    if let Some(value) = vj_compression_state_slots {
        buffer.write_bits(value as u64, 8);
    }
    if pcomp_ip_enabled(pcomp_negotiation) {
        buffer.write_bits(ip_header_compression_state_slots_tcp.unwrap() as u64, 8);
        buffer.write_bits(ip_header_compression_state_slots_non_tcp.unwrap() as u64, 16);
        buffer.write_bits(maximum_interval_between_full_headers.unwrap() as u64, 8);
        buffer.write_bits(maximum_time_interval_between_full_headers.unwrap() as u64, 8);
        buffer.write_bits(largest_header_size.unwrap() as u64, 8);
    }

    Ok(())
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

impl SnActivatePdpContextDemand {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::ActivatePdpContext)?;

        let sndcp_version = buffer.read_field(4, "sndcp_version")? as u8;
        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let address_type_identifier = AddressTypeIdentifierInDemand::try_from(buffer.read_field(3, "address_type_identifier")?)?;

        let ipv4_address = if address_type_identifier == AddressTypeIdentifierInDemand::Ipv4Static {
            Some(buffer.read_field(32, "ipv4_address")? as u32)
        } else {
            None
        };
        let primary_nsapi = if address_type_identifier == AddressTypeIdentifierInDemand::PrimaryNsapiForSecondaryPdp {
            Some(buffer.read_field(4, "primary_nsapi")? as u8)
        } else {
            None
        };

        let packet_data_ms_type = PacketDataMsType::try_from(buffer.read_field(4, "packet_data_ms_type")?)?;
        let pcomp_negotiation = buffer.read_field(8, "pcomp_negotiation")? as u8;
        let (
            vj_compression_state_slots,
            ip_header_compression_state_slots_tcp,
            ip_header_compression_state_slots_non_tcp,
            maximum_interval_between_full_headers,
            maximum_time_interval_between_full_headers,
            largest_header_size,
        ) = parse_pcomp_conditionals(buffer, pcomp_negotiation)?;

        let obit = delimiters::read_obit(buffer)?;
        let (access_point_name_index, type34_elements) = if obit {
            let access_point_name_index = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "access_point_name_index")? as u16)
            } else {
                None
            };
            (access_point_name_index, parse_type34_chain(buffer)?)
        } else {
            (None, Vec::new())
        };

        Ok(SnActivatePdpContextDemand {
            sndcp_version,
            nsapi,
            address_type_identifier,
            ipv4_address,
            primary_nsapi,
            packet_data_ms_type,
            pcomp_negotiation,
            vj_compression_state_slots,
            ip_header_compression_state_slots_tcp,
            ip_header_compression_state_slots_non_tcp,
            maximum_interval_between_full_headers,
            maximum_time_interval_between_full_headers,
            largest_header_size,
            access_point_name_index,
            type34_elements,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        if self.sndcp_version > 15 {
            return Err(PduParseErr::InvalidValue {
                field: "sndcp_version",
                value: self.sndcp_version as u64,
            });
        }

        let needs_ipv4 = self.address_type_identifier == AddressTypeIdentifierInDemand::Ipv4Static;
        if needs_ipv4 != self.ipv4_address.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "ipv4_address",
                reason: "IPv4 address is conditional on ATID IPv4 static",
            });
        }

        let needs_primary_nsapi = self.address_type_identifier == AddressTypeIdentifierInDemand::PrimaryNsapiForSecondaryPdp;
        if needs_primary_nsapi != self.primary_nsapi.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "primary_nsapi",
                reason: "primary NSAPI is conditional on ATID secondary PDP",
            });
        }

        buffer.write_bits(SnPduType::ActivatePdpContext.into_raw(), 4);
        buffer.write_bits(self.sndcp_version as u64, 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.address_type_identifier.into_raw(), 3);
        if let Some(value) = self.ipv4_address {
            buffer.write_bits(value as u64, 32);
        }
        if let Some(value) = self.primary_nsapi {
            buffer.write_bits(value as u64, 4);
        }
        buffer.write_bits(self.packet_data_ms_type.into_raw(), 4);
        buffer.write_bits(self.pcomp_negotiation as u64, 8);
        write_pcomp_conditionals(
            buffer,
            self.pcomp_negotiation,
            self.vj_compression_state_slots,
            self.ip_header_compression_state_slots_tcp,
            self.ip_header_compression_state_slots_non_tcp,
            self.maximum_interval_between_full_headers,
            self.maximum_time_interval_between_full_headers,
            self.largest_header_size,
        )?;

        let obit = self.access_point_name_index.is_some() || !self.type34_elements.is_empty();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.access_point_name_index.is_some() as u8);
            if let Some(value) = self.access_point_name_index {
                buffer.write_bits(value as u64, 16);
            }
            write_type34_chain(buffer, &self.type34_elements)?;
        }

        Ok(())
    }
}

impl SnActivatePdpContextAccept {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::ActivatePdpContext)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let pdu_priority_max = buffer.read_field(3, "pdu_priority_max")? as u8;
        let ready_timer = buffer.read_field(4, "ready_timer")? as u8;
        let standby_timer = buffer.read_field(4, "standby_timer")? as u8;
        let response_wait_timer = buffer.read_field(4, "response_wait_timer")? as u8;
        let type_identifier_in_accept = TypeIdentifierInAccept::try_from(buffer.read_field(3, "type_identifier_in_accept")?)?;
        let ipv4_address = match type_identifier_in_accept {
            TypeIdentifierInAccept::Ipv4Static | TypeIdentifierInAccept::Ipv4Dynamic => Some(buffer.read_field(32, "ipv4_address")? as u32),
            TypeIdentifierInAccept::NoAddress => None,
        };
        let pcomp_negotiation = buffer.read_field(8, "pcomp_negotiation")? as u8;
        let (
            vj_compression_state_slots,
            ip_header_compression_state_slots_tcp,
            ip_header_compression_state_slots_non_tcp,
            maximum_interval_between_full_headers,
            maximum_time_interval_between_full_headers,
            largest_header_size,
        ) = parse_pcomp_conditionals(buffer, pcomp_negotiation)?;
        let maximum_transmission_unit = buffer.read_field(3, "maximum_transmission_unit")? as u8;

        let obit = delimiters::read_obit(buffer)?;
        let (sndcp_network_endpoint_identifier, swmi_ipv6_information, swmi_mobile_ipv4_information, type34_elements) = if obit {
            let sndcp_network_endpoint_identifier = if delimiters::read_pbit(buffer)? {
                Some(buffer.read_field(16, "sndcp_network_endpoint_identifier")? as u16)
            } else {
                None
            };
            let swmi_ipv6_information = if delimiters::read_pbit(buffer)? {
                Some(SndcpRawType2Element {
                    len_bits: 98,
                    data: read_raw_bits(buffer, 98, "swmi_ipv6_information")?,
                })
            } else {
                None
            };
            let swmi_mobile_ipv4_information = if delimiters::read_pbit(buffer)? {
                Some(SndcpRawType2Element {
                    len_bits: 71,
                    data: read_raw_bits(buffer, 71, "swmi_mobile_ipv4_information")?,
                })
            } else {
                None
            };
            (
                sndcp_network_endpoint_identifier,
                swmi_ipv6_information,
                swmi_mobile_ipv4_information,
                parse_type34_chain(buffer)?,
            )
        } else {
            (None, None, None, Vec::new())
        };

        Ok(SnActivatePdpContextAccept {
            nsapi,
            pdu_priority_max,
            ready_timer,
            standby_timer,
            response_wait_timer,
            type_identifier_in_accept,
            ipv4_address,
            pcomp_negotiation,
            vj_compression_state_slots,
            ip_header_compression_state_slots_tcp,
            ip_header_compression_state_slots_non_tcp,
            maximum_interval_between_full_headers,
            maximum_time_interval_between_full_headers,
            largest_header_size,
            maximum_transmission_unit,
            sndcp_network_endpoint_identifier,
            swmi_ipv6_information,
            swmi_mobile_ipv4_information,
            type34_elements,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;
        if self.pdu_priority_max > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "pdu_priority_max",
                value: self.pdu_priority_max as u64,
            });
        }
        if self.ready_timer > 15 || self.standby_timer > 15 || self.response_wait_timer > 15 {
            return Err(PduParseErr::InvalidValue { field: "timer", value: 16 });
        }
        if self.maximum_transmission_unit > 7 {
            return Err(PduParseErr::InvalidValue {
                field: "maximum_transmission_unit",
                value: self.maximum_transmission_unit as u64,
            });
        }

        let needs_ipv4 = matches!(
            self.type_identifier_in_accept,
            TypeIdentifierInAccept::Ipv4Static | TypeIdentifierInAccept::Ipv4Dynamic
        );
        if needs_ipv4 != self.ipv4_address.is_some() {
            return Err(PduParseErr::Inconsistency {
                field: "ipv4_address",
                reason: "IPv4 address is conditional on TIA IPv4 static or dynamic",
            });
        }

        buffer.write_bits(SnPduType::ActivatePdpContext.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.pdu_priority_max as u64, 3);
        buffer.write_bits(self.ready_timer as u64, 4);
        buffer.write_bits(self.standby_timer as u64, 4);
        buffer.write_bits(self.response_wait_timer as u64, 4);
        buffer.write_bits(self.type_identifier_in_accept.into_raw(), 3);
        if let Some(value) = self.ipv4_address {
            buffer.write_bits(value as u64, 32);
        }
        buffer.write_bits(self.pcomp_negotiation as u64, 8);
        write_pcomp_conditionals(
            buffer,
            self.pcomp_negotiation,
            self.vj_compression_state_slots,
            self.ip_header_compression_state_slots_tcp,
            self.ip_header_compression_state_slots_non_tcp,
            self.maximum_interval_between_full_headers,
            self.maximum_time_interval_between_full_headers,
            self.largest_header_size,
        )?;
        buffer.write_bits(self.maximum_transmission_unit as u64, 3);

        let obit = self.sndcp_network_endpoint_identifier.is_some()
            || self.swmi_ipv6_information.is_some()
            || self.swmi_mobile_ipv4_information.is_some()
            || !self.type34_elements.is_empty();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            delimiters::write_pbit(buffer, self.sndcp_network_endpoint_identifier.is_some() as u8);
            if let Some(value) = self.sndcp_network_endpoint_identifier {
                buffer.write_bits(value as u64, 16);
            }

            delimiters::write_pbit(buffer, self.swmi_ipv6_information.is_some() as u8);
            if let Some(value) = &self.swmi_ipv6_information {
                if value.len_bits != 98 {
                    return Err(PduParseErr::InconsistentLength {
                        expected: 98,
                        found: value.len_bits,
                    });
                }
                write_raw_bits(buffer, &value.data, value.len_bits)?;
            }

            delimiters::write_pbit(buffer, self.swmi_mobile_ipv4_information.is_some() as u8);
            if let Some(value) = &self.swmi_mobile_ipv4_information {
                if value.len_bits != 71 {
                    return Err(PduParseErr::InconsistentLength {
                        expected: 71,
                        found: value.len_bits,
                    });
                }
                write_raw_bits(buffer, &value.data, value.len_bits)?;
            }

            write_type34_chain(buffer, &self.type34_elements)?;
        }

        Ok(())
    }
}

impl SnActivatePdpContextReject {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "sn_pdu_type")?;
        expect_pdu_type!(pdu_type, SnPduType::ActivatePdpContextReject)?;

        let nsapi = buffer.read_field(4, "nsapi")? as u8;
        let activation_reject_cause = buffer.read_field(8, "activation_reject_cause")? as u8;
        let obit = delimiters::read_obit(buffer)?;
        let type34_elements = if obit { parse_type34_chain(buffer)? } else { Vec::new() };

        Ok(SnActivatePdpContextReject {
            nsapi,
            activation_reject_cause,
            type34_elements,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        validate_nsapi(self.nsapi)?;

        buffer.write_bits(SnPduType::ActivatePdpContextReject.into_raw(), 4);
        buffer.write_bits(self.nsapi as u64, 4);
        buffer.write_bits(self.activation_reject_cause as u64, 8);

        let obit = !self.type34_elements.is_empty();
        delimiters::write_obit(buffer, obit as u8);
        if obit {
            write_type34_chain(buffer, &self.type34_elements)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_dynamic_ipv4_demand() -> SnActivatePdpContextDemand {
        SnActivatePdpContextDemand {
            sndcp_version: 1,
            nsapi: 1,
            address_type_identifier: AddressTypeIdentifierInDemand::Ipv4Dynamic,
            ipv4_address: None,
            primary_nsapi: None,
            packet_data_ms_type: PacketDataMsType::TypeA,
            pcomp_negotiation: 0,
            vj_compression_state_slots: None,
            ip_header_compression_state_slots_tcp: None,
            ip_header_compression_state_slots_non_tcp: None,
            maximum_interval_between_full_headers: None,
            maximum_time_interval_between_full_headers: None,
            largest_header_size: None,
            access_point_name_index: None,
            type34_elements: Vec::new(),
        }
    }

    #[test]
    fn activate_demand_dynamic_ipv4_minimal_bit_layout() {
        let pdu = minimal_dynamic_ipv4_demand();

        let mut encoded = BitBuffer::new_autoexpand(32);
        pdu.to_bitbuf(&mut encoded).unwrap();

        assert_eq!(encoded.to_bitstr(), "0000000100010010000000000000");

        encoded.seek(0);
        let decoded = SnActivatePdpContextDemand::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn activate_demand_with_access_point_name_writes_final_mbit() {
        let pdu = SnActivatePdpContextDemand {
            access_point_name_index: Some(0x1234),
            ..minimal_dynamic_ipv4_demand()
        };

        let mut encoded = BitBuffer::new_autoexpand(64);
        pdu.to_bitbuf(&mut encoded).unwrap();

        assert_eq!(
            encoded.to_bitstr(),
            "0000000100010010000000000001".to_owned() + "1" + "0001001000110100" + "0"
        );

        encoded.seek(0);
        let decoded = SnActivatePdpContextDemand::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn protocol_configuration_options_ppp_chap_layout() {
        let pco = SndcpProtocolConfigurationOptions {
            configuration_protocol: PCO_CONFIGURATION_PROTOCOL_PPP,
            protocols: vec![SndcpProtocolConfigurationUnit {
                protocol_identity: PCO_PROTOCOL_CHAP,
                contents: vec![0x01, 0x02, 0x00, 0x04],
            }],
        };

        let element = pco.to_type34_element().unwrap();
        assert_eq!(element.element_id, TYPE34_ELEMENT_PROTOCOL_CONFIGURATION_OPTIONS);
        assert_eq!(element.len_bits, 60);

        let mut bits = BitBuffer::from_bytes(&element.data);
        bits.set_raw_end(element.len_bits);
        assert_eq!(
            bits.to_bitstr(),
            [
                "0000",                             // PPP configuration protocol
                "1100001000100011",                 // CHAP protocol identity 0xC223
                "00000100",                         // contents length in octets
                "00000001000000100000000000000100", // CHAP packet bytes
            ]
            .concat()
        );

        let decoded = SndcpProtocolConfigurationOptions::from_type34_element(&element).unwrap().unwrap();
        assert_eq!(decoded, pco);
    }

    #[test]
    fn activate_accept_dynamic_ipv4_minimal_bit_layout() {
        let pdu = SnActivatePdpContextAccept {
            nsapi: 1,
            pdu_priority_max: 4,
            ready_timer: 8,
            standby_timer: 4,
            response_wait_timer: 5,
            type_identifier_in_accept: TypeIdentifierInAccept::Ipv4Dynamic,
            ipv4_address: Some(0x0A000002),
            pcomp_negotiation: 0,
            vj_compression_state_slots: None,
            ip_header_compression_state_slots_tcp: None,
            ip_header_compression_state_slots_non_tcp: None,
            maximum_interval_between_full_headers: None,
            maximum_time_interval_between_full_headers: None,
            largest_header_size: None,
            maximum_transmission_unit: 4,
            sndcp_network_endpoint_identifier: None,
            swmi_ipv6_information: None,
            swmi_mobile_ipv4_information: None,
            type34_elements: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(80);
        pdu.to_bitbuf(&mut encoded).unwrap();

        let expected = [
            "0000",                             // SN PDU type
            "0001",                             // NSAPI
            "100",                              // PDU priority max
            "1000",                             // READY timer
            "0100",                             // STANDBY timer
            "0101",                             // RESPONSE_WAIT timer
            "010",                              // dynamic IPv4
            "00001010000000000000000000000010", // 10.0.0.2
            "00000000",                         // no PCOMP
            "100",                              // MTU 1500
            "0",                                // no optional elements
        ]
        .concat();
        assert_eq!(encoded.to_bitstr(), expected);

        encoded.seek(0);
        let decoded = SnActivatePdpContextAccept::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }

    #[test]
    fn activate_reject_minimal_bit_layout() {
        let pdu = SnActivatePdpContextReject {
            nsapi: 1,
            activation_reject_cause: 2,
            type34_elements: Vec::new(),
        };

        let mut encoded = BitBuffer::new_autoexpand(24);
        pdu.to_bitbuf(&mut encoded).unwrap();

        assert_eq!(encoded.to_bitstr(), "00110001000000100");

        encoded.seek(0);
        let decoded = SnActivatePdpContextReject::from_bitbuf(&mut encoded).unwrap();
        assert_eq!(decoded, pdu);
        assert_eq!(encoded.get_len_remaining(), 0);
    }
}
