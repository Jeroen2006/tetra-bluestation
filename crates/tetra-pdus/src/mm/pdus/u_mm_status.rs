use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::typed_pdu_fields::{Type3FieldGeneric, delimiters, typed};
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::status_uplink::StatusUplink;
use crate::mm::enums::type34_elem_id_ul::MmType34ElemIdUl;
use crate::mm::fields::dm_ms_address::DmMsAddress;
use crate::mm::fields::dmo_carrier::DmoCarrier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UMmStatusGatewayPayload {
    Start {
        addresses: Vec<DmMsAddress>,
        dmo_carrier: Option<DmoCarrier>,
    },
    Continue {
        dmo_carrier: Option<DmoCarrier>,
    },
    Addresses(Vec<DmMsAddress>),
    Empty,
}

/// U-MM STATUS (TS 100 392-2 16.9.3.5 and EN 300 396-5 annex B).
#[derive(Debug)]
pub struct UMmStatus {
    pub status_uplink: StatusUplink,
    /// Kept for existing non-gateway status consumers.
    pub status_uplink_dependent_information: Option<u64>,
    pub status_uplink_dependent_information_len: Option<usize>,
    pub gateway_payload: Option<UMmStatusGatewayPayload>,
    /// Annex B optional Type-3 proprietary information.
    pub proprietary: Option<Type3FieldGeneric>,
}

impl UMmStatus {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeUl::UMmStatus)?;
        let value = buffer.read_field(6, "status_uplink")?;
        let status_uplink = StatusUplink::try_from(value).map_err(|_| PduParseErr::InvalidValue {
            field: "status_uplink",
            value,
        })?;
        let bits_left = buffer.get_len_remaining();
        let (gateway_payload, proprietary) = match status_uplink {
            StatusUplink::RequestToStartDmGatewayOperation => {
                read_reserved(buffer)?;
                let addresses = read_addresses(buffer)?;
                let (dmo_carrier, proprietary) = read_gateway_optionals(buffer)?;
                (Some(UMmStatusGatewayPayload::Start { addresses, dmo_carrier }), proprietary)
            }
            StatusUplink::RequestToContinuedmGatewayOperation => {
                read_reserved(buffer)?;
                let (dmo_carrier, proprietary) = read_gateway_optionals(buffer)?;
                (Some(UMmStatusGatewayPayload::Continue { dmo_carrier }), proprietary)
            }
            StatusUplink::RequestToAddDmMsAddresses
            | StatusUplink::RequestToRemoveDmMsAddresses
            | StatusUplink::RequestToReplaceDmMsAddresses => {
                read_reserved(buffer)?;
                let addresses = read_addresses(buffer)?;
                let (_, proprietary) = read_gateway_optionals(buffer)?;
                (Some(UMmStatusGatewayPayload::Addresses(addresses)), proprietary)
            }
            StatusUplink::RequestToStopDmGatewayOperation
            | StatusUplink::AcceptanceToRemovalOfDmMsAddresses
            | StatusUplink::AcceptanceToChangeRegistrationLabel
            | StatusUplink::AcceptanceToStopDmGatewayOperation => {
                read_reserved(buffer)?;
                let (_, proprietary) = read_gateway_optionals(buffer)?;
                (Some(UMmStatusGatewayPayload::Empty), proprietary)
            }
            _ => (None, None),
        };
        let status_uplink_dependent_information = if gateway_payload.is_none() && bits_left > 0 {
            Some(buffer.read_field(bits_left, "status_uplink_dependent_information")?)
        } else {
            None
        };
        Ok(Self {
            status_uplink,
            status_uplink_dependent_information,
            status_uplink_dependent_information_len: (gateway_payload.is_none() && bits_left > 0).then_some(bits_left),
            gateway_payload,
            proprietary,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeUl::UMmStatus.into_raw(), 4);
        buffer.write_bits(self.status_uplink.into_raw(), 6);
        if let Some(payload) = &self.gateway_payload {
            write_gateway_payload(self.status_uplink, payload, &self.proprietary, buffer)?;
        } else if let Some(value) = self.status_uplink_dependent_information {
            buffer.write_bits(
                value,
                self.status_uplink_dependent_information_len.ok_or(PduParseErr::FieldNotPresent {
                    field: Some("status_uplink_dependent_information_len"),
                })?,
            );
        }
        Ok(())
    }
}

fn read_addresses(buffer: &mut BitBuffer) -> Result<Vec<DmMsAddress>, PduParseErr> {
    let count = buffer.read_field(4, "number_of_dm_ms_addresses")? as usize;
    (0..count).map(|_| DmMsAddress::from_bitbuf(buffer)).collect()
}
fn write_addresses(addresses: &[DmMsAddress], buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    if addresses.len() > 15 {
        return Err(PduParseErr::InvalidValue {
            field: "number_of_dm_ms_addresses",
            value: addresses.len() as u64,
        });
    }
    buffer.write_bits(addresses.len() as u64, 4);
    for address in addresses {
        address.to_bitbuf(buffer)?;
    }
    Ok(())
}
fn read_reserved(buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    let reserved = buffer.read_field(8, "reserved")?;
    if reserved != 0 {
        return Err(PduParseErr::InvalidValue {
            field: "reserved",
            value: reserved,
        });
    }
    Ok(())
}
fn read_gateway_optionals(buffer: &mut BitBuffer) -> Result<(Option<DmoCarrier>, Option<Type3FieldGeneric>), PduParseErr> {
    let obit = delimiters::read_obit(buffer)?;
    let dmo_carrier = typed::parse_type2_struct(obit, buffer, DmoCarrier::from_bitbuf)?;
    let proprietary = typed::parse_type3_generic(obit, buffer, MmType34ElemIdUl::Proprietary)?;
    if obit && buffer.read_field(1, "trailing_mbit")? != 0 {
        return Err(PduParseErr::InvalidTrailingMbitValue);
    }
    Ok((dmo_carrier, proprietary))
}
fn write_gateway_optionals(
    dmo_carrier: &Option<DmoCarrier>,
    proprietary: &Option<Type3FieldGeneric>,
    buffer: &mut BitBuffer,
) -> Result<(), PduParseErr> {
    let obit = dmo_carrier.is_some() || proprietary.is_some();
    delimiters::write_obit(buffer, obit as u8);
    if !obit {
        return Ok(());
    }
    typed::write_type2_struct(obit, buffer, dmo_carrier, DmoCarrier::to_bitbuf)?;
    typed::write_type3_generic(obit, buffer, proprietary, MmType34ElemIdUl::Proprietary)?;
    delimiters::write_mbit(buffer, 0);
    Ok(())
}
fn write_gateway_payload(
    status: StatusUplink,
    payload: &UMmStatusGatewayPayload,
    proprietary: &Option<Type3FieldGeneric>,
    buffer: &mut BitBuffer,
) -> Result<(), PduParseErr> {
    match (status, payload) {
        (StatusUplink::RequestToStartDmGatewayOperation, UMmStatusGatewayPayload::Start { addresses, dmo_carrier }) => {
            buffer.write_bits(0, 8);
            write_addresses(addresses, buffer)?;
            write_gateway_optionals(dmo_carrier, proprietary, buffer)?;
        }
        (StatusUplink::RequestToContinuedmGatewayOperation, UMmStatusGatewayPayload::Continue { dmo_carrier }) => {
            buffer.write_bits(0, 8);
            write_gateway_optionals(dmo_carrier, proprietary, buffer)?;
        }
        (
            StatusUplink::RequestToAddDmMsAddresses
            | StatusUplink::RequestToRemoveDmMsAddresses
            | StatusUplink::RequestToReplaceDmMsAddresses,
            UMmStatusGatewayPayload::Addresses(addresses),
        ) => {
            buffer.write_bits(0, 8);
            write_addresses(addresses, buffer)?;
            write_gateway_optionals(&None, proprietary, buffer)?;
        }
        (
            StatusUplink::RequestToStopDmGatewayOperation
            | StatusUplink::AcceptanceToRemovalOfDmMsAddresses
            | StatusUplink::AcceptanceToChangeRegistrationLabel
            | StatusUplink::AcceptanceToStopDmGatewayOperation,
            UMmStatusGatewayPayload::Empty,
        ) => {
            buffer.write_bits(0, 8);
            write_gateway_optionals(&None, proprietary, buffer)?;
        }
        _ => {
            return Err(PduParseErr::InvalidValue {
                field: "gateway_status_payload",
                value: status.into_raw(),
            });
        }
    }
    Ok(())
}

impl fmt::Display for UMmStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UMmStatus {{ status_uplink: {:?}, gateway_payload: {:?} }}",
            self.status_uplink, self.gateway_payload
        )
    }
}
