use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::mm_pdu_type_ul::MmPduTypeUl;
use crate::mm::enums::status_uplink::StatusUplink;
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
        let gateway_payload = match status_uplink {
            StatusUplink::RequestToStartDmGatewayOperation => Some(UMmStatusGatewayPayload::Start {
                addresses: read_addresses(buffer)?,
                dmo_carrier: read_optional_dmo_carrier(buffer)?,
            }),
            StatusUplink::RequestToContinuedmGatewayOperation => Some(UMmStatusGatewayPayload::Continue {
                dmo_carrier: read_optional_dmo_carrier(buffer)?,
            }),
            StatusUplink::RequestToAddDmMsAddresses
            | StatusUplink::RequestToRemoveDmMsAddresses
            | StatusUplink::RequestToReplaceDmMsAddresses => Some(UMmStatusGatewayPayload::Addresses(read_addresses(buffer)?)),
            StatusUplink::RequestToStopDmGatewayOperation
            | StatusUplink::AcceptanceToRemovalOfDmMsAddresses
            | StatusUplink::AcceptanceToChangeRegistrationLabel
            | StatusUplink::AcceptanceToStopDmGatewayOperation => Some(UMmStatusGatewayPayload::Empty),
            _ => None,
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
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeUl::UMmStatus.into_raw(), 4);
        buffer.write_bits(self.status_uplink.into_raw(), 6);
        if let Some(payload) = &self.gateway_payload {
            write_gateway_payload(self.status_uplink, payload, buffer)?;
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
fn read_optional_dmo_carrier(buffer: &mut BitBuffer) -> Result<Option<DmoCarrier>, PduParseErr> {
    match buffer.get_len_remaining() {
        0 => Ok(None),
        13 | 25 => DmoCarrier::from_bitbuf(buffer).map(Some),
        bits => Err(PduParseErr::InvalidValue {
            field: "dmo_carrier_length",
            value: bits as u64,
        }),
    }
}
fn write_gateway_payload(status: StatusUplink, payload: &UMmStatusGatewayPayload, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    match (status, payload) {
        (StatusUplink::RequestToStartDmGatewayOperation, UMmStatusGatewayPayload::Start { addresses, dmo_carrier }) => {
            write_addresses(addresses, buffer)?;
            if let Some(carrier) = dmo_carrier {
                carrier.to_bitbuf(buffer)?;
            }
        }
        (StatusUplink::RequestToContinuedmGatewayOperation, UMmStatusGatewayPayload::Continue { dmo_carrier }) => {
            if let Some(carrier) = dmo_carrier {
                carrier.to_bitbuf(buffer)?;
            }
        }
        (
            StatusUplink::RequestToAddDmMsAddresses
            | StatusUplink::RequestToRemoveDmMsAddresses
            | StatusUplink::RequestToReplaceDmMsAddresses,
            UMmStatusGatewayPayload::Addresses(addresses),
        ) => write_addresses(addresses, buffer)?,
        (
            StatusUplink::RequestToStopDmGatewayOperation
            | StatusUplink::AcceptanceToRemovalOfDmMsAddresses
            | StatusUplink::AcceptanceToChangeRegistrationLabel
            | StatusUplink::AcceptanceToStopDmGatewayOperation,
            UMmStatusGatewayPayload::Empty,
        ) => {}
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
