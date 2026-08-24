use core::fmt;

use tetra_core::expect_pdu_type;
use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

use crate::mm::enums::mm_pdu_type_dl::MmPduTypeDl;
use crate::mm::enums::status_downlink::StatusDownlink;
use crate::mm::fields::dm_ms_address::DmMsAddress;
use crate::mm::fields::energy_saving_information::EnergySavingInformation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DMmStatusGatewayPayload {
    RejectedAddresses(Vec<DmMsAddress>),
    RetainedAddressSet(bool),
    RemoveAddresses(Vec<DmMsAddress>),
    Empty,
}

/// D-MM STATUS (TS 100 392-2 16.9.2.5 and EN 300 396-5 annex B).
#[derive(Debug)]
pub struct DMmStatus {
    pub status_downlink: StatusDownlink,
    pub energy_saving_information: Option<EnergySavingInformation>,
    pub gateway_payload: Option<DMmStatusGatewayPayload>,
}

impl DMmStatus {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let pdu_type = buffer.read_field(4, "pdu_type")?;
        expect_pdu_type!(pdu_type, MmPduTypeDl::DMmStatus)?;
        let value = buffer.read_field(6, "status_downlink")?;
        let status_downlink = StatusDownlink::try_from(value).map_err(|_| PduParseErr::InvalidValue {
            field: "status_downlink",
            value,
        })?;
        let (energy_saving_information, gateway_payload) = match status_downlink {
            StatusDownlink::ChangeOfEnergySavingModeRequest | StatusDownlink::ChangeOfEnergySavingModeResponse => {
                (Some(EnergySavingInformation::from_bitbuf(buffer)?), None)
            }
            StatusDownlink::AcceptanceToStartDmGatewayOperation | StatusDownlink::AcceptanceOfDmMsAddresses => {
                (None, Some(DMmStatusGatewayPayload::RejectedAddresses(read_addresses(buffer)?)))
            }
            StatusDownlink::AcceptanceToContinueDmGatewayOperation => {
                let retained = buffer.read_field(1, "retained_dm_ms_address_set")? != 0;
                let reserved = buffer.read_field(7, "reserved")?;
                if reserved != 0 {
                    return Err(PduParseErr::InvalidValue {
                        field: "reserved",
                        value: reserved,
                    });
                }
                (None, Some(DMmStatusGatewayPayload::RetainedAddressSet(retained)))
            }
            StatusDownlink::CommandToRemoveDmMsAddresses => (None, Some(DMmStatusGatewayPayload::RemoveAddresses(read_addresses(buffer)?))),
            StatusDownlink::RejectionToStartDmGatewayOperation
            | StatusDownlink::RejectionToContinueDmGatewayOperation
            | StatusDownlink::AcceptanceToStopDmGatewayOperation
            | StatusDownlink::CommandToChangeRegistrationLabel
            | StatusDownlink::CommandToStopDmGatewayOperation => (None, Some(DMmStatusGatewayPayload::Empty)),
            _ => (None, None),
        };
        Ok(Self {
            status_downlink,
            energy_saving_information,
            gateway_payload,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(MmPduTypeDl::DMmStatus.into_raw(), 4);
        buffer.write_bits(self.status_downlink.into_raw(), 6);
        match self.status_downlink {
            StatusDownlink::ChangeOfEnergySavingModeRequest | StatusDownlink::ChangeOfEnergySavingModeResponse => self
                .energy_saving_information
                .as_ref()
                .ok_or(PduParseErr::FieldNotPresent {
                    field: Some("energy_saving_information"),
                })?
                .to_bitbuf(buffer)?,
            _ => {
                if let Some(payload) = &self.gateway_payload {
                    write_gateway_payload(self.status_downlink, payload, buffer)?;
                }
            }
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
fn write_gateway_payload(status: StatusDownlink, payload: &DMmStatusGatewayPayload, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
    match (status, payload) {
        (
            StatusDownlink::AcceptanceToStartDmGatewayOperation | StatusDownlink::AcceptanceOfDmMsAddresses,
            DMmStatusGatewayPayload::RejectedAddresses(addresses),
        ) => write_addresses(addresses, buffer)?,
        (StatusDownlink::AcceptanceToContinueDmGatewayOperation, DMmStatusGatewayPayload::RetainedAddressSet(retained)) => {
            buffer.write_bits(*retained as u64, 1);
            buffer.write_bits(0, 7);
        }
        (StatusDownlink::CommandToRemoveDmMsAddresses, DMmStatusGatewayPayload::RemoveAddresses(addresses)) => {
            write_addresses(addresses, buffer)?
        }
        (
            StatusDownlink::RejectionToStartDmGatewayOperation
            | StatusDownlink::RejectionToContinueDmGatewayOperation
            | StatusDownlink::AcceptanceToStopDmGatewayOperation
            | StatusDownlink::CommandToChangeRegistrationLabel
            | StatusDownlink::CommandToStopDmGatewayOperation,
            DMmStatusGatewayPayload::Empty,
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

impl fmt::Display for DMmStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DMmStatus {{ status_downlink: {}, gateway_payload: {:?} }}",
            self.status_downlink, self.gateway_payload
        )
    }
}
