use core::fmt;

use tetra_core::pdu_parse_error::PduParseErr;

/// SNDCP PDU type, ETSI EN 300 392-2 table 28.121.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnPduType {
    ActivatePdpContext = 0,
    DeactivatePdpContextAccept = 1,
    DeactivatePdpContextDemand = 2,
    ActivatePdpContextReject = 3,
    Unitdata = 4,
    Data = 5,
    DataTransmitRequest = 6,
    DataTransmitResponse = 7,
    EndOfData = 8,
    Reconnect = 9,
    Page = 10,
    NotSupported = 11,
    DataPriority = 12,
    Modify = 13,
}

impl TryFrom<u64> for SnPduType {
    type Error = PduParseErr;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SnPduType::ActivatePdpContext),
            1 => Ok(SnPduType::DeactivatePdpContextAccept),
            2 => Ok(SnPduType::DeactivatePdpContextDemand),
            3 => Ok(SnPduType::ActivatePdpContextReject),
            4 => Ok(SnPduType::Unitdata),
            5 => Ok(SnPduType::Data),
            6 => Ok(SnPduType::DataTransmitRequest),
            7 => Ok(SnPduType::DataTransmitResponse),
            8 => Ok(SnPduType::EndOfData),
            9 => Ok(SnPduType::Reconnect),
            10 => Ok(SnPduType::Page),
            11 => Ok(SnPduType::NotSupported),
            12 => Ok(SnPduType::DataPriority),
            13 => Ok(SnPduType::Modify),
            found => Err(PduParseErr::InvalidElemId { found }),
        }
    }
}

impl SnPduType {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for SnPduType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
