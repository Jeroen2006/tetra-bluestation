use core::fmt;

use tetra_core::pdu_parse_error::PduParseErr;

/// Packet data MS type, ETSI EN 300 392-2 table 28.97.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDataMsType {
    TypeA = 0,
    TypeB = 1,
    TypeC = 2,
    TypeD = 3,
}

impl TryFrom<u64> for PacketDataMsType {
    type Error = PduParseErr;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketDataMsType::TypeA),
            1 => Ok(PacketDataMsType::TypeB),
            2 => Ok(PacketDataMsType::TypeC),
            3 => Ok(PacketDataMsType::TypeD),
            found => Err(PduParseErr::InvalidElemId { found }),
        }
    }
}

impl PacketDataMsType {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for PacketDataMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
