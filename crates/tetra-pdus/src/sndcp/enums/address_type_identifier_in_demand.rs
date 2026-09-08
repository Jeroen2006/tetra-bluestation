use core::fmt;

use tetra_core::pdu_parse_error::PduParseErr;

/// Address Type Identifier in Demand, ETSI EN 300 392-2 table 28.51.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressTypeIdentifierInDemand {
    Ipv4Static = 0,
    Ipv4Dynamic = 1,
    Ipv6 = 2,
    MobileIpv4ForeignAgent = 3,
    MobileIpv4CoLocated = 4,
    PrimaryNsapiForSecondaryPdp = 5,
}

impl TryFrom<u64> for AddressTypeIdentifierInDemand {
    type Error = PduParseErr;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AddressTypeIdentifierInDemand::Ipv4Static),
            1 => Ok(AddressTypeIdentifierInDemand::Ipv4Dynamic),
            2 => Ok(AddressTypeIdentifierInDemand::Ipv6),
            3 => Ok(AddressTypeIdentifierInDemand::MobileIpv4ForeignAgent),
            4 => Ok(AddressTypeIdentifierInDemand::MobileIpv4CoLocated),
            5 => Ok(AddressTypeIdentifierInDemand::PrimaryNsapiForSecondaryPdp),
            found => Err(PduParseErr::InvalidElemId { found }),
        }
    }
}

impl AddressTypeIdentifierInDemand {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for AddressTypeIdentifierInDemand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
