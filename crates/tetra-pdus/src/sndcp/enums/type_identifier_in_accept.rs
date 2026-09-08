use core::fmt;

use tetra_core::pdu_parse_error::PduParseErr;

/// Type Identifier in Accept, ETSI EN 300 392-2 table 28.126.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeIdentifierInAccept {
    NoAddress = 0,
    Ipv4Static = 1,
    Ipv4Dynamic = 2,
}

impl TryFrom<u64> for TypeIdentifierInAccept {
    type Error = PduParseErr;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TypeIdentifierInAccept::NoAddress),
            1 => Ok(TypeIdentifierInAccept::Ipv4Static),
            2 => Ok(TypeIdentifierInAccept::Ipv4Dynamic),
            found => Err(PduParseErr::InvalidElemId { found }),
        }
    }
}

impl TypeIdentifierInAccept {
    pub fn into_raw(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for TypeIdentifierInAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
