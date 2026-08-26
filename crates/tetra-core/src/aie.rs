//! Key-free Air Interface Encryption context carried between stack layers.
//!
//! An [`AieContext`] identifies *what* must be protected and at which exact
//! air-interface time. It intentionally contains no key bytes and is safe to
//! carry in SAP primitives and diagnostic metadata.

use crate::TdmaTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AieDirection {
    Uplink,
    Downlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AieAlgorithm {
    Tea1,
    Tea3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sc2KeyIdentifier {
    pub algorithm: AieAlgorithm,
    pub sckn: u8,
    pub sck_vn: u16,
}

impl Sc2KeyIdentifier {
    pub const fn new(algorithm: AieAlgorithm, sckn: u8, sck_vn: u16) -> Option<Self> {
        if sckn > 31 {
            return None;
        }
        Some(Self { algorithm, sckn, sck_vn })
    }
}

/// Stable identity of the air-interface peer or circuit. A group or call does
/// not imply E2EE; it only identifies the SC2 AIE context to be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AieSubject {
    /// Cell-wide broadcast/control signalling that is deliberately not bound
    /// to an individual terminal or call.
    System,
    Individual {
        issi: u32,
    },
    Group {
        gssi: u32,
    },
    Call {
        call_id: u32,
        issi: Option<u32>,
        gssi: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AieScope {
    MacResource,
    MacData,
    MacFragment,
    BasicLink,
    Facch,
    Traffic,
}

/// Contiguous type-1 bit range covered by AIE.  This is protocol metadata,
/// not key material: it tells LMAC which clear header/fill bits it must leave
/// untouched after the exact burst time is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AieCipherRegion {
    pub start: usize,
    pub len: usize,
}

impl AieCipherRegion {
    pub const fn new(start: usize, len: usize) -> Self {
        Self { start, len }
    }
}

/// Policy request from an upper layer. It deliberately has no TDMA time: UMAC
/// binds it only when the actual transmit/receive slot is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AieRequest {
    Clear { subject: AieSubject, scope: AieScope },
    Sc2 { subject: AieSubject, scope: AieScope },
}

impl AieRequest {
    pub const fn clear(subject: AieSubject, scope: AieScope) -> Self {
        Self::Clear { subject, scope }
    }

    pub const fn sc2(subject: AieSubject, scope: AieScope) -> Self {
        Self::Sc2 { subject, scope }
    }

    /// Retain the policy/subject while selecting the concrete MAC region that
    /// is about to be sent.  UMAC uses this when a MAC-RESOURCE turns into a
    /// sequence of MAC-FRAG/MAC-END PDUs.
    pub const fn with_scope(self, scope: AieScope) -> Self {
        match self {
            Self::Clear { subject, .. } => Self::clear(subject, scope),
            Self::Sc2 { subject, .. } => Self::sc2(subject, scope),
        }
    }

    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Sc2 { .. })
    }

    /// Returns whether two requests require the same on-air protection.  The
    /// MAC scope can differ between a received `MAC-DATA` and its returning
    /// BL-ACK, but the ciphering state itself must be identical.
    pub fn same_protection_as(self, other: Self) -> bool {
        match (self, other) {
            // A clear bootstrap/control PDU can legitimately use `System`
            // as its originating subject while the return MAC-DATA is bound
            // to the responding ISSI.  The protection state is still the
            // same: neither side uses a cipher context.
            (Self::Clear { .. }, Self::Clear { .. }) => true,
            (Self::Sc2 { subject: left, .. }, Self::Sc2 { subject: right, .. }) => left == right,
            _ => false,
        }
    }
}

/// Fully bound air-interface context for one direction and one exact TDMA
/// slot. This is the only AIE type that may cross the UMAC/LMAC boundary.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AieContext {
    Clear {
        subject: AieSubject,
        direction: AieDirection,
        time: TdmaTime,
        scope: AieScope,
    },
    Sc2 {
        subject: AieSubject,
        direction: AieDirection,
        time: TdmaTime,
        scope: AieScope,
        key: Sc2KeyIdentifier,
    },
}

impl AieContext {
    pub const fn system_clear(direction: AieDirection, time: TdmaTime, scope: AieScope) -> Self {
        Self::clear(AieSubject::System, direction, time, scope)
    }
    pub const fn clear(subject: AieSubject, direction: AieDirection, time: TdmaTime, scope: AieScope) -> Self {
        Self::Clear {
            subject,
            direction,
            time,
            scope,
        }
    }

    pub const fn sc2(subject: AieSubject, direction: AieDirection, time: TdmaTime, scope: AieScope, key: Sc2KeyIdentifier) -> Self {
        Self::Sc2 {
            subject,
            direction,
            time,
            scope,
            key,
        }
    }

    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::Sc2 { .. })
    }

    pub const fn time(self) -> TdmaTime {
        match self {
            Self::Clear { time, .. } | Self::Sc2 { time, .. } => time,
        }
    }
}
