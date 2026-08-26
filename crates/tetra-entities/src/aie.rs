//! BS-facing AIE API.
//!
//! The implementation lives with the runtime configuration so only that
//! central provider can access the SCK. Entities use key-free core
//! request/context types. The future crypto boundary will be implemented in
//! this provider rather than exposing SCK bytes to an entity or SAP.

pub use tetra_config::bluestation::{AieContextError, BsAieKeyProvider};
use tetra_core::{AieRequest, AieScope, AieSubject};

/// Bootstrap MM PDUs intentionally remain clear until the MAC AIE path is
/// connected. This is explicit policy, never an implicit SC1 fallback.
pub const fn clear_mm_request(issi: u32) -> AieRequest {
    AieRequest::clear(AieSubject::Individual { issi }, AieScope::BasicLink)
}

/// A key-free request for an SC2 protected individual MAC resource. UMAC must
/// supply the actual direction and final TDMA time to the central provider.
pub const fn sc2_resource_request(issi: u32) -> AieRequest {
    AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource)
}
