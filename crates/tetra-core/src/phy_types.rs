//! PHY-layer types that are used across multiple layers
//!
//! These types originate from the PHY layer but are referenced by LMAC, UMAC,
//! and SAP primitives, so they live in tetra-core to avoid circular dependencies.

/// Signed confidence for a received bit: negative is 0, positive is 1, zero is
/// an erasure.  The magnitude is consumed by soft-decision Viterbi decoding.
pub type SoftBit = i8;

/// Raw RF measurements attached to one physical uplink burst. Floating-point
/// values stay inside the BS process; the SwMI wire format uses fixed point.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UplinkRfObservation {
    /// Distinguishes a full-slot burst (0) from control subslots (1 and 2).
    pub burst_index: u8,
    pub received_power_linear: f32,
    pub frequency_offset_hz: f32,
    pub training_error_bits: u16,
    pub training_bit_count: u16,
    pub training_evm_percent: f32,
    pub relative_arrival_symbols: f32,
}

/// Identifies which block(s) within a timeslot
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PhyBlockNum {
    /// Both half-slots combined (full slot)
    Both,
    /// First half-slot only
    Block1,
    /// Second half-slot only
    Block2,
    /// Block number not determined
    Undefined,
}

/// Physical block types
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PhyBlockType {
    BBK,
    /// TODO FIXME Merge SB1 and SB2 into SDB
    SB1,
    SB2,
    NDB,
    NUB,
    SSN1,
    SSN2,
}

/// Burst types (Clause 9.4.4.1)
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum BurstType {
    /// Control Uplink Burst
    CUB,
    /// Normal Uplink Burst
    NUB,
    /// Normal Downlink Burst (continuous and discontinuous)
    NDB,
    /// Synchronization Downlink Burst (continuous and discontinuous)
    SDB,
}

/// Training sequences
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum TrainingSequence {
    /// 22 n bits
    NormalTrainSeq1 = 1,
    /// 22 p bits
    NormalTrainSeq2 = 2,
    /// 22 q bits
    NormalTrainSeq3 = 3,
    /// 30 x bits
    ExtendedTrainSeq = 4,
    /// 38 y bits
    SyncTrainSeq = 5,
    /// Not found
    #[default]
    NotFound = 0,
}
