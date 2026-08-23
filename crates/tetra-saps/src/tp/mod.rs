use tetra_core::{BitBuffer, BurstType, PhyBlockNum, PhyBlockType, SoftBit, TdmaTime, TrainingSequence};

#[derive(Debug, Clone)]
pub struct TpUnitdataInd {
    /// Exact TDMA time of the received uplink burst, captured by PHY.
    /// Consumers must not reconstruct this from their own local clock.
    pub ul_time: TdmaTime,
    pub train_type: TrainingSequence,
    pub burst_type: BurstType,
    pub block_type: PhyBlockType,
    /// Undefined for BBK. For all others: [ Block1 | Block2 | Both ]
    pub block_num: PhyBlockNum,
    /// Optional signed reliability for every bit in `block`.
    pub soft_bits: Option<Vec<SoftBit>>,
    pub block: BitBuffer,
}

#[derive(Debug, Clone)]
pub struct TpUnitdataReqSlot {
    pub train_type: TrainingSequence,
    pub burst_type: BurstType,
    pub bbk: Option<BitBuffer>,
    pub blk1: Option<BitBuffer>,
    pub blk2: Option<BitBuffer>,
}
