pub mod enums;

use tetra_core::{AieCipherRegion, AieRequest, BitBuffer, PhyBlockNum, PhysicalChannel, TdmaTime, Todo};

use crate::tmv::enums::logical_chans::LogicalChannel;

// The TMV-UNITDATA request primitive shall be used to request the lower MAC to transmit a MAC block
#[derive(Debug, Clone)]
pub struct TmvUnitdataReq {
    pub mac_block: BitBuffer,
    pub logical_channel: LogicalChannel,
    pub scrambling_code: u32,
    /// Key-free AIE policy. LMAC binds it to the final physical TDMA time.
    pub air_interface_encryption: Option<AieRequest>,
    /// Type-1 region to cipher. MAC headers and fill remain clear.
    pub cipher_region: Option<AieCipherRegion>,
}

#[derive(Debug, Clone)]
pub struct TmvUnitdataReqSlot {
    /// Timeslot at which this block is to be transmitted
    pub ts: TdmaTime,
    pub ul_phy_chan: PhysicalChannel,

    /// First MAC block in this timeslot. May be received from LLC
    /// If none was received, UMAC auto-generates a SYNC SB1 broadcast block
    /// Can either fill a subslot or a full slot, depending on logical channel
    pub blk1: Option<TmvUnitdataReq>,

    /// Second MAC block, if blk1 is half-slot. May be received from LLC
    /// If none was received, UMAC auto-generates a SYSINFO block
    /// Can only be present if blk1 is not a full slot
    pub blk2: Option<TmvUnitdataReq>,

    /// The BBK block. We might consider letting the LMAC generate this automatically.
    pub bbk: Option<TmvUnitdataReq>,
}

/// The TMV-UNITDATA indication primitive shall be used by the lower MAC to deliver a received MAC block;
#[derive(Debug, Clone)]
pub struct TmvUnitdataInd {
    pub pdu: BitBuffer,

    /// While not in the spec, the Umac needs to know which block this is.
    /// For instance, in order to determine the owner of a UL halfslot containing a MAC-FRAG (which doesn't contain an SSI field)
    pub block_num: PhyBlockNum,

    pub logical_channel: LogicalChannel,

    /// Exact TDMA time captured by PHY for this uplink block. UMAC must use
    /// this for the SC2 IV, never an estimate from its scheduling clock.
    pub ul_time: TdmaTime,

    /// If no CRC is present on this message type (for example, for AACH), crc_pass is set to True
    pub crc_pass: bool,
    pub scrambling_code: u32,
}

/// Indicates a CRC-failed uplink control block that LMAC discarded.
/// UMAC uses common-channel SCH/HU failures for random-access load estimation.
#[derive(Debug, Clone, Copy)]
pub struct TmvCrcInd {
    pub logical_channel: LogicalChannel,
    pub block_num: PhyBlockNum,
    pub common_control: bool,
}

/// Clause 23.2.1
/// The TMV-CONFIGURE primitive shall be used to provide the lower MAC with information about the configuration
/// of the channel or about the format of a received slot.

#[derive(Debug, Clone, Default)]
pub struct TmvConfigureReq {
    // pub channel_info: Option<Todo>,
    /// Received from umac upon change of network information
    pub scrambling_code: Option<u32>,
    // Energy economy or part-time reception or napping information
    // pub energy_economy_info: Option<Todo>,
    pub is_traffic: Option<bool>,
    /// Used by Umac to signal Lmac that the second half of the slot is stolen
    pub blk2_stolen: Option<bool>,
    pub tch_type_and_interleaving_depth: Option<Todo>,
    // pub monitoring_pattern_info: Option<Todo>,
    /// NOTE time not usually passed down but convenient for detecting fr18 etc.
    pub time: Option<TdmaTime>,
    /// Active key-free traffic contexts for this radio slot. These are sent
    /// independently of a TX block so uplink decrypting uses PHY's receive
    /// time rather than a scheduler estimate.
    pub downlink_traffic_aie: Option<Option<AieRequest>>,
    pub uplink_traffic_aie: Option<Option<AieRequest>>,
}

#[derive(Debug, Clone)]
pub struct TmvConfigureConf {
    pub channel_info: Todo,
}
