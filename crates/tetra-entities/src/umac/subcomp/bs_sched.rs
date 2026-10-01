use std::collections::{HashMap, HashSet};

use tetra_config::bluestation::{AieContextError, BsAieKeyProvider, RuntimeAieConfig, RuntimeOperatorSettings, RuntimeSc3Aie};
use tetra_core::{
    AieCipherRegion, AieContext, AieDirection, AieRequest, AieScope, AieSubject, BitBuffer, Direction, PhyBlockNum, PhysicalChannel,
    SsiType, TdmaTime, TetraAddress, Todo, TxReporter, unimplemented_log,
};
use tetra_saps::{
    control::call_control::Circuit,
    tmv::{TmvUnitdataReq, TmvUnitdataReqSlot, enums::logical_chans::LogicalChannel},
};

use crate::{
    lmac::components::scrambler,
    umac::subcomp::{bs_frag::BsFragger, circuit_mgr::CircuitMgr, fillbits},
};
use tetra_pdus::umac::enums::access_code::AccessCode;
use tetra_pdus::umac::structs::access_field::AccessField;
use tetra_pdus::umac::structs::base_frame_length::BaseFrameLength;
use tetra_pdus::{
    llc::enums::llc_pdu_type::LlcPduType,
    mle::pdus::{d_mle_sync::DMleSync, d_mle_sysinfo::DMleSysinfo},
    umac::{
        enums::{
            access_assign_dl_usage::AccessAssignDlUsage, access_assign_ul_usage::AccessAssignUlUsage,
            basic_slotgrant_cap_alloc::BasicSlotgrantCapAlloc, basic_slotgrant_granting_delay::BasicSlotgrantGrantingDelay,
            reservation_requirement::ReservationRequirement,
        },
        fields::basic_slotgrant::BasicSlotgrant,
        pdus::{
            access_assign::AccessAssign, access_assign_fr18::AccessAssignFr18, access_define::AccessDefine, mac_resource::MacResource,
            mac_sync::MacSync, mac_sysinfo::MacSysinfo,
        },
    },
};

use crate::umac::subcomp::random_access::{RandomAccessParameters, RandomAccessUpdate};

/// We submit this many TX timeslots ahead of the current time
pub const MACSCHED_TX_AHEAD: usize = 1;

// We schedule up to this many frames ahead
pub const MACSCHED_NUM_FRAMES: usize = 18;

const NULL_PDU_LEN_BITS: usize = 16;

pub const SCH_HD_CAP: usize = 124;
pub const SCH_F_CAP: usize = 268;
pub const TCH_S_CAP: usize = 274;

// The default access frame marker used in access fields
const DEFAULT_ACCESS_FRAME_MARKER: BaseFrameLength = BaseFrameLength::Subslots2;

/// Number of timeslots the scheduler operates on. May become larger when secondary carriers are supported.
pub const NUM_TIMESLOTS: usize = 4;

/// Values 14 and 15 have special meanings in the four-bit Basic slot
/// granting delay field, so an ordinary delayed opportunity is encodable only
/// through 13.
const MAX_BASIC_SLOT_GRANT_DELAY: usize = 13;

/// Capacity values that have an exact Basic slot granting encoding.
const EXACT_BASIC_SLOT_GRANT_CAPACITIES: [usize; 14] = [1, 2, 3, 4, 5, 6, 8, 10, 13, 17, 24, 34, 51, 68];

/// Keep an ordinary packet-data uplink turn within six TDMA frames.  This
/// leaves regular receive opportunities for a frequency-simplex terminal
/// without reducing a three-slot PDCH to one-slot grants.
const PACKET_DATA_UPLINK_TURN_TIMESLOTS: i32 = 6 * 4;

/// When downlink work is waiting for a frequency-simplex terminal, admit one
/// ordinary uplink slot per turn so both directions continue to make progress.
const PACKET_DATA_BIDIRECTIONAL_MAX_GRANT_SLOTS: usize = 1;

/// After the mandatory one-slot switching guard, leave one complete TDMA
/// frame in which the terminal can receive acknowledgements and service
/// signalling before announcing another uplink turn.
const PACKET_DATA_RECEIVE_TURN_TIMESLOTS: i32 = 4;

#[derive(Debug, Clone, Copy)]
struct PendingPacketDataGrant {
    addr: TetraAddress,
    bearer: (u64, u64),
    request_time: TdmaTime,
    remaining_slots: usize,
    is_halfslot: bool,
    continues_fragment: bool,
}

#[derive(Debug, Clone, Copy)]
struct PacketDataGrantWindow {
    bearer: (u64, u64),
    first_uplink: TdmaTime,
    last_uplink: TdmaTime,
    next_grant_downlink: TdmaTime,
}

/// Select the SYSINFO variant for an actual BNCH transmission.
///
/// EN 300 392-2 table 9.33 maps the mandatory frame-18 BNCH across all four
/// timeslots; the SYSINFO contents are not tied to that timeslot. Keep every
/// frame-18 occurrence on the hyperframe/default-access variant for robust
/// initial cell acquisition. On the additional BNCH opportunities in frames
/// 1..=17, alternate per pair of TDMA frames. In particular, TS1 emits BNCH
/// on its even frames in this scheduler, so FN2/FN6/FN10/FN14 carry default
/// access while FN4/FN8/FN12/FN16 carry Extended Services plus SCKN/SCK-VN.
fn use_default_access_sysinfo(time: TdmaTime) -> bool {
    !time.is_sc2_security_sysinfo_opportunity() && (time.f == 18 || ((time.f - 1) / 2) % 2 == 0)
}

/// Close a signalling MAC block with a valid Null PDU and/or fill bits.
///
/// A freshly allocated BitBuffer is zero-filled, but trailing zeroes are not a
/// valid MAC block termination. Return whether a Null PDU and fill bits were
/// inserted so callers can include the result in diagnostics.
fn finalize_downlink_mac_block(buf: &mut BitBuffer) -> (bool, bool) {
    let remaining = buf.get_len_remaining();
    if remaining == 0 {
        return (false, false);
    }

    let null_pdu_inserted = remaining >= NULL_PDU_LEN_BITS;
    if null_pdu_inserted {
        MacResource::null_pdu().to_bitbuf(buf);
    }

    let fill_bits_inserted = buf.get_len_remaining() > 0;
    if fill_bits_inserted {
        fillbits::addition::write(buf, None);
    }

    assert_eq!(buf.get_len_remaining(), 0, "signalling MAC block was not finalized");
    (null_pdu_inserted, fill_bits_inserted)
}

#[derive(Debug)]
pub struct PrecomputedUmacPdus {
    pub mac_sysinfo1: MacSysinfo,
    pub mac_sysinfo2: MacSysinfo,
    pub access_define: Option<AccessDefine>,
    pub access_define_interval_multiframes: u8,
    pub mle_sysinfo: DMleSysinfo,
    pub mac_sync: MacSync,
    pub mle_sync: DMleSync,
}

#[derive(Debug, Clone, Copy)]
pub struct TimeslotSchedule {
    pub ul1: Option<u32>,
    pub ul2: Option<u32>,
    // pub dl: Option<TmvUnitdataReq>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssociatedBestEffortKind {
    CallRepeat(u16),
    Frame18Broadcast(u32),
}

impl AssociatedBestEffortKind {
    fn is_frame18_only(self) -> bool {
        matches!(self, Self::Frame18Broadcast(_))
    }
}

#[derive(Debug)]
struct AssociatedBestEffortElem {
    kind: AssociatedBestEffortKind,
    elem: DlSchedElem,
}

/// One non-fragmentable GCK change demand that must occupy every
/// physical frame-18 immediately before a local SC3G activation.  This is
/// intentionally separate from the normal and best-effort queues: neither
/// call traffic nor packet data may delay `Immediate`.
#[derive(Clone)]
struct FinalGckRolloverImmediate {
    activation: TdmaTime,
    pdu: MacResource,
    sdu: BitBuffer,
    aie_request: AieRequest,
}

// #[derive(Debug)]
pub struct BsChannelScheduler {
    pub cur_dltime: TdmaTime,
    scrambling_code: u32,
    common_scch_count: u8,
    configured_no_minimum_mode: bool,
    force_common_sysinfo: bool,
    precomps: PrecomputedUmacPdus,
    /// Collect dltx traffic here that can't be sent this slot.
    /// Swapped back into the dltx_queues method at the end of the tick.
    dltx_next_slot_queue: Vec<DlSchedElem>,
    /// Four queues for scheduled downlink traffic, one per timeslot
    dltx_queues: [Vec<DlSchedElem>; 4],
    /// Downlink held for one frame because the addressed half-duplex terminal
    /// owns a physically overlapping packet-data uplink opportunity.
    dltx_half_duplex_queues: [Vec<DlSchedElem>; 4],
    /// Associated-control messages. These are consumed only in FN18 on an
    /// assigned channel and therefore never steal a normal speech frame.
    assoc_dltx_queues: [Vec<DlSchedElem>; 4],
    /// Expendable periodic associated repeats. Call repeats may also use an
    /// idle hangtime frame; network broadcasts are restricted to free FN18.
    /// Both classes remain below all ordinary assigned-channel signalling.
    assoc_best_effort_queues: [Vec<AssociatedBestEffortElem>; 4],
    /// One reservation for each physical TS.  The same air PDU is copied to
    /// TS1..TS4 on FN18, using the legal BSCH/SCH-HD and SCH-HD/BNCH mappings
    /// where the multiframe requires them.
    final_gck_rollover_immediate: [Option<FinalGckRolloverImmediate>; 4],
    ulsched: [[TimeslotSchedule; MACSCHED_NUM_FRAMES]; 4],
    /// Uplink reservations announced in an associated FN18 grant. They are
    /// kept separate from the ordinary 18-frame ring because the associated
    /// grant and its reserved control opportunity are built together.
    associated_ulsched: Vec<(TdmaTime, TimeslotSchedule)>,

    circuits: CircuitMgr,

    /// When true, the given timeslot is in call hangtime: keep circuit allocated but stop
    /// sending traffic-plane TCH blocks. Instead, transmit signalling-plane idle (Null PDUs)
    /// and signal UL usage as AssignedOnly so MS can request the floor.
    hangtime: [bool; 4],

    /// Per-timeslot set of SSIs whose RandomAccessAck was dropped by dl_drop_all_except_stolen.
    /// The next STCH built for a matching SSI should carry random_access_flag=true to properly
    /// acknowledge the random access per ETSI 21.4.3.1.
    pending_ra_acks: [Vec<u32>; 4],
    /// Raw base-frame-length encoding for unreserved common access fields.
    random_access_frame_len: u8,
    secondary_access: [Option<RandomAccessUpdate>; 2],
    aie_provider: Option<BsAieKeyProvider>,
    /// Key-free policy for the downlink speech portion of an active traffic
    /// circuit. A missing policy is deliberately not converted to clear.
    traffic_aie: [Option<AieRequest>; 4],
    /// Packet-data bearers use an assigned CP/SCH/F resource rather than a
    /// circuit-mode TCH. The generation fences delayed close commands after
    /// a voice call has already reused the physical slot.
    packet_bearers: [Option<(u64, u64)>; 4],
    /// Highest generation observed for each bearer id. Tombstones remain
    /// after close so a delayed Open cannot resurrect an older bearer.
    packet_bearer_generations: HashMap<u64, u64>,
    /// Latest unsatisfied total-capacity report per terminal.  Repeated MAC
    /// reservation requirements replace rather than add to this value.
    pending_packet_data_grants: HashMap<u32, PendingPacketDataGrant>,
    /// Complete basic-grant interval per terminal, including gaps caused by
    /// non-PDCH timeslots or CLCH.  A frequency-simplex terminal cannot
    /// receive addressed signalling inside this interval.
    packet_data_grant_windows: HashMap<u32, PacketDataGrantWindow>,
    /// Bearers in drain keep carrying their final downlink control, but no
    /// longer receive new ordinary packet-data uplink grants.
    draining_packet_bearers: HashSet<(u64, u64)>,
    packet_grant_round_robin_after: Option<u32>,
}

#[derive(Debug)]
pub enum DlSchedElem {
    /// A SYSINFO or neighboring cells info block. The integer determines which of the precomputed blocks to use (SYSINFO1, SYSINFO2, NEIGHBORING_CELLS
    Broadcast(Todo),

    /// A received MAC-ACCESS PDU still has to be acknowledged
    /// Address and protection state of the MAC-ACCESS being acknowledged.
    /// A standalone response must retain SC2/ESI state; it may not create a
    /// clear response merely because no upper-layer resource was queued.
    RandomAccessAck(TetraAddress, AieRequest),

    /// A slotgrant response, which has to be transmitted with high priority or the delay numbers will be off
    /// ssi and BasicSlotgrant are provided.
    Grant(TetraAddress, BasicSlotgrant),

    /// A MAC-RESOURCE PDU. May be split into fragments upon processing, in which case a FragBuf will be inserted after processing the resource.
    Resource(MacResource, BitBuffer, Option<TxReporter>, AieRequest, Option<[bool; 4]>),

    /// A capacity request received on an active assigned channel. The grant
    /// and its corresponding future FN18 reservation must be built together,
    /// when the actual associated FN18 transmission time is known.
    AssociatedGrantRequest(TetraAddress, ReservationRequirement, usize),

    /// A FragBuf containing remaining non-transmitted information after a MAC-RESOURCE start has been transmitted
    FragBuf(BsFragger, Option<[bool; 4]>),

    /// Pre-built STCH block for FACCH/stealing a half-slot from the traffic channel.
    /// Contains a 124-bit MAC-RESOURCE control block, for example a short
    /// floor-control PDU.
    Stealing(BitBuffer, Option<TxReporter>, AieRequest, Option<AieCipherRegion>),
}

impl DlSchedElem {
    fn is_cancelled(&self) -> bool {
        match self {
            Self::Resource(_, _, Some(reporter), _, _) | Self::Stealing(_, Some(reporter), ..) => reporter.is_discarded(),
            Self::FragBuf(fragger, _) => fragger.is_cancelled(),
            _ => false,
        }
    }

    fn is_original_advanced_data(&self) -> bool {
        matches!(
            self,
            Self::Resource(_, sdu, _, _, _)
                if sdu.peek_bits(4) == Some(LlcPduType::AlDataAlFinal.into_raw())
        )
    }
}

const EMPTY_SCHED_ELEM: TimeslotSchedule = TimeslotSchedule {
    ul1: None,
    ul2: None,
    // dl: None,
};
const EMPTY_SCHED_CHANNEL: [TimeslotSchedule; MACSCHED_NUM_FRAMES] = [EMPTY_SCHED_ELEM; MACSCHED_NUM_FRAMES];
const EMPTY_SCHED: [[TimeslotSchedule; MACSCHED_NUM_FRAMES]; 4] = [EMPTY_SCHED_CHANNEL; 4];

impl BsChannelScheduler {
    pub fn new(scrambling_code: u32, precomps: PrecomputedUmacPdus) -> Self {
        Self::new_inner(scrambling_code, precomps, None)
    }

    pub fn new_with_aie_provider(scrambling_code: u32, precomps: PrecomputedUmacPdus, aie_provider: BsAieKeyProvider) -> Self {
        Self::new_inner(scrambling_code, precomps, Some(aie_provider))
    }

    fn new_inner(scrambling_code: u32, precomps: PrecomputedUmacPdus, aie_provider: Option<BsAieKeyProvider>) -> Self {
        BsChannelScheduler {
            cur_dltime: TdmaTime { t: 0, f: 0, m: 0, h: 0 }, // Intentionally invalid, updated in tick function
            scrambling_code,
            common_scch_count: 0,
            configured_no_minimum_mode: precomps.mle_sysinfo.bs_service_details.no_minimum_mode,
            force_common_sysinfo: false,
            precomps,
            dltx_next_slot_queue: Vec::new(),
            dltx_queues: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            dltx_half_duplex_queues: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            assoc_dltx_queues: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            assoc_best_effort_queues: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            final_gck_rollover_immediate: std::array::from_fn(|_| None),
            ulsched: EMPTY_SCHED,
            associated_ulsched: Vec::new(),
            circuits: CircuitMgr::new(),
            hangtime: [false, false, false, false],
            pending_ra_acks: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
            secondary_access: [None; 2],
            random_access_frame_len: 4,
            aie_provider,
            traffic_aie: [None; 4],
            packet_bearers: [None; 4],
            packet_bearer_generations: HashMap::new(),
            pending_packet_data_grants: HashMap::new(),
            packet_data_grant_windows: HashMap::new(),
            draining_packet_bearers: HashSet::new(),
            packet_grant_round_robin_after: None,
        }
    }

    pub fn open_packet_bearer(&mut self, bearer_id: u64, generation: u64, bitmap: u8) -> bool {
        if self
            .packet_bearer_generations
            .get(&bearer_id)
            .is_some_and(|known| generation < *known)
        {
            return false;
        }
        self.packet_bearer_generations.insert(bearer_id, generation);
        self.draining_packet_bearers.retain(|(id, _)| *id != bearer_id);
        self.pending_packet_data_grants
            .retain(|_, request| request.bearer.0 != bearer_id || request.bearer.1 == generation);
        for slot in &mut self.packet_bearers {
            if slot.is_some_and(|(id, _)| id == bearer_id) {
                *slot = None;
            }
        }
        for timeslot in 2..=4 {
            if bitmap & (1 << (timeslot - 1)) != 0 {
                self.packet_bearers[timeslot as usize - 1] = Some((bearer_id, generation));
            }
        }
        self.discard_inactive_frame18_broadcasts();
        true
    }

    pub fn close_packet_bearer(&mut self, bearer_id: u64, generation: u64) -> bool {
        if self.packet_bearer_generations.get(&bearer_id) != Some(&generation) {
            return false;
        }
        for slot in &mut self.packet_bearers {
            if *slot == Some((bearer_id, generation)) {
                *slot = None;
            }
        }
        self.pending_packet_data_grants
            .retain(|_, request| request.bearer != (bearer_id, generation));
        self.draining_packet_bearers.remove(&(bearer_id, generation));
        self.discard_inactive_frame18_broadcasts();
        true
    }

    pub fn set_packet_bearer_draining(&mut self, bearer_id: u64, generation: u64) {
        if self.packet_bearers_match(bearer_id, generation) {
            self.draining_packet_bearers.insert((bearer_id, generation));
            self.pending_packet_data_grants
                .retain(|_, request| request.bearer != (bearer_id, generation));
        }
    }

    pub fn detach_packet_data_terminal(&mut self, issi: u32) {
        self.pending_packet_data_grants.remove(&issi);
    }

    pub fn packet_bearer_is_active(&self, timeslot: u8) -> bool {
        (2..=4).contains(&timeslot) && self.packet_bearers[timeslot as usize - 1].is_some()
    }

    pub fn packet_bearers_match(&self, bearer_id: u64, generation: u64) -> bool {
        self.packet_bearers.contains(&Some((bearer_id, generation)))
    }

    pub fn assigned_channel_is_active(&self, timeslot: u8) -> bool {
        self.packet_bearer_is_active(timeslot)
            || self.circuits.is_active(Direction::Dl, timeslot)
            || self.circuits.is_active(Direction::Ul, timeslot)
    }

    /// Return each physical TCH/PDCH on which an assigned MS may currently be
    /// listening. TS1 remains the MCCH and receives the original broadcast.
    pub fn active_assigned_channels(&self) -> Vec<u8> {
        (2..=4).filter(|timeslot| self.assigned_channel_is_active(*timeslot)).collect()
    }

    fn discard_inactive_frame18_broadcasts(&mut self) {
        for timeslot in 2..=4 {
            if !self.assigned_channel_is_active(timeslot) {
                self.assoc_best_effort_queues[timeslot as usize - 1].retain(|queued| !queued.kind.is_frame18_only());
            }
        }
    }

    /// Enter/leave hangtime for a traffic timeslot (2..=4).
    pub fn set_hangtime(&mut self, ts: u8, active: bool) {
        if !(1..=4).contains(&ts) {
            tracing::warn!("BsChannelScheduler::set_hangtime: invalid ts {}", ts);
            return;
        }

        let idx = ts as usize - 1;
        let was_active = self.hangtime[idx];
        if was_active == active {
            return;
        }
        self.hangtime[idx] = active;

        // EN 300 392-2 clauses 23.4.2.1.5/.6 let an MS continue downlink
        // reconstruction when the assigned channel changes between SACCH and
        // FACCH. Move the queued work with that mode change instead of
        // discarding it at the exact floor transition.
        let moved = if active {
            self.move_associated_control_to_facch(ts)
        } else {
            self.move_facch_control_to_sacch(ts)
        };
        if moved > 0 {
            tracing::info!(
                dltime = %self.cur_dltime,
                ts,
                moved,
                destination = if active { "FACCH" } else { "SACCH" },
                "preserved pending assigned-channel signalling across mode transition"
            );
        }

        tracing::info!(
            "BsChannelScheduler: hangtime {} for ts {}",
            if active { "ENABLED" } else { "DISABLED" },
            ts,
        );
    }

    /// Move normal associated signalling into the fast control queue when a
    /// traffic slot enters hangtime. Frames 1..17 are then available and the
    /// message should not remain blocked waiting for a SACCH acknowledgement
    /// grant that is deliberately unavailable in hangtime.
    fn move_associated_control_to_facch(&mut self, timeslot: u8) -> usize {
        let idx = timeslot as usize - 1;
        let queued = std::mem::take(&mut self.assoc_dltx_queues[idx]);
        let moved = queued.len();
        for mut elem in queued {
            if let DlSchedElem::FragBuf(fragger, _) = &mut elem {
                fragger.allow_ungranted_final_response();
            }
            self.dltx_queues[idx].push(elem);
        }
        moved
    }

    /// Move pending FACCH signalling into the frame-18 associated queue when
    /// speech resumes. FACCH slot grants from frames 1..17 are withdrawn by
    /// the mode change (Core TIP note 113), while their correlated random
    /// access acknowledgement remains meaningful on the migrated resource.
    fn move_facch_control_to_sacch(&mut self, timeslot: u8) -> usize {
        let idx = timeslot as usize - 1;
        let queued = std::mem::take(&mut self.dltx_queues[idx]);
        let mut moved = Vec::new();
        let mut acknowledgements = Vec::new();
        let mut kept = Vec::new();

        for elem in queued {
            match elem {
                elem @ (DlSchedElem::Resource(..) | DlSchedElem::FragBuf(..) | DlSchedElem::AssociatedGrantRequest(..)) => moved.push(elem),
                DlSchedElem::RandomAccessAck(address, _) => acknowledgements.push(address.ssi),
                DlSchedElem::Stealing(..) => kept.push(elem),
                DlSchedElem::Grant(..) | DlSchedElem::Broadcast(_) => {
                    tracing::debug!(
                        dltime = %self.cur_dltime,
                        ts = timeslot,
                        element = ?elem,
                        "discarding FACCH-only scheduling metadata while entering traffic mode"
                    );
                }
            }
        }

        for issi in acknowledgements {
            let matching_resource = moved.iter_mut().find_map(|elem| match elem {
                DlSchedElem::Resource(pdu, ..) if pdu.addr.is_some_and(|address| address.ssi == issi) => Some(pdu),
                _ => None,
            });
            if let Some(resource) = matching_resource {
                resource.random_access_flag = true;
            } else if !self.pending_ra_acks[idx].contains(&issi) {
                // A later FACCH/STCH response can still acknowledge this
                // access if no correlated resource was waiting right now.
                self.pending_ra_acks[idx].push(issi);
            }
        }

        let moved_count = moved.len();
        self.dltx_queues[idx] = kept;
        self.assoc_dltx_queues[idx].extend(moved);
        moved_count
    }

    pub fn is_hangtime(&self, ts: u8) -> bool {
        if !(1..=4).contains(&ts) {
            tracing::warn!("BsChannelScheduler::is_hangtime: invalid ts {}", ts);
            return false;
        }
        self.hangtime[ts as usize - 1]
    }

    /// A granted floor must be advertised as traffic before the queued FACCH
    /// D-TX GRANTED is emitted.  Otherwise an MS interprets NormalTrainSeq2
    /// as two signalling half-slots rather than STCH.
    pub fn begin_floor_grant_transition(&mut self, ts: u8, source_issi: u32) {
        if !(2..=4).contains(&ts) {
            tracing::warn!(ts, "floor grant transition requested for invalid traffic timeslot");
            return;
        }
        tracing::info!(ts, source_issi, "ending hangtime before FACCH D-TX GRANTED");
        self.set_hangtime(ts, false);
    }

    fn is_hangtime_effective(&self, ts: u8) -> bool {
        let idx = ts as usize - 1;
        if !self.hangtime[idx] {
            return false;
        }
        // If a stealing block is still queued for this slot, keep traffic mode
        // so it can be delivered via FACCH.
        !self.has_pending_stealing(ts)
    }

    fn has_pending_stealing(&self, ts: u8) -> bool {
        let slot = ts as usize - 1;
        self.dltx_queues
            .get(slot)
            .map(|q| q.iter().any(|e| matches!(e, DlSchedElem::Stealing(..))))
            .unwrap_or(false)
    }

    fn generate_hangtime_idle_schf(&self) -> BitBuffer {
        // Full-slot SCH/F carrying a Null PDU (idle).
        let mut buf = BitBuffer::new(SCH_F_CAP);
        let pdu = MacResource::null_pdu();
        pdu.to_bitbuf(&mut buf);
        buf
    }

    // pub fn set_scrambling_code(&mut self, scrambling_code: u32) {
    //     self.scrambling_code = scrambling_code;
    //     unimplemented!("need to refresh some msgs possibly");
    // }

    pub fn broadcast_parameters(&self) -> &PrecomputedUmacPdus {
        &self.precomps
    }

    // pub fn set_precomputed_msgs(&mut self, precomps: PrecomputedUmacPdus) {
    //     self.precomps = precomps;
    //     unimplemented!("need to refresh some msgs possibly");
    // }

    /// Update the System Wide Services flag in the broadcast SYSINFO.
    pub fn set_system_wide_services_state(&mut self, enabled: bool) {
        if self.precomps.mle_sysinfo.bs_service_details.system_wide_services != enabled {
            self.precomps.mle_sysinfo.bs_service_details.system_wide_services = enabled;
            // Should already be signalled at SwMI interface level
            tracing::debug!(
                "BsChannelScheduler: system_wide_services {}",
                if enabled { "ENABLED" } else { "DISABLED" }
            );
        }
    }

    /// Update the authentication-required bit in the broadcast Extended
    /// Services information element.
    pub fn set_authentication_required(&mut self, required: bool) {
        let Some(ext_services) = self.precomps.mac_sysinfo2.ext_services.as_mut() else {
            tracing::warn!(required, "cannot update authentication policy: Extended Services is not present");
            return;
        };
        if ext_services.auth_required != required {
            ext_services.auth_required = required;
            tracing::info!(required, "BS SYSINFO authentication policy updated");
        }
    }

    /// Replace the active AIE broadcast policy. SYSINFO 1 keeps the
    /// hyperframe field; with SC2 active SYSINFO 2 uses the mutually exclusive
    /// cipher-key field and carries the current 16-bit SCK-VN. Variant
    /// selection follows BNCH occurrences rather than timeslot identity.
    pub fn set_aie_config(&mut self, aie: &RuntimeAieConfig) {
        self.set_aie_config_for_air_time(aie, self.cur_dltime);
    }

    /// Update SYSINFO for the slot which is actually going on air. UMAC
    /// finalizes one future downlink slot per tick; at an Absolute-IV
    /// boundary the target SCK must therefore be selected before the runtime
    /// `sc2` field itself is promoted.
    pub fn set_aie_config_for_air_time(&mut self, aie: &RuntimeAieConfig, air_time: TdmaTime) {
        let sc2 = aie.downlink_sc2_identity_at(air_time);
        let sc3 = aie.enabled.then(|| aie.sc3.as_ref()).flatten();
        let Some(ext_services) = self.precomps.mac_sysinfo2.ext_services.as_mut() else {
            tracing::warn!("cannot update AIE policy: Extended Services is not present");
            return;
        };
        let previous = (
            ext_services.class1_supported,
            ext_services.class2_supported,
            ext_services.class3_supported,
            ext_services.sck_n,
            ext_services.dck_retrieval_during_cell_select,
            ext_services.dck_retrieval_during_cell_reselect,
            ext_services.linked_gck_crypto_periods,
            ext_services.short_gck_vn,
            ext_services.gck_supported,
            self.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn,
            self.precomps.mle_sysinfo.bs_service_details.aie_service,
        );
        ext_services.class1_supported = aie.enabled && aie.sc1_allowed;
        ext_services.class2_supported = sc2.is_some();
        ext_services.class3_supported = sc3.is_some();
        ext_services.sck_n = sc2.map(|key| key.sckn);
        ext_services.dck_retrieval_during_cell_select = sc3.map(|sc3| sc3.dck_retrieval_during_initial_cell_selection);
        ext_services.dck_retrieval_during_cell_reselect = sc3.map(|sc3| sc3.dck_retrieval_during_cell_reselection);
        ext_services.linked_gck_crypto_periods = sc3.map(|sc3| sc3.linked_gck_crypto_periods());
        // A scheduled SC3G boundary is selected by the actual air slot. This
        // keeps SYSINFO's short GCK-VN in lock-step with MGCK selection at
        // TS1/FN1, even though the scheduler constructs one slot ahead.
        ext_services.short_gck_vn = sc3.map(|sc3| (sc3.gck_vn_at(air_time) & 0x03) as u8);
        ext_services.gck_supported = sc3.is_some_and(RuntimeSc3Aie::gck_supported);
        self.precomps.mle_sysinfo.bs_service_details.aie_service = aie.enabled;

        self.precomps.mac_sysinfo1.cipher_key_id_or_sck_vn = None;
        if let Some(sc2) = sc2 {
            // The 16-bit SYSINFO cipher-key field is an SCK Version Number
            // when SC2 is advertised; it is a CCK identifier only for SC3.
            self.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn = Some(sc2.sck_vn);
            self.precomps.mac_sysinfo2.hyperframe_number = None;
        } else if let Some(sc3) = sc3 {
            self.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn = Some(sc3.cck_id);
            self.precomps.mac_sysinfo2.hyperframe_number = None;
        } else {
            self.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn = None;
            self.precomps.mac_sysinfo2.hyperframe_number = Some(air_time.h);
        }
        let current = (
            ext_services.class1_supported,
            ext_services.class2_supported,
            ext_services.class3_supported,
            ext_services.sck_n,
            ext_services.dck_retrieval_during_cell_select,
            ext_services.dck_retrieval_during_cell_reselect,
            ext_services.linked_gck_crypto_periods,
            ext_services.short_gck_vn,
            ext_services.gck_supported,
            self.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn,
            self.precomps.mle_sysinfo.bs_service_details.aie_service,
        );
        if current != previous {
            if let Some(sc2) = sc2 {
                tracing::info!(
                    dltime = %air_time,
                    sckn = sc2.sckn,
                    sck_vn = sc2.sck_vn,
                    algorithm = ?sc2.algorithm,
                    sc1_allowed = aie.sc1_allowed,
                    "BS SYSINFO AIE policy updated for air slot"
                );
            } else if let Some(sc3) = sc3 {
                tracing::info!(
                    dltime = %air_time,
                    cck_id = sc3.cck_id,
                    gck_vn = sc3.gck_vn_at(air_time),
                    short_gck_vn = ext_services.short_gck_vn,
                    sc1_allowed = aie.sc1_allowed,
                    "BS SYSINFO SC3 AIE policy updated for air slot"
                );
            } else {
                tracing::info!(dltime = %air_time, "BS SYSINFO AIE policy disabled for air slot");
            }
        }

        // TTR 001-11 clause 6.2.7.1.1: an encrypted DUMMY PDU carrying the
        // new Short SCK-VN makes an encrypting MS change the key immediately.
        // Pure TCH/S has no MAC header, so listeners already in a call would
        // otherwise have no on-channel two-bit selector at the exact
        // Absolute-IV boundary and could remain on the old SCK until later
        // signalling. Insert one DUMMY on every active traffic leg when the
        // advertised SCK identity changes from one valid SC2 key to another.
        if previous.1 && current.1 && (previous.2, previous.3) != (current.2, current.3) {
            self.enqueue_sc2_changeover_dummies(air_time);
        }
    }

    fn enqueue_sc2_changeover_dummies(&mut self, air_time: TdmaTime) {
        let mut pending = Vec::new();

        for timeslot in 2..=4 {
            if !self.circuits.is_active(Direction::Dl, timeslot) {
                continue;
            }
            let Some(traffic_request) = self.traffic_aie[timeslot as usize - 1] else {
                continue;
            };
            let subject = match traffic_request {
                AieRequest::Sc2 { subject, .. } | AieRequest::Sc3 { subject, .. } => subject,
                AieRequest::Clear { .. } => continue,
            };

            // A DUMMY is addressed to the listening MS(s), not to the call
            // object. Group traffic already has a group subject; a private
            // traffic leg is converted to its destination ISSI for this
            // control-only indication.
            let (address, request) = match subject {
                AieSubject::Group { gssi } => (
                    TetraAddress::new(gssi, SsiType::Gssi),
                    AieRequest::sc2(AieSubject::Group { gssi }, AieScope::MacResource),
                ),
                AieSubject::Individual { issi } | AieSubject::Call { issi: Some(issi), .. } => (
                    TetraAddress::issi(issi),
                    AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacResource),
                ),
                AieSubject::Call { gssi: Some(gssi), .. } => (
                    TetraAddress::new(gssi, SsiType::Gssi),
                    AieRequest::sc2(AieSubject::Group { gssi }, AieScope::MacResource),
                ),
                AieSubject::System
                | AieSubject::Call {
                    issi: None, gssi: None, ..
                } => continue,
            };

            let mut resource = MacResource {
                fill_bits: false,
                pos_of_grant: 0,
                encryption_mode: 0,
                random_access_flag: false,
                length_ind: 0,
                addr: Some(address),
                event_label: None,
                usage_marker: self.circuits.get_usage(Direction::Dl, timeslot),
                power_control_element: None,
                slot_granting_element: None,
                chan_alloc_element: None,
            };
            let fill_bits = resource.update_len_and_fill_ind(0);
            let resource = match self.prepare_downlink_resource(resource, request, air_time) {
                Ok(resource) => resource,
                Err(error) => {
                    tracing::warn!(?error, dltime = %air_time, timeslot, "cannot build SC2 changeover DUMMY");
                    continue;
                }
            };
            let header_len = resource.compute_header_len();
            let mut block = BitBuffer::new(SCH_HD_CAP);
            resource.to_bitbuf(&mut block);
            fillbits::addition::write(&mut block, Some(fill_bits));
            finalize_downlink_mac_block(&mut block);

            pending.push((timeslot, block, request, AieCipherRegion::new(header_len, 0)));
        }

        for (timeslot, block, request, region) in pending {
            // This indication is tied to the Absolute IV and therefore takes
            // priority over ordinary queued FACCH. The latter remains queued
            // for the next traffic frame.
            self.dltx_queues[timeslot as usize - 1].insert(0, DlSchedElem::Stealing(block, None, request, Some(region)));
            tracing::info!(dltime = %air_time, timeslot, "queued encrypted SC2 changeover DUMMY on active traffic channel");
        }
    }

    /// Fully wipe the schedule
    pub fn purge_schedule(&mut self) {
        self.dltx_queues = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        self.dltx_half_duplex_queues = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        self.assoc_dltx_queues = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        self.ulsched = EMPTY_SCHED;
        self.associated_ulsched.clear();
        self.pending_packet_data_grants.clear();
        self.packet_data_grant_windows.clear();
        self.packet_grant_round_robin_after = None;
    }

    /// Sets the current downlink time to the given TdmaTime
    /// Wipes the schedule, as it can no longer be guaranteed to be valid
    pub fn set_dl_time(&mut self, new_ts: TdmaTime) {
        self.cur_dltime = new_ts;
        self.purge_schedule();
    }

    pub fn ul_ts_to_sched_index(&self, ts: &TdmaTime) -> usize {
        let to_index = (ts.f as usize - 1) + ((ts.m as usize - 1) * 18) + (ts.h as usize * 18 * 60);
        to_index % MACSCHED_NUM_FRAMES
    }

    ///////// UPLINK GRANT PROCESSING /////////

    /// Return the timeslots that count as consecutive signalling
    /// opportunities for a basic slot grant received on `timeslot`.
    ///
    /// TTR 001-05 section 6.10 requires every timeslot in a multislot PDCH to
    /// be counted for granting delay and reserved access. Circuit and common
    /// control channels continue to have one opportunity per TDMA frame.
    fn basic_grant_timeslots(&self, timeslot: u8) -> Vec<u8> {
        let Some(bearer) = self.packet_bearers.get(timeslot as usize - 1).copied().flatten() else {
            return vec![timeslot];
        };

        (2..=4)
            .filter(|candidate| self.packet_bearers[*candidate as usize - 1] == Some(bearer))
            .collect()
    }

    fn packet_bearer_for_timeslot(&self, timeslot: u8) -> Option<(u64, u64)> {
        self.packet_bearers.get(timeslot as usize - 1).copied().flatten()
    }

    fn packet_data_request_slots(res_req: ReservationRequirement) -> (usize, bool) {
        match res_req {
            ReservationRequirement::Req1Subslot => (1, true),
            ReservationRequirement::Req1Slot => (1, false),
            ReservationRequirement::Req2Slots => (2, false),
            ReservationRequirement::Req3Slots => (3, false),
            ReservationRequirement::Req4Slots => (4, false),
            ReservationRequirement::Req5Slots => (5, false),
            ReservationRequirement::Req6Slots => (6, false),
            ReservationRequirement::Req8Slots => (8, false),
            ReservationRequirement::Req10Slots => (10, false),
            ReservationRequirement::Req13Slots => (13, false),
            ReservationRequirement::Req17Slots => (17, false),
            ReservationRequirement::Req24Slots => (24, false),
            ReservationRequirement::Req34Slots => (34, false),
            ReservationRequirement::Req51Slots => (51, false),
            ReservationRequirement::Req68Slots => (68, false),
            // The all-ones encoding is a lower bound, not a request for an
            // arbitrary sentinel quantity.
            ReservationRequirement::ReqOver68 => (69, false),
        }
    }

    /// Count full uplink slots already reserved for this terminal after the
    /// reservation request. A packet-data MS reports the total remaining
    /// need in each following MAC-DATA capacity request; treating every
    /// request as additional capacity grows the schedule faster than the MS
    /// can consume it and removes its half-duplex downlink opportunities.
    fn pending_packet_data_full_slot_grants_after(&self, after: TdmaTime, pdch_slots: &[u8], ssi: u32) -> usize {
        (1..MACSCHED_NUM_FRAMES * 4)
            .map(|distance| after.add_timeslots(distance as i32))
            .filter(|candidate| pdch_slots.contains(&candidate.t) && !candidate.is_mandatory_clch())
            .filter(|candidate| {
                let elem = &self.ulsched[candidate.t as usize - 1][self.ul_ts_to_sched_index(candidate)];
                elem.ul1 == Some(ssi) && elem.ul2 == Some(ssi)
            })
            .count()
    }

    fn record_packet_data_grant_window(&mut self, ssi: u32, bearer: (u64, u64), first_uplink: TdmaTime, last_uplink: TdmaTime) {
        // Uplink timing is represented two logical timeslots before the
        // physically overlapping downlink timing.  Consequently the three
        // forbidden DL positions around an UL slot are UL+1, UL+2 and UL+3.
        // The first free DL position is last+4; reserve a complete frame from
        // there before another ordinary grant may be sent.
        let next_grant_downlink = last_uplink.add_timeslots(4 + PACKET_DATA_RECEIVE_TURN_TIMESLOTS);
        let window = PacketDataGrantWindow {
            bearer,
            first_uplink,
            last_uplink,
            next_grant_downlink,
        };
        self.packet_data_grant_windows.insert(ssi, window);
        tracing::debug!(
            issi = ssi,
            bearer_id = bearer.0,
            generation = bearer.1,
            first_uplink = %first_uplink,
            last_uplink = %last_uplink,
            next_grant_downlink = %next_grant_downlink,
            "recorded frequency-simplex packet-data grant interval"
        );
    }

    fn packet_data_downlink_is_blocked(&self, issi: u32, downlink: TdmaTime) -> bool {
        self.packet_data_grant_windows.get(&issi).is_some_and(|window| {
            let blocked_from = window.first_uplink.add_timeslots(1);
            let blocked_through = window.last_uplink.add_timeslots(3);
            downlink.diff(blocked_from) >= 0 && blocked_through.diff(downlink) >= 0
        })
    }

    /// Store the latest total remaining need reported by a packet-data MS.
    /// The report includes future slots that have already been granted, so
    /// only the shortfall is retained for the next uplink turn.
    pub fn queue_packet_data_capacity_request(
        &mut self,
        request_time: TdmaTime,
        addr: TetraAddress,
        res_req: ReservationRequirement,
        continues_fragment: bool,
    ) -> bool {
        let Some(bearer) = self.packet_bearer_for_timeslot(request_time.t) else {
            return false;
        };
        if self.draining_packet_bearers.contains(&bearer) {
            tracing::debug!(?addr, %request_time, bearer_id = bearer.0, "ignoring new packet-data grant while bearer drains");
            return true;
        }

        let (requested_slots, is_halfslot) = Self::packet_data_request_slots(res_req);
        let pdch_slots = self.basic_grant_timeslots(request_time.t);
        let already_granted = if is_halfslot {
            0
        } else {
            self.pending_packet_data_full_slot_grants_after(request_time, &pdch_slots, addr.ssi)
        };
        let shortfall = requested_slots.saturating_sub(already_granted);
        if shortfall == 0 {
            self.pending_packet_data_grants.remove(&addr.ssi);
            tracing::debug!(
                ?addr,
                %request_time,
                requested_slots,
                already_granted,
                "current packet-data grant covers latest reservation requirement"
            );
            return true;
        }

        self.pending_packet_data_grants.insert(
            addr.ssi,
            PendingPacketDataGrant {
                addr,
                bearer,
                request_time,
                remaining_slots: shortfall,
                is_halfslot,
                continues_fragment,
            },
        );
        tracing::debug!(
            ?addr,
            %request_time,
            requested_slots,
            already_granted,
            shortfall,
            continues_fragment,
            "queued packet-data capacity shortfall"
        );
        true
    }

    /// An uplink MAC block without a reservation requirement releases any
    /// unannounced remainder.  Announced slots stay reserved until their
    /// natural end because the BS cannot withdraw capacity already granted.
    pub fn clear_pending_packet_data_capacity(&mut self, issi: u32, uplink: TdmaTime) {
        if self.pending_packet_data_grants.remove(&issi).is_some() {
            tracing::debug!(issi, %uplink, "cleared unannounced packet-data capacity after final uplink PDU");
        }
    }

    fn packet_data_grant_ready_at(&self, request: PendingPacketDataGrant, downlink: TdmaTime) -> bool {
        self.packet_data_grant_windows
            .get(&request.addr.ssi)
            .is_none_or(|window| window.bearer != request.bearer || downlink.diff(window.next_grant_downlink) >= 0)
    }

    fn packet_data_random_access_ack_allows_slot(&self, issi: u32, timeslot: u8) -> bool {
        let mut any_ack = false;
        let mut ack_on_this_slot = false;
        for (slot, queue) in self.dltx_queues.iter().enumerate() {
            if queue
                .iter()
                .any(|elem| matches!(elem, DlSchedElem::RandomAccessAck(addr, _) if addr.ssi_type == SsiType::Issi && addr.ssi == issi))
            {
                any_ack = true;
                ack_on_this_slot |= slot == timeslot as usize - 1;
            }
        }
        !any_ack || ack_on_this_slot
    }

    fn expire_packet_data_grant_windows(&mut self, now: TdmaTime) {
        let pending = &self.pending_packet_data_grants;
        self.packet_data_grant_windows
            .retain(|issi, window| pending.contains_key(issi) || window.next_grant_downlink.diff(now) >= 0);
    }

    fn reserve_packet_data_turn(&mut self, grant_downlink: TdmaTime, request: PendingPacketDataGrant) -> Option<(BasicSlotgrant, usize)> {
        let pdch_slots = self.basic_grant_timeslots(grant_downlink.t);
        let turn_capacity = match pdch_slots.len() {
            0 => return None,
            1 => 6,
            2 => 10,
            _ => 17,
        };
        let downlink_waiting = !request.continues_fragment && self.has_pending_packet_data_downlink_for_issi(request.addr.ssi);
        let maximum = request.remaining_slots.min(turn_capacity).min(if downlink_waiting {
            PACKET_DATA_BIDIRECTIONAL_MAX_GRANT_SLOTS
        } else {
            turn_capacity
        });
        let candidate_capacities: Vec<usize> = if request.is_halfslot {
            vec![1]
        } else {
            EXACT_BASIC_SLOT_GRANT_CAPACITIES
                .iter()
                .rev()
                .copied()
                .filter(|capacity| *capacity <= maximum)
                .collect()
        };

        for granted_slots in candidate_capacities {
            let Some((skips, grant_timestamps)) =
                self.ul_find_grant_opportunity_from(grant_downlink, grant_downlink.t, granted_slots, request.is_halfslot, 0)
            else {
                continue;
            };
            if skips > MAX_BASIC_SLOT_GRANT_DELAY
                || grant_timestamps
                    .last()
                    .is_some_and(|last| last.diff(grant_downlink) >= PACKET_DATA_UPLINK_TURN_TIMESLOTS)
            {
                continue;
            }

            let subslot = self.ul_reserve_grant(request.addr.ssi, grant_timestamps, request.is_halfslot);
            let capacity_allocation = if request.is_halfslot {
                match subslot {
                    1 => BasicSlotgrantCapAlloc::FirstSubslotGranted,
                    2 => BasicSlotgrantCapAlloc::SecondSubslotGranted,
                    _ => unreachable!("subslot grant must reserve one half"),
                }
            } else {
                BasicSlotgrantCapAlloc::from_req_slotcount(granted_slots)
            };
            let granting_delay = if skips == 0 {
                BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity
            } else {
                BasicSlotgrantGrantingDelay::DelayNOpportunities(skips as u8)
            };
            return Some((
                BasicSlotgrant {
                    capacity_allocation,
                    granting_delay,
                },
                granted_slots,
            ));
        }
        None
    }

    /// At most one queued packet-data request is turned into an on-air grant
    /// in a physical downlink slot.  Fragment continuations are considered
    /// first; equal-priority terminals rotate by ISSI.
    fn schedule_ready_packet_data_grant(&mut self, downlink: TdmaTime) {
        if downlink.f == 18 {
            return;
        }
        let Some(bearer) = self.packet_bearer_for_timeslot(downlink.t) else {
            return;
        };
        if self.draining_packet_bearers.contains(&bearer) {
            return;
        }

        let mut candidates = self
            .pending_packet_data_grants
            .values()
            .copied()
            .filter(|request| {
                request.bearer == bearer
                    && self.packet_data_grant_ready_at(*request, downlink)
                    && self.packet_data_random_access_ack_allows_slot(request.addr.ssi, downlink.t)
                    && (request.continues_fragment || !self.has_pending_advanced_link_ack_request_for_issi(request.addr.ssi))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|request| (!request.continues_fragment, request.addr.ssi));
        if candidates.is_empty() {
            return;
        }

        let priority = candidates[0].continues_fragment;
        let same_priority = candidates
            .iter()
            .copied()
            .filter(|request| request.continues_fragment == priority)
            .collect::<Vec<_>>();
        let request = self
            .packet_grant_round_robin_after
            .and_then(|after| same_priority.iter().copied().find(|request| request.addr.ssi > after))
            .unwrap_or(same_priority[0]);

        let Some((grant, granted_slots)) = self.reserve_packet_data_turn(downlink, request) else {
            return;
        };
        if request.is_halfslot || granted_slots >= request.remaining_slots {
            self.pending_packet_data_grants.remove(&request.addr.ssi);
        } else if let Some(pending) = self.pending_packet_data_grants.get_mut(&request.addr.ssi) {
            pending.remaining_slots -= granted_slots;
        }
        self.packet_grant_round_robin_after = Some(request.addr.ssi);
        tracing::info!(
            address = ?request.addr,
            request = %request.request_time,
            grant_downlink = %downlink,
            requested_shortfall = request.remaining_slots,
            granted_slots,
            grant = ?grant,
            "scheduled next frequency-simplex packet-data uplink turn"
        );
        self.dl_enqueue_grant(downlink.t, request.addr, grant);
    }

    /// Finds a grant opportunity for uplink transmission.
    /// If num_slots is 1, is_halfslot may specifiy whether only a half slot is needed
    /// Returns (opportunities_to_skip, Vec<timestamps_of_granted_slots>)
    /// Returns None if no suitable opportunity is found in the schedule
    pub fn ul_find_grant_opportunity(&self, t: u8, num_slots: usize, is_halfslot: bool) -> Option<(usize, Vec<TdmaTime>)> {
        self.ul_find_grant_opportunity_after(t, num_slots, is_halfslot, 0)
    }

    /// Find an uplink grant after at least `minimum_delay` signalling
    /// opportunities on the current channel.  An anticipated advanced-link
    /// acknowledgement needs receiver processing time; on a multislot
    /// pi/4-DQPSK PDCH TTR 001-05 table 5 requires a minimum delay equal to
    /// the number of assigned timeslots.
    fn ul_find_grant_opportunity_after(
        &self,
        t: u8,
        num_slots: usize,
        is_halfslot: bool,
        minimum_delay: usize,
    ) -> Option<(usize, Vec<TdmaTime>)> {
        let first_opportunity = self.cur_dltime.forward_to_timeslot(t);
        self.ul_find_grant_opportunity_from(first_opportunity, t, num_slots, is_halfslot, minimum_delay)
    }

    fn ul_find_grant_opportunity_from(
        &self,
        first_opportunity: TdmaTime,
        t: u8,
        num_slots: usize,
        is_halfslot: bool,
        minimum_delay: usize,
    ) -> Option<(usize, Vec<TdmaTime>)> {
        let channel_timeslots = self.basic_grant_timeslots(t);
        let mut grant_timeslots = Vec::with_capacity(num_slots);
        let mut opportunities_skipped = 0;

        assert!(!is_halfslot || num_slots == 1, "is_halfslot set for num_slots > 1");

        // Include all 18 schedule frames. In an active UL-TCH only FN18
        // remains an eligible associated-access opportunity for another
        // terminal.
        // Walk absolute slots so all members of a multislot PDCH are counted.
        // The ring contains 18 frames per physical timeslot, hence 18 * 4 is
        // the largest useful search horizon without revisiting a reservation.
        for dist in 0..MACSCHED_NUM_FRAMES * 4 {
            let candidate_t = first_opportunity.add_timeslots(dist as i32);
            if !channel_timeslots.contains(&candidate_t.t) {
                continue;
            }

            tracing::trace!(
                "ul_find_grant_opportunity: considering candidate ul_ts {}, have {:?}",
                candidate_t,
                grant_timeslots
            );

            if opportunities_skipped < minimum_delay {
                opportunities_skipped += 1;
                continue;
            }

            if candidate_t.is_mandatory_clch() {
                // A predefined CLCH is included when counting granting-delay
                // opportunities, but it is skipped while consuming granted
                // full-slot capacity.  Before the grant starts it therefore
                // advances the encoded delay; inside a grant it creates a
                // permitted hole without ending the basic allocation.
                if grant_timeslots.is_empty() {
                    opportunities_skipped += 1;
                }
                continue;
            }

            // A transmitting MS owns UL TCH in FN1..17.  Other terminals may
            // receive associated access only in the control frame, avoiding a
            // collision with the active speaker.  During hangtime the slot is
            // FACCH again and normal grant selection remains available.
            if self.circuits.is_active(Direction::Ul, candidate_t.t) && !self.is_hangtime(candidate_t.t) && candidate_t.f != 18 {
                continue;
            }

            let index = self.ul_ts_to_sched_index(&candidate_t);
            let elem = &self.ulsched[candidate_t.t as usize - 1][index];
            // tracing::debug!("ul_find_grant_opportunity: sched[{}] ts {}: {:?}", index, candidate_t, elem);
            if (elem.ul1.is_none() && elem.ul2.is_none()) || (is_halfslot && (elem.ul1.is_none() || elem.ul2.is_none())) {
                // Free UL slot, add this timeslot to result vec
                grant_timeslots.push(candidate_t);
                // continue;
            } else {
                // Something is here, clear our grant timeslots
                opportunities_skipped += grant_timeslots.len() + 1;
                grant_timeslots.clear();
            }

            // Check if done
            if grant_timeslots.len() == num_slots {
                return Some((opportunities_skipped, grant_timeslots));
            }
        }

        // If we get here, we did not find a suitable grant opportunity
        None
    }

    /// Reserves all slots designated in a grant option
    /// If only one halfslot is needed, returns 1 or 2 designating which slot was reserved
    pub fn ul_reserve_grant(&mut self, ssi: u32, grant_timestamps: Vec<TdmaTime>, is_halfslot: bool) -> u8 {
        assert!(!grant_timestamps.is_empty());
        assert!(!is_halfslot || grant_timestamps.len() == 1);
        // let ts = grant_timestamps[0].t as usize;
        let first_uplink = grant_timestamps[0];
        let last_uplink = *grant_timestamps.last().expect("non-empty grant");
        let mut subslot = 0;
        for ts in grant_timestamps {
            let index = self.ul_ts_to_sched_index(&ts);

            let elem: &mut TimeslotSchedule = &mut self.ulsched[ts.t as usize - 1][index];
            if is_halfslot {
                if elem.ul1.is_none() {
                    elem.ul1 = Some(ssi);
                    subslot = 1;
                } else {
                    assert!(elem.ul2.is_none(), "ul_reserve_grant: ul2 already set for ts {:?}, ssi {}", ts, ssi);
                    elem.ul2 = Some(ssi);
                    subslot = 2;
                }
            } else {
                assert!(elem.ul1.is_none(), "ul_reserve_grant: ul1 already set for ts {:?}, ssi {}", ts, ssi);
                assert!(elem.ul2.is_none(), "ul_reserve_grant: ul2 already set for ts {:?}, ssi {}", ts, ssi);
                elem.ul1 = Some(ssi);
                elem.ul2 = Some(ssi);
            }
        }

        if let Some(bearer) = self.packet_bearer_for_timeslot(first_uplink.t) {
            self.record_packet_data_grant_window(ssi, bearer, first_uplink, last_uplink);
        }

        subslot
    }

    /// Tries to find a way to satisfy a granting request, and reserves the slots in the schedule.
    /// If successful, returns a BasicSlotgrant with the granting delay and capacity allocation.
    pub fn ul_process_cap_req(&mut self, timeslot: u8, addr: TetraAddress, res_req: &ReservationRequirement) -> Option<BasicSlotgrant> {
        if self.packet_bearer_is_active(timeslot) {
            let request_time = self.cur_dltime.forward_to_timeslot(timeslot).add_timeslots(-4);
            return self.ul_process_packet_data_cap_req_at(request_time, addr, res_req, false);
        }
        self.ul_process_cap_req_after(timeslot, addr, res_req, 0)
    }

    /// Process a reservation that continues an uplink MAC fragment chain.
    ///
    /// A fragmented acknowledgement can be the response that releases an
    /// advanced-link downlink window. It must therefore be allowed to finish
    /// even while data for this MS remains queued on the downlink; withholding
    /// that grant creates a half-duplex deadlock and makes the MS retry the
    /// first fragment after T.202.
    pub fn ul_process_fragment_cap_req(
        &mut self,
        timeslot: u8,
        addr: TetraAddress,
        res_req: &ReservationRequirement,
    ) -> Option<BasicSlotgrant> {
        if self.packet_bearer_is_active(timeslot) {
            let request_time = self.cur_dltime.forward_to_timeslot(timeslot).add_timeslots(-4);
            return self.ul_process_packet_data_cap_req_at(request_time, addr, res_req, true);
        }
        self.ul_process_cap_req_after(timeslot, addr, res_req, 0)
    }

    /// Grant capacity on an assigned packet-data channel without duplicating
    /// slots that were announced by earlier, still outstanding grants.
    /// EN 300 392-2 permits granting fewer slots than requested; selecting the
    /// largest exactly encodable shortfall keeps traffic moving when the full
    /// request does not fit inside the 4-bit granting-delay horizon.
    fn ul_process_packet_data_cap_req_at(
        &mut self,
        request_time: TdmaTime,
        addr: TetraAddress,
        res_req: &ReservationRequirement,
        _continues_fragment: bool,
    ) -> Option<BasicSlotgrant> {
        let pdch_slots = self.basic_grant_timeslots(request_time.t);
        let (requested_cap, is_halfslot) = Self::packet_data_request_slots(*res_req);
        let pending_cap = if is_halfslot {
            0
        } else {
            self.pending_packet_data_full_slot_grants_after(request_time, &pdch_slots, addr.ssi)
        };
        let additional_cap = requested_cap.saturating_sub(pending_cap);
        if !is_halfslot && additional_cap == 0 {
            tracing::debug!(
                address = ?addr,
                request = %request_time,
                requested_cap,
                pending_cap,
                "existing packet-data uplink grants satisfy capacity request"
            );
            return None;
        }

        let turn_capacity = match pdch_slots.len() {
            0 => return None,
            1 => 6,
            2 => 10,
            _ => 17,
        };
        let maximum_grant = additional_cap.min(turn_capacity);
        let candidate_capacities: Vec<usize> = if is_halfslot {
            vec![1]
        } else {
            EXACT_BASIC_SLOT_GRANT_CAPACITIES
                .iter()
                .rev()
                .copied()
                .filter(|capacity| *capacity <= maximum_grant)
                .collect()
        };

        for granted_cap in candidate_capacities {
            let Some((skips, grant_timestamps)) = self.ul_find_grant_opportunity_after(request_time.t, granted_cap, is_halfslot, 0) else {
                continue;
            };
            if skips > MAX_BASIC_SLOT_GRANT_DELAY
                || grant_timestamps
                    .last()
                    .is_some_and(|last| last.diff(self.cur_dltime.forward_to_timeslot(request_time.t)) >= PACKET_DATA_UPLINK_TURN_TIMESLOTS)
            {
                continue;
            }
            let subslot = self.ul_reserve_grant(addr.ssi, grant_timestamps, is_halfslot);
            let capacity_allocation = if is_halfslot {
                match subslot {
                    1 => BasicSlotgrantCapAlloc::FirstSubslotGranted,
                    2 => BasicSlotgrantCapAlloc::SecondSubslotGranted,
                    _ => unreachable!("subslot must be 1 or 2"),
                }
            } else {
                BasicSlotgrantCapAlloc::from_req_slotcount(granted_cap)
            };
            let granting_delay = if skips == 0 {
                BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity
            } else {
                BasicSlotgrantGrantingDelay::DelayNOpportunities(skips as u8)
            };
            tracing::debug!(
                address = ?addr,
                request = %request_time,
                requested_cap,
                pending_cap,
                additional_cap,
                granted_cap,
                skips,
                "reserved packet-data uplink capacity"
            );
            return Some(BasicSlotgrant {
                capacity_allocation,
                granting_delay,
            });
        }

        tracing::debug!(
            address = ?addr,
            request = %request_time,
            requested_cap,
            pending_cap,
            additional_cap,
            "no encodable packet-data uplink shortfall grant is currently available"
        );
        None
    }

    fn ul_process_cap_req_after(
        &mut self,
        timeslot: u8,
        addr: TetraAddress,
        res_req: &ReservationRequirement,
        minimum_delay: usize,
    ) -> Option<BasicSlotgrant> {
        if self.circuits.is_active(Direction::Ul, timeslot) && !self.is_hangtime(timeslot) {
            let grant_frame = self.next_associated_fn18(timeslot);
            return self.ul_process_associated_fn18_cap_req(grant_frame, addr, res_req);
        }

        let is_halfslot = res_req == &ReservationRequirement::Req1Subslot;
        let requested_cap = if is_halfslot { 1 } else { res_req.to_req_slotcount() };

        // Find a suitable grant opportunity
        let grant_op = self.ul_find_grant_opportunity_after(timeslot, requested_cap, is_halfslot, minimum_delay);

        tracing::debug!(
            "ul_process_cap_req: addr {}, res_req {:?}, requested_cap {}, is_halfslot {}, grant_op: {:?}",
            addr,
            res_req,
            requested_cap,
            is_halfslot,
            grant_op
        );

        // If found, reserve the slots and return a BasicSlotgrant
        if let Some((skips, grant_timestamps)) = grant_op {
            let grant_delay = match skips {
                0 => BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity,
                1..=MAX_BASIC_SLOT_GRANT_DELAY => BasicSlotgrantGrantingDelay::DelayNOpportunities(skips as u8),
                _ => {
                    tracing::debug!(
                        address = ?addr,
                        res_req = ?res_req,
                        skips,
                        "deferring uplink grant beyond encodable Basic slot granting delay"
                    );
                    return None;
                }
            };
            // Reserve the target granting opportunity. Get subslot (only relevant for halfslot reservation)
            let subslot = self.ul_reserve_grant(addr.ssi, grant_timestamps, is_halfslot);

            // tracing::info!("After grant:")
            // self.dump_ul_schedule_full(false);

            // Build BasicSlotgrant response element
            let cap_alloc = if res_req == &ReservationRequirement::Req1Subslot {
                match subslot {
                    1 => BasicSlotgrantCapAlloc::FirstSubslotGranted,
                    2 => BasicSlotgrantCapAlloc::SecondSubslotGranted,
                    _ => unreachable!("ul_process_cap_req: subslot must be 1 or 2, got {}", subslot),
                }
            } else {
                BasicSlotgrantCapAlloc::from_req_slotcount(requested_cap)
            };
            Some(BasicSlotgrant {
                capacity_allocation: cap_alloc,
                granting_delay: grant_delay,
            })
        } else {
            tracing::warn!(
                "ul_process_cap_req: no suitable grant opportunity found for addr {}, res_req {:?}",
                addr,
                res_req
            );
            None
        }
    }

    /// Reserve one FN18 uplink slot needed for the BL-ACK of an
    /// acknowledged downlink resource sent through the associated SACCH.
    ///
    /// With an active uplink speaker, frames 1..17 belong to that speaker's
    /// TCH. The addressed listener can acknowledge SDS in the corresponding
    /// frame-18 SCH/F.  Traffic-mode transmissions occupy the entire slot
    /// (EN 300 392-2 clause 19.4.2.4.1), so both uplink subslots must be
    /// reserved even though the BL-ACK itself is short. The grant is included
    /// in the same MAC-RESOURCE as the BL-DATA and uses the zero-delay FN18
    /// opportunity.
    pub fn ul_prepare_associated_basic_link_ack_grant(&mut self, timeslot: u8, addr: TetraAddress) -> Option<BasicSlotgrant> {
        if !(2..=4).contains(&timeslot) || !self.circuits.is_active(Direction::Ul, timeslot) || self.is_hangtime(timeslot) {
            return None;
        }

        let grant_frame = self.next_associated_fn18(timeslot);
        self.ul_process_associated_fn18_cap_req(grant_frame, addr, &ReservationRequirement::Req1Slot)
    }

    /// Prepare an associated BL-ACK grant after the actual downlink FN18 is
    /// known. This is intentionally separate from the enqueue-time helper:
    /// the downlink may be deferred when that FN18 is a mandatory BSCH/BNCH.
    pub fn ul_prepare_associated_basic_link_ack_grant_at(&mut self, tx_time: TdmaTime, addr: TetraAddress) -> Option<BasicSlotgrant> {
        if tx_time.f != 18
            || !(2..=4).contains(&tx_time.t)
            || !self.circuits.is_active(Direction::Ul, tx_time.t)
            || self.is_hangtime(tx_time.t)
        {
            return None;
        }

        self.ul_process_associated_fn18_cap_req(tx_time, addr, &ReservationRequirement::Req1Slot)
    }

    fn next_associated_fn18(&self, timeslot: u8) -> TdmaTime {
        let mut frame = self.cur_dltime.forward_to_timeslot(timeslot);
        while frame.f != 18 {
            frame = frame.add_timeslots(4);
        }
        frame
    }

    /// Reserve the corresponding FN18 uplink opportunity for an associated
    /// grant. The A/B mode under investigation uses granting delay 0000, so
    /// the MS answers in the same FN18 as the downlink grant. This schedule is
    /// deliberately separate from `ulsched`, whose 18-frame ring is not used
    /// for associated control reservations.
    fn ul_process_associated_fn18_cap_req(
        &mut self,
        grant_frame: TdmaTime,
        addr: TetraAddress,
        res_req: &ReservationRequirement,
    ) -> Option<BasicSlotgrant> {
        let is_halfslot = res_req == &ReservationRequirement::Req1Subslot;
        let requested_cap = if is_halfslot { 1 } else { res_req.to_req_slotcount() };

        let target_frame = grant_frame;

        let schedule_index = self.associated_ulsched.iter().position(|(timestamp, _)| *timestamp == target_frame);
        let schedule = if let Some(index) = schedule_index {
            &mut self.associated_ulsched[index].1
        } else {
            self.associated_ulsched
                .push((target_frame, TimeslotSchedule { ul1: None, ul2: None }));
            &mut self.associated_ulsched.last_mut().unwrap().1
        };

        let capacity_allocation = if is_halfslot {
            // Subslot 1 is the predefined CLCH position on this FN18. It is
            // not available for a reserved SCH/HU response, while subslot 2
            // remains usable with the same zero-delay FN18 grant.
            if target_frame.is_mandatory_clch() {
                if schedule.ul2.is_none() {
                    schedule.ul2 = Some(addr.ssi);
                    BasicSlotgrantCapAlloc::SecondSubslotGranted
                } else {
                    tracing::warn!(
                        "ul_process_associated_fn18_cap_req: FN18 {} subslot 2 is already reserved",
                        target_frame
                    );
                    return None;
                }
            } else if schedule.ul1.is_none() {
                schedule.ul1 = Some(addr.ssi);
                BasicSlotgrantCapAlloc::FirstSubslotGranted
            } else if schedule.ul2.is_none() {
                schedule.ul2 = Some(addr.ssi);
                BasicSlotgrantCapAlloc::SecondSubslotGranted
            } else {
                tracing::warn!("ul_process_associated_fn18_cap_req: FN18 {} is fully reserved", target_frame);
                return None;
            }
        } else if target_frame.is_mandatory_clch() {
            // A full-slot grant would overlap the predefined CLCH in
            // subslot 1. Do not encode a relative grant that the MS cannot
            // use; the caller must request a subslot instead.
            tracing::warn!(
                "ul_process_associated_fn18_cap_req: FN18 {} is a predefined CLCH; full-slot grant rejected",
                target_frame
            );
            return None;
        } else if schedule.ul1.is_none() && schedule.ul2.is_none() {
            // EN 300 392-2 clause 23.5.2.2.4 requires a BS whose assigned
            // traffic channel is in SACCH to grant only one reserved slot at
            // a time.  A capacity request can nevertheless ask for two or
            // more slots while an uplink TM-SDU is being fragmented. Grant
            // this FN18; the associated scheduler queues the ungranted
            // remainder because MAC-FRAG cannot repeat the requirement.
            schedule.ul1 = Some(addr.ssi);
            schedule.ul2 = Some(addr.ssi);
            BasicSlotgrantCapAlloc::Grant1Slot
        } else {
            tracing::warn!("ul_process_associated_fn18_cap_req: FN18 {} is already reserved", target_frame);
            return None;
        };

        tracing::debug!(
            "ul_process_associated_fn18_cap_req: addr {}, res_req {:?}, grant frame {}, target frame {}",
            addr,
            res_req,
            grant_frame,
            target_frame
        );
        if requested_cap > 1 {
            tracing::info!(
                requested_slots = requested_cap,
                granted_slots = 1,
                address = ?addr,
                dltime = %target_frame,
                "partially granting associated SACCH capacity request"
            );
        }
        Some(BasicSlotgrant {
            capacity_allocation,
            granting_delay: BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity,
        })
    }

    /// Returns schedule info for the given uplink timeslot and full-or-subslot
    /// If Both is requested, schedule is assumed to have matching allocation for two subslots
    /// If not, a warning is issued and None is returned.
    pub fn ul_get_slot_owner(&self, ts: TdmaTime, slot: PhyBlockNum) -> Option<u32> {
        let sched = self
            .associated_ulsched
            .iter()
            .find_map(|(timestamp, schedule)| (*timestamp == ts).then_some(schedule))
            .unwrap_or_else(|| &self.ulsched[ts.t as usize - 1][self.ul_ts_to_sched_index(&ts)]);
        match slot {
            PhyBlockNum::Block1 => sched.ul1,
            PhyBlockNum::Block2 => sched.ul2,
            PhyBlockNum::Both => {
                if sched.ul1 != sched.ul2 {
                    tracing::warn!("ul_get_slot_owner: requested Both but ul1 {:?} != ul2 {:?}", sched.ul1, sched.ul2);
                    return None;
                }
                sched.ul1
            }
            _ => unreachable!(),
        }
    }

    fn ul_get_usage(&self, ts: TdmaTime) -> AccessAssignUlUsage {
        let ul_sched = self
            .associated_ulsched
            .iter()
            .find_map(|(timestamp, schedule)| (*timestamp == ts).then_some(schedule))
            .unwrap_or_else(|| &self.ulsched[ts.t as usize - 1][self.ul_ts_to_sched_index(&ts)]);
        match (ul_sched.ul1, ul_sched.ul2) {
            (Some(_), Some(_)) => AccessAssignUlUsage::AssignedOnly,
            (Some(_), None) => AccessAssignUlUsage::CommonAndAssigned,
            (None, None) => AccessAssignUlUsage::CommonOnly,
            _ => unreachable!("ul2 can't be set with ul1 None"),
        }
    }

    fn packet_data_elem_issi(elem: &DlSchedElem) -> Option<u32> {
        match elem {
            DlSchedElem::Grant(addr, _) | DlSchedElem::RandomAccessAck(addr, _) | DlSchedElem::AssociatedGrantRequest(addr, ..)
                if addr.ssi_type == SsiType::Issi =>
            {
                Some(addr.ssi)
            }
            DlSchedElem::Resource(pdu, _, _, aie_request, _) => Self::aie_individual_issi(*aie_request)
                .or_else(|| pdu.addr.filter(|addr| addr.ssi_type == SsiType::Issi).map(|addr| addr.ssi)),
            DlSchedElem::FragBuf(fragger, _) => fragger.individual_issi(),
            _ => None,
        }
    }

    /// Whether packet data or service signalling for this terminal is waiting
    /// for a downlink opportunity. A frequency-simplex terminal cannot receive
    /// it while using an uplink grant.
    fn has_pending_packet_data_downlink_for_issi(&self, issi: u32) -> bool {
        self.dltx_queues
            .iter()
            .chain(self.dltx_half_duplex_queues.iter())
            .flat_map(|queue| queue.iter())
            .chain(self.dltx_next_slot_queue.iter())
            .any(|elem| !elem.is_cancelled() && Self::packet_data_elem_issi(elem) == Some(issi))
    }

    fn aie_individual_issi(aie_request: AieRequest) -> Option<u32> {
        match aie_request {
            AieRequest::Clear {
                subject: AieSubject::Individual { issi },
                ..
            }
            | AieRequest::Sc2 {
                subject: AieSubject::Individual { issi },
                ..
            }
            | AieRequest::Sc3 {
                subject: AieSubject::Individual { issi },
                ..
            } => Some(issi),
            _ => None,
        }
    }

    fn advanced_link_segment_identity(sdu: &BitBuffer) -> Option<(bool, bool, u8, u8)> {
        if sdu.get_len_remaining() < 17 || sdu.peek_bits_startoffset(0, 4) != Some(LlcPduType::AlDataAlFinal.into_raw()) {
            return None;
        }
        Some((
            sdu.peek_bits_startoffset(4, 1)? != 0,
            sdu.peek_bits_startoffset(5, 1)? != 0,
            sdu.peek_bits_startoffset(6, 3)? as u8,
            sdu.peek_bits_startoffset(9, 8)? as u8,
        ))
    }

    fn has_pending_advanced_link_ack_request_for_issi(&self, issi: u32) -> bool {
        self.dltx_queues
            .iter()
            .chain(self.dltx_half_duplex_queues.iter())
            .flat_map(|queue| queue.iter())
            .chain(self.dltx_next_slot_queue.iter())
            .any(|elem| {
                let DlSchedElem::Resource(pdu, sdu, _, aie_request, Some(_)) = elem else {
                    return false;
                };
                if elem.is_cancelled() || !Self::advanced_link_segment_identity(sdu).is_some_and(|(_, ar, _, _)| ar) {
                    return false;
                }
                Self::aie_individual_issi(*aie_request)
                    .or_else(|| pdu.addr.filter(|addr| addr.ssi_type == SsiType::Issi).map(|addr| addr.ssi))
                    == Some(issi)
            })
    }

    fn sched_elem_advanced_link_sequence(elem: &DlSchedElem) -> Option<(u32, u8, u8)> {
        match elem {
            DlSchedElem::Resource(_, sdu, _, aie_request, Some(_)) => {
                let (_, _, ns, ss) = Self::advanced_link_segment_identity(sdu)?;
                let issi = Self::aie_individual_issi(*aie_request)?;
                Some((issi, ns, ss))
            }
            _ => None,
        }
    }

    fn has_earlier_pending_advanced_link_segment(&self, issi: u32, ns: u8, ss: u8) -> bool {
        self.dltx_queues
            .iter()
            .chain(self.dltx_half_duplex_queues.iter())
            .flat_map(|queue| queue.iter())
            .chain(self.dltx_next_slot_queue.iter())
            .filter_map(BsChannelScheduler::sched_elem_advanced_link_sequence)
            .any(|(pending_issi, pending_ns, pending_ss)| {
                if pending_issi != issi {
                    return false;
                }
                if pending_ns == ns {
                    return pending_ss < ss;
                }
                // A window has at most three original-link TL-SDUs.  Keep its
                // complete older TL-SDU on air before a newer one starts: the
                // only AR then follows the full downlink batch, avoiding a
                // half-duplex downlink/uplink turn between every TL-SDU.
                (1..=3).contains(&(ns.wrapping_sub(pending_ns) & 0x07))
            })
    }

    fn dl_defer_packet_data_resource_to_next_pdch(
        &mut self,
        current_ts: u8,
        elem: DlSchedElem,
        packet_data_slots: [bool; 4],
        reason: &'static str,
    ) {
        let target_ts = self
            .next_packet_data_control_after(current_ts, packet_data_slots)
            .unwrap_or(current_ts);
        if target_ts == current_ts {
            self.dltx_next_slot_queue.push(elem);
        } else {
            self.dltx_queues[target_ts as usize - 1].push(elem);
        }
        tracing::debug!(
            current_ts,
            target_ts,
            reason,
            "deferred packet-data resource to the next assigned PDCH opportunity"
        );
    }

    /// Apply the complete forbidden interval from TTR 001-05 figure 1.  The
    /// terminal may use only some granted slots, but it is not required to
    /// monitor the downlink anywhere between the first and last slot.
    fn dl_defer_packet_data_for_concurrent_uplink(&mut self, ts: TdmaTime) -> usize {
        if !self.packet_bearer_is_active(ts.t) {
            return 0;
        }

        let blocked_issis = self
            .packet_data_grant_windows
            .keys()
            .copied()
            .filter(|issi| self.packet_data_downlink_is_blocked(*issi, ts))
            .collect::<HashSet<_>>();
        if blocked_issis.is_empty() {
            return 0;
        }

        let queue = &mut self.dltx_queues[ts.t as usize - 1];
        let mut deferred = Vec::new();
        let mut index = 0;
        while index < queue.len() {
            let should_defer = Self::packet_data_elem_issi(&queue[index]).is_some_and(|issi| blocked_issis.contains(&issi));
            if should_defer {
                deferred.push(queue.remove(index));
            } else {
                index += 1;
            }
        }

        let count = deferred.len();
        if count > 0 {
            tracing::debug!(
                dltime = %ts,
                count,
                "deferred assigned packet-data downlink around half-duplex uplink"
            );
            self.dltx_half_duplex_queues[ts.t as usize - 1].extend(deferred);
        }
        count
    }

    fn requeue_half_duplex_deferred_before_newer_items(&mut self, slot: usize) {
        if self.dltx_half_duplex_queues[slot].is_empty() {
            return;
        }
        let mut older = std::mem::take(&mut self.dltx_half_duplex_queues[slot]);
        older.append(&mut self.dltx_queues[slot]);
        self.dltx_queues[slot] = older;
    }

    ////////// DOWNLINK SCHEDULING /////////

    /// Registers that we should transmit a MAC-RESOURCE or similar with a grant, somewhere this tick
    pub fn dl_enqueue_grant(&mut self, ts: u8, addr: TetraAddress, grant: BasicSlotgrant) {
        tracing::debug!("dl_enqueue_grant: ts {} enqueueing PDU {:?} for addr {}", ts, grant, addr);
        let elem = DlSchedElem::Grant(addr, grant);
        self.dltx_queues[ts as usize - 1].push(elem);
    }

    pub fn dl_enqueue_random_access_ack(&mut self, ts: u8, addr: TetraAddress, aie_request: AieRequest) {
        tracing::debug!(
            "dl_enqueue_random_access_ack: ts {} enqueueing random access acknowledgementfor addr {}",
            ts,
            addr
        );
        let elem = DlSchedElem::RandomAccessAck(addr, aie_request.with_scope(AieScope::MacResource));
        self.dltx_queues[ts as usize - 1].push(elem);
    }

    pub fn is_common_control(&self, slot: u8) -> bool {
        (1..=self.common_scch_count + 1).contains(&slot)
    }

    pub fn set_common_control_channels(&mut self, physical: u8, advertised: u8, transition: bool) {
        self.common_scch_count = physical;
        self.force_common_sysinfo = transition;
        self.precomps.mac_sysinfo1.num_of_csch = advertised;
        self.precomps.mac_sysinfo2.num_of_csch = advertised;
        // TIP Core excludes minimum mode with common SCCH operation. Do not
        // advertise minimum-mode entry while the physical SCCHs are present.
        self.precomps.mle_sysinfo.bs_service_details.no_minimum_mode = self.configured_no_minimum_mode || physical > 0;
    }

    pub fn common_slot_is_drained(&self, slot: u8) -> bool {
        let i = usize::from(slot - 1);
        self.dltx_queues[i].is_empty()
            && self.dltx_half_duplex_queues[i].is_empty()
            && self.assoc_dltx_queues[i].is_empty()
            && self.assoc_best_effort_queues[i].is_empty()
            && self.pending_ra_acks[i].is_empty()
            && !self.circuits.is_active(Direction::Dl, slot)
            && !self.circuits.is_active(Direction::Ul, slot)
            && !self.packet_bearer_is_active(slot)
            && self.ulsched[i]
                .iter()
                .all(|reservation| reservation.ul1.is_none() && reservation.ul2.is_none())
    }

    pub fn trace_common_control_wait(&self, slot: u8) {
        let i = usize::from(slot - 1);
        tracing::debug!(
            slot,
            downlink = self.dltx_queues[i].len(),
            half_duplex = self.dltx_half_duplex_queues[i].len(),
            associated = self.assoc_dltx_queues[i].len(),
            best_effort = self.assoc_best_effort_queues[i].len(),
            random_access_acks = self.pending_ra_acks[i].len(),
            downlink_circuit = self.circuits.is_active(Direction::Dl, slot),
            uplink_circuit = self.circuits.is_active(Direction::Ul, slot),
            packet_bearer = self.packet_bearer_is_active(slot),
            reservations = self.ulsched[i].iter().filter(|r| r.ul1.is_some() || r.ul2.is_some()).count(),
            "waiting for common SCCH resource drain"
        );
    }

    /// An unallocated slot cannot drain ordinary signalling by itself. Move
    /// unstarted basic-link resources to MCCH before making it an SCCH. MAC
    /// fragments and packet resources belong to the old physical link: drop
    /// them with their reporters so LLC retries instead of migrating a partial
    /// transfer. Never withdraw an already announced uplink reservation.
    pub fn prepare_free_common_control_slot(&mut self, slot: u8) -> bool {
        let i = usize::from(slot - 1);
        if self.assigned_channel_is_active(slot)
            || self.ulsched[i].iter().any(|r| r.ul1.is_some() || r.ul2.is_some())
            || self
                .associated_ulsched
                .iter()
                .any(|(time, _)| time.t == slot && time.age(self.cur_dltime) <= 16)
        {
            return false;
        }
        self.dl_drop_associated_control(slot);
        let mut queued = std::mem::take(&mut self.dltx_queues[i]);
        queued.append(&mut self.dltx_half_duplex_queues[i]);
        let count = queued.len();
        for elem in queued {
            match elem {
                DlSchedElem::Resource(_, sdu, None, _, None) if sdu.get_len() == 0 => {
                    // An old MAC-only grant/RA response has no higher-layer
                    // payload to recover after its physical resource drained.
                }
                DlSchedElem::Resource(mut pdu, sdu, reporter, aie, None) => {
                    // Grants are relative to the channel on which they are
                    // sent. MCCH will reserve a fresh ACK grant when needed.
                    pdu.slot_granting_element = None;
                    pdu.update_len_and_fill_ind(sdu.get_len());
                    self.dltx_queues[0].push(DlSchedElem::Resource(pdu, sdu, reporter, aie, None));
                }
                DlSchedElem::Resource(_, _, Some(reporter), _, Some(_)) | DlSchedElem::Stealing(_, Some(reporter), ..) => {
                    if reporter.get_state() == tetra_core::TxState::Pending {
                        reporter.mark_discarded();
                    }
                }
                // Dropping a fragger notifies its reporter. Unsent old-link
                // grant/RA metadata is no longer applicable to the free slot.
                _ => {}
            }
        }
        self.pending_ra_acks[i].clear();
        if count > 0 {
            tracing::info!(
                slot,
                count,
                "recovered queued signalling from free slot before common SCCH allocation"
            );
        }
        self.common_slot_is_drained(slot)
    }

    pub fn retire_common_control_slot(&mut self, slot: u8, target: u8) {
        let old = usize::from(slot - 1);
        let target = usize::from(target - 1);
        let moved = std::mem::take(&mut self.dltx_queues[old]);
        self.dltx_queues[target].extend(moved);
    }

    pub fn dl_enqueue_common_tma(&mut self, ts: u8, pdu: MacResource, sdu: BitBuffer, reporter: Option<TxReporter>, aie: AieRequest) {
        let ts = if self.is_common_control(ts) { ts } else { 1 };
        self.dltx_queues[usize::from(ts - 1)].push(DlSchedElem::Resource(pdu, sdu, reporter, aie, None));
    }

    pub fn dl_enqueue_tma(&mut self, pdu: MacResource, sdu: BitBuffer, tx_reporter: Option<TxReporter>, aie_request: AieRequest) {
        // Get all timeslots on which a relevant MS is listening
        // let timeslots: [u8; NUM_TIMESLOTS] = self.identify_timeslots_for_ssi(pdu.addr);
        // No explicit assigned-channel route means common-control delivery on
        // MCCH TS1. Assigned traffic-channel signalling takes the separate
        // associated-channel path before reaching this fallback.
        tracing::trace!("downlink has no assigned-channel route; using MCCH TS1");
        let timeslots: [u8; NUM_TIMESLOTS] = [1, 0, 0, 0];

        // Queue the message for all timeslots on which we should transmit this message.
        // The loop basically prevents cloning the last element.
        for i in 0..NUM_TIMESLOTS {
            let ts = timeslots[i];
            let next_ts = if i < NUM_TIMESLOTS - 1 { timeslots[i + 1] } else { 0 };
            assert!(ts > 0);

            tracing::debug!(
                "dl_enqueue_tma: ts {} enqueueing {} PDU {:?} SDU {}",
                if tx_reporter.is_some() { "reported" } else { "" },
                ts,
                pdu,
                sdu.dump_bin(),
            );

            if next_ts > 0 {
                // There is another ts for which we need to transmit this message.
                // Clone the message now and push it to the current ts.
                let elem = DlSchedElem::Resource(pdu.clone(), sdu.clone(), tx_reporter.clone(), aie_request, None);
                self.dltx_queues[ts as usize - 1].push(elem);
            } else {
                // This is the last ts on which we need to transmit this message
                let elem = DlSchedElem::Resource(pdu, sdu, tx_reporter, aie_request, None);
                self.dltx_queues[ts as usize - 1].push(elem);
                break;
            }
        }
    }

    /// An all-MS security notice released for an EE reception frame takes
    /// precedence over ordinary queued MCCH resources. In-progress MAC
    /// fragments and announced uplink grants retain their scheduler priority.
    pub fn dl_enqueue_ee_mcch_tma(&mut self, pdu: MacResource, sdu: BitBuffer, reporter: TxReporter, aie_request: AieRequest) {
        self.dl_enqueue_ee_common_tma(1, pdu, sdu, reporter, aie_request);
    }

    pub fn dl_enqueue_ee_common_tma(&mut self, slot: u8, pdu: MacResource, sdu: BitBuffer, reporter: TxReporter, aie_request: AieRequest) {
        let slot = if self.is_common_control(slot) { slot } else { 1 };
        self.dltx_queues[usize::from(slot - 1)].insert(0, DlSchedElem::Resource(pdu, sdu, Some(reporter), aie_request, None));
    }

    /// Queue ordinary signalling on a currently allocated, non-traffic
    /// channel.  This is used for a tracked listener during hangtime: the MS
    /// is still tuned to that slot, but no speech is being carried so FN1-17
    /// are available and waiting for FN18 only adds avoidable latency.
    pub fn dl_enqueue_tma_on_timeslot(
        &mut self,
        ts: u8,
        pdu: MacResource,
        sdu: BitBuffer,
        tx_reporter: Option<TxReporter>,
        aie_request: AieRequest,
    ) {
        assert!((1..=4).contains(&ts), "invalid downlink timeslot");
        self.dltx_queues[ts as usize - 1].push(DlSchedElem::Resource(pdu, sdu, tx_reporter, aie_request, None));
    }

    /// Queue packet data on one member of the MS's assigned multislot bearer.
    /// The complete slot bitmap remains attached to the resource so a MAC
    /// fragment can continue on the next physical PDCH opportunity.
    pub fn dl_enqueue_packet_tma_on_timeslot(
        &mut self,
        ts: u8,
        pdu: MacResource,
        sdu: BitBuffer,
        tx_reporter: Option<TxReporter>,
        aie_request: AieRequest,
        packet_data_slots: [bool; 4],
    ) {
        assert!((2..=4).contains(&ts), "packet data must use an assigned PDCH timeslot");
        assert!(
            packet_data_slots[ts as usize - 1],
            "packet-data target must be part of the MS allocation"
        );
        self.dltx_queues[ts as usize - 1].push(DlSchedElem::Resource(pdu, sdu, tx_reporter, aie_request, Some(packet_data_slots)));
    }

    pub fn dl_enqueue_associated_tma(
        &mut self,
        ts: u8,
        pdu: MacResource,
        sdu: BitBuffer,
        tx_reporter: Option<TxReporter>,
        aie_request: AieRequest,
    ) {
        assert!((2..=4).contains(&ts), "associated control must use an assigned timeslot");
        let queue = &mut self.assoc_dltx_queues[ts as usize - 1];
        tracing::debug!(
            ts,
            addr = ?pdu.addr,
            sdu_bits = sdu.get_len(),
            queued_before = queue.len(),
            "queued associated FN18 control resource"
        );
        queue.push(DlSchedElem::Resource(pdu, sdu, tx_reporter, aie_request, None));
    }

    /// Queue an expendable associated repeat. At most one copy per key waits
    /// on a bearer, preventing the periodic producer from building backlog
    /// when speech/control leaves fewer free opportunities than expected.
    pub fn dl_enqueue_associated_best_effort_tma(&mut self, ts: u8, key: u16, pdu: MacResource, sdu: BitBuffer, aie_request: AieRequest) {
        self.dl_enqueue_associated_best_effort(ts, AssociatedBestEffortKind::CallRepeat(key), pdu, sdu, aie_request);
    }

    /// Queue the all-MS neighbour broadcast below SDS, grants, call control,
    /// packet data and periodic call repeats. It has no frames 1..17 fallback.
    pub fn dl_enqueue_associated_frame18_broadcast(&mut self, ts: u8, pdu: MacResource, sdu: BitBuffer, aie_request: AieRequest) {
        let gssi = pdu.addr.map_or(0, |address| address.ssi);
        self.dl_enqueue_associated_best_effort(ts, AssociatedBestEffortKind::Frame18Broadcast(gssi), pdu, sdu, aie_request);
    }

    /// Reserve the four physical FN18 resources directly before a TS1/FN1
    /// SC3G change.  This is called only by the marker carried with the
    /// `D-CK CHANGE DEMAND` whose time type is `Immediate`.
    pub fn reserve_gck_rollover_immediate(
        &mut self,
        activation: TdmaTime,
        pdu: MacResource,
        sdu: BitBuffer,
        aie_request: AieRequest,
    ) -> Result<(), &'static str> {
        if !activation.is_valid() || activation.t != 1 || activation.f != 1 {
            return Err("SC3G rollover activation must be TS1/FN1");
        }
        if !pdu
            .addr
            .is_some_and(|address| address.ssi != 0 && address.ssi_type == SsiType::Gssi)
        {
            return Err("SC3G rollover Immediate must be GSSI addressed");
        }
        // A final `Immediate` is an atomic four-timeslot operation. A
        // previous request can be left partly reserved if a cell is reset or
        // its old activation was superseded before its FN18. Treating that
        // stale fragment as a collision made the new marker fail completely,
        // so no MS received the mandatory final notification. There can be
        // only one locally staged SC3G rollover; a marker accepted while the
        // preceding TS4/FN17 is finalized is authoritative and replaces every
        // old fragment as one set.
        let replaced = self
            .final_gck_rollover_immediate
            .iter()
            .flatten()
            .any(|existing| existing.activation != activation);
        if replaced {
            let previous = self
                .final_gck_rollover_immediate
                .iter()
                .flatten()
                .map(|existing| existing.activation)
                .next();
            tracing::warn!(
                previous_activation = ?previous,
                activation = %activation,
                "replacing stale partial SC3G GCK rollover Immediate reservation"
            );
        }
        let reservation = FinalGckRolloverImmediate {
            activation,
            pdu,
            sdu,
            aie_request,
        };
        self.final_gck_rollover_immediate = std::array::from_fn(|_| Some(reservation.clone()));
        Ok(())
    }

    fn take_final_gck_rollover_immediate(&mut self, ts: TdmaTime) -> Option<FinalGckRolloverImmediate> {
        if ts.f != 18 {
            return None;
        }
        let slot = usize::from(ts.t - 1);
        let item = self.final_gck_rollover_immediate[slot].as_ref()?;
        // TS1..TS4 of this FN18 are respectively four, three, two and one
        // timeslots before the TS1/FN1 change.  `diff` is wrap-safe at the
        // hyperframe boundary.
        if !(1..=4).contains(&item.activation.diff(ts)) {
            return None;
        }
        self.final_gck_rollover_immediate[slot].take()
    }

    #[cfg(test)]
    pub(crate) fn pending_final_gck_rollover_count(&self) -> usize {
        self.final_gck_rollover_immediate
            .iter()
            .filter(|reservation| reservation.is_some())
            .count()
    }

    fn build_final_gck_rollover_resource(&mut self, item: FinalGckRolloverImmediate, ts: TdmaTime, capacity: usize) -> BitBuffer {
        let pdu = self
            .prepare_downlink_resource(item.pdu, item.aie_request, ts)
            .expect("reserved SC3G GCK rollover Immediate has a valid old-key context");
        let mut buffer = BitBuffer::new(capacity);
        let mut fragger = BsFragger::new_with_aie(pdu, item.sdu, None, item.aie_request);
        let complete = fragger.get_next_chunk(&mut buffer);
        assert!(
            complete,
            "reserved SC3G GCK rollover Immediate must fit in one FN18 signalling resource"
        );
        self.cipher_fresh_downlink_chunk(&mut fragger, &mut buffer, ts)
            .expect("reserved SC3G GCK rollover Immediate ciphering must succeed");
        finalize_downlink_mac_block(&mut buffer);
        buffer
    }

    fn build_final_gck_rollover_slot(&mut self, item: FinalGckRolloverImmediate, ts: TdmaTime) -> TmvUnitdataReqSlot {
        let assigned_channel = ts.t != 1 && self.assigned_channel_is_active(ts.t);
        // Preserve the MM-selected GSSI, including the CMG address on an
        // assigned channel. It must not become the voice talkgroup address.
        let ul_phy_chan = if assigned_channel {
            PhysicalChannel::Tp
        } else {
            PhysicalChannel::Cp
        };
        let sch_hd = |scheduler: &mut Self, item: FinalGckRolloverImmediate| TmvUnitdataReq {
            logical_channel: LogicalChannel::SchHd,
            mac_block: scheduler.build_final_gck_rollover_resource(item, ts, SCH_HD_CAP),
            scrambling_code: scheduler.scrambling_code,
            air_interface_encryption: None,
            cipher_region: None,
        };
        if ts.is_mandatory_bsch() {
            let mut sync = BitBuffer::new(60);
            self.precomps.mac_sync.to_bitbuf(&mut sync);
            self.precomps.mle_sync.to_bitbuf(&mut sync);
            TmvUnitdataReqSlot {
                ts,
                blk1: Some(TmvUnitdataReq {
                    logical_channel: LogicalChannel::Bsch,
                    mac_block: sync,
                    scrambling_code: scrambler::SCRAMB_INIT,
                    air_interface_encryption: None,
                    cipher_region: None,
                }),
                blk2: Some(sch_hd(self, item)),
                bbk: None,
                ul_phy_chan,
            }
        } else if ts.is_mandatory_bnch() {
            let mut sysinfo = BitBuffer::new(SCH_HD_CAP);
            if use_default_access_sysinfo(ts) {
                self.precomps.mac_sysinfo1.to_bitbuf(&mut sysinfo);
            } else {
                self.precomps.mac_sysinfo2.to_bitbuf(&mut sysinfo);
            }
            self.precomps.mle_sysinfo.to_bitbuf(&mut sysinfo);
            TmvUnitdataReqSlot {
                ts,
                blk1: Some(sch_hd(self, item)),
                blk2: Some(TmvUnitdataReq {
                    logical_channel: LogicalChannel::Bnch,
                    mac_block: sysinfo,
                    scrambling_code: self.scrambling_code,
                    air_interface_encryption: None,
                    cipher_region: None,
                }),
                bbk: None,
                ul_phy_chan,
            }
        } else {
            TmvUnitdataReqSlot {
                ts,
                blk1: Some(TmvUnitdataReq {
                    logical_channel: LogicalChannel::SchF,
                    mac_block: self.build_final_gck_rollover_resource(item, ts, SCH_F_CAP),
                    scrambling_code: self.scrambling_code,
                    air_interface_encryption: None,
                    cipher_region: None,
                }),
                blk2: None,
                bbk: None,
                ul_phy_chan,
            }
        }
    }

    fn dl_enqueue_associated_best_effort(
        &mut self,
        ts: u8,
        kind: AssociatedBestEffortKind,
        pdu: MacResource,
        sdu: BitBuffer,
        aie_request: AieRequest,
    ) {
        assert!((2..=4).contains(&ts), "associated control must use an assigned timeslot");
        let queue = &mut self.assoc_best_effort_queues[ts as usize - 1];
        if queue.iter().any(|queued| queued.kind == kind) {
            tracing::trace!(ts, ?kind, "coalescing duplicate best-effort associated repeat");
            return;
        }
        tracing::debug!(
            ts,
            ?kind,
            addr = ?pdu.addr,
            sdu_bits = sdu.get_len(),
            queued_before = queue.len(),
            "queued best-effort associated repeat"
        );
        queue.push(AssociatedBestEffortElem {
            kind,
            elem: DlSchedElem::Resource(pdu, sdu, None, aie_request, None),
        });
    }

    /// Deliver a capacity grant through the target channel's FN18 control
    /// frame. This makes the preceding AACH reservation and the grant PDU
    /// visible on the same associated channel, without downlink stealing.
    pub fn dl_enqueue_associated_grant(&mut self, ts: u8, addr: TetraAddress, grant: BasicSlotgrant) {
        assert!((2..=4).contains(&ts), "associated grant must use an assigned timeslot");
        // A MAC-ACCESS reservation is complete only once the BS acknowledges
        // that random access.  In the normal control path this flag is added
        // while integrating a queued RandomAccessAck; on FN18 we build the
        // associated response directly, so it must be present here.
        let pdu = Self::dl_make_minimal_resource(&addr, Some(grant), true);
        self.assoc_dltx_queues[ts as usize - 1].push(DlSchedElem::Resource(
            pdu,
            BitBuffer::new(0),
            None,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
            None,
        ));
    }

    /// Queue an associated-channel capacity request without reserving its
    /// target FN18 yet. A mandatory BSCH/BNCH can defer this request, so the
    /// grant and reservation must be derived from the FN18 that really
    /// carries the MAC-RESOURCE.
    pub fn dl_enqueue_associated_grant_request(&mut self, ts: u8, addr: TetraAddress, res_req: ReservationRequirement) {
        assert!((2..=4).contains(&ts), "associated grant must use an assigned timeslot");
        let requested_slots = if res_req == ReservationRequirement::Req1Subslot {
            1
        } else {
            res_req.to_req_slotcount()
        };
        tracing::debug!(
            ts,
            address = ?addr,
            res_req = ?res_req,
            requested_slots,
            "queued associated FN18 grant request"
        );
        self.assoc_dltx_queues[ts as usize - 1].push(DlSchedElem::AssociatedGrantRequest(addr, res_req, requested_slots));
    }

    /// Bind the upper-layer policy to this exact scheduled downlink slot and
    /// prepare the clear MAC header. Addressed encrypted resources use an
    /// IESI or GESI; an assigned packet advanced link keeps its clear event
    /// label because that label replaces the SSI in the MAC header.
    fn prepare_downlink_resource(&self, mut pdu: MacResource, request: AieRequest, time: TdmaTime) -> Result<MacResource, AieContextError> {
        let context = self.resolve_downlink_context(request, time)?;
        if context.is_encrypted() {
            match request {
                AieRequest::Sc2 { subject, .. } | AieRequest::Sc3 { subject, .. } => {
                    if let Some(address) = pdu.addr.as_mut() {
                        let expected_type = match subject {
                            AieSubject::Individual { .. } => SsiType::Issi,
                            AieSubject::Group { .. } => SsiType::Gssi,
                            _ => return Err(AieContextError::InvalidContext),
                        };
                        if address.ssi_type != expected_type
                            && !(matches!(subject, AieSubject::Individual { .. }) && address.ssi_type == SsiType::Ssi)
                        {
                            return Err(AieContextError::InvalidContext);
                        }
                        address.ssi = self
                            .aie_provider
                            .as_ref()
                            .ok_or(AieContextError::Sc2Disabled)?
                            .encrypted_short_identity(context, address.ssi)?;
                        address.ssi_type = SsiType::Esi;
                    } else if pdu.event_label.is_none() || !matches!(subject, AieSubject::Individual { .. }) {
                        return Err(AieContextError::InvalidContext);
                    }
                }
                _ => return Err(AieContextError::InvalidContext),
            }
            pdu.encryption_mode = match context {
                AieContext::Sc2 { key, .. } => 0b10 | (key.sck_vn as u8 & 1),
                AieContext::Sc3 { key, .. } => 0b10 | (key.cck_id as u8 & 1),
                AieContext::Clear { .. } => 0,
            };
        }
        Ok(pdu)
    }

    /// Cipher the exact payload region written by one MAC-RESOURCE,
    /// MAC-FRAG, or MAC-END.  Each fragment resolves a fresh context at its
    /// own slot, thereby resetting the KSS as required by phase modulation.
    fn cipher_fresh_downlink_chunk(
        &self,
        fragger: &mut BsFragger,
        mac_block: &mut BitBuffer,
        time: TdmaTime,
    ) -> Result<(), AieContextError> {
        let Some(region) = fragger.take_cipher_region() else {
            return Ok(());
        };
        let context = self.resolve_downlink_context(region.request, time)?;
        if context.is_encrypted() {
            self.aie_provider
                .as_ref()
                .ok_or(AieContextError::Sc2Disabled)?
                .cipher_downlink_mac(context, mac_block, region.start, region.len)?;
        }
        Ok(())
    }

    fn resolve_downlink_context(&self, request: AieRequest, time: TdmaTime) -> Result<AieContext, AieContextError> {
        match request {
            AieRequest::Clear { subject, scope } => Ok(AieContext::clear(subject, AieDirection::Downlink, time, scope)),
            AieRequest::Sc2 { .. } | AieRequest::Sc3 { .. } => {
                self.aie_provider
                    .as_ref()
                    .ok_or(AieContextError::Sc2Disabled)?
                    .resolve(request, AieDirection::Downlink, time)
            }
        }
    }

    fn dl_build_associated_control_block(&mut self, ts: TdmaTime) -> Option<BitBuffer> {
        let item = {
            let queue = &mut self.assoc_dltx_queues[ts.t as usize - 1];
            queue.retain(|item| !item.is_cancelled());
            // A fragmented TM-SDU owns this SACCH until MAC-END.  EN 300
            // 392-2 clauses 23.4.2.1.5 and 23.4.3.1.1 require the receiver to
            // reconstruct continuation fragments on this control channel;
            // transmitting another fragment start first would make it discard
            // the partial TM-SDU.  Supported uplink grants remain immediate,
            // while acknowledged downlinks take precedence over ordinary
            // associated signalling.  Multi-slot capacity requests are
            // served one FN18 slot at a time as required for SACCH.
            let pos = queue
                .iter()
                .position(|item| matches!(item, DlSchedElem::FragBuf(..)))
                .or_else(|| {
                    queue
                        .iter()
                        .position(|item| matches!(item, DlSchedElem::AssociatedGrantRequest(..)))
                })
                .or_else(|| {
                    queue
                        .iter()
                        .position(|item| matches!(item, DlSchedElem::Resource(_, _, Some(reporter), _, _) if reporter.expects_ack()))
                })
                .or_else(|| {
                    queue
                        .iter()
                        .position(|item| matches!(item, DlSchedElem::Resource(..) | DlSchedElem::AssociatedGrantRequest(..)))
                })?;
            queue.remove(pos)
        };
        let mut buf = BitBuffer::new(SCH_F_CAP);
        match item {
            DlSchedElem::Resource(mut pdu, sdu, reporter, aie_request, packet_data_slots) => {
                let acknowledged_addr = reporter.as_ref().is_some_and(TxReporter::expects_ack).then_some(pdu.addr).flatten();
                // TTR 001-01 14.1.14 permits a current-channel grant in either
                // MAC-RESOURCE or MAC-END.  Grant in MAC-RESOURCE only when
                // the complete BL-DATA fits there.  A fragmented SDS cannot
                // be acknowledged until MAC-END, so its grant is added at the
                // actual transmission time of that final fragment below.
                let resource_len_with_grant = pdu.compute_header_len()
                    + usize::from(pdu.slot_granting_element.is_none() && acknowledged_addr.is_some()) * 8
                    + sdu.get_len();
                let resource_fill = fillbits::addition::compute_required(resource_len_with_grant, SCH_F_CAP);
                let completes_in_resource = resource_len_with_grant + resource_fill <= SCH_F_CAP;
                if completes_in_resource
                    && pdu.slot_granting_element.is_none()
                    && let Some(addr) = acknowledged_addr
                {
                    let Some(grant) = self.ul_prepare_associated_basic_link_ack_grant_at(ts, addr) else {
                        self.assoc_dltx_queues[ts.t as usize - 1]
                            .insert(0, DlSchedElem::Resource(pdu, sdu, reporter, aie_request, packet_data_slots));
                        return None;
                    };
                    tracing::info!(
                        dltime = %ts,
                        address = ?addr,
                        grant = ?grant,
                        "prepared FN18 basic-link acknowledgement grant in complete MAC-RESOURCE"
                    );
                    pdu.slot_granting_element = Some(grant);
                    pdu.update_len_and_fill_ind(sdu.get_len());
                }
                tracing::debug!(
                    dltime = %ts,
                    addr = ?pdu.addr,
                    sdu_bits = sdu.get_len(),
                    queued_after_pop = self.assoc_dltx_queues[ts.t as usize - 1].len(),
                    "building associated FN18 control block"
                );
                let pdu = match self.prepare_downlink_resource(pdu, aie_request, ts) {
                    Ok(pdu) => pdu,
                    Err(error) => {
                        tracing::warn!(dltime = %ts, ?error, "dropping associated MAC resource without a valid AIE context");
                        if let Some(reporter) = reporter.as_ref()
                            && reporter.get_state() == tetra_core::TxState::Pending
                        {
                            reporter.mark_discarded();
                        }
                        return None;
                    }
                };
                let mut fragger = BsFragger::new_with_aie(pdu, sdu, reporter, aie_request);
                let written_before = buf.get_len_written();
                let complete = fragger.get_next_chunk(&mut buf);
                if let Err(error) = self.cipher_fresh_downlink_chunk(&mut fragger, &mut buf, ts) {
                    tracing::warn!(dltime = %ts, ?error, "dropping associated MAC resource after AIE cipher failure");
                    return None;
                }
                if !complete {
                    if written_before == 0 && buf.get_len_written() == 0 {
                        tracing::warn!(dltime = %ts, "dropping associated MAC resource that cannot make progress in an empty SCH/F");
                    } else {
                        if acknowledged_addr.is_some() && fragger.has_started() {
                            fragger.require_final_slot_grant();
                        }
                        self.assoc_dltx_queues[ts.t as usize - 1].insert(0, DlSchedElem::FragBuf(fragger, packet_data_slots));
                    }
                }
            }
            DlSchedElem::FragBuf(mut fragger, packet_data_slots) => {
                if fragger.expects_ack() && fragger.can_finish_with_slot_grant(buf.get_len_remaining()) {
                    let Some(issi) = fragger.individual_issi() else {
                        tracing::warn!(dltime = %ts, "associated acknowledged fragment has no individual address for its MAC-END grant");
                        self.assoc_dltx_queues[ts.t as usize - 1].insert(0, DlSchedElem::FragBuf(fragger, packet_data_slots));
                        return None;
                    };
                    let addr = TetraAddress::issi(issi);
                    let Some(grant) = self.ul_prepare_associated_basic_link_ack_grant_at(ts, addr) else {
                        self.assoc_dltx_queues[ts.t as usize - 1].insert(0, DlSchedElem::FragBuf(fragger, packet_data_slots));
                        return None;
                    };
                    tracing::info!(
                        dltime = %ts,
                        address = ?addr,
                        grant = ?grant,
                        "prepared FN18 basic-link acknowledgement grant in final MAC-END"
                    );
                    fragger.set_completion_slot_grant(grant);
                }
                let written_before = buf.get_len_written();
                let complete = fragger.get_next_chunk(&mut buf);
                if let Err(error) = self.cipher_fresh_downlink_chunk(&mut fragger, &mut buf, ts) {
                    tracing::warn!(dltime = %ts, ?error, "dropping associated MAC fragment after AIE cipher failure");
                    return None;
                }
                if !complete {
                    if written_before == 0 && buf.get_len_written() == 0 {
                        tracing::warn!(dltime = %ts, "dropping associated MAC fragment that cannot make progress in an empty SCH/F");
                    } else {
                        self.assoc_dltx_queues[ts.t as usize - 1].insert(0, DlSchedElem::FragBuf(fragger, packet_data_slots));
                    }
                }
            }
            DlSchedElem::AssociatedGrantRequest(addr, res_req, requested_slots) => {
                let Some(grant) = self.ul_process_associated_fn18_cap_req(ts, addr, &res_req) else {
                    tracing::warn!(
                        dltime = %ts,
                        address = ?addr,
                        res_req = ?res_req,
                        "associated FN18 grant could not be allocated; retrying request"
                    );
                    self.assoc_dltx_queues[ts.t as usize - 1].push(DlSchedElem::AssociatedGrantRequest(addr, res_req, requested_slots));
                    return None;
                };

                tracing::info!(
                    dltime = %ts,
                    address = ?addr,
                    grant = ?grant,
                    "prepared associated FN18 grant at actual transmission time"
                );
                let pdu = Self::dl_make_minimal_resource(&addr, Some(grant), true);
                let request = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
                let mut fragger = BsFragger::new_with_aie(pdu, BitBuffer::new(0), None, request);
                if !fragger.get_next_chunk(&mut buf) {
                    self.assoc_dltx_queues[ts.t as usize - 1].push(DlSchedElem::FragBuf(fragger, None));
                }

                // On SACCH the BS may grant only one reserved slot at a time
                // (23.5.2.2.4), but the original reservation requirement is
                // for the complete remainder of the fragmented TM-SDU. A
                // MAC-FRAG has no reservation-requirement field, so the MS
                // cannot ask again after using this slot. Queue every
                // outstanding slot as another one-slot grant for a later
                // FN18, as explicitly permitted by 23.4.2.1.2.
                if requested_slots > 1 {
                    let remaining_slots = requested_slots - 1;
                    self.assoc_dltx_queues[ts.t as usize - 1].push(DlSchedElem::AssociatedGrantRequest(
                        addr,
                        ReservationRequirement::from_req_slotcount(remaining_slots),
                        remaining_slots,
                    ));
                    tracing::info!(
                        dltime = %ts,
                        address = ?addr,
                        remaining_slots,
                        "queued remaining associated SACCH capacity"
                    );
                }
            }
            _ => unreachable!(),
        }

        let remaining_before = buf.get_len_remaining();
        let (null_pdu_inserted, fill_bits_inserted) = finalize_downlink_mac_block(&mut buf);
        tracing::info!(
            dltime = %ts,
            timeslot = ts.t,
            physical_channel = ?PhysicalChannel::Tp,
            logical_channel = ?LogicalChannel::SchF,
            used_bits = buf.get_pos() - remaining_before,
            remaining_bits_before = remaining_before,
            null_pdu_inserted,
            fill_bits_inserted,
            "building associated FN18 SACCH"
        );
        Some(buf)
    }

    /// Build one expendable associated repeat. This queue is deliberately
    /// separate from normal control so an in-progress low-priority message can
    /// be abandoned when SDS, a grant, or any other signalling arrives.
    fn dl_build_best_effort_associated_control_block(&mut self, ts: TdmaTime, permit_frame18_broadcast: bool) -> Option<BitBuffer> {
        let queue = &self.assoc_best_effort_queues[ts.t as usize - 1];
        // Periodic call control is more useful than the neighbour carousel and
        // therefore wins even if its item was queued later. Outside FN18 the
        // frame18-only class is deliberately not eligible at all.
        let index = queue
            .iter()
            .position(|queued| !queued.kind.is_frame18_only())
            .or_else(|| permit_frame18_broadcast.then_some(0).filter(|_| !queue.is_empty()))?;
        let AssociatedBestEffortElem { kind, elem: item } = self.assoc_best_effort_queues[ts.t as usize - 1].remove(index);
        if kind.is_frame18_only() {
            assert!(
                ts.f == 18 && !ts.is_mandatory_bsch() && !ts.is_mandatory_bnch(),
                "frame-18 broadcast selected outside a free frame-18 slot"
            );
        }
        let mut buf = BitBuffer::new(SCH_F_CAP);
        match item {
            DlSchedElem::Resource(pdu, sdu, _, aie_request, packet_data_slots) => {
                let pdu = match self.prepare_downlink_resource(pdu, aie_request, ts) {
                    Ok(pdu) => pdu,
                    Err(error) => {
                        tracing::debug!(dltime = %ts, ?kind, ?error, "dropping best-effort associated repeat without a valid AIE context");
                        return None;
                    }
                };
                let mut fragger = BsFragger::new_with_aie(pdu, sdu, None, aie_request);
                let written_before = buf.get_len_written();
                let complete = fragger.get_next_chunk(&mut buf);
                if let Err(error) = self.cipher_fresh_downlink_chunk(&mut fragger, &mut buf, ts) {
                    tracing::debug!(dltime = %ts, ?kind, ?error, "dropping best-effort associated repeat after AIE cipher failure");
                    return None;
                }
                if !complete {
                    if written_before == 0 && buf.get_len_written() == 0 {
                        tracing::debug!(dltime = %ts, ?kind, "dropping best-effort associated repeat that cannot make progress");
                    } else {
                        self.assoc_best_effort_queues[ts.t as usize - 1].insert(
                            index,
                            AssociatedBestEffortElem {
                                kind,
                                elem: DlSchedElem::FragBuf(fragger, packet_data_slots),
                            },
                        );
                    }
                }
            }
            DlSchedElem::FragBuf(mut fragger, packet_data_slots) => {
                let written_before = buf.get_len_written();
                let complete = fragger.get_next_chunk(&mut buf);
                if let Err(error) = self.cipher_fresh_downlink_chunk(&mut fragger, &mut buf, ts) {
                    tracing::debug!(dltime = %ts, ?kind, ?error, "dropping best-effort associated fragment after AIE cipher failure");
                    return None;
                }
                if !complete {
                    if written_before == 0 && buf.get_len_written() == 0 {
                        tracing::debug!(dltime = %ts, ?kind, "dropping best-effort associated fragment that cannot make progress");
                    } else {
                        self.assoc_best_effort_queues[ts.t as usize - 1].insert(
                            index,
                            AssociatedBestEffortElem {
                                kind,
                                elem: DlSchedElem::FragBuf(fragger, packet_data_slots),
                            },
                        );
                    }
                }
            }
            _ => unreachable!("best-effort associated queue accepts only resources and fragments"),
        }

        let remaining_before = buf.get_len_remaining();
        finalize_downlink_mac_block(&mut buf);
        tracing::debug!(
            dltime = %ts,
            timeslot = ts.t,
            ?kind,
            used_bits = SCH_F_CAP - remaining_before,
            "building best-effort associated SCH/F control block"
        );
        Some(buf)
    }

    /// A different MAC resource between a MAC-FRAG and MAC-END invalidates
    /// the receiver's fragment chain. Drop only the partial expendable copy;
    /// its next periodic occurrence will start again from MAC-RESOURCE.
    fn cancel_interrupted_best_effort_fragment(&mut self, timeslot: u8) {
        let queue = &mut self.assoc_best_effort_queues[timeslot as usize - 1];
        let before = queue.len();
        queue.retain(|queued| !matches!(&queued.elem, DlSchedElem::FragBuf(..)));
        if queue.len() != before {
            tracing::debug!(
                dltime = %self.cur_dltime,
                ts = timeslot,
                "discarding interrupted best-effort fragment chain"
            );
        }
    }

    /// Consumes and returns true if a pending random access ack exists for the given SSI on
    /// this timeslot. Used when building STCH blocks so the MAC-RESOURCE can carry
    /// random_access_flag=true per ETSI 21.4.3.1.
    pub fn take_pending_ra_ack(&mut self, ts: u8, ssi: u32) -> bool {
        let pending = &mut self.pending_ra_acks[ts as usize - 1];
        if let Some(pos) = pending.iter().position(|&s| s == ssi) {
            pending.remove(pos);
            true
        } else {
            false
        }
    }

    /// Whether a received MAC-ACCESS still has an acknowledgement queued for
    /// this ISSI. Its correlated downlink response is an immediate response
    /// procedure, not unsolicited MCCH traffic, so UMAC must not EE-defer it.
    pub fn has_pending_random_access_ack(&self, ssi: u32) -> bool {
        self.pending_ra_acks.iter().any(|pending| pending.contains(&ssi))
            || self.dltx_queues.iter().any(|queue| {
                queue
                    .iter()
                    .any(|element| matches!(element, DlSchedElem::RandomAccessAck(address, _) if address.ssi == ssi))
            })
    }

    /// Enqueue a pre-built STCH block for FACCH/stealing on a traffic timeslot.
    /// The block must be 124 type1 bits containing MAC-U-SIGNAL header + TM-SDU.
    pub fn dl_enqueue_stealing(
        &mut self,
        ts: u8,
        block: BitBuffer,
        tx_reporter: Option<TxReporter>,
        aie_request: AieRequest,
        cipher_region: Option<AieCipherRegion>,
    ) {
        tracing::info!(
            dltime = %self.cur_dltime,
            ts,
            stch_bits = block.get_len(),
            hangtime = self.is_hangtime(ts),
            queued_before = self.dltx_queues[ts as usize - 1].len(),
            "queued FACCH/STCH block"
        );
        self.dltx_queues[ts as usize - 1].push(DlSchedElem::Stealing(block, tx_reporter, aie_request, cipher_region));
    }

    /// Update the policy that accompanies ordinary TCH/S speech on a circuit.
    /// The provider still resolves it in LMAC at the actual TX time.
    pub fn set_traffic_aie(&mut self, ts: u8, request: Option<AieRequest>) {
        if (1..=4).contains(&ts) {
            self.traffic_aie[ts as usize - 1] = request;
        }
    }

    pub(crate) fn traffic_aie(&self, ts: u8) -> Option<AieRequest> {
        (1..=4).contains(&ts).then(|| self.traffic_aie[ts as usize - 1]).flatten()
    }

    fn next_packet_data_control_after(&self, current_ts: u8, allowed_slots: [bool; 4]) -> Option<u8> {
        if !(2..=4).contains(&current_ts) {
            return None;
        }
        (current_ts + 1..=4)
            .chain(2..current_ts)
            .find(|ts| allowed_slots[*ts as usize - 1] && self.packet_bearer_is_active(*ts))
    }

    fn dl_enqueue_tma_frag_continuation(&mut self, current_ts: u8, fragger: BsFragger, packet_data_slots: Option<[bool; 4]>) {
        let elem = DlSchedElem::FragBuf(fragger, packet_data_slots);
        let target_ts = packet_data_slots
            .and_then(|slots| self.next_packet_data_control_after(current_ts, slots))
            .unwrap_or(current_ts);
        if target_ts == current_ts {
            tracing::debug!(target_ts, "queueing MAC fragment on the same timeslot next frame");
            self.dltx_next_slot_queue.push(elem);
        } else {
            tracing::debug!(current_ts, target_ts, "striping packet-data MAC fragment to the next assigned PDCH");
            self.dltx_queues[target_ts as usize - 1].push(elem);
        }
    }

    pub fn dl_schedule_tmb(&mut self, _traffic: BitBuffer, _ts: &TdmaTime) {
        unimplemented!("Broadcast scheduling not implemented yet");
    }

    // pub fn dl_schedule_tmd(&mut self, _traffic: BitBuffer, _ts: &TdmaTime) {
    //     unimplemented!("Traffic scheduling not implemented yet");
    // }

    pub fn dl_schedule_tmd(&mut self, ts: u8, block: Vec<u8>) {
        self.circuits.put_block(ts, block);
    }

    pub fn circuit_is_active(&self, dir: Direction, ts: u8) -> bool {
        self.circuits.is_active(dir, ts)
    }

    /// Return every active downlink traffic bearer and its usage marker.
    /// An all-MS STCH broadcast must be copied to each of these channels;
    /// choosing only the first active circuit leaves listeners on the other
    /// group calls unaware of the pending key change.
    pub fn active_downlink_traffic_channels(&self) -> Vec<(u8, u8)> {
        (2..=4)
            .filter_map(|timeslot| self.circuits.get_usage(Direction::Dl, timeslot).map(|usage| (timeslot, usage)))
            .collect()
    }

    pub fn close_circuit(&mut self, dir: Direction, ts: u8) -> Option<Circuit> {
        // Clearing hangtime here is safe: if the circuit is gone, this timeslot is no longer in use.
        if (1..=4).contains(&ts) {
            self.hangtime[ts as usize - 1] = false;
        }
        let closed = self.circuits.close_circuit(dir, ts);

        // An associated basic link exists only while its physical resource
        // allocation exists (ETSI TS 100 392-2 clause 22.3.2.1).  A resource
        // can be queued for the next usable FN18 when both directions of the
        // circuit are closed.  Report that queued transmission as discarded;
        // otherwise LLC never receives a MAC completion, never starts its
        // retry handling, and every later acknowledged PDU for the SSI remains
        // blocked behind the orphaned item indefinitely.
        if closed.is_some()
            && (1..=4).contains(&ts)
            && !self.circuits.is_active(Direction::Dl, ts)
            && !self.circuits.is_active(Direction::Ul, ts)
        {
            self.dl_drop_associated_control(ts);
        }

        closed
    }

    pub fn create_circuit(&mut self, dir: Direction, circuit: Circuit) {
        // New/updated circuit implies traffic mode.
        if (1..=4).contains(&circuit.ts) {
            self.hangtime[circuit.ts as usize - 1] = false;
        }
        self.circuits.create_circuit(dir, circuit);
    }

    /// Takes a block or None value.
    /// If block is present and some signalling channel, and space is available,
    /// adds a trailing Null PDU.
    /// If blk is None, returns None.
    /// Otherwise, returns blk unchanged (eg. for SYNC, broadcast, etc).
    pub fn try_add_null_pdus(&mut self, blk: Option<TmvUnitdataReq>) -> Option<TmvUnitdataReq> {
        if let Some(mut b) = blk {
            // STCH: MAC-U-SIGNAL occupies entire half-slot (3-bit header + 121-bit TM-SDU).
            // No additional MAC PDUs may be concatenated; receiver passes all bits after header to LLC.
            // Adding a null PDU would corrupt TM-SDU (misinterpreted as optional CMCE element flags).
            if b.logical_channel == LogicalChannel::SchHd || b.logical_channel == LogicalChannel::SchF {
                let remaining_before = b.mac_block.get_len_remaining();
                let (null_pdu_inserted, fill_bits_inserted) = finalize_downlink_mac_block(&mut b.mac_block);
                tracing::debug!(
                    logical_channel = ?b.logical_channel,
                    used_bits = b.mac_block.get_pos() - remaining_before,
                    remaining_bits_before = remaining_before,
                    null_pdu_inserted,
                    fill_bits_inserted,
                    "finalized downlink signalling MAC block"
                );
            }

            Some(b)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the first scheduled resource for the given timeslot and address
    pub fn dl_get_scheduled_resource_for_ssi(&mut self, ts: TdmaTime, addr: &TetraAddress) -> Option<&mut DlSchedElem> {
        let queue = &mut self.dltx_queues[ts.t as usize - 1];

        for index in 0..queue.len() {
            let elem = &mut queue[index];
            if let DlSchedElem::Resource(pdu, _sdu, _repeat, _aie_request, _) = elem {
                if let Some(pdu_ssi) = pdu.addr {
                    if pdu_ssi.ssi == addr.ssi {
                        // Found a resource for this address
                        return queue.get_mut(index);
                    }
                }
            }
        }
        // No resource for this address was found
        None
    }

    /// Make a minimal resource to contain a grant or a random access acknowledgement
    pub fn dl_make_minimal_resource(addr: &TetraAddress, grant: Option<BasicSlotgrant>, random_access_ack: bool) -> MacResource {
        let mut pdu = MacResource {
            fill_bits: false, // updated later
            pos_of_grant: 0,
            encryption_mode: 0,
            random_access_flag: random_access_ack,
            length_ind: 0, // updated later
            addr: Some(*addr),
            event_label: None,
            usage_marker: None,
            power_control_element: None,
            slot_granting_element: grant,
            chan_alloc_element: None,
        };
        pdu.update_len_and_fill_ind(0);
        pdu
    }

    /// Takes and removes all grants, random access acknowledgements and
    /// deferred grant requests from the given timeslot's queue.
    pub fn dl_take_all_grants_and_acks(&mut self, timeslot: u8) -> Vec<DlSchedElem> {
        let queue = &mut self.dltx_queues[timeslot as usize - 1];
        let mut taken = Vec::new();

        let mut i = 0;
        while i < queue.len() {
            if matches!(
                queue[i],
                DlSchedElem::Grant(_, _) | DlSchedElem::RandomAccessAck(..) | DlSchedElem::AssociatedGrantRequest(..)
            ) {
                let elem = queue.remove(i);
                taken.push(elem);
            } else {
                i += 1;
            }
        }
        taken
    }

    /// Removes all elements from the schedule, except stolen blocks. This function is used
    /// when leaving hangtime to clear out any stale grants, resources, etc that can only be processed in signaling mode,
    /// while keeping stealing blocks that may still need to be transmitted via FACCH.
    /// Discarded elements are reported as such via tx_reporter if available. Returns true if elements were discarded.
    pub fn dl_drop_all_except_stolen(&mut self, timeslot: u8) -> bool {
        let queue = &mut self.dltx_queues[timeslot as usize - 1];
        let mut i = 0;
        let mut item_was_discarded = false;
        while i < queue.len() {
            if matches!(queue[i], DlSchedElem::Stealing(..)) {
                i += 1;
            } else {
                // Found a to-be-discarded element.
                // Remove, log, and call tx_reporter::mark_discarded() if applicable
                let elem = queue.remove(i);
                item_was_discarded = true;
                tracing::warn!(
                    dltime = %self.cur_dltime,
                    ts = timeslot,
                    element = ?elem,
                    "discarding pending signalling while leaving hangtime"
                );

                match elem {
                    DlSchedElem::Resource(_, _, tx_reporter, _, _) => {
                        // Report as discarded manually
                        if let Some(tx_reporter) = tx_reporter {
                            tx_reporter.mark_discarded();
                        }
                    }

                    DlSchedElem::FragBuf(..) => {
                        // Fragger self-marks any unsent fragments as discarded when dropped, so we don't need to do anything here.
                    }

                    DlSchedElem::RandomAccessAck(addr, _) => {
                        // Save the SSI so the next STCH for this address can carry
                        // random_access_flag=true (ETSI 21.4.3.1)
                        self.pending_ra_acks[timeslot as usize - 1].push(addr.ssi);
                    }

                    DlSchedElem::Grant(..) | DlSchedElem::Broadcast(_) => {
                        // Silently dropped as internal or not equipped with a tx_reporter
                    }
                    _ => unreachable!(),
                }
            }
        }

        item_was_discarded
    }

    /// Discard control waiting on an associated basic link whose circuit has
    /// been removed.  Resource reporters wake LLC so the same TL-SDU can be
    /// retried on a currently available link (normally MCCH).  Dropping a
    /// partial fragger performs the same notification in `BsFragger::drop`.
    fn dl_drop_associated_control(&mut self, timeslot: u8) -> bool {
        let queued = std::mem::take(&mut self.assoc_dltx_queues[timeslot as usize - 1]);
        let best_effort = std::mem::take(&mut self.assoc_best_effort_queues[timeslot as usize - 1]);
        let had_items = !queued.is_empty() || !best_effort.is_empty();

        for elem in queued {
            tracing::warn!(
                dltime = %self.cur_dltime,
                ts = timeslot,
                element = ?elem,
                "discarding associated control after circuit removal"
            );

            if let DlSchedElem::Resource(_, _, Some(tx_reporter), _, _) = &elem
                && tx_reporter.get_state() == tetra_core::TxState::Pending
            {
                tx_reporter.mark_discarded();
            }
            // `FragBuf` marks a still-pending reporter discarded on drop.
        }

        if !best_effort.is_empty() {
            tracing::debug!(
                dltime = %self.cur_dltime,
                ts = timeslot,
                count = best_effort.len(),
                "discarding best-effort associated repeats after circuit removal"
            );
        }

        had_items
    }

    pub fn dl_integrate_sched_elems_for_timeslot(&mut self, ts: TdmaTime) {
        // Remove all grants and acks from queue and collect them into a vec
        let grants_and_acks = self.dl_take_all_grants_and_acks(ts.t);

        // Process grants and acks
        for elem in grants_and_acks {
            let elem = match elem {
                DlSchedElem::AssociatedGrantRequest(addr, res_req, remaining_slots) => {
                    let Some(grant) = self.ul_process_cap_req(ts.t, addr, &res_req) else {
                        self.dltx_queues[ts.t as usize - 1].push(DlSchedElem::AssociatedGrantRequest(addr, res_req, remaining_slots));
                        continue;
                    };
                    DlSchedElem::Grant(addr, grant)
                }
                elem => elem,
            };
            // Try to find existing resource for this address
            let addr = match &elem {
                DlSchedElem::Grant(addr, _) => addr,
                DlSchedElem::RandomAccessAck(addr, _) => addr,
                _ => panic!(),
            };
            let mac_resource = self.dl_get_scheduled_resource_for_ssi(ts, addr);
            match mac_resource {
                Some(DlSchedElem::Resource(pdu, _sdu, _repeat, _aie_request, _)) => {
                    // Integrate grant into the resource
                    match &elem {
                        DlSchedElem::Grant(_, grant) => {
                            tracing::debug!(
                                "dl_integrate_sched_elems_for_timeslot: Integrating grant {:?} into resource for addr {}",
                                grant,
                                addr
                            );
                            pdu.slot_granting_element = Some(grant.clone());
                        }
                        DlSchedElem::RandomAccessAck(..) => {
                            tracing::debug!(
                                "dl_integrate_sched_elems_for_timeslot: Integrating ack into resource for addr {}",
                                addr
                            );
                            pdu.random_access_flag = true;
                        }
                        _ => panic!(),
                    }
                }
                None => {
                    // No resource for this address was found, create a new one
                    let (pdu, aie_request) = match &elem {
                        DlSchedElem::Grant(_, grant) => {
                            tracing::debug!(
                                "dl_integrate_sched_elems_for_timeslot: Creating new resource for addr {} with grant {:?}",
                                addr,
                                grant
                            );
                            (
                                Self::dl_make_minimal_resource(addr, Some(grant.clone()), false),
                                AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
                            )
                        }
                        DlSchedElem::RandomAccessAck(_, aie_request) => {
                            tracing::debug!(
                                "dl_integrate_sched_elems_for_timeslot: Creating new resource for addr {} with ack",
                                addr
                            );
                            (Self::dl_make_minimal_resource(addr, None, true), *aie_request)
                        }
                        _ => panic!(),
                    };

                    // Push new resource into the queue. These do not need a tx_reporter
                    let dlsched_res = DlSchedElem::Resource(pdu, BitBuffer::new(0), None, aie_request, None);
                    self.dltx_queues[ts.t as usize - 1].push(dlsched_res);
                }
                _ => panic!(),
            }
        }
    }

    fn dl_build_block_from_signalling_schedule(&mut self, ts: TdmaTime) -> Option<BitBuffer> {
        let mut buf_opt = None;

        while !self.dltx_queues[ts.t as usize - 1].is_empty() {
            let opt = self.dl_take_prioritized_sched_item(ts);

            match opt {
                Some(sched_elem) => {
                    match sched_elem {
                        DlSchedElem::Broadcast(_) => {
                            unimplemented_log!("finalize_ts_for_tick: Broadcast scheduling not implemented");
                        }

                        DlSchedElem::Resource(mut pdu, sdu, tx_reporter, aie_request, packet_data_slots) => {
                            // Allocate bitbuf if not already done
                            let mut buf = buf_opt.unwrap_or_else(|| BitBuffer::new(SCH_F_CAP));
                            let al_identity = Self::advanced_link_segment_identity(&sdu);
                            if al_identity.is_some() && buf.get_len_written() != 0 {
                                // TIP 6.5 sizes a normal original-link segment
                                // for a complete SCH/F MAC-RESOURCE.  Starting
                                // it in the tail of an associated block forces
                                // an avoidable MAC fragment chain and changes
                                // the radio retransmission unit.  Finish the
                                // higher-priority block and start this packet
                                // data segment in the next slot instead.
                                let elem = DlSchedElem::Resource(pdu, sdu, tx_reporter, aie_request, packet_data_slots);
                                if let Some(slots) = packet_data_slots {
                                    self.dl_defer_packet_data_resource_to_next_pdch(
                                        ts.t,
                                        elem,
                                        slots,
                                        "fresh SCH/F required for AL segment",
                                    );
                                } else {
                                    self.dltx_next_slot_queue.push(elem);
                                }
                                buf_opt = Some(buf);
                                break;
                            }
                            let facch_ack_addr = (self.is_hangtime(ts.t)
                                && self.circuits.is_active(Direction::Ul, ts.t)
                                && tx_reporter.as_ref().is_some_and(TxReporter::expects_ack))
                            .then_some(pdu.addr)
                            .flatten();
                            let advanced_ack_addr = (self.packet_bearer_is_active(ts.t)
                                && tx_reporter.as_ref().is_some_and(TxReporter::expects_ack)
                                && sdu
                                    .peek_bits(6)
                                    .is_some_and(|header| header >> 2 == LlcPduType::AlDataAlFinal.into_raw() && header & 1 == 1))
                            .then(|| {
                                pdu.addr.or_else(|| match aie_request {
                                    AieRequest::Clear {
                                        subject: AieSubject::Individual { issi },
                                        ..
                                    }
                                    | AieRequest::Sc2 {
                                        subject: AieSubject::Individual { issi },
                                        ..
                                    }
                                    | AieRequest::Sc3 {
                                        subject: AieSubject::Individual { issi },
                                        ..
                                    } => Some(TetraAddress::issi(issi)),
                                    _ => None,
                                })
                            })
                            .flatten();
                            let acknowledged_addr = facch_ack_addr.or(advanced_ack_addr);
                            let resource_len_with_grant = pdu.compute_header_len()
                                + usize::from(pdu.slot_granting_element.is_none() && acknowledged_addr.is_some()) * 8
                                + sdu.get_len();
                            let resource_fill = fillbits::addition::compute_required(resource_len_with_grant, buf.get_len_remaining());
                            let completes_in_resource = resource_len_with_grant + resource_fill <= buf.get_len_remaining();
                            if completes_in_resource
                                && pdu.slot_granting_element.is_none()
                                && let Some(addr) = acknowledged_addr
                            {
                                let minimum_delay = if advanced_ack_addr.is_some() {
                                    self.basic_grant_timeslots(ts.t).len()
                                } else {
                                    0
                                };
                                let Some(grant) =
                                    self.ul_process_cap_req_after(ts.t, addr, &ReservationRequirement::Req1Slot, minimum_delay)
                                else {
                                    self.dltx_next_slot_queue.push(DlSchedElem::Resource(
                                        pdu,
                                        sdu,
                                        tx_reporter,
                                        aie_request,
                                        packet_data_slots,
                                    ));
                                    buf_opt = Some(buf);
                                    break;
                                };
                                tracing::info!(
                                    dltime = %ts,
                                    address = ?addr,
                                    grant = ?grant,
                                    advanced_link = advanced_ack_addr.is_some(),
                                    "prepared anticipated acknowledgement grant in complete MAC-RESOURCE"
                                );
                                pdu.slot_granting_element = Some(grant);
                                pdu.update_len_and_fill_ind(sdu.get_len());
                            }
                            // Create fragger, either to send the whole PDU or to start fragmentation
                            let pdu = match self.prepare_downlink_resource(pdu, aie_request, ts) {
                                Ok(pdu) => pdu,
                                Err(error) => {
                                    tracing::warn!(dltime = %ts, ?error, "dropping MAC resource without a valid AIE context");
                                    if let Some(reporter) = tx_reporter.as_ref()
                                        && reporter.get_state() == tetra_core::TxState::Pending
                                    {
                                        reporter.mark_discarded();
                                    }
                                    buf_opt = Some(buf);
                                    continue;
                                }
                            };
                            let mut fragger = BsFragger::new_with_aie(pdu, sdu, tx_reporter, aie_request);
                            let written_before = buf.get_len_written();
                            let complete = fragger.get_next_chunk(&mut buf);
                            if let Err(error) = self.cipher_fresh_downlink_chunk(&mut fragger, &mut buf, ts) {
                                tracing::warn!(dltime = %ts, ?error, "dropping MAC resource after AIE cipher failure");
                                return None;
                            }
                            if !complete {
                                if written_before == 0 && buf.get_len_written() == 0 {
                                    tracing::warn!(dltime = %ts, "dropping MAC resource that cannot make progress in an empty SCH/F");
                                } else {
                                    // Fragmentation was started, or a partially
                                    // occupied block caused a valid deferral.
                                    if facch_ack_addr.is_some() && fragger.has_started() {
                                        fragger.require_final_slot_grant();
                                    }
                                    self.dl_enqueue_tma_frag_continuation(ts.t, fragger, packet_data_slots);
                                }
                            }
                            buf_opt = Some(buf);
                        }

                        DlSchedElem::FragBuf(mut fragger, packet_data_slots) => {
                            // Allocate bitbuf if not already done
                            let mut buf = buf_opt.unwrap_or_else(|| BitBuffer::new(SCH_F_CAP));
                            if self.is_hangtime(ts.t)
                                && self.circuits.is_active(Direction::Ul, ts.t)
                                && fragger.expects_ack()
                                && fragger.can_finish_with_slot_grant(buf.get_len_remaining())
                            {
                                let Some(issi) = fragger.individual_issi() else {
                                    tracing::warn!(dltime = %ts, "FACCH acknowledged fragment has no individual address for its MAC-END grant");
                                    self.dl_enqueue_tma_frag_continuation(ts.t, fragger, packet_data_slots);
                                    buf_opt = Some(buf);
                                    break;
                                };
                                let addr = TetraAddress::issi(issi);
                                let Some(grant) = self.ul_process_cap_req(ts.t, addr, &ReservationRequirement::Req1Slot) else {
                                    self.dl_enqueue_tma_frag_continuation(ts.t, fragger, packet_data_slots);
                                    buf_opt = Some(buf);
                                    break;
                                };
                                tracing::info!(
                                    dltime = %ts,
                                    address = ?addr,
                                    grant = ?grant,
                                    "prepared FACCH basic-link acknowledgement grant in final MAC-END"
                                );
                                fragger.set_completion_slot_grant(grant);
                            }
                            let written_before = buf.get_len_written();
                            let complete = fragger.get_next_chunk(&mut buf);
                            if let Err(error) = self.cipher_fresh_downlink_chunk(&mut fragger, &mut buf, ts) {
                                tracing::warn!(dltime = %ts, ?error, "dropping MAC fragment after AIE cipher failure");
                                return None;
                            }
                            if !complete {
                                if written_before == 0 && buf.get_len_written() == 0 {
                                    tracing::warn!(dltime = %ts, "dropping MAC fragment that cannot make progress in an empty SCH/F");
                                } else {
                                    self.dl_enqueue_tma_frag_continuation(ts.t, fragger, packet_data_slots);
                                }
                            }
                            buf_opt = Some(buf);
                        }

                        DlSchedElem::Stealing(_, tx_reporter, ..) => {
                            // Stealing items should only appear on traffic timeslots; discard if found here
                            tracing::warn!(
                                "dl_build_block_from_signalling_schedule: Stealing item found on non-traffic ts {}, discarding",
                                ts.t
                            );
                            if let Some(tx_reporter) = tx_reporter {
                                tx_reporter.mark_discarded();
                            }
                        }

                        _ => panic!("finalize_ts_for_tick: Unexpected DlSchedElem type: {:?}", sched_elem),
                    }
                }
                None => {
                    // No more items to process, we can finalize this timeslot
                    break;
                }
            }
        }

        // If any signalling could not be sent this slot, it should be in the next slot queue
        // Swap next slot queue into current slot queue, to schedule it for next frame
        if !self.dltx_next_slot_queue.is_empty() {
            let queue = &mut self.dltx_queues[ts.t as usize - 1];
            // A missing acknowledgement grant stops this block early. Keep
            // both the element that requested the unavailable grant and every
            // lower-priority element which has not been visited yet. A full
            // uplink schedule is transient and must not turn queued SDS into
            // either a scheduler panic or a dropped TxReporter.
            self.dltx_next_slot_queue.append(queue);
            std::mem::swap(queue, &mut self.dltx_next_slot_queue);
        }

        if let Some(buf) = buf_opt.as_mut() {
            let remaining_before = buf.get_len_remaining();
            let (null_pdu_inserted, fill_bits_inserted) = finalize_downlink_mac_block(buf);
            tracing::debug!(
                dltime = %ts,
                logical_channel = ?LogicalChannel::SchF,
                used_bits = buf.get_pos() - remaining_before,
                remaining_bits_before = remaining_before,
                null_pdu_inserted,
                fill_bits_inserted,
                "finalized downlink signalling MAC block"
            );
        }

        buf_opt
    }

    /// Build traffic block for active circuit. Returns (tch_block, optional_stch_block):
    /// - tch_block: speech/silence (274 bits)
    /// - stch_block: STCH signaling (124 bits) for FACCH stealing (EN 300 392-2, clause 23.5)
    /// Also reports transmission, if a TxReporter was attached to the DlSchedElem::Stealing element
    fn dl_build_traffic_block(
        &mut self,
        ts: TdmaTime,
    ) -> (
        BitBuffer,
        Option<AieRequest>,
        Option<(BitBuffer, AieRequest, Option<AieCipherRegion>)>,
    ) {
        // Get speech data or silence
        let tch_buf = if let Some(block) = self.circuits.take_block(ts.t) {
            if block.len().saturating_mul(8) < TCH_S_CAP {
                // Network/media input is not allowed to make the RF timing
                // task panic. A malformed frame is replaced by a TCH/S
                // silence frame; the next valid frame may still be sent.
                tracing::warn!(
                    ts = ts.t,
                    supplied_bits = block.len().saturating_mul(8),
                    required_bits = TCH_S_CAP,
                    "dropping short downlink TCH/S frame and transmitting silence"
                );
                BitBuffer::new(TCH_S_CAP)
            } else {
                let mut buf = BitBuffer::from_vec(block);
                // Raw ACELP speech (274 bits for TCH/S).
                // Clamp to TCH_S_CAP as Vec may be larger (e.g. 280 bits).
                buf.set_raw_end(buf.get_raw_start() + TCH_S_CAP);
                buf
            }
        } else {
            // No voice data queued — send silence frame (all zeros).
            // This is normal during hangtime or between voice bursts.
            BitBuffer::new(TCH_S_CAP)
        };

        // Check for FACCH/stealing: take a queued Stealing item (highest priority signaling)
        let (stch_opt, tx_reporter_opt) = {
            let q = &mut self.dltx_queues[ts.t as usize - 1];
            if let Some(i) = q.iter().position(|e| matches!(e, DlSchedElem::Stealing(..))) {
                match q.remove(i) {
                    DlSchedElem::Stealing(buf, tx_reporter, request, region) => (Some((buf, request, region)), tx_reporter),
                    _ => unreachable!(),
                }
            } else {
                (None, None)
            }
        };

        // Warn about other queued signaling that can't be sent via stealing yet
        if stch_opt.is_none() && !self.dltx_queues[ts.t as usize - 1].is_empty() {
            tracing::warn!("dl_build_traffic_block: queued signaling on ts {} but no stealing item", ts.t);
        }

        // If desired, report transmission
        if let Some(tx_reporter) = tx_reporter_opt {
            tx_reporter.mark_transmitted();
        }

        (tch_buf, self.traffic_aie[ts.t as usize - 1], stch_opt)
    }

    /// Return first queued grant.
    /// If none; return first in-progress fragmented message.
    /// If none; return first to-be-transmitted resource.
    /// If none, return None.
    pub fn dl_take_prioritized_sched_item(&mut self, ts: TdmaTime) -> Option<DlSchedElem> {
        if ts.f == 18 {
            // No resources on frame 18
            return None;
        }

        // Map 1-based ts to 0-based index, bail on 0 or out of range.
        let slot = ts.t as usize - 1;
        let q = self.dltx_queues.get_mut(slot).unwrap();
        q.retain(|item| !item.is_cancelled());

        // Return grants first
        if let Some(i) = q.iter().position(|e| matches!(e, DlSchedElem::Grant(_, _))) {
            return Some(q.remove(i));
        }

        // Packet-data grants are normally integrated into a MAC-RESOURCE
        // before prioritization.  Emit that resource first so its reserved
        // uplink slots cannot become an unannounced allocation.
        if let Some(i) = q
            .iter()
            .position(|e| matches!(e, DlSchedElem::Resource(pdu, ..) if pdu.slot_granting_element.is_some()))
        {
            return Some(q.remove(i));
        }

        // Return FragBufs next
        if let Some(i) = q.iter().position(|e| matches!(e, DlSchedElem::FragBuf(..))) {
            return Some(q.remove(i));
        }

        // Non-packet signalling precedes advanced-link packet data.  This
        // also ensures that a full-sized AL segment starts in an otherwise
        // empty SCH/F block instead of forcing a control PDU to wait behind
        // low-priority IP traffic.
        if let Some(i) = q
            .iter()
            .position(|e| matches!(e, DlSchedElem::Resource(..)) && !e.is_original_advanced_data())
        {
            return Some(q.remove(i));
        }

        // Return advanced-link Resources last. A complete TL-SDU is striped
        // over all assigned PDCH slots, so the next physical slot can contain
        // a later S(S) while its predecessor is waiting on another slot. Pick
        // an eligible segment directly instead of removing and requeueing all
        // later segments on every radio opportunity. The latter is quadratic
        // for a large IP packet and can itself disturb the timing task.
        let eligible_advanced = self.dltx_queues[slot].iter().enumerate().find_map(|(index, elem)| {
            if !elem.is_original_advanced_data() {
                return None;
            }
            let Some((issi, ns, ss)) = Self::sched_elem_advanced_link_sequence(elem) else {
                // Control and test paths can carry an advanced PDU without
                // the packet-route metadata used for cross-slot ordering.
                return Some(index);
            };
            (!self.has_earlier_pending_advanced_link_segment(issi, ns, ss)).then_some(index)
        });
        if let Some(i) = eligible_advanced {
            let q = &mut self.dltx_queues[slot];
            return Some(q.remove(i));
        }

        None
    }

    pub fn tick_start(&mut self, ts: TdmaTime) {
        // Increment current time
        self.cur_dltime = self.cur_dltime.add_timeslots(1);
        assert!(
            ts == self.cur_dltime,
            "BsChannelScheduler tick_start: ts mismatch, expected {}, got {}",
            self.cur_dltime,
            ts
        );
    }

    pub fn set_secondary_random_access_definition(&mut self, slot: u8, update: RandomAccessUpdate) {
        if (2..=3).contains(&slot) {
            self.secondary_access[usize::from(slot - 2)] = Some(update);
        }
    }

    fn access_definition_for_slot(&self, slot: u8) -> RandomAccessUpdate {
        if (2..=3).contains(&slot) {
            self.secondary_access[usize::from(slot - 2)].unwrap_or_else(|| self.random_access_definition())
        } else {
            self.random_access_definition()
        }
    }

    pub fn set_random_access_definition(&mut self, parameters: RandomAccessParameters, frame_len: u8) {
        if let Some(access_define) = self.precomps.access_define.as_mut() {
            access_define.imm = parameters.imm;
            access_define.wt = parameters.wt;
            access_define.nu = parameters.nu;
            access_define.frame_len_factor = parameters.frame_len_factor;
            access_define.ts_pointer = parameters.ts_pointer;
            access_define.min_pdu_prio = parameters.min_pdu_prio;
        }
        self.random_access_frame_len = frame_len.clamp(1, 15);
        tracing::info!(
            "BsChannelScheduler: common random-access definition IMM={} WT={} Nu={} FL={} frame_len={}",
            parameters.imm,
            parameters.wt,
            parameters.nu,
            parameters.frame_len_factor,
            self.random_access_frame_len
        );
    }

    /// Refresh the on-air SYSINFO and ACCESS-DEFINE fields at a radio tick.
    /// Other precomputed PDUs, including SwMI-owned AIE state, stay intact.
    pub fn apply_live_operator_settings(&mut self, settings: &RuntimeOperatorSettings, current: RandomAccessUpdate) {
        for sysinfo in [&mut self.precomps.mac_sysinfo1, &mut self.precomps.mac_sysinfo2] {
            sysinfo.ms_txpwr_max_cell = settings.ms_txpwr_max_cell;
            sysinfo.rxlev_access_min = settings.rxlev_access_min;
            sysinfo.access_parameter = settings.access_parameter;
        }
        self.precomps.access_define_interval_multiframes = settings.random_access.update_interval_multiframes;
        if settings.random_access.enabled {
            self.precomps.access_define = Some(AccessDefine {
                common_or_assigned_control: false,
                access_code: 0,
                imm: current.parameters.imm,
                wt: current.parameters.wt,
                nu: current.parameters.nu,
                frame_len_factor: current.parameters.frame_len_factor,
                ts_pointer: current.parameters.ts_pointer,
                min_pdu_prio: current.parameters.min_pdu_prio,
                opt_field_flag: 0,
                subscriber_class: None,
                gssi: None,
            });
            self.random_access_frame_len = current.frame_len;
        } else {
            self.precomps.access_define = None;
            self.random_access_frame_len = 4;
        }
    }

    /// Exactly the access-code A values currently prepared for transmission.
    pub fn random_access_definition(&self) -> RandomAccessUpdate {
        let a = self.precomps.access_define.as_ref();
        let d = self.precomps.mac_sysinfo1.default_access_code.as_ref();
        RandomAccessUpdate {
            parameters: RandomAccessParameters {
                imm: a.map(|v| v.imm).or_else(|| d.map(|v| v.imm)).unwrap_or(8),
                wt: a.map(|v| v.wt).or_else(|| d.map(|v| v.wt)).unwrap_or(5),
                nu: a.map(|v| v.nu).or_else(|| d.map(|v| v.nu)).unwrap_or(5),
                frame_len_factor: a.map(|v| v.frame_len_factor).or_else(|| d.map(|v| v.fl_factor)).unwrap_or(false),
                ts_pointer: a.map(|v| v.ts_pointer).or_else(|| d.map(|v| v.ts_ptr)).unwrap_or(0),
                min_pdu_prio: a.map(|v| v.min_pdu_prio).or_else(|| d.map(|v| v.min_pdu_prio)).unwrap_or(0),
            },
            frame_len: self.random_access_frame_len,
        }
    }

    fn should_emit_access_define(&self, ts: TdmaTime) -> bool {
        let interval = self.precomps.access_define_interval_multiframes.max(1);
        self.precomps.access_define.is_some() && self.is_common_control(ts.t) && ts.f == 2 && (ts.m - 1) % interval == 0
    }

    fn common_access_frame_len(&self, slot: u8) -> BaseFrameLength {
        BaseFrameLength::try_from(self.access_definition_for_slot(slot).frame_len as u64).unwrap_or(DEFAULT_ACCESS_FRAME_MARKER)
    }

    /// Prepares a scheduled FUTURE timeslot for transfer to lmac and transmission
    /// Generates BBK block
    /// If the timeslot is not full, generates SYNC SB1/SB2 blocks.
    /// Increments cur_ts by one timeslot.
    /// Caller should check timestamp of returned DlTxElem to prevent desync
    pub fn finalize_ts_for_tick(&mut self) -> TmvUnitdataReqSlot {
        // We finalize a FUTURE slot: cur_ts plus some number of timeslots
        let ts = self.cur_dltime.add_timeslots(MACSCHED_TX_AHEAD as i32);
        self.precomps.mac_sync.time = ts;
        self.precomps.mac_sysinfo1.cipher_key_id_or_sck_vn = None;
        self.precomps.mac_sysinfo1.hyperframe_number = Some(ts.h);
        if self.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn.is_none() {
            self.precomps.mac_sysinfo2.hyperframe_number = Some(ts.h);
        } else {
            self.precomps.mac_sysinfo2.hyperframe_number = None;
        }

        let dl_circuit_active = self.circuits.is_active(Direction::Dl, ts.t) && ts.f != 18;
        let ul_circuit_active = self.circuits.is_active(Direction::Ul, ts.t) && ts.f != 18;

        // During hangtime we stop sending traffic frames and switch to signalling mode.
        // Keep traffic mode while FACCH/stealing is still queued for delivery.
        let hang_effective = if (2..=4).contains(&ts.t) {
            self.is_hangtime_effective(ts.t)
        } else {
            false
        };

        let dl_is_traffic = dl_circuit_active && !hang_effective;
        let ul_is_traffic = ul_circuit_active && !hang_effective;

        // This consumes the dedicated reservation before every normal queue,
        // call block or packet-data opportunity.  It is the one exception to
        // the scheduler's ordinary signalling priority because EN 300 392-7
        // fixes `Immediate` to the following TS1/FN1 boundary.
        let final_gck_rollover_immediate = self.take_final_gck_rollover_immediate(ts);

        // Build the block for this timeslot with anything scheduled (traffic or signalling)
        // For traffic timeslots, also check for FACCH/stealing (STCH half-slot)
        let ul_phy = if ul_is_traffic { PhysicalChannel::Tp } else { PhysicalChannel::Cp };

        let frame18_broadcast_slot = ts.is_mandatory_bsch() || ts.is_mandatory_bnch();
        let slot = ts.t as usize - 1;
        let normal_associated_pending = !self.assoc_dltx_queues[slot].is_empty();
        let non_frame18_best_effort_pending = self.assoc_best_effort_queues[slot]
            .iter()
            .any(|queued| !queued.kind.is_frame18_only());
        // PDCH traffic and hangtime signalling use the ordinary per-slot
        // queue. A network broadcast must not consume their FN18 opportunity.
        let ordinary_downlink_pending = (self.packet_bearer_is_active(ts.t) || hang_effective) && !self.dltx_queues[slot].is_empty();
        if ts.f == 18
            && frame18_broadcast_slot
            && (!self.assoc_dltx_queues[ts.t as usize - 1].is_empty() || !self.assoc_best_effort_queues[ts.t as usize - 1].is_empty())
        {
            tracing::debug!(
                dltime = %ts,
                mandatory_bsch = ts.is_mandatory_bsch(),
                mandatory_bnch = ts.is_mandatory_bnch(),
                queued_associated = self.assoc_dltx_queues[ts.t as usize - 1].len(),
                queued_best_effort = self.assoc_best_effort_queues[ts.t as usize - 1].len(),
                "deferring associated SACCH control for mandatory frame-18 broadcast"
            );
        }
        let mut elem = if let Some(item) = final_gck_rollover_immediate {
            tracing::info!(
                dltime = %ts,
                activation = %item.activation,
                target = ?item.pdu.addr,
                mandatory_bsch = ts.is_mandatory_bsch(),
                mandatory_bnch = ts.is_mandatory_bnch(),
                "transmitting final SC3G GCK rollover Immediate on FN18"
            );
            self.build_final_gck_rollover_slot(item, ts)
        } else if self.force_common_sysinfo && ts.f == 18 {
            TmvUnitdataReqSlot {
                ts,
                blk1: None,
                blk2: None,
                bbk: None,
                ul_phy_chan: ul_phy,
            }
        } else if ts.f == 18
            && ts.t != 1
            && !frame18_broadcast_slot
            && self.assigned_channel_is_active(ts.t)
            && (!ordinary_downlink_pending || normal_associated_pending || non_frame18_best_effort_pending)
        {
            // FN18 is the assigned channel's fixed ACCH opportunity.  Do not
            // borrow capacity from FN1..17 for ordinary call signalling. A
            // rotating FN18 position is mandatory BSCH or BNCH, however;
            // that broadcast has priority over SACCH and the associated
            // queue must remain intact until the next usable FN18.
            // Associated FN18 remains on the assigned TP physical resource,
            // while its logical channel is SCH/F and therefore uses signalling
            // coding in LMAC (encode_cp), not TCH speech coding.
            if normal_associated_pending {
                self.cancel_interrupted_best_effort_fragment(ts.t);
            }
            let associated_control = if normal_associated_pending {
                self.dl_build_associated_control_block(ts)
            } else if !self.assoc_best_effort_queues[ts.t as usize - 1].is_empty() {
                self.dl_build_best_effort_associated_control_block(ts, true)
            } else {
                None
            };
            if associated_control.is_some() {
                tracing::info!(
                    dltime = %ts,
                    assigned_channel = true,
                    physical_channel = ?PhysicalChannel::Tp,
                    logical_channel = ?LogicalChannel::SchF,
                    "transmitting queued associated FN18 SCH/F control block"
                );
            }
            let buf = associated_control.unwrap_or_else(|| {
                let mut idle = BitBuffer::new(SCH_F_CAP);
                finalize_downlink_mac_block(&mut idle);
                idle
            });
            TmvUnitdataReqSlot {
                ts,
                blk1: Some(TmvUnitdataReq {
                    logical_channel: LogicalChannel::SchF,
                    mac_block: buf,
                    scrambling_code: self.scrambling_code,
                    air_interface_encryption: None,
                    cipher_region: None,
                }),
                blk2: None,
                bbk: None,
                ul_phy_chan: PhysicalChannel::Tp,
            }
        } else if dl_is_traffic {
            let (tch_buf, traffic_aie, stch_opt) = self.dl_build_traffic_block(ts);

            if let Some((stch_buf, stch_aie, stch_region)) = stch_opt {
                // FACCH/Stealing: 1st half = STCH signaling, 2nd half = TCH speech.
                // NDB uses NormalTrainSeq2 for independent half-slot demodulation (EN 300 392-2, clause 23.5).
                tracing::info!(
                    dltime = %ts,
                    ts = ts.t,
                    hangtime = self.is_hangtime(ts.t),
                    hangtime_effective = hang_effective,
                    ul_phy = ?ul_phy,
                    stch_bits = stch_buf.get_len(),
                    tch_bits = tch_buf.get_len(),
                    "transmitting FACCH/STCH as traffic burst (NormalTrainSeq2 expected)"
                );
                TmvUnitdataReqSlot {
                    ts,
                    blk1: Some(TmvUnitdataReq {
                        logical_channel: LogicalChannel::Stch,
                        mac_block: stch_buf,
                        scrambling_code: self.scrambling_code,
                        air_interface_encryption: Some(stch_aie.with_scope(AieScope::Facch)),
                        // MAC-U-SIGNAL (3b) and MAC-RESOURCE header stay clear.
                        cipher_region: stch_region,
                    }),
                    blk2: Some(TmvUnitdataReq {
                        logical_channel: LogicalChannel::TchS,
                        mac_block: tch_buf,
                        scrambling_code: self.scrambling_code,
                        air_interface_encryption: traffic_aie.map(|request| request.with_scope(AieScope::Traffic)),
                        // TCH/S AIE applies to the 274-bit traffic SDU
                        // before channel coding, not to the 432 coded bits.
                        cipher_region: traffic_aie.map(|_| tetra_core::AieCipherRegion::new(0, TCH_S_CAP)),
                    }),
                    bbk: None,
                    ul_phy_chan: ul_phy,
                }
            } else {
                // Normal traffic: full-slot TCH
                TmvUnitdataReqSlot {
                    ts,
                    blk1: Some(TmvUnitdataReq {
                        logical_channel: LogicalChannel::TchS,
                        mac_block: tch_buf,
                        scrambling_code: self.scrambling_code,
                        air_interface_encryption: traffic_aie.map(|request| request.with_scope(AieScope::Traffic)),
                        cipher_region: traffic_aie.map(|_| tetra_core::AieCipherRegion::new(0, TCH_S_CAP)),
                    }),
                    blk2: None,
                    bbk: None,
                    ul_phy_chan: ul_phy,
                }
            }
        } else {
            // Signalling mode (either no circuit, or hangtime on an allocated timeslot)
            // A retained reservation requirement becomes a grant only after
            // the previous frequency-simplex uplink turn and receive window.
            self.schedule_ready_packet_data_grant(ts);
            self.dl_defer_packet_data_for_concurrent_uplink(ts);

            // Integrate all grants and random access acks into resources (either existing or new)
            self.dl_integrate_sched_elems_for_timeslot(ts);

            // Fill our signalling block with scheduled items (if any). Building
            // may move a fragmented ordinary message back into the queue, so
            // the emitted block itself is the reliable interruption signal.
            let normal_buf = self.dl_build_block_from_signalling_schedule(ts);
            if normal_buf.is_some() {
                self.cancel_interrupted_best_effort_fragment(ts.t);
            }
            let buf = normal_buf.or_else(|| {
                (ts.f != 18 && hang_effective && dl_circuit_active && !self.assoc_best_effort_queues[ts.t as usize - 1].is_empty())
                    .then(|| self.dl_build_best_effort_associated_control_block(ts, false))
                    .flatten()
            });
            if let Some(buf) = buf {
                TmvUnitdataReqSlot {
                    ts,
                    blk1: Some(TmvUnitdataReq {
                        logical_channel: LogicalChannel::SchF,
                        mac_block: buf,
                        scrambling_code: self.scrambling_code,
                        air_interface_encryption: None,
                        cipher_region: None,
                    }),
                    blk2: None,
                    bbk: None,
                    ul_phy_chan: ul_phy,
                }
            } else {
                // If this is an allocated traffic slot in hangtime, keep it alive with an idle SCH/F (Null PDU).
                // Otherwise, fall back to default SYNC/SYSINFO.
                if hang_effective && dl_circuit_active {
                    TmvUnitdataReqSlot {
                        ts,
                        blk1: Some(TmvUnitdataReq {
                            logical_channel: LogicalChannel::SchF,
                            mac_block: self.generate_hangtime_idle_schf(),
                            scrambling_code: self.scrambling_code,
                            air_interface_encryption: None,
                            cipher_region: None,
                        }),
                        blk2: None,
                        bbk: None,
                        ul_phy_chan: ul_phy,
                    }
                } else {
                    // Put default SYNC/SYSINFO frame
                    TmvUnitdataReqSlot {
                        ts,
                        blk1: None,
                        blk2: None,
                        bbk: None,
                        ul_phy_chan: ul_phy,
                    }
                }
            }
        };

        // FN18 may carry only control (SACCH/FACCH), never a traffic block.
        if ts.f == 18 {
            if let Some(block) = elem.blk1.as_ref() {
                assert!(!block.logical_channel.is_traffic());
            }
        }

        // Construct the BBK block to reflect UL/DL usage
        assert!(elem.bbk.is_none(), "BBK block already set");
        elem.bbk = Some(self.generate_bbk_block(ts));

        // tracing::trace!("finalize_ts_for_tick: have {}{}{}",
        //     if elem.bbk.is_some() { "bbk " } else { "" },
        //     if elem.blk1.is_some() { "blk1 " } else { "" },
        //     if elem.blk2.is_some() { "blk2 " } else { "" });

        // Populate blk1 if empty: BSCH on frame 18, SCH/HD on other frames
        if elem.blk1.is_none() {
            elem.blk1 = Some(self.generate_default_blks(ts));
        };

        // Check if second block may still be populated (blk1 is half-slot and blk2 is None)
        let blk1_lchan = elem.blk1.as_ref().unwrap().logical_channel;

        if blk1_lchan == LogicalChannel::Stch {
            // FACCH/Stealing: blk1 = STCH signaling, blk2 = TCH speech (already set above)
            assert!(elem.blk2.is_some(), "STCH blk1 must have blk2 (TCH half-slot)");
        } else if elem.blk2.is_none() && (blk1_lchan == LogicalChannel::Bsch || blk1_lchan == LogicalChannel::SchHd) {
            // Populate blk2 with SYSINFO if blk1 is half-slot (not STCH)
            // Check blk1 is indeed short (124 for half-slot or 60 for SYNC)
            assert!(elem.blk1.as_ref().unwrap().mac_block.get_len() <= 124);

            let mut buf = BitBuffer::new(124);

            // SYSINFO variant scheduling is independent of the timeslot on
            // which table 9.33 maps this BNCH occurrence.
            if use_default_access_sysinfo(ts) {
                let mut sysinfo = self.precomps.mac_sysinfo1.clone();
                if self.is_common_control(ts.t) {
                    if let Some(default) = sysinfo.default_access_code.as_mut() {
                        let definition = self.access_definition_for_slot(ts.t).parameters;
                        default.imm = definition.imm;
                        default.wt = definition.wt;
                        default.nu = definition.nu;
                        default.fl_factor = definition.frame_len_factor;
                        default.ts_ptr = definition.ts_pointer;
                        default.min_pdu_prio = definition.min_pdu_prio;
                    }
                }
                sysinfo.to_bitbuf(&mut buf);
            } else {
                self.precomps.mac_sysinfo2.to_bitbuf(&mut buf);
            }
            self.precomps.mle_sysinfo.to_bitbuf(&mut buf);

            elem.blk2 = Some(TmvUnitdataReq {
                logical_channel: LogicalChannel::Bnch,
                mac_block: buf,
                scrambling_code: self.scrambling_code,
                air_interface_encryption: None,
                cipher_region: None,
            })
        } else if elem.blk2.is_none() {
            // Full-slot block (TCH or SCH/F): just verify it fills both half slots
            assert!(
                elem.blk1.as_ref().unwrap().mac_block.get_len() >= 268,
                "blk1 should be full-slot but is too short"
            );
        }

        assert!(elem.bbk.is_some(), "BBK block is not set, this should not happen");
        assert!(elem.blk1.is_some(), "blk1 block is not set, this should not happen");

        // If signalling channels are here, and there is spare room, we need to close them with a Null pdu
        elem.blk1 = self.try_add_null_pdus(elem.blk1);
        elem.blk2 = self.try_add_null_pdus(elem.blk2);

        // Move all BitBuffer positions to the start of the window
        elem.bbk.as_mut().unwrap().mac_block.seek(0);
        elem.blk1.as_mut().unwrap().mac_block.seek(0);
        if let Some(blk2) = elem.blk2.as_mut() {
            blk2.mac_block.seek(0);
        }

        // tracing::warn!("start finalize");
        // self.dump_ul_schedule_full(true);

        // Clear UL schedule for this timeslot
        let index = self.ul_ts_to_sched_index(&ts.add_timeslots(-4));
        self.ulsched[ts.t as usize - 1][index].ul1 = None;
        self.ulsched[ts.t as usize - 1][index].ul2 = None;

        // Keep an FN18 grant long enough for the delayed UL receive path to
        // consume it, then discard it before a later multiframe can reuse it.
        self.associated_ulsched.retain(|(reservation_ts, _)| reservation_ts.age(ts) <= 16);

        // Retry half-duplex packet-data work in this physical timeslot's next
        // TDMA frame, ahead of data that arrived while the MS was transmitting.
        self.requeue_half_duplex_deferred_before_newer_items(ts.t as usize - 1);
        self.expire_packet_data_grant_windows(ts);

        // tracing::warn!("end finalize");
        // self.dump_ul_schedule_full(true);

        // We now have our bbk, blk1 and (optional) blk2
        elem
    }

    fn generate_bbk_block(&self, ts: TdmaTime) -> TmvUnitdataReq {
        let (ul_traffic_usage, dl_traffic_usage) = if ts.f == 18 {
            (None, None)
        } else {
            (
                self.circuits.get_usage(Direction::Ul, ts.t),
                self.circuits.get_usage(Direction::Dl, ts.t),
            )
        };

        // Generate BBK block
        let mut aach_bb = BitBuffer::new(14);

        if ts.f != 18 {
            let aach = match ts.t {
                // MCCH (TS1)
                slot if self.is_common_control(slot) => {
                    // 23.3.1.1.2
                    // "During normal mode operation, it shall always be assumed that slot 1 on the
                    // downlink is for common control as part of the MCCH."
                    assert!(dl_traffic_usage.is_none(), "DL ts 1 can't be traffic");

                    // TODO FIXME: It *is* possible for UL TS1 to carry traffic.
                    //
                    // 23.3.4 Independent allocation of uplink and downlink
                    // "A BS may allocate uplink and downlink channels for different purposes. Some examples are listed below:"
                    // "[...] common control on downlink MCCH (slot 1); uplink slot 1 of main carrier allocated for a circuit mode call;"
                    //
                    // That said, it's not something that tetra-bluestation does right now, so this assert is still sensible.
                    assert!(ul_traffic_usage.is_none(), "UL TS 1 can't currently be traffic");

                    // Indicate any reserved slots in the uplink with base_frame_len=ReservedSubslot
                    AccessAssign::DownlinkCommonControlUplinkCommonOnly {
                        access_field_1: AccessField {
                            access_code: AccessCode::AccessCodeA,
                            base_frame_len: if self.ul_get_slot_owner(ts, PhyBlockNum::Block1).is_some() {
                                BaseFrameLength::ReservedSubslot
                            } else {
                                self.common_access_frame_len(ts.t)
                            },
                        },
                        access_field_2: AccessField {
                            access_code: AccessCode::AccessCodeA,
                            base_frame_len: if self.ul_get_slot_owner(ts, PhyBlockNum::Block2).is_some() {
                                BaseFrameLength::ReservedSubslot
                            } else {
                                self.common_access_frame_len(ts.t)
                            },
                        },
                    }
                }

                // Additional channels (TS2..TS4)
                2..=4 => {
                    // ACCESS-ASSIGN has only one access field when the uplink
                    // is assigned-only, so that field applies to both
                    // subslots (TS 100 392-2, 23.5.1.4.2).  Once either
                    // subslot has been granted, advertise both as reserved as
                    // required by 23.5.2.2.7.  Otherwise another MS may start
                    // random access in the same uplink slot and collide with
                    // the individually granted transmission.
                    let assigned_access_field = AccessField {
                        access_code: AccessCode::AccessCodeA,
                        base_frame_len: if self.ul_get_slot_owner(ts, PhyBlockNum::Block1).is_some()
                            || self.ul_get_slot_owner(ts, PhyBlockNum::Block2).is_some()
                        {
                            BaseFrameLength::ReservedSubslot
                        } else {
                            DEFAULT_ACCESS_FRAME_MARKER
                        },
                    };
                    if self.is_hangtime(ts.t) && (dl_traffic_usage.is_some() || ul_traffic_usage.is_some()) {
                        // Hangtime: immediately switch AACH to AssignedControl so radios
                        // detect the end of traffic in the same frame as D-TX CEASED.
                        // The timeslot may still be in traffic mode (for STCH delivery) but
                        // the AACH reflects the new channel state.
                        AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                            downlink_usage_marker: AccessAssignDlUsage::AssignedControl,
                            access_field: assigned_access_field,
                        }
                    } else {
                        match (dl_traffic_usage, ul_traffic_usage) {
                            (Some(dl_usage), Some(ul_usage)) => AccessAssign::DownlinkDefinedUplinkDefined {
                                downlink_usage_marker: AccessAssignDlUsage::Traffic(dl_usage),
                                uplink_usage_marker: AccessAssignUlUsage::Traffic(ul_usage),
                            },
                            // Core TIP 14.1.1.4: downlink TCH and uplink
                            // FACCH has assigned-only access, not an UL UMt.
                            (Some(dl_usage), None) => AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                                downlink_usage_marker: AccessAssignDlUsage::Traffic(dl_usage),
                                access_field: assigned_access_field,
                            },
                            // Core TIP 14.1.1.5: downlink FACCH plus uplink TCH.
                            (None, Some(ul_usage)) => AccessAssign::DownlinkDefinedUplinkDefined {
                                downlink_usage_marker: AccessAssignDlUsage::AssignedControl,
                                uplink_usage_marker: AccessAssignUlUsage::Traffic(ul_usage),
                            },
                            (None, None) if self.packet_bearer_is_active(ts.t) => AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                                downlink_usage_marker: AccessAssignDlUsage::AssignedControl,
                                access_field: assigned_access_field,
                            },
                            (None, None)
                                if self.circuits.is_active(Direction::Dl, ts.t) || self.circuits.is_active(Direction::Ul, ts.t) =>
                            {
                                AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                                    downlink_usage_marker: AccessAssignDlUsage::AssignedControl,
                                    access_field: assigned_access_field,
                                }
                            }
                            (None, None) => AccessAssign::DownlinkDefinedUplinkDefined {
                                downlink_usage_marker: AccessAssignDlUsage::Unallocated,
                                uplink_usage_marker: AccessAssignUlUsage::Unallocated,
                            },
                        }
                    }
                }

                _ => panic!("finalize_ts_for_tick: invalid timeslot {}", ts.t),
            };

            aach.to_bitbuf(&mut aach_bb);
        } else {
            // Frame 18 is the SACCH control frame for an assigned TCH.
            assert!(ul_traffic_usage.is_none() && dl_traffic_usage.is_none());

            let assigned_channel = ts.t != 1 && self.assigned_channel_is_active(ts.t);
            let access_field_1 = AccessField {
                access_code: AccessCode::AccessCodeA,
                base_frame_len: if self.ul_get_slot_owner(ts, PhyBlockNum::Block1).is_some() {
                    BaseFrameLength::ReservedSubslot
                } else if ts.is_mandatory_clch() {
                    // The predefined FN18 CLCH position applies to the
                    // physical channel even when it is an assigned channel.
                    // It remains unavailable for ordinary reserved access.
                    BaseFrameLength::CLCHSubslot
                } else {
                    self.common_access_frame_len(ts.t)
                },
            };
            let access_field_2 = AccessField {
                access_code: AccessCode::AccessCodeA,
                base_frame_len: if self.ul_get_slot_owner(ts, PhyBlockNum::Block2).is_some() {
                    BaseFrameLength::ReservedSubslot
                } else {
                    self.common_access_frame_len(ts.t)
                },
            };
            let aach = if assigned_channel {
                AccessAssignFr18::UplinkAssignedOnly {
                    access_field_1,
                    access_field_2,
                }
            } else {
                AccessAssignFr18::UplinkCommonOnly {
                    access_field_1,
                    access_field_2,
                }
            };

            tracing::info!(
                dltime = %ts,
                assigned_channel,
                clch = ts.is_mandatory_clch(),
                ul_ssn1_reserved = self.ul_get_slot_owner(ts, PhyBlockNum::Block1).is_some(),
                ul_ssn2_reserved = self.ul_get_slot_owner(ts, PhyBlockNum::Block2).is_some(),
                aach = ?aach,
                "generated FN18 ACCESS-ASSIGN"
            );

            aach.to_bitbuf(&mut aach_bb);
        };

        TmvUnitdataReq {
            logical_channel: LogicalChannel::Aach,
            mac_block: aach_bb,
            scrambling_code: self.scrambling_code,
            air_interface_encryption: None,
            cipher_region: None,
        }
    }

    fn generate_default_blks(&self, ts: TdmaTime) -> TmvUnitdataReq {
        match (ts.f, ts.t) {
            (1..=17, slot) if self.is_common_control(slot) => {
                // Two options: [Blk1: SCH/HD Null | Blk2: BNCH SYSINFO] or [Both: SCH/F Null]
                // Alternate every frame
                match if self.force_common_sysinfo { 0 } else { ts.f % 2 } {
                    0 => {
                        // ACCESS-DEFINE shares the SCH/HD half-slot with the normal
                        // SYSINFO BNCH block at the stable MCCH position.
                        let mut buf1 = BitBuffer::new(SCH_HD_CAP);
                        if self.should_emit_access_define(ts) {
                            let mut access = self.precomps.access_define.as_ref().expect("checked above").clone();
                            let definition = self.access_definition_for_slot(ts.t).parameters;
                            access.imm = definition.imm;
                            access.wt = definition.wt;
                            access.nu = definition.nu;
                            access.frame_len_factor = definition.frame_len_factor;
                            access.ts_pointer = definition.ts_pointer;
                            access.min_pdu_prio = definition.min_pdu_prio;
                            access.to_bitbuf(&mut buf1);
                        } else {
                            MacResource::null_pdu().to_bitbuf(&mut buf1);
                        }
                        TmvUnitdataReq {
                            logical_channel: LogicalChannel::SchHd,
                            mac_block: buf1,
                            scrambling_code: self.scrambling_code,
                            air_interface_encryption: None,
                            cipher_region: None,
                        }
                    }
                    1 => {
                        // Full-slot Null PDU
                        let mut buf = BitBuffer::new(SCH_F_CAP);
                        let blk = MacResource::null_pdu();
                        blk.to_bitbuf(&mut buf);
                        TmvUnitdataReq {
                            logical_channel: LogicalChannel::SchF,
                            mac_block: buf,
                            scrambling_code: self.scrambling_code,
                            air_interface_encryption: None,
                            cipher_region: None,
                        }
                    }
                    _ => panic!(), // never happens
                }
            }
            (1..=17, 2..=4) if self.packet_bearer_is_active(ts.t) => {
                // A pi/4-DQPSK PDCH is an assigned signalling channel.  In
                // frames 1..17 an otherwise idle packet slot must therefore
                // remain SCH/F; transmitting BSCH + MLE-SYNC here makes an MS
                // lose the assigned channel immediately after accepting the
                // Replace allocation.  Frame 18 deliberately falls through
                // to BSCH below for monitoring and linearisation (TTR 001-05
                // section 6.10.1).
                let mut buf = BitBuffer::new(SCH_F_CAP);
                MacResource::null_pdu().to_bitbuf(&mut buf);
                TmvUnitdataReq {
                    logical_channel: LogicalChannel::SchF,
                    mac_block: buf,
                    scrambling_code: self.scrambling_code,
                    air_interface_encryption: None,
                    cipher_region: None,
                }
            }
            (1..=17, 2..=4) | (18, _) => {
                // SYNC + SYSINFO (added later)
                let mut buf = BitBuffer::new(60);
                self.precomps.mac_sync.to_bitbuf(&mut buf);
                self.precomps.mle_sync.to_bitbuf(&mut buf);
                TmvUnitdataReq {
                    logical_channel: LogicalChannel::Bsch,
                    mac_block: buf,
                    scrambling_code: scrambler::SCRAMB_INIT,
                    air_interface_encryption: None,
                    cipher_region: None,
                }
            }
            _ => panic!(), // never happens
        }
    }

    pub fn dump_ul_schedule(&self, skip_empty: bool) {
        let ts = self.cur_dltime;
        tracing::info!("Dumping uplink schedule for {}:", ts);
        for dist in 0..MACSCHED_NUM_FRAMES - 1 {
            let ts = ts.add_timeslots(dist as i32 * 4);
            let index = self.ul_ts_to_sched_index(&ts);
            let elem = &self.ulsched[ts.t as usize - 1][index];
            if skip_empty && elem.ul1.is_none() && elem.ul2.is_none() {
                continue;
            }
            tracing::info!("  Schedule {}: {:?}", ts, elem);
        }
    }

    pub fn dump_ul_schedule_full(&self, skip_empty: bool) {
        tracing::info!("Dumping uplink schedule for {}:", self.cur_dltime);

        for dist in 0..MACSCHED_NUM_FRAMES - 1 {
            let ts = self.cur_dltime.add_timeslots(dist as i32 * 4);
            let index = self.ul_ts_to_sched_index(&ts);
            if skip_empty
                && self.ulsched[0][index].ul1.is_none()
                && self.ulsched[0][index].ul2.is_none()
                && self.ulsched[1][index].ul1.is_none()
                && self.ulsched[1][index].ul2.is_none()
                && self.ulsched[2][index].ul1.is_none()
                && self.ulsched[2][index].ul2.is_none()
                && self.ulsched[3][index].ul1.is_none()
                && self.ulsched[3][index].ul2.is_none()
            {
                continue;
            }
            tracing::info!(
                "  Schedule {}: ({} / {})  ({} / {})  ({} / {})  ({} / {})",
                ts,
                self.ulsched[0][index].ul1.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[0][index].ul2.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[1][index].ul1.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[1][index].ul2.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[2][index].ul1.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[2][index].ul2.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[3][index].ul1.map_or("-".to_string(), |v| v.to_string()),
                self.ulsched[3][index].ul2.map_or("-".to_string(), |v| v.to_string())
            );
        }
    }

    pub fn dump_dl_queue(&self) {
        tracing::info!("Dumping downlink queue:");
        for (index, elem) in self.dltx_queues.iter().enumerate() {
            for e in elem {
                tracing::trace!("  ts[{}] {:?}", index, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use tetra_core::{
        address::{SsiType, TetraAddress},
        debug::setup_logging_default,
    };

    use tetra_pdus::{
        mle::{
            fields::bs_service_details::BsServiceDetails,
            pdus::{d_mle_sync::DMleSync, d_mle_sysinfo::DMleSysinfo},
        },
        umac::{
            enums::sysinfo_opt_field_flag::SysinfoOptFieldFlag,
            fields::{
                sysinfo_default_def_for_access_code_a::SysinfoDefaultDefForAccessCodeA, sysinfo_ext_services::SysinfoExtendedServices,
            },
            pdus::{mac_end_dl::MacEndDl, mac_sync::MacSync, mac_sysinfo::MacSysinfo},
        },
    };

    use super::*;

    pub fn get_testing_slotter() -> BsChannelScheduler {
        let _guard = setup_logging_default(None);
        let ext_services = SysinfoExtendedServices {
            auth_required: false,
            class1_supported: true,
            class2_supported: true,
            class3_supported: false,
            sck_n: Some(0),
            dck_retrieval_during_cell_select: None,
            dck_retrieval_during_cell_reselect: None,
            linked_gck_crypto_periods: None,
            short_gck_vn: None,
            sdstl_addressing_method: 2,
            gck_supported: false,
            section: 0,
            section_data: 0,
        };

        let def_access = SysinfoDefaultDefForAccessCodeA {
            imm: 8,
            wt: 5,
            nu: 5,
            fl_factor: false,
            ts_ptr: 0,
            min_pdu_prio: 0,
        };

        let sysinfo1 = MacSysinfo {
            main_carrier: 1001,
            freq_band: 4,
            freq_offset_index: 0,
            duplex_spacing: 0,
            reverse_operation: false,
            num_of_csch: 0,
            ms_txpwr_max_cell: 5,
            rxlev_access_min: 3,
            access_parameter: 7,
            radio_dl_timeout: 3,
            cipher_key_id_or_sck_vn: None,
            hyperframe_number: Some(0),
            option_field: SysinfoOptFieldFlag::DefaultDefForAccCodeA,
            ts_common_frames: None,
            default_access_code: Some(def_access),
            ext_services: None,
        };

        let sysinfo2 = MacSysinfo {
            main_carrier: sysinfo1.main_carrier,
            freq_band: sysinfo1.freq_band,
            freq_offset_index: sysinfo1.freq_offset_index,
            duplex_spacing: sysinfo1.duplex_spacing,
            reverse_operation: sysinfo1.reverse_operation,
            num_of_csch: sysinfo1.num_of_csch,
            ms_txpwr_max_cell: sysinfo1.ms_txpwr_max_cell,
            rxlev_access_min: sysinfo1.rxlev_access_min,
            access_parameter: sysinfo1.access_parameter,
            radio_dl_timeout: sysinfo1.radio_dl_timeout,
            cipher_key_id_or_sck_vn: sysinfo1.cipher_key_id_or_sck_vn,
            hyperframe_number: sysinfo1.hyperframe_number,
            option_field: SysinfoOptFieldFlag::ExtServicesBroadcast,
            ts_common_frames: None,
            default_access_code: None,
            ext_services: Some(ext_services),
        };

        let mle_sysinfo_pdu = DMleSysinfo {
            location_area: 2,
            subscriber_class: 65535, // All subscriber classes allowed
            bs_service_details: BsServiceDetails {
                registration: true,
                deregistration: true,
                priority_cell: false,
                no_minimum_mode: true,
                migration: false,
                system_wide_services: true,
                voice_service: true,
                circuit_mode_data_service: false,
                sndcp_service: false,
                aie_service: false,
                advanced_link: false,
            },
        };

        let mac_sync_pdu = MacSync {
            system_code: 1,
            colour_code: 1,
            time: TdmaTime::default(),
            sharing_mode: 0, // Continuous transmission
            ts_reserved_frames: 0,
            u_plane_dtx: false,
            frame_18_ext: false,
        };

        let mle_sync_pdu = DMleSync {
            mcc: 204,
            mnc: 1337,
            neighbor_cell_broadcast: 2,
            cell_load_ca: 0,
            late_entry_supported: true,
        };

        let precomps = PrecomputedUmacPdus {
            mac_sysinfo1: sysinfo1,
            mac_sysinfo2: sysinfo2,
            access_define: None,
            access_define_interval_multiframes: 1,
            mle_sysinfo: mle_sysinfo_pdu,
            mac_sync: mac_sync_pdu,
            mle_sync: mle_sync_pdu,
        };

        let mut sched = BsChannelScheduler::new(1, precomps);
        sched.set_dl_time(TdmaTime::default().add_timeslots(2));
        sched
    }

    fn enable_test_sc3(sched: &mut BsChannelScheduler) {
        sched.set_aie_config(&RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(tetra_config::bluestation::RuntimeSc3Aie::new(
                tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea3,
                23,
                [0x6c; 10],
                true,
                false,
            )),
            rollover: None,
        });
    }

    #[test]
    fn scch_expansion_recovers_free_slot_signalling_after_uplink_grants_drain() {
        let mut sched = get_testing_slotter();
        sched.cur_dltime = TdmaTime::default();
        let addr = TetraAddress::issi(77468);
        let aie = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        let grant = sched.ul_process_cap_req(3, addr, &ReservationRequirement::Req1Slot).unwrap();
        let resource = BsChannelScheduler::dl_make_minimal_resource(&addr, Some(grant), false);
        let reporter = TxReporter::new();
        let fragmented = TxReporter::new();
        sched.dltx_queues[2].push(DlSchedElem::Resource(
            resource.clone(),
            BitBuffer::from_bitstr("1010"),
            Some(reporter.clone()),
            aie,
            None,
        ));
        sched.dltx_queues[2].push(DlSchedElem::FragBuf(
            BsFragger::new_with_aie(resource, BitBuffer::from_bitstr("1010"), Some(fragmented.clone()), aie),
            None,
        ));
        assert!(!sched.prepare_free_common_control_slot(3));
        assert_eq!(sched.dltx_queues[2].len(), 2);
        assert_eq!(fragmented.get_state(), tetra_core::TxState::Pending);
        for reservation in &mut sched.ulsched[2] {
            reservation.ul1 = None;
            reservation.ul2 = None;
        }
        assert!(sched.prepare_free_common_control_slot(3));
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert_eq!(fragmented.get_state(), tetra_core::TxState::Discarded);
        let DlSchedElem::Resource(pdu, _, _, _, _) = &sched.dltx_queues[0][0] else {
            panic!("MCCH resource")
        };
        assert!(pdu.slot_granting_element.is_none());
        assert!(sched.common_slot_is_drained(3));
    }

    #[test]
    fn common_scch_has_common_aach_independent_access_and_sysinfo() {
        let mut sched = get_testing_slotter();
        sched.set_common_control_channels(2, 2, false);
        let mut access = sched.random_access_definition();
        access.frame_len = 6;
        access.parameters.imm = 3;
        sched.set_secondary_random_access_definition(2, access);
        for slot in 1..=3 {
            let time = TdmaTime { t: slot, f: 2, m: 1, h: 0 };
            let mut aach = sched.generate_bbk_block(time).mac_block;
            aach.seek(0);
            let aach = AccessAssign::from_bitbuf(&mut aach).unwrap();
            let AccessAssign::DownlinkCommonControlUplinkCommonOnly { access_field_1, .. } = aach else {
                panic!("common AACH")
            };
            assert_eq!(access_field_1.base_frame_len, sched.common_access_frame_len(slot));
            sched.cur_dltime = time.add_timeslots(-(MACSCHED_TX_AHEAD as i32));
            let result = sched.finalize_ts_for_tick();
            assert_eq!(result.blk1.as_ref().unwrap().logical_channel, LogicalChannel::SchHd);
            let mut bnch = result.blk2.unwrap().mac_block;
            bnch.seek(0);
            let sysinfo = MacSysinfo::from_bitbuf(&mut bnch).unwrap();
            assert_eq!(sysinfo.num_of_csch, 2);
            assert_eq!(sysinfo.default_access_code.unwrap().imm, if slot == 2 { 3 } else { 8 });
        }
    }

    #[test]
    fn scch_decrease_broadcasts_new_configuration_on_every_frame18_slot() {
        let mut sched = get_testing_slotter();
        sched.set_common_control_channels(2, 0, true);
        let time = TdmaTime { t: 2, f: 18, m: 1, h: 0 };
        let index = sched.ul_ts_to_sched_index(&time);
        sched.ulsched[1][index].ul1 = Some(77468);
        assert!(!sched.common_slot_is_drained(2));
        for slot in 1..=4 {
            sched.cur_dltime = TdmaTime { t: slot, ..time }.add_timeslots(-(MACSCHED_TX_AHEAD as i32));
            let result = sched.finalize_ts_for_tick();
            assert_eq!(result.blk1.unwrap().logical_channel, LogicalChannel::Bsch);
            let mut bnch = result.blk2.unwrap().mac_block;
            bnch.seek(0);
            assert_eq!(MacSysinfo::from_bitbuf(&mut bnch).unwrap().num_of_csch, 0);
        }
    }

    #[test]
    fn cell_monitor_uses_effective_broadcast_parameters_and_tdma_time() {
        use crate::monitoring::CellSnapshot;
        let mut sched = get_testing_slotter();
        let time = TdmaTime {
            h: 65535,
            m: 60,
            f: 18,
            t: 4,
        };
        let mut settings = RuntimeOperatorSettings::default();
        settings.ms_txpwr_max_cell = 6;
        settings.rxlev_access_min = 5;
        settings.access_parameter = 9;
        sched.apply_live_operator_settings(&settings, sched.random_access_definition());
        sched.set_system_wide_services_state(false);
        enable_test_sc3(&mut sched);
        sched.precomps.mle_sync.mcc = 310;
        sched.precomps.mle_sync.mnc = 1234;
        sched.precomps.mle_sysinfo.location_area = 102;
        sched.precomps.mac_sysinfo1.freq_band = 4;
        sched.precomps.mac_sysinfo1.main_carrier = 864;
        sched.precomps.mac_sysinfo1.freq_offset_index = 1;
        let snapshot = CellSnapshot::from_broadcast(sched.broadcast_parameters(), time, None);
        assert_eq!(snapshot.time, time);
        assert_eq!((snapshot.mcc, snapshot.mnc, snapshot.location_area), (310, 1234, 102));
        assert_eq!(
            (snapshot.ms_txpwr_max_cell, snapshot.rxlev_access_min, snapshot.access_parameter),
            (6, 5, 9)
        );
        assert_eq!(snapshot.frequencies_hz, Some((421_606_250, 411_606_250)));
        assert!(snapshot.services.contains(&("System-wide services".into(), false)));
        assert!(snapshot.services.contains(&("Security class 3".into(), true)));
        sched.precomps.mac_sysinfo1.reverse_operation = true;
        sched.precomps.mac_sysinfo1.duplex_spacing = 7;
        let snapshot = CellSnapshot::from_broadcast(sched.broadcast_parameters(), time, Some(7_600_000));
        assert_eq!(snapshot.frequencies_hz, Some((421_606_250, 429_206_250)));
    }

    #[test]
    fn live_operator_settings_update_both_sysinfo_variants_and_access_define() {
        let mut sched = get_testing_slotter();
        let mut settings = RuntimeOperatorSettings::default();
        settings.ms_txpwr_max_cell = 6;
        settings.rxlev_access_min = 5;
        settings.access_parameter = 9;
        settings.random_access.enabled = true;
        settings.random_access.update_interval_multiframes = 3;
        let mut current = sched.random_access_definition();
        current.parameters.imm = 4;
        current.frame_len = 6;
        sched.apply_live_operator_settings(&settings, current);
        assert_eq!(sched.precomps.mac_sysinfo1.ms_txpwr_max_cell, 6);
        assert_eq!(sched.precomps.mac_sysinfo2.rxlev_access_min, 5);
        assert_eq!(sched.precomps.mac_sysinfo1.access_parameter, 9);
        assert_eq!(sched.precomps.access_define_interval_multiframes, 3);
        assert_eq!(sched.precomps.access_define.as_ref().unwrap().imm, 4);
        assert_eq!(sched.random_access_definition().frame_len, 6);

        settings.random_access.enabled = false;
        sched.apply_live_operator_settings(&settings, current);
        assert!(sched.precomps.access_define.is_none());
        assert_eq!(sched.random_access_definition().frame_len, 4);
    }

    #[test]
    fn missing_dck_discards_mcch_reporter() {
        let mut sched = get_testing_slotter();
        enable_test_sc3(&mut sched);
        let addr = TetraAddress::issi(77_468);
        let reporter = TxReporter::new();
        sched.dl_enqueue_tma(
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("1010"),
            Some(reporter.clone()),
            AieRequest::sc3(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let _ = sched.dl_build_block_from_signalling_schedule(TdmaTime { t: 1, f: 3, m: 1, h: 0 });

        assert_eq!(reporter.get_state(), tetra_core::TxState::Discarded);
    }

    #[test]
    fn missing_dck_discards_associated_reporter() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        enable_test_sc3(&mut sched);
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 1,
                    direction,
                    ts: 2,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        let addr = TetraAddress::issi(77_468);
        let reporter = TxReporter::new();
        sched.dl_enqueue_associated_tma(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("1010"),
            Some(reporter.clone()),
            AieRequest::sc3(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let _ = sched.dl_build_associated_control_block(TdmaTime { t: 2, f: 18, m: 2, h: 0 });

        assert_eq!(reporter.get_state(), tetra_core::TxState::Discarded);
    }

    #[test]
    fn encrypted_packet_resource_keeps_its_event_label() {
        use tetra_config::bluestation::{RuntimeSc3Aie, RuntimeSc3Dck, RuntimeSc3TeaAlgorithm, SharedConfig};

        let parsed_config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example BS configuration");
        let config = SharedConfig::from_parts(parsed_config, None);
        let issi = 77_479;
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea3, 23, [0x6c; 10], true, false);
        sc3.install_dck(issi, RuntimeSc3Dck::new([0x47; 16], [0xd3; 10], true, None));
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let mut sched = get_testing_slotter();
        sched.aie_provider = Some(BsAieKeyProvider::new(config));
        let request = AieRequest::sc3(AieSubject::Individual { issi }, AieScope::MacResource);
        let resource = MacResource {
            addr: None,
            event_label: Some(5),
            ..MacResource::default()
        };

        let prepared = sched
            .prepare_downlink_resource(resource, request, TdmaTime::default())
            .expect("encrypted event-label resource");

        assert!(prepared.addr.is_none());
        assert_eq!(prepared.event_label, Some(5));
        assert_ne!(prepared.encryption_mode, 0);
    }

    #[test]
    fn cancelled_concurrent_copies_leave_control_queues() {
        let mut sched = get_testing_slotter();
        let addr = TetraAddress::issi(77_468);

        let associated_reporter = TxReporter::new();
        sched.dl_enqueue_associated_tma(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("1010"),
            Some(associated_reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );
        associated_reporter.mark_discarded();
        assert!(
            sched
                .dl_build_associated_control_block(TdmaTime { t: 2, f: 18, m: 2, h: 0 })
                .is_none()
        );
        assert!(sched.assoc_dltx_queues[1].is_empty());

        let mcch_reporter = TxReporter::new();
        sched.dl_enqueue_tma(
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("1010"),
            Some(mcch_reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );
        mcch_reporter.mark_discarded();
        assert!(sched.dl_take_prioritized_sched_item(TdmaTime { t: 1, f: 2, m: 2, h: 0 }).is_none());
        assert!(sched.dltx_queues[0].is_empty());
    }

    #[test]
    fn all_ms_gck_notice_uses_cck_and_precedes_ordinary_mcch() {
        use tetra_config::bluestation::{RuntimeSc3Aie, RuntimeSc3TeaAlgorithm, SharedConfig};

        let parsed = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example BS configuration");
        let config = SharedConfig::from_parts(parsed, None);
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x35; 10], true, true)),
            rollover: None,
        };
        let mut sched = get_testing_slotter();
        sched.aie_provider = Some(BsAieKeyProvider::new(config));
        let time = TdmaTime { t: 1, f: 5, m: 1, h: 1 };
        let request = AieRequest::sc3(AieSubject::Group { gssi: 0x00ff_ffff }, AieScope::MacResource);
        let context = sched.resolve_downlink_context(request, time).expect("all-MS CCK context");
        assert!(matches!(context, AieContext::Sc3 { key, .. } if key.key_type == tetra_core::Sc3KeyType::Cck));

        let broadcast = TetraAddress::new(0x00ff_ffff, SsiType::Gssi);
        let prepared = sched
            .prepare_downlink_resource(BsChannelScheduler::dl_make_minimal_resource(&broadcast, None, false), request, time)
            .expect("protected all-MS resource");
        assert_eq!(prepared.addr.expect("encrypted broadcast address").ssi_type, SsiType::Esi);
        assert_ne!(prepared.encryption_mode, 0);

        let ordinary = TetraAddress::issi(77_468);
        sched.dl_enqueue_tma(
            BsChannelScheduler::dl_make_minimal_resource(&ordinary, None, false),
            BitBuffer::from_bitstr("1010"),
            None,
            AieRequest::clear(AieSubject::Individual { issi: ordinary.ssi }, AieScope::MacResource),
        );
        sched.dl_enqueue_ee_mcch_tma(
            BsChannelScheduler::dl_make_minimal_resource(&broadcast, None, false),
            BitBuffer::from_bitstr("00100010010000100000000000000100111"),
            TxReporter::new_unacked(),
            request,
        );
        let first = sched.dl_take_prioritized_sched_item(time).expect("EE notice queued");
        assert!(matches!(first, DlSchedElem::Resource(pdu, ..)
            if pdu.addr.is_some_and(|address| address.ssi == broadcast.ssi && address.ssi_type == broadcast.ssi_type)));
    }

    #[test]
    fn sc2_sysinfo_alternates_hyperframe_and_cipher_key_field() {
        let mut sched = get_testing_slotter();
        sched.set_aie_config(&RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(tetra_config::bluestation::RuntimeSc2Aie::new(
                tetra_config::bluestation::RuntimeSc2TeaAlgorithm::Tea3,
                30,
                7,
                [0x5a; 10],
            )),
            sc3: None,
            rollover: None,
        });

        assert_eq!(sched.precomps.mac_sysinfo1.cipher_key_id_or_sck_vn, None);
        assert!(sched.precomps.mac_sysinfo1.hyperframe_number.is_some());
        assert_eq!(sched.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn, Some(7));
        assert_eq!(sched.precomps.mac_sysinfo2.hyperframe_number, None);
        let ext = sched.precomps.mac_sysinfo2.ext_services.as_ref().expect("Extended Services");
        assert!(!ext.class1_supported);
        assert!(ext.class2_supported);
        assert_eq!(ext.sck_n, Some(30));
        assert!(sched.precomps.mle_sysinfo.bs_service_details.aie_service);
    }

    #[test]
    fn sc3_sysinfo_advertises_cck_and_retrieval_policy() {
        let mut sched = get_testing_slotter();
        sched.set_aie_config(&RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(tetra_config::bluestation::RuntimeSc3Aie::new(
                tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea3,
                23,
                [0x6c; 10],
                true,
                false,
            )),
            rollover: None,
        });

        assert_eq!(sched.precomps.mac_sysinfo2.cipher_key_id_or_sck_vn, Some(23));
        let ext = sched.precomps.mac_sysinfo2.ext_services.as_ref().expect("Extended Services");
        assert!(!ext.class2_supported);
        assert!(ext.class3_supported);
        assert_eq!(ext.sck_n, None);
        assert_eq!(ext.dck_retrieval_during_cell_select, Some(true));
        assert_eq!(ext.dck_retrieval_during_cell_reselect, Some(false));
        assert_eq!(ext.linked_gck_crypto_periods, Some(false));
        assert_eq!(ext.short_gck_vn, Some(0));

        // Exercise the actual on-air serializer; merely inspecting the
        // precomputed structure did not catch missing mandatory SC3 bits.
        let mut encoded = BitBuffer::new_autoexpand(128);
        sched.precomps.mac_sysinfo2.to_bitbuf(&mut encoded);
        encoded.seek(0);
        let decoded = MacSysinfo::from_bitbuf(&mut encoded).expect("decode SC3 SYSINFO");
        let decoded_ext = decoded.ext_services.expect("decoded Extended Services");
        assert!(decoded_ext.class3_supported);
        assert_eq!(decoded_ext.linked_gck_crypto_periods, Some(false));
        assert_eq!(decoded_ext.short_gck_vn, Some(0));
    }

    #[test]
    fn sysinfo_variant_follows_bnch_occurrence_not_timeslot() {
        let at = |t, f| TdmaTime { t, f, m: 1, h: 0 };

        // All timeslots use the same contents for a given BNCH frame.
        assert_eq!(use_default_access_sysinfo(at(1, 4)), use_default_access_sysinfo(at(2, 4)));
        // Actual additional TS1 BNCH opportunities alternate both required
        // variants rather than permanently selecting by TS1.
        assert!(use_default_access_sysinfo(at(1, 2)));
        assert!(!use_default_access_sysinfo(at(1, 4)));
        assert!(use_default_access_sysinfo(at(1, 6)));
        assert!(!use_default_access_sysinfo(at(1, 8)));
        // Rollover planning selects only the stable TS1 occurrences of the
        // Extended Services variant, so its Absolute IV and the broadcast
        // SCKN/SCK-VN update cannot drift apart.
        for frame in [4, 8, 12, 16] {
            let time = at(1, frame);
            assert!(time.is_sc2_security_sysinfo_opportunity());
            assert!(!use_default_access_sysinfo(time));
        }
        // Mandatory control-frame SYSINFO always retains hyperframe data for
        // terminals acquiring or reacquiring the cell.
        for t in 1..=4 {
            assert!(use_default_access_sysinfo(at(t, 18)));
        }
    }

    #[test]
    fn sc2_changeover_dummy_is_an_addressed_decodable_stch_pdu() {
        use tetra_config::bluestation::{RuntimeSc2Aie, RuntimeSc2TeaAlgorithm, SharedConfig};
        use tetra_saps::{control::enums::circuit_mode_type::CircuitModeType, tp::TpUnitdataInd};

        let parsed_config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example BS configuration");
        let config = SharedConfig::from_parts(parsed_config, None);
        let old_key = [0x11; 10];
        let target_key = [0x22; 10];
        let old = RuntimeSc2Aie::new(RuntimeSc2TeaAlgorithm::Tea1, 27, 18, old_key);
        let target = RuntimeSc2Aie::new(RuntimeSc2TeaAlgorithm::Tea1, 28, 19, target_key);
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: Some(old.clone()),
                sc3: None,
                rollover: None,
            };
        }

        let mut sched = get_testing_slotter();
        sched.aie_provider = Some(BsAieKeyProvider::new(config.clone()));
        sched.create_circuit(
            Direction::Dl,
            Circuit {
                call_id: 1,
                direction: Direction::Dl,
                ts: 2,
                usage: 15,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );
        sched.set_traffic_aie(2, Some(AieRequest::sc2(AieSubject::Group { gssi: 91 }, AieScope::Traffic)));

        let air_time = TdmaTime { t: 2, f: 12, m: 49, h: 7 };
        let old_aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(old),
            sc3: None,
            rollover: None,
        };
        sched.set_aie_config_for_air_time(&old_aie, air_time.add_timeslots(-1));

        // The scheduler only emits a transition DUMMY when both the previous
        // and current policies are valid SC2 identities.  Promote the shared
        // key provider and the advertised policy together, as production does
        // at the Absolute-IV boundary.
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: Some(target.clone()),
                sc3: None,
                rollover: None,
            };
        }
        let aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: Some(target),
            sc3: None,
            rollover: None,
        };
        sched.set_aie_config_for_air_time(&aie, air_time);
        sched.cur_dltime = air_time.add_timeslots(-(MACSCHED_TX_AHEAD as i32));
        let slot = sched.finalize_ts_for_tick();

        assert_eq!(slot.ts, air_time);
        let stch = slot.blk1.expect("changeover must steal the first half-slot");
        let speech = slot.blk2.expect("second half-slot must remain TCH/S");
        assert_eq!(stch.logical_channel, LogicalChannel::Stch);
        assert_eq!(stch.mac_block.get_len(), SCH_HD_CAP);
        assert_eq!(stch.cipher_region, Some(AieCipherRegion::new(49, 0)));
        assert_eq!(speech.logical_channel, LogicalChannel::TchS);
        assert_eq!(speech.mac_block.get_len(), TCH_S_CAP);

        // Exercise the real STCH 124 -> 216 channel coding and decoding path,
        // then parse the recovered MAC-RESOURCE.  This proves that the block
        // is not merely the right length but is recognizable as an addressed
        // DUMMY after its actual half-slot FEC/interleaving/scrambling.
        let encoded = crate::lmac::components::errorcontrol::encode_cp(stch.clone());
        assert_eq!(encoded.get_len(), 216);
        let (decoded, crc_ok) = crate::lmac::components::errorcontrol::decode_cp(
            LogicalChannel::Stch,
            TpUnitdataInd {
                ul_time: air_time,
                train_type: tetra_core::TrainingSequence::NormalTrainSeq2,
                burst_type: tetra_core::BurstType::NDB,
                block_type: tetra_core::PhyBlockType::NDB,
                block_num: PhyBlockNum::Block1,
                soft_bits: None,
                rf_observation: None,
                block: encoded,
            },
            Some(stch.scrambling_code),
        );
        assert!(crc_ok, "changeover DUMMY STCH CRC must survive the half-slot coding path");
        let mut decoded = decoded.expect("decoded STCH");
        decoded.seek(0);
        let dummy = MacResource::from_bitbuf(&mut decoded).expect("decoded changeover DUMMY MAC-RESOURCE");

        assert_eq!(
            dummy.encryption_mode, 0b11,
            "odd target SCK-VN must be present in the clear MAC header"
        );
        assert_eq!(dummy.length_ind, 7, "addressed DUMMY contains a header and no TM-SDU");
        assert!(dummy.fill_bits);
        assert_eq!(dummy.usage_marker, Some(15));
        let esi = dummy.addr.expect("DUMMY must address the listening group").ssi;
        let target_plain = tetra_crypto::ta61_inverse(&target_key, &[(esi >> 16) as u8, (esi >> 8) as u8, esi as u8]);
        let old_plain = tetra_crypto::ta61_inverse(&old_key, &[(esi >> 16) as u8, (esi >> 8) as u8, esi as u8]);
        assert_eq!(u32::from_be_bytes([0, target_plain[0], target_plain[1], target_plain[2]]), 91);
        assert_ne!(
            u32::from_be_bytes([0, old_plain[0], old_plain[1], old_plain[2]]),
            91,
            "the transition DUMMY must use the target-key GESI, not a stale old-key address"
        );
    }

    #[test]
    fn test_halfslot_grants() {
        let mut sched = get_testing_slotter();
        let resreq = ReservationRequirement::Req1Subslot;
        let addr = TetraAddress {
            ssi_type: SsiType::Issi,
            ssi: 1234,
        };
        let grant1 = sched.ul_process_cap_req(1, addr, &resreq);
        tracing::info!("grant1: {:?}", grant1);
        assert!(grant1.is_some(), "ul_process_cap_req should return Some, but got None");

        sched.dump_ul_schedule(false);

        let u1 = sched.ul_get_usage(TdmaTime { t: 1, f: 1, m: 1, h: 0 });
        let u2 = sched.ul_get_usage(TdmaTime { t: 1, f: 2, m: 1, h: 0 });
        let u3 = sched.ul_get_usage(TdmaTime { t: 1, f: 3, m: 1, h: 0 });
        tracing::info!("usage ts 1/2/3: {:?}/{:?}/{:?}", u1, u2, u3);

        let cap_alloc1 = grant1.unwrap().capacity_allocation;
        assert_eq!(
            cap_alloc1,
            BasicSlotgrantCapAlloc::FirstSubslotGranted,
            "ul_process_cap_req should return FirstSubslotGranted, but got {:?}",
            cap_alloc1
        );
        let grant2 = sched.ul_process_cap_req(1, addr, &resreq);
        tracing::info!("grant2: {:?}", grant2);
        assert!(grant2.is_some(), "ul_process_cap_req should return Some, but got None");
        let cap_alloc2 = grant2.unwrap().capacity_allocation;
        assert_eq!(
            cap_alloc2,
            BasicSlotgrantCapAlloc::SecondSubslotGranted,
            "ul_process_cap_req should return SecondSubslotGranted, but got {:?}",
            cap_alloc2
        );

        sched.dump_ul_schedule(false);

        let u1 = sched.ul_get_usage(TdmaTime { t: 1, f: 1, m: 1, h: 0 });
        let u2 = sched.ul_get_usage(TdmaTime { t: 1, f: 2, m: 1, h: 0 });
        let u3 = sched.ul_get_usage(TdmaTime { t: 1, f: 3, m: 1, h: 0 });
        tracing::info!("usage ts 1/2/3: {:?}/{:?}/{:?}", u1, u2, u3);

        sched.dump_ul_schedule(false);
    }

    #[test]
    fn test_halfslot_and_fullslot_grant() {
        let mut sched = get_testing_slotter();
        let resreq1 = ReservationRequirement::Req1Subslot;
        let addr = TetraAddress {
            ssi_type: SsiType::Issi,
            ssi: 1234,
        };

        sched.dump_ul_schedule(true);
        let grant1 = sched.ul_process_cap_req(1, addr, &resreq1);
        tracing::info!("grant1: {:?}", grant1);

        let u1 = sched.ul_get_usage(TdmaTime { t: 1, f: 1, m: 1, h: 0 });
        let u2 = sched.ul_get_usage(TdmaTime { t: 1, f: 2, m: 1, h: 0 });
        let u3 = sched.ul_get_usage(TdmaTime { t: 1, f: 3, m: 1, h: 0 });
        tracing::info!("usage ts 1/2/3: {:?}/{:?}/{:?}", u1, u2, u3);

        assert!(grant1.is_some());
        let cap_alloc1 = grant1.unwrap().capacity_allocation;
        assert_eq!(cap_alloc1, BasicSlotgrantCapAlloc::FirstSubslotGranted);

        sched.dump_ul_schedule(true);
        let resreq2 = ReservationRequirement::Req3Slots;
        let Some(grant2) = sched.ul_process_cap_req(1, addr, &resreq2) else {
            panic!()
        };
        tracing::info!("grant2: {:?}", grant2);
        sched.dump_ul_schedule(true);

        let u1 = sched.ul_get_usage(TdmaTime { t: 1, f: 1, m: 1, h: 0 });
        let u2 = sched.ul_get_usage(TdmaTime { t: 1, f: 2, m: 1, h: 0 });
        let u3 = sched.ul_get_usage(TdmaTime { t: 1, f: 3, m: 1, h: 0 });
        tracing::info!("usage ts 1/2/3: {:?}/{:?}/{:?}", u1, u2, u3);

        assert_eq!(grant2.capacity_allocation, BasicSlotgrantCapAlloc::Grant3Slots);
        assert_eq!(grant2.granting_delay, BasicSlotgrantGrantingDelay::DelayNOpportunities(1));
    }

    #[test]
    fn multislot_packet_grant_counts_every_assigned_timeslot() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));

        let grant = sched
            .ul_process_cap_req(4, TetraAddress::issi(77_479), &ReservationRequirement::Req8Slots)
            .expect("three-slot PDCH must provide eight consecutive opportunities");

        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant8Slots);
        assert_eq!(grant.granting_delay, BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity);
        let first = sched.cur_dltime.forward_to_timeslot(4);
        let expected_offsets = [0, 2, 3, 4, 6, 7, 8, 10];
        for offset in expected_offsets {
            assert_eq!(
                sched.ul_get_slot_owner(first.add_timeslots(offset), PhyBlockNum::Both),
                Some(77_479)
            );
        }
        assert_eq!(
            sched.ul_get_slot_owner(first.add_timeslots(1), PhyBlockNum::Both),
            None,
            "TS1 is not part of the packet bearer"
        );
    }

    #[test]
    fn two_slot_packet_grant_uses_one_bounded_turn_for_a_total_request() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b0110));
        let addr = TetraAddress::issi(77_479);
        let request_time = sched.cur_dltime.forward_to_timeslot(2).add_timeslots(-4);

        let first = sched
            .ul_process_packet_data_cap_req_at(request_time, addr, &ReservationRequirement::Req10Slots, false)
            .expect("initial two-slot grant");
        assert_eq!(first.capacity_allocation, BasicSlotgrantCapAlloc::Grant10Slots);
        assert!(
            sched
                .ul_process_packet_data_cap_req_at(request_time, addr, &ReservationRequirement::Req10Slots, false)
                .is_none(),
            "a repeated total request must not add another ten slots"
        );
    }

    #[test]
    fn packet_shortfall_is_granted_after_the_receive_turn_without_new_random_access() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let addr = TetraAddress::issi(77_479);
        let grant_time = TdmaTime { t: 2, f: 3, m: 1, h: 0 };
        assert!(sched.queue_packet_data_capacity_request(grant_time.add_timeslots(-4), addr, ReservationRequirement::Req34Slots, false));

        sched.schedule_ready_packet_data_grant(grant_time);
        let first = sched.dltx_queues[grant_time.t as usize - 1]
            .iter()
            .find_map(|elem| match elem {
                DlSchedElem::Grant(_, grant) => Some(grant),
                _ => None,
            })
            .expect("first retained request must produce a grant");
        assert_eq!(first.capacity_allocation, BasicSlotgrantCapAlloc::Grant17Slots);
        assert_eq!(sched.pending_packet_data_grants[&addr.ssi].remaining_slots, 17);

        let first_window = sched.packet_data_grant_windows[&addr.ssi];
        sched.dltx_queues[grant_time.t as usize - 1].clear();
        sched.schedule_ready_packet_data_grant(first_window.next_grant_downlink.add_timeslots(-1));
        assert!(
            sched.dltx_queues.iter().all(Vec::is_empty),
            "no additional grant may be sent before the receive turn ends"
        );

        sched.schedule_ready_packet_data_grant(first_window.next_grant_downlink);
        assert!(
            sched.dltx_queues[first_window.next_grant_downlink.t as usize - 1].iter().any(
                |elem| matches!(elem, DlSchedElem::Grant(_, grant) if grant.capacity_allocation == BasicSlotgrantCapAlloc::Grant17Slots)
            ),
            "the retained shortfall must progress without another MAC-ACCESS"
        );
        assert!(!sched.pending_packet_data_grants.contains_key(&addr.ssi));
    }

    #[test]
    fn fragment_continuation_precedes_an_ordinary_packet_request() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let ordinary = TetraAddress::issi(77_479);
        let fragment = TetraAddress::issi(77_480);
        let grant_time = TdmaTime { t: 2, f: 3, m: 1, h: 0 };
        assert!(sched.queue_packet_data_capacity_request(grant_time, ordinary, ReservationRequirement::Req3Slots, false));
        assert!(sched.queue_packet_data_capacity_request(grant_time, fragment, ReservationRequirement::Req3Slots, true));

        sched.schedule_ready_packet_data_grant(grant_time);
        assert!(matches!(
            sched.dltx_queues[grant_time.t as usize - 1].first(),
            Some(DlSchedElem::Grant(addr, _)) if addr.ssi == fragment.ssi && addr.ssi_type == fragment.ssi_type
        ));
    }

    #[test]
    fn queued_packet_downlink_limits_an_ordinary_uplink_turn_to_one_slot() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let addr = TetraAddress::issi(77_479);
        let grant_time = TdmaTime { t: 2, f: 3, m: 1, h: 0 };
        let slots = [false, true, true, true];
        sched.dl_enqueue_packet_tma_on_timeslot(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("10010000000000000"),
            None,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
            slots,
        );
        assert!(sched.queue_packet_data_capacity_request(grant_time, addr, ReservationRequirement::Req10Slots, false));

        sched.schedule_ready_packet_data_grant(grant_time);
        assert!(
            sched.dltx_queues[grant_time.t as usize - 1].iter().any(
                |elem| matches!(elem, DlSchedElem::Grant(_, grant) if grant.capacity_allocation == BasicSlotgrantCapAlloc::Grant1Slot)
            )
        );
        assert_eq!(sched.pending_packet_data_grants[&addr.ssi].remaining_slots, 9);
    }

    #[test]
    fn fragment_uplink_continuation_is_not_limited_by_waiting_downlink() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let addr = TetraAddress::issi(77_480);
        let grant_time = TdmaTime { t: 2, f: 3, m: 1, h: 0 };
        let slots = [false, true, true, true];
        sched.dl_enqueue_packet_tma_on_timeslot(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("10010000000000000"),
            None,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
            slots,
        );
        assert!(sched.queue_packet_data_capacity_request(grant_time, addr, ReservationRequirement::Req3Slots, true));

        sched.schedule_ready_packet_data_grant(grant_time);
        assert!(
            sched.dltx_queues[grant_time.t as usize - 1].iter().any(
                |elem| matches!(elem, DlSchedElem::Grant(_, grant) if grant.capacity_allocation == BasicSlotgrantCapAlloc::Grant3Slots)
            )
        );
    }

    #[test]
    fn pending_al_ack_request_precedes_an_ordinary_capacity_grant() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let addr = TetraAddress::issi(77_479);
        let grant_time = TdmaTime { t: 2, f: 3, m: 1, h: 0 };
        let slots = [false, true, true, true];
        sched.dl_enqueue_packet_tma_on_timeslot(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("10011100000000000"),
            Some(TxReporter::new()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
            slots,
        );
        assert!(sched.queue_packet_data_capacity_request(grant_time, addr, ReservationRequirement::Req3Slots, false));

        sched.schedule_ready_packet_data_grant(grant_time);
        assert!(
            sched
                .dltx_queues
                .iter()
                .flatten()
                .all(|elem| !matches!(elem, DlSchedElem::Grant(..))),
            "the AL-FINAL-AR must leave without a competing ordinary uplink grant"
        );
        assert!(sched.pending_packet_data_grants.contains_key(&addr.ssi));

        assert!(sched.queue_packet_data_capacity_request(grant_time, addr, ReservationRequirement::Req3Slots, true));
        sched.schedule_ready_packet_data_grant(grant_time);
        assert!(
            sched.dltx_queues[grant_time.t as usize - 1]
                .iter()
                .any(|elem| matches!(elem, DlSchedElem::Grant(..)))
        );
    }

    #[test]
    fn initial_packet_grant_waits_for_the_random_access_ack_timeslot() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let addr = TetraAddress::issi(77_479);
        let request_time = TdmaTime { t: 4, f: 3, m: 1, h: 0 };
        sched.dl_enqueue_random_access_ack(
            request_time.t,
            addr,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );
        assert!(sched.queue_packet_data_capacity_request(request_time, addr, ReservationRequirement::Req6Slots, false));

        sched.schedule_ready_packet_data_grant(request_time.forward_to_timeslot(2));
        assert!(
            !sched.dltx_queues[1].iter().any(|elem| matches!(elem, DlSchedElem::Grant(..))),
            "the grant must not get separated from its pending random-access acknowledgement"
        );
        sched.schedule_ready_packet_data_grant(request_time);
        assert!(sched.dltx_queues[3].iter().any(|elem| matches!(elem, DlSchedElem::Grant(..))));
    }

    #[test]
    fn clch_counts_for_grant_delay_but_not_as_full_slot_capacity() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b0010));
        let clch = TdmaTime { t: 2, f: 18, m: 5, h: 0 };
        assert!(clch.is_mandatory_clch());

        let (delay, slots) = sched
            .ul_find_grant_opportunity_from(clch, 2, 1, false, 0)
            .expect("the first usable slot after CLCH must be found");
        assert_eq!(delay, 1, "CLCH is one granting-delay opportunity");
        assert_eq!(slots, vec![clch.add_timeslots(4)]);
        assert!(!slots[0].is_mandatory_clch());
    }

    #[test]
    fn packet_downlink_waits_for_the_complete_basic_grant_interval() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b0110));
        let addr = TetraAddress::issi(77_479);
        let first_uplink = TdmaTime { t: 2, f: 4, m: 1, h: 0 };
        let last_uplink = first_uplink.add_timeslots(4);
        sched.ul_reserve_grant(addr.ssi, vec![first_uplink, first_uplink.add_timeslots(1), last_uplink], false);

        for offset in 1..=7 {
            assert!(
                sched.packet_data_downlink_is_blocked(addr.ssi, first_uplink.add_timeslots(offset)),
                "the complete grant, its internal gap and both switching guards must be blocked"
            );
        }
        assert!(!sched.packet_data_downlink_is_blocked(addr.ssi, first_uplink));
        assert!(!sched.packet_data_downlink_is_blocked(addr.ssi, first_uplink.add_timeslots(8)));

        let downlink = first_uplink.add_timeslots(4);

        let mut resource = BsChannelScheduler::dl_make_minimal_resource(&addr, None, false);
        resource.addr = None;
        resource.event_label = Some(9);
        sched.dltx_queues[1].push(DlSchedElem::Resource(
            resource,
            BitBuffer::from_bitstr("10010000"),
            None,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
            Some([false, true, true, false]),
        ));
        sched.dl_enqueue_random_access_ack(
            downlink.t,
            addr,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        assert_eq!(sched.dl_defer_packet_data_for_concurrent_uplink(downlink), 2);
        assert!(sched.dltx_queues[1].is_empty());
        assert_eq!(sched.dltx_half_duplex_queues[1].len(), 2);

        sched.requeue_half_duplex_deferred_before_newer_items(1);
        assert_eq!(sched.dltx_queues[1].len(), 2);
        assert!(sched.dltx_half_duplex_queues[1].is_empty());
    }

    #[test]
    fn anticipated_advanced_ack_grant_waits_one_multislot_frame() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let minimum_delay = sched.basic_grant_timeslots(2).len();

        let grant = sched
            .ul_process_cap_req_after(2, TetraAddress::issi(77_479), &ReservationRequirement::Req1Slot, minimum_delay)
            .expect("three-slot PDCH must leave enough AL-ACK processing time");

        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant1Slot);
        assert_eq!(grant.granting_delay, BasicSlotgrantGrantingDelay::DelayNOpportunities(3));
    }

    #[test]
    fn packet_al_final_ar_carries_anticipated_ack_grant() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let issi = 77_479;
        let mut resource = BsChannelScheduler::dl_make_minimal_resource(&TetraAddress::issi(issi), None, false);
        resource.addr = None;
        resource.event_label = Some(3);
        let sdu = BitBuffer::from_bitstr("10011100000000000");
        resource.update_len_and_fill_ind(sdu.get_len());
        sched.dl_enqueue_tma_on_timeslot(
            2,
            resource,
            sdu,
            Some(TxReporter::new()),
            AieRequest::clear(AieSubject::Individual { issi }, AieScope::MacResource),
        );

        let time = TdmaTime { t: 2, f: 3, m: 1, h: 0 };
        sched.cur_dltime = time;
        let mut block = sched
            .dl_build_block_from_signalling_schedule(time)
            .expect("AL-FINAL-AR must be scheduled");
        block.seek(0);
        let decoded = MacResource::from_bitbuf(&mut block).expect("MAC-RESOURCE must decode");
        let grant = decoded.slot_granting_element.expect("AL-FINAL-AR must contain a slot grant");

        assert_eq!(decoded.event_label, Some(3));
        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant1Slot);
        assert_eq!(grant.granting_delay, BasicSlotgrantGrantingDelay::DelayNOpportunities(3));
    }

    #[test]
    fn grant_beyond_basic_delay_range_waits_without_reserving() {
        let mut sched = get_testing_slotter();
        let timeslot = 4;
        sched.cur_dltime = TdmaTime { t: 3, f: 1, m: 1, h: 0 };
        let first_opportunity = sched.cur_dltime.forward_to_timeslot(timeslot);
        let mut occupied = 0;
        let mut first_unencodable = None;

        for dist in 0..MACSCHED_NUM_FRAMES {
            let candidate = first_opportunity.add_timeslots(dist as i32 * 4);
            if candidate.is_mandatory_clch() {
                continue;
            }
            if occupied == MAX_BASIC_SLOT_GRANT_DELAY + 1 {
                first_unencodable = Some(candidate);
                break;
            }
            let index = sched.ul_ts_to_sched_index(&candidate);
            sched.ulsched[timeslot as usize - 1][index] = TimeslotSchedule {
                ul1: Some(90_001),
                ul2: Some(90_001),
            };
            occupied += 1;
        }

        let first_unencodable = first_unencodable.expect("test schedule must contain a fifteenth ordinary opportunity");
        assert_eq!(occupied, MAX_BASIC_SLOT_GRANT_DELAY + 1);
        assert!(
            sched
                .ul_find_grant_opportunity(timeslot, 1, false)
                .is_some_and(|(skips, _)| skips > MAX_BASIC_SLOT_GRANT_DELAY)
        );

        let grant = sched.ul_process_cap_req(timeslot, TetraAddress::issi(77_468), &ReservationRequirement::Req1Slot);
        assert!(grant.is_none(), "an ordinary delay above 13 cannot be encoded in four bits");
        assert_eq!(
            sched.ul_get_slot_owner(first_unencodable, PhyBlockNum::Both),
            None,
            "an unadvertised future opportunity must not be reserved"
        );
    }

    #[test]
    fn test_active_uplink_uses_same_frame18_grant_delay() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        sched.create_circuit(
            Direction::Ul,
            Circuit {
                call_id: 1,
                direction: Direction::Ul,
                ts: 2,
                usage: 6,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );

        let grant = sched
            .ul_process_cap_req(
                2,
                TetraAddress {
                    ssi_type: SsiType::Issi,
                    ssi: 1234,
                },
                &ReservationRequirement::Req1Subslot,
            )
            .expect("active traffic channel must offer a FN18 capacity grant");

        assert_eq!(
            grant.granting_delay,
            BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity,
            "associated access A/B test must use zero delay"
        );
        let target = TdmaTime { t: 2, f: 18, m: 1, h: 0 };
        assert!(target.is_mandatory_clch());
        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::SecondSubslotGranted);
        assert_eq!(
            sched.ul_get_slot_owner(target, PhyBlockNum::Block1),
            None,
            "the predefined CLCH must retain the first FN18 subslot"
        );
        assert_eq!(
            sched.ul_get_slot_owner(target, PhyBlockNum::Block2),
            Some(1234),
            "the corresponding FN18 second subslot must be reserved for the granted MS"
        );
    }

    #[test]
    fn test_associated_ack_full_slot_waits_past_predefined_clch() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        sched.create_circuit(
            Direction::Ul,
            Circuit {
                call_id: 1,
                direction: Direction::Ul,
                ts: 2,
                usage: 6,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );
        sched.cur_dltime = TdmaTime { t: 1, f: 18, m: 5, h: 0 };

        let addr = TetraAddress::new(1234, SsiType::Issi);
        let clch = TdmaTime { t: 2, f: 18, m: 5, h: 0 };
        assert!(clch.is_mandatory_clch());
        assert!(
            sched.ul_prepare_associated_basic_link_ack_grant(2, addr).is_none(),
            "a traffic-mode BL-ACK must not share its full slot with CLCH"
        );
        assert_eq!(
            sched.ul_get_slot_owner(clch, PhyBlockNum::Both),
            None,
            "the predefined CLCH opportunity must remain unreserved"
        );

        sched.cur_dltime = TdmaTime { t: 1, f: 18, m: 6, h: 0 };
        let usable = TdmaTime { t: 2, f: 18, m: 6, h: 0 };
        assert!(!usable.is_mandatory_clch());
        let grant = sched
            .ul_prepare_associated_basic_link_ack_grant(2, addr)
            .expect("the next non-CLCH FN18 must provide a full-slot grant");
        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant1Slot);
        assert_eq!(
            sched.ul_get_slot_owner(usable, PhyBlockNum::Both),
            Some(1234),
            "both subslots must belong to the traffic-mode BL-ACK"
        );
    }

    #[test]
    fn test_associated_sacch_defers_for_mandatory_frame18_broadcast() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 1,
                    direction,
                    ts: 2,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress {
            ssi_type: SsiType::Issi,
            ssi: 1234,
        };
        let reporter = TxReporter::new();
        sched.dl_enqueue_associated_tma(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::new(0),
            Some(reporter),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        // In multiframe 1, frame 18 slot 2 is the mandatory BSCH position.
        let mandatory = TdmaTime { t: 2, f: 18, m: 1, h: 0 };
        assert!(mandatory.is_mandatory_bsch());
        sched.cur_dltime = mandatory.add_timeslots(-1);
        let mandatory_slot = sched.finalize_ts_for_tick();
        assert_eq!(mandatory_slot.blk1.unwrap().logical_channel, LogicalChannel::Bsch);
        assert_eq!(
            sched.assoc_dltx_queues[1].len(),
            1,
            "SACCH data must wait for the next usable control frame"
        );

        // Slot 2 in multiframe 2 has no mandatory BSCH/BNCH assignment.
        let usable = TdmaTime { t: 2, f: 18, m: 2, h: 0 };
        assert!(!usable.is_mandatory_bsch() && !usable.is_mandatory_bnch());
        sched.cur_dltime = usable.add_timeslots(-1);
        let usable_slot = sched.finalize_ts_for_tick();
        let blk1 = usable_slot.blk1.as_ref().expect("associated FN18 must contain SCH/F");
        assert_eq!(blk1.logical_channel, LogicalChannel::SchF);
        assert_eq!(usable_slot.ul_phy_chan, PhysicalChannel::Tp);
        let mut mac_block = blk1.mac_block.clone();
        mac_block.seek(0);
        let resource = MacResource::from_bitbuf(&mut mac_block).expect("valid associated FN18 resource");
        assert!(!resource.is_null_pdu(), "associated FN18 must not be replaced by a Null PDU");
        assert_eq!(
            resource.addr.map(|address| address.ssi),
            Some(addr.ssi),
            "associated FN18 grant must target the queued address"
        );
        assert!(
            resource.slot_granting_element.is_some(),
            "grant must be built at actual FN18 transmission time"
        );
        let grant = resource.slot_granting_element.expect("grant checked above");
        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant1Slot);
        assert_eq!(
            sched.ul_get_slot_owner(usable, PhyBlockNum::Both),
            Some(1234),
            "ACK reservation must follow the actual transmitted FN18 grant"
        );
        assert!(sched.assoc_dltx_queues[1].is_empty());
    }

    #[test]
    fn fragmented_associated_downlink_grants_ack_in_final_mac_end() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 37,
                    direction,
                    ts: 3,
                    usage: 40,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        let reporter = TxReporter::new();
        sched.dl_enqueue_associated_tma(
            3,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr(&"10".repeat(115)[..229]),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let first_time = TdmaTime { t: 3, f: 18, m: 3, h: 0 };
        assert!(!first_time.is_mandatory_bsch() && !first_time.is_mandatory_bnch());
        let mut first = sched
            .dl_build_associated_control_block(first_time)
            .expect("first associated fragment");
        first.seek(0);
        let resource = MacResource::from_bitbuf(&mut first).expect("fragmented MAC-RESOURCE");
        assert_eq!(
            resource.length_ind,
            tetra_pdus::umac::pdus::mac_resource::MAC_RESOURCE_LENGTH_FRAG_START
        );
        assert!(resource.slot_granting_element.is_none(), "the MS cannot acknowledge before MAC-END");
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert_eq!(sched.ul_get_slot_owner(first_time, PhyBlockNum::Block1), None);
        assert_eq!(sched.ul_get_slot_owner(first_time, PhyBlockNum::Block2), None);

        let mut final_time = first_time.add_timeslots(18 * 4);
        while final_time.is_mandatory_bsch() || final_time.is_mandatory_bnch() {
            final_time = final_time.add_timeslots(18 * 4);
        }
        let mut final_block = sched
            .dl_build_associated_control_block(final_time)
            .expect("final associated fragment");
        final_block.seek(0);
        let end = MacEndDl::from_bitbuf(&mut final_block).expect("MAC-END with acknowledgement grant");
        let grant = end.slot_granting_element.expect("final MAC-END must grant the BL-ACK response");
        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant1Slot);
        assert_eq!(sched.ul_get_slot_owner(final_time, PhyBlockNum::Both), Some(addr.ssi));
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);
        assert!(sched.assoc_dltx_queues[2].is_empty());
    }

    #[test]
    fn sc3_fragmented_sacch_roundtrip_keeps_mac_end_grant_clear() {
        use tetra_config::bluestation::{RuntimeSc3Aie, RuntimeSc3Dck, RuntimeSc3TeaAlgorithm, SharedConfig};
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let parsed_config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example BS configuration");
        let config = SharedConfig::from_parts(parsed_config, None);
        let addr = TetraAddress::issi(77_468);
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea3, 23, [0x6c; 10], true, false);
        sc3.install_dck(addr.ssi, RuntimeSc3Dck::new([0x47; 16], [0xd3; 10], true, None));
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let provider = BsAieKeyProvider::new(config);

        let mut sched = get_testing_slotter();
        sched.aie_provider = Some(provider.clone());
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 37,
                    direction,
                    ts: 3,
                    usage: 40,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let original_sdu_bits = &"10".repeat(115)[..229];
        let request = AieRequest::sc3(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        sched.dl_enqueue_associated_tma(
            3,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr(original_sdu_bits),
            Some(TxReporter::new()),
            request,
        );

        let first_time = TdmaTime { t: 3, f: 18, m: 3, h: 0 };
        assert!(!first_time.is_mandatory_bsch() && !first_time.is_mandatory_bnch());
        let mut first = sched
            .dl_build_associated_control_block(first_time)
            .expect("first encrypted associated fragment");

        // MAC-RESOURCE remains parseable before deciphering. Decipher only
        // its TM-SDU with the KSS for the actual first FN18 occurrence.
        first.seek(0);
        let first_resource = MacResource::from_bitbuf(&mut first).expect("clear MAC-RESOURCE header");
        assert_eq!(
            first_resource.length_ind,
            tetra_pdus::umac::pdus::mac_resource::MAC_RESOURCE_LENGTH_FRAG_START
        );
        assert_ne!(first_resource.encryption_mode, 0);
        let first_payload_start = first.get_raw_pos();
        let first_context = provider
            .resolve(request.with_scope(AieScope::MacResource), AieDirection::Downlink, first_time)
            .expect("first SC3 context");
        provider
            .cipher_downlink_mac(first_context, &mut first, first_payload_start, SCH_F_CAP - first_payload_start)
            .expect("decipher first fragment");
        first.set_raw_start(first_payload_start);
        let mut reconstructed = first.to_bitstr();

        let mut final_time = first_time.add_timeslots(18 * 4);
        while final_time.is_mandatory_bsch() || final_time.is_mandatory_bnch() {
            final_time = final_time.add_timeslots(18 * 4);
        }
        let mut final_block = sched.dl_build_associated_control_block(final_time).expect("encrypted MAC-END");

        // The complete MAC-END header, including its BL-ACK slot grant and
        // channel-allocation flag, must be usable while the TM-SDU is still
        // ciphered (EN 300 392-7 clause 6.7.1.2).
        final_block.seek(0);
        let end = MacEndDl::from_bitbuf(&mut final_block).expect("clear MAC-END header");
        let grant = end.slot_granting_element.expect("clear final BL-ACK grant");
        assert_eq!(grant.capacity_allocation, BasicSlotgrantCapAlloc::Grant1Slot);
        assert!(end.chan_alloc_element.is_none());
        let final_payload_start = final_block.get_raw_pos();
        let pdu_len_bits = end.length_ind as usize * 8;
        let fill_bits = if end.fill_bits {
            fillbits::removal::get_num_fill_bits(&final_block, pdu_len_bits, false)
        } else {
            0
        };
        let final_payload_len = pdu_len_bits - final_payload_start - fill_bits;
        let final_context = provider
            .resolve(request.with_scope(AieScope::MacFragment), AieDirection::Downlink, final_time)
            .expect("final SC3 context");
        provider
            .cipher_downlink_mac(final_context, &mut final_block, final_payload_start, final_payload_len)
            .expect("decipher final fragment");
        final_block.set_raw_end(final_payload_start + final_payload_len);
        final_block.set_raw_start(final_payload_start);
        reconstructed += &final_block.to_bitstr();

        assert_eq!(reconstructed, original_sdu_bits);
    }

    #[test]
    fn multislot_uplink_grant_precedes_and_downlink_keeps_sacch_until_mac_end() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 3;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 37,
                    direction,
                    ts: timeslot,
                    usage: 40,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        let reporter = TxReporter::new();
        let ordinary_addr = TetraAddress::new(92, SsiType::Gssi);
        let pending_uplink = TetraAddress::new(77_479, SsiType::Issi);

        // Reproduce the live remote-control response: the MS starts an uplink
        // fragment and asks for two more slots while other control and SDS
        // are waiting on the same SACCH.
        sched.dl_enqueue_associated_grant_request(timeslot, pending_uplink, ReservationRequirement::Req2Slots);
        sched.dl_enqueue_associated_tma(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&ordinary_addr, None, false),
            BitBuffer::from_bitstr("1010"),
            None,
            AieRequest::clear(AieSubject::Group { gssi: ordinary_addr.ssi }, AieScope::MacResource),
        );
        sched.dl_enqueue_associated_tma(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr(&"10".repeat(115)[..229]),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let first_time = TdmaTime {
            t: timeslot,
            f: 18,
            m: 3,
            h: 0,
        };
        assert!(!first_time.is_mandatory_bsch() && !first_time.is_mandatory_bnch());
        let mut grant_block = sched
            .dl_build_associated_control_block(first_time)
            .expect("multi-slot request must receive partial SACCH capacity");
        grant_block.seek(0);
        let grant_resource = MacResource::from_bitbuf(&mut grant_block).expect("partial grant MAC-RESOURCE");
        assert_eq!(grant_resource.addr.map(|address| address.ssi), Some(pending_uplink.ssi));
        assert_eq!(
            grant_resource
                .slot_granting_element
                .expect("multi-slot request must be granted one FN18 at a time")
                .capacity_allocation,
            BasicSlotgrantCapAlloc::Grant1Slot
        );
        assert_eq!(sched.ul_get_slot_owner(first_time, PhyBlockNum::Both), Some(pending_uplink.ssi));

        assert!(
            sched.assoc_dltx_queues[timeslot as usize - 1]
                .iter()
                .any(|item| matches!(item, DlSchedElem::AssociatedGrantRequest(_, ReservationRequirement::Req1Slot, 1)))
        );

        let mut second_grant_time = first_time.add_timeslots(18 * 4);
        while second_grant_time.is_mandatory_bsch() || second_grant_time.is_mandatory_bnch() {
            second_grant_time = second_grant_time.add_timeslots(18 * 4);
        }
        let mut second_grant_block = sched
            .dl_build_associated_control_block(second_grant_time)
            .expect("the remainder of a partial request must be granted without another MAC-ACCESS");
        second_grant_block.seek(0);
        let second_grant_resource = MacResource::from_bitbuf(&mut second_grant_block).expect("remaining grant MAC-RESOURCE");
        assert_eq!(second_grant_resource.addr.map(|address| address.ssi), Some(pending_uplink.ssi));
        assert_eq!(
            second_grant_resource
                .slot_granting_element
                .expect("remaining slot must be explicitly granted")
                .capacity_allocation,
            BasicSlotgrantCapAlloc::Grant1Slot
        );
        assert_eq!(
            sched.ul_get_slot_owner(second_grant_time, PhyBlockNum::Both),
            Some(pending_uplink.ssi)
        );

        let mut data_time = second_grant_time.add_timeslots(18 * 4);
        while data_time.is_mandatory_bsch() || data_time.is_mandatory_bnch() {
            data_time = data_time.add_timeslots(18 * 4);
        }
        let mut first = sched
            .dl_build_associated_control_block(data_time)
            .expect("acknowledged SDS must follow the complete uplink grant and precede unrelated group control");
        first.seek(0);
        let resource = MacResource::from_bitbuf(&mut first).expect("fragmented MAC-RESOURCE");
        assert_eq!(resource.addr.map(|address| address.ssi), Some(addr.ssi));
        assert_eq!(
            resource.length_ind,
            tetra_pdus::umac::pdus::mac_resource::MAC_RESOURCE_LENGTH_FRAG_START
        );
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert!(matches!(
            sched.assoc_dltx_queues[timeslot as usize - 1].first(),
            Some(DlSchedElem::FragBuf(..))
        ));

        // Even newly queued acknowledged data must not interrupt an active
        // reconstruction chain on this SACCH.
        let later_addr = TetraAddress::new(77_480, SsiType::Issi);
        sched.dl_enqueue_associated_tma(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&later_addr, None, false),
            BitBuffer::from_bitstr(&"01".repeat(115)[..229]),
            Some(TxReporter::new()),
            AieRequest::clear(AieSubject::Individual { issi: later_addr.ssi }, AieScope::MacResource),
        );

        let mut final_time = data_time.add_timeslots(18 * 4);
        while final_time.is_mandatory_bsch() || final_time.is_mandatory_bnch() {
            final_time = final_time.add_timeslots(18 * 4);
        }
        let mut final_block = sched
            .dl_build_associated_control_block(final_time)
            .expect("active fragment must finish at the next usable SACCH");
        final_block.seek(0);
        let end = MacEndDl::from_bitbuf(&mut final_block).expect("continuation must be MAC-END");
        assert_eq!(
            end.slot_granting_element
                .expect("final fragment must carry the BL-ACK grant")
                .capacity_allocation,
            BasicSlotgrantCapAlloc::Grant1Slot
        );
        assert_eq!(sched.ul_get_slot_owner(final_time, PhyBlockNum::Both), Some(addr.ssi));
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);
    }

    #[test]
    fn closing_assigned_link_discards_queued_associated_control() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 2;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 7,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        let reporter = TxReporter::new();
        sched.dl_enqueue_associated_tma(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::new(0),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        // The associated link still exists while one circuit direction is
        // active, so closing only DL must not discard its queued control.
        assert!(sched.close_circuit(Direction::Dl, timeslot).is_some());
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert_eq!(sched.assoc_dltx_queues[timeslot as usize - 1].len(), 1);

        // Closing the last direction removes the associated basic link.  The
        // queued PDU must be reported to LLC instead of becoming immortal.
        assert!(sched.close_circuit(Direction::Ul, timeslot).is_some());
        assert_eq!(reporter.get_state(), tetra_core::TxState::Discarded);
        assert!(sched.assoc_dltx_queues[timeslot as usize - 1].is_empty());
    }

    #[test]
    fn entering_hangtime_finishes_fragmented_sds_on_facch() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 3;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 41,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        let reporter = TxReporter::new();
        sched.dl_enqueue_associated_tma(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr(&"10".repeat(115)[..229]),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let first = TdmaTime {
            t: timeslot,
            f: 18,
            m: 3,
            h: 0,
        };
        let mut first_block = sched.dl_build_associated_control_block(first).expect("first SACCH fragment");
        first_block.seek(0);
        assert_eq!(
            MacResource::from_bitbuf(&mut first_block).expect("fragment start").length_ind,
            tetra_pdus::umac::pdus::mac_resource::MAC_RESOURCE_LENGTH_FRAG_START
        );
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);

        sched.set_hangtime(timeslot, true);
        assert!(sched.assoc_dltx_queues[timeslot as usize - 1].is_empty());
        assert!(matches!(
            sched.dltx_queues[timeslot as usize - 1].first(),
            Some(DlSchedElem::FragBuf(..))
        ));

        let facch_time = TdmaTime {
            t: timeslot,
            f: 5,
            m: 4,
            h: 0,
        };
        sched.cur_dltime = facch_time.add_timeslots(-1);
        let slot = sched.finalize_ts_for_tick();
        assert_eq!(slot.ul_phy_chan, PhysicalChannel::Cp);
        let mut final_block = slot.blk1.expect("final FACCH fragment").mac_block;
        final_block.seek(0);
        assert!(
            MacEndDl::from_bitbuf(&mut final_block)
                .expect("MAC-END on FACCH")
                .slot_granting_element
                .is_some()
        );
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);
    }

    #[test]
    fn full_hangtime_uplink_schedule_defers_all_pending_signalling() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 3;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 45,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(timeslot, true);

        // Force every ordinary uplink grant opportunity to be occupied. The
        // reliable resource cannot be sent until a BL-ACK slot is available.
        for slot in &mut sched.ulsched[timeslot as usize - 1] {
            slot.ul1 = Some(90_001);
            slot.ul2 = Some(90_001);
        }

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        let reporter = TxReporter::new();
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("10101010"),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&TetraAddress::issi(77_479), None, false),
            BitBuffer::from_bitstr("01010101"),
            None,
            AieRequest::clear(AieSubject::Individual { issi: 77_479 }, AieScope::MacResource),
        );

        let facch_time = TdmaTime {
            t: timeslot,
            f: 5,
            m: 4,
            h: 0,
        };
        sched.cur_dltime = facch_time.add_timeslots(-1);
        let _ = sched.finalize_ts_for_tick();

        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert_eq!(sched.dltx_queues[timeslot as usize - 1].len(), 2);
        assert!(sched.dltx_next_slot_queue.is_empty());
    }

    #[test]
    fn full_facch_block_defers_unstarted_ack_delivery_without_panicking() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 3;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 46,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(timeslot, true);

        // Reproduce the live crash: a group setup fills the FACCH block, then
        // an acknowledged individual delivery is considered in the same
        // scheduler pass but cannot write even its MAC-RESOURCE header.
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&TetraAddress::new(92, SsiType::Gssi), None, false),
            BitBuffer::from_bitstr(&"10".repeat(160)),
            None,
            AieRequest::clear(AieSubject::Group { gssi: 92 }, AieScope::MacResource),
        );
        let addr = TetraAddress::new(430_892, SsiType::Issi);
        let reporter = TxReporter::new();
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("10101010"),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let first_time = TdmaTime {
            t: timeslot,
            f: 5,
            m: 4,
            h: 0,
        };
        sched.cur_dltime = first_time.add_timeslots(-1);
        let _ = sched.finalize_ts_for_tick();
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert!(
            sched.dltx_queues[timeslot as usize - 1]
                .iter()
                .any(|elem| matches!(elem, DlSchedElem::FragBuf(fragger, _) if !fragger.has_started())),
            "the untouched individual resource must remain queued"
        );

        let second_time = first_time.add_timeslots(4);
        sched.cur_dltime = second_time.add_timeslots(-1);
        let _ = sched.finalize_ts_for_tick();
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);
    }

    #[test]
    fn packet_advanced_segment_waits_for_empty_sch_f_block() {
        let mut sched = get_testing_slotter();
        let timeslot = 2;
        let addr = TetraAddress::issi(77_468);
        let aie = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);

        // Deliberately enqueue packet data first.  Ordinary control still has
        // formatter priority and consumes part of this block.
        let advanced = BitBuffer::from_bitstr(&format!("1001{}", "0".repeat(221)));
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            advanced,
            None,
            aie,
        );
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr("00010000"),
            None,
            aie,
        );

        let time = TdmaTime {
            h: 0,
            m: 1,
            f: 1,
            t: timeslot,
        };
        assert!(sched.dl_build_block_from_signalling_schedule(time).is_some());
        assert!(sched.dltx_next_slot_queue.is_empty());
        assert_eq!(sched.dltx_queues[timeslot as usize - 1].len(), 1);
        assert!(
            sched.dltx_queues[timeslot as usize - 1][0].is_original_advanced_data(),
            "the AL segment must remain intact for an empty next SCH/F block"
        );
        assert!(
            !matches!(sched.dltx_queues[timeslot as usize - 1][0], DlSchedElem::FragBuf(..)),
            "the AL segment must not start a MAC fragment chain in residual capacity"
        );
    }

    #[test]
    fn packet_fragment_continues_on_next_assigned_pdch() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b0110));
        let slots = [false, true, true, false];
        let addr = TetraAddress::issi(77_468);
        let aie = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        sched.dl_enqueue_packet_tma_on_timeslot(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr(&"0".repeat(SCH_F_CAP * 2)),
            None,
            aie,
            slots,
        );

        let time = TdmaTime { h: 0, m: 1, f: 1, t: 2 };
        assert!(sched.dl_build_block_from_signalling_schedule(time).is_some());
        assert!(sched.dltx_queues[1].is_empty());
        assert!(matches!(
            sched.dltx_queues[2].first(),
            Some(DlSchedElem::FragBuf(_, Some(found))) if *found == slots
        ));
    }

    #[test]
    fn multislot_al_segments_wait_for_their_predecessor_and_then_use_each_pdch() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let slots = [false, true, true, true];
        let addr = TetraAddress::issi(77_468);
        let aie = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        let segment = |ss: u8| BitBuffer::from_bitstr(&format!("100100000{:08b}{}", ss, "0".repeat(32)));
        sched.dl_enqueue_packet_tma_on_timeslot(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            segment(0),
            None,
            aie,
            slots,
        );
        sched.dl_enqueue_packet_tma_on_timeslot(
            3,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            segment(1),
            None,
            aie,
            slots,
        );
        sched.dl_enqueue_packet_tma_on_timeslot(
            4,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            segment(2),
            None,
            aie,
            slots,
        );

        assert_eq!(
            BsChannelScheduler::sched_elem_advanced_link_sequence(&sched.dltx_queues[1][0]),
            Some((addr.ssi, 0, 0))
        );
        assert!(sched.has_earlier_pending_advanced_link_segment(addr.ssi, 0, 1));
        // TS3 must not bypass S(S)=0 while TS2 still owns it.
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 3 })
                .is_none()
        );
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 2 })
                .is_some()
        );
        assert!(sched.dltx_queues[1].is_empty());

        // Once S(S)=0 has left TS2, the next physical slots deliver S(S)=1
        // and S(S)=2 without waiting for another TDMA frame.
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 3 })
                .is_some()
        );
        assert!(sched.dltx_queues[2].is_empty());
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 4 })
                .is_some()
        );
        assert!(sched.dltx_queues[3].is_empty());
    }

    #[test]
    fn multislot_al_batch_finishes_an_older_ns_before_a_newer_ns() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));
        let slots = [false, true, true, true];
        let addr = TetraAddress::issi(77_468);
        let aie = AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource);
        let segment = |ns: u8, ss: u8| BitBuffer::from_bitstr(&format!("100100{ns:03b}{ss:08b}{}", "0".repeat(32)));

        for (timeslot, ns, ss) in [(2, 0, 0), (3, 0, 1), (4, 1, 0)] {
            sched.dl_enqueue_packet_tma_on_timeslot(
                timeslot,
                BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
                segment(ns, ss),
                None,
                aie,
                slots,
            );
        }

        // The later N(S) must not start while the older TL-SDU remains in
        // the queue on another PDCH. The only reserved uplink turn follows
        // the full N.272 batch, not each individual TL-SDU.
        assert!(sched.has_earlier_pending_advanced_link_segment(addr.ssi, 1, 0));
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 4 })
                .is_none()
        );
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 2 })
                .is_some()
        );
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 3 })
                .is_some()
        );
        assert!(
            sched
                .dl_build_block_from_signalling_schedule(TdmaTime { h: 0, m: 1, f: 1, t: 4 })
                .is_some()
        );
    }

    #[test]
    fn blocked_al_segment_does_not_hide_another_links_ready_segment() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b0110));
        let slots = [false, true, true, false];
        let first = TetraAddress::issi(77_468);
        let second = TetraAddress::issi(77_479);
        let segment = |ss: u8| BitBuffer::from_bitstr(&format!("100100000{:08b}{}", ss, "0".repeat(32)));
        for (timeslot, addr, ss) in [(2, first, 0), (3, first, 1), (3, second, 0)] {
            sched.dl_enqueue_packet_tma_on_timeslot(
                timeslot,
                BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
                segment(ss),
                None,
                AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
                slots,
            );
        }

        let current = TdmaTime { h: 0, m: 1, f: 1, t: 3 };
        assert!(sched.dl_build_block_from_signalling_schedule(current).is_some());
        let remaining: Vec<(u32, u8)> = sched.dltx_queues[2]
            .iter()
            .filter_map(BsChannelScheduler::sched_elem_advanced_link_sequence)
            .map(|(issi, _, ss)| (issi, ss))
            .collect();
        assert_eq!(remaining, vec![(first.ssi, 1)]);
    }

    #[test]
    fn resuming_traffic_finishes_fragmented_sds_on_sacch() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 2;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 42,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(timeslot, true);

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        let reporter = TxReporter::new();
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::from_bitstr(&"10".repeat(115)[..229]),
            Some(reporter.clone()),
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let facch_time = TdmaTime {
            t: timeslot,
            f: 5,
            m: 2,
            h: 0,
        };
        sched.cur_dltime = facch_time.add_timeslots(-1);
        let first_slot = sched.finalize_ts_for_tick();
        let mut first_block = first_slot.blk1.expect("first FACCH fragment").mac_block;
        first_block.seek(0);
        assert_eq!(
            MacResource::from_bitbuf(&mut first_block).expect("fragment start").length_ind,
            tetra_pdus::umac::pdus::mac_resource::MAC_RESOURCE_LENGTH_FRAG_START
        );
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);

        sched.set_hangtime(timeslot, false);
        assert!(sched.dltx_queues[timeslot as usize - 1].is_empty());
        assert!(matches!(
            sched.assoc_dltx_queues[timeslot as usize - 1].first(),
            Some(DlSchedElem::FragBuf(..))
        ));

        let sacch_time = (2..=18)
            .map(|m| TdmaTime {
                t: timeslot,
                f: 18,
                m,
                h: 0,
            })
            .find(|time| !time.is_mandatory_bsch() && !time.is_mandatory_bnch())
            .expect("usable SACCH frame");
        sched.cur_dltime = sacch_time.add_timeslots(-1);
        let final_slot = sched.finalize_ts_for_tick();
        assert_eq!(final_slot.ul_phy_chan, PhysicalChannel::Tp);
        let mut final_block = final_slot.blk1.expect("final SACCH fragment").mac_block;
        final_block.seek(0);
        let end = MacEndDl::from_bitbuf(&mut final_block).expect("MAC-END on SACCH");
        assert!(end.slot_granting_element.is_some());
        assert_eq!(reporter.get_state(), tetra_core::TxState::Transmitted);
    }

    #[test]
    fn resuming_traffic_preserves_unstarted_sds_and_access_ack() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 2;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 43,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(timeslot, true);

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        sched.dl_enqueue_tma_on_timeslot(
            timeslot,
            BsChannelScheduler::dl_make_minimal_resource(&addr, None, false),
            BitBuffer::new(0),
            None,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );
        sched.dl_enqueue_random_access_ack(
            timeslot,
            addr,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        sched.set_hangtime(timeslot, false);
        assert!(sched.dltx_queues[timeslot as usize - 1].is_empty());
        let Some(DlSchedElem::Resource(resource, ..)) = sched.assoc_dltx_queues[timeslot as usize - 1].first() else {
            panic!("SDS resource must move to SACCH");
        };
        assert!(
            resource.random_access_flag,
            "the correlated MAC-ACCESS acknowledgement must move with the resource"
        );
    }

    #[test]
    fn entering_hangtime_rehomes_pending_associated_capacity_request() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let timeslot = 3;
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 44,
                    direction,
                    ts: timeslot,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress::new(77_468, SsiType::Issi);
        sched.dl_enqueue_associated_grant_request(timeslot, addr, ReservationRequirement::Req1Subslot);
        sched.set_hangtime(timeslot, true);
        assert!(sched.assoc_dltx_queues[timeslot as usize - 1].is_empty());
        assert!(matches!(
            sched.dltx_queues[timeslot as usize - 1].first(),
            Some(DlSchedElem::AssociatedGrantRequest(..))
        ));

        let facch_time = TdmaTime {
            t: timeslot,
            f: 5,
            m: 2,
            h: 0,
        };
        sched.cur_dltime = facch_time.add_timeslots(-1);
        let slot = sched.finalize_ts_for_tick();
        let mut block = slot.blk1.expect("FACCH grant response").mac_block;
        block.seek(0);
        let resource = MacResource::from_bitbuf(&mut block).expect("grant MAC-RESOURCE");
        assert_eq!(resource.addr.map(|address| address.ssi), Some(addr.ssi));
        assert!(resource.slot_granting_element.is_some());
        assert!(sched.dltx_queues[timeslot as usize - 1].is_empty());
    }

    #[test]
    fn best_effort_associated_repeat_waits_for_normal_control_and_coalesces() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 7,
                    direction,
                    ts: 2,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let repeated_group = TetraAddress::new(91, SsiType::Gssi);
        for _ in 0..2 {
            sched.dl_enqueue_associated_best_effort_tma(
                2,
                9,
                BsChannelScheduler::dl_make_minimal_resource(&repeated_group, None, false),
                BitBuffer::new(0),
                AieRequest::clear(AieSubject::Group { gssi: repeated_group.ssi }, AieScope::MacResource),
            );
        }
        assert_eq!(sched.assoc_best_effort_queues[1].len(), 1, "same periodic call must be coalesced");

        let sds_addr = TetraAddress::new(77_468, SsiType::Issi);
        sched.dl_enqueue_associated_tma(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&sds_addr, None, false),
            BitBuffer::new(0),
            None,
            AieRequest::clear(AieSubject::Individual { issi: sds_addr.ssi }, AieScope::MacResource),
        );

        let first = TdmaTime { t: 2, f: 18, m: 2, h: 0 };
        assert!(!first.is_mandatory_bsch() && !first.is_mandatory_bnch());
        sched.cur_dltime = first.add_timeslots(-1);
        let first_slot = sched.finalize_ts_for_tick();
        let mut first_bits = first_slot.blk1.expect("associated control").mac_block;
        first_bits.seek(0);
        let first_resource = MacResource::from_bitbuf(&mut first_bits).expect("normal control resource");
        assert_eq!(first_resource.addr.map(|addr| addr.ssi), Some(sds_addr.ssi));
        assert_eq!(
            sched.assoc_best_effort_queues[1].len(),
            1,
            "best effort must remain queued behind SDS"
        );

        let second = (3..=18)
            .map(|m| TdmaTime { t: 2, f: 18, m, h: 0 })
            .find(|time| !time.is_mandatory_bsch() && !time.is_mandatory_bnch())
            .expect("another usable FN18");
        sched.cur_dltime = second.add_timeslots(-1);
        let second_slot = sched.finalize_ts_for_tick();
        let mut second_bits = second_slot.blk1.expect("best-effort control").mac_block;
        second_bits.seek(0);
        let second_resource = MacResource::from_bitbuf(&mut second_bits).expect("best-effort control resource");
        assert_eq!(second_resource.addr.map(|addr| addr.ssi), Some(repeated_group.ssi));
        assert!(sched.assoc_best_effort_queues[1].is_empty());
    }

    #[test]
    fn best_effort_associated_repeat_uses_hangtime_frame() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 7,
                    direction,
                    ts: 3,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(3, true);

        let repeated_group = TetraAddress::new(92, SsiType::Gssi);
        sched.dl_enqueue_associated_best_effort_tma(
            3,
            10,
            BsChannelScheduler::dl_make_minimal_resource(&repeated_group, None, false),
            BitBuffer::new(0),
            AieRequest::clear(AieSubject::Group { gssi: repeated_group.ssi }, AieScope::MacResource),
        );

        let time = TdmaTime { t: 3, f: 5, m: 2, h: 0 };
        sched.cur_dltime = time.add_timeslots(-1);
        let slot = sched.finalize_ts_for_tick();
        assert_eq!(slot.blk1.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::SchF));
        let mut bits = slot.blk1.expect("hangtime control").mac_block;
        bits.seek(0);
        let resource = MacResource::from_bitbuf(&mut bits).expect("hangtime best-effort resource");
        assert_eq!(resource.addr.map(|addr| addr.ssi), Some(repeated_group.ssi));
        assert!(sched.assoc_best_effort_queues[2].is_empty());
    }

    #[test]
    fn frame18_broadcast_waits_for_free_tch_fn18_and_ordinary_signalling() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 7,
                    direction,
                    ts: 2,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(2, true);

        let broadcast_addr = TetraAddress::new(0x00ff_ffff, SsiType::Gssi);
        for _ in 0..2 {
            sched.dl_enqueue_associated_frame18_broadcast(
                2,
                BsChannelScheduler::dl_make_minimal_resource(&broadcast_addr, None, false),
                BitBuffer::new(0),
                AieRequest::clear(AieSubject::Group { gssi: broadcast_addr.ssi }, AieScope::MacResource),
            );
        }
        assert_eq!(
            sched.assoc_best_effort_queues[1].len(),
            1,
            "pending network broadcasts must be coalesced"
        );

        // Even though hangtime makes frames 1..17 available for signalling,
        // this class is restricted to FN18.
        let non_fn18 = TdmaTime { t: 2, f: 5, m: 1, h: 0 };
        sched.cur_dltime = non_fn18.add_timeslots(-1);
        let non_fn18_slot = sched.finalize_ts_for_tick();
        let mut non_fn18_bits = non_fn18_slot.blk1.expect("hangtime idle control").mac_block;
        non_fn18_bits.seek(0);
        let non_fn18_resource = MacResource::from_bitbuf(&mut non_fn18_bits).expect("hangtime null resource");
        assert!(non_fn18_resource.addr.is_none());
        assert_eq!(sched.assoc_best_effort_queues[1].len(), 1);

        // MN1/TS2 is a mandatory BSCH occurrence, not a free associated slot.
        let mandatory = TdmaTime { t: 2, f: 18, m: 1, h: 0 };
        assert!(mandatory.is_mandatory_bsch() || mandatory.is_mandatory_bnch());
        sched.cur_dltime = mandatory.add_timeslots(-1);
        let mandatory_slot = sched.finalize_ts_for_tick();
        assert_eq!(
            mandatory_slot.blk1.as_ref().map(|block| block.logical_channel),
            Some(LogicalChannel::Bsch)
        );
        assert_eq!(sched.assoc_best_effort_queues[1].len(), 1);

        // An ordinary associated SDS resource owns the first free FN18 and
        // leaves the broadcast queued.
        let sds_addr = TetraAddress::new(77_468, SsiType::Issi);
        sched.dl_enqueue_associated_tma(
            2,
            BsChannelScheduler::dl_make_minimal_resource(&sds_addr, None, false),
            BitBuffer::new(0),
            None,
            AieRequest::clear(AieSubject::Individual { issi: sds_addr.ssi }, AieScope::MacResource),
        );
        let first_free = TdmaTime { t: 2, f: 18, m: 2, h: 0 };
        assert!(!first_free.is_mandatory_bsch() && !first_free.is_mandatory_bnch());
        sched.cur_dltime = first_free.add_timeslots(-1);
        let sds_slot = sched.finalize_ts_for_tick();
        let mut sds_bits = sds_slot.blk1.expect("ordinary associated FN18 control").mac_block;
        sds_bits.seek(0);
        let sds_resource = MacResource::from_bitbuf(&mut sds_bits).expect("SDS MAC-RESOURCE");
        assert_eq!(sds_resource.addr.map(|addr| addr.ssi), Some(sds_addr.ssi));
        assert_eq!(sched.assoc_best_effort_queues[1].len(), 1);

        let second_free = TdmaTime { t: 2, f: 18, m: 4, h: 0 };
        assert!(!second_free.is_mandatory_bsch() && !second_free.is_mandatory_bnch());
        sched.cur_dltime = second_free.add_timeslots(-1);
        let broadcast_slot = sched.finalize_ts_for_tick();
        let mut broadcast_bits = broadcast_slot.blk1.expect("network broadcast FN18 control").mac_block;
        broadcast_bits.seek(0);
        let broadcast_resource = MacResource::from_bitbuf(&mut broadcast_bits).expect("broadcast MAC-RESOURCE");
        assert_eq!(broadcast_resource.addr.map(|addr| addr.ssi), Some(broadcast_addr.ssi));
        assert!(sched.assoc_best_effort_queues[1].is_empty());
    }

    #[test]
    fn frame18_broadcast_waits_for_pdch_downlink() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(83, 1, 0b0100));
        assert_eq!(sched.active_assigned_channels(), vec![3]);

        let broadcast_addr = TetraAddress::new(0x00ff_ffff, SsiType::Gssi);
        sched.dl_enqueue_associated_frame18_broadcast(
            3,
            BsChannelScheduler::dl_make_minimal_resource(&broadcast_addr, None, false),
            BitBuffer::new(0),
            AieRequest::clear(AieSubject::Group { gssi: broadcast_addr.ssi }, AieScope::MacResource),
        );

        let data_addr = TetraAddress::new(77_479, SsiType::Issi);
        sched.dl_enqueue_packet_tma_on_timeslot(
            3,
            BsChannelScheduler::dl_make_minimal_resource(&data_addr, None, false),
            BitBuffer::new(0),
            None,
            AieRequest::clear(AieSubject::Individual { issi: data_addr.ssi }, AieScope::MacResource),
            [false, false, true, false],
        );

        // Frame 18 has no ordinary PDCH resource scheduling.  A pending
        // packet downlink still blocks an all-MS broadcast here, so it is
        // delivered first in the next PDCH opportunity.
        let first_free = TdmaTime { t: 3, f: 18, m: 1, h: 0 };
        assert!(!first_free.is_mandatory_bsch() && !first_free.is_mandatory_bnch());
        sched.cur_dltime = first_free.add_timeslots(-1);
        let _frame18_slot = sched.finalize_ts_for_tick();
        assert_eq!(sched.assoc_best_effort_queues[2].len(), 1);
        assert_eq!(sched.dltx_queues[2].len(), 1);

        let data_time = TdmaTime { t: 3, f: 1, m: 2, h: 0 };
        sched.cur_dltime = data_time.add_timeslots(-1);
        let data_slot = sched.finalize_ts_for_tick();
        let mut data_bits = data_slot.blk1.expect("pending PDCH downlink").mac_block;
        data_bits.seek(0);
        let data_resource = MacResource::from_bitbuf(&mut data_bits).expect("PDCH MAC-RESOURCE");
        assert_eq!(data_resource.addr.map(|addr| addr.ssi), Some(data_addr.ssi));
        assert!(sched.dltx_queues[2].is_empty());

        let second_free = TdmaTime { t: 3, f: 18, m: 3, h: 0 };
        assert!(!second_free.is_mandatory_bsch() && !second_free.is_mandatory_bnch());
        sched.cur_dltime = second_free.add_timeslots(-1);
        let broadcast_slot = sched.finalize_ts_for_tick();
        let mut broadcast_bits = broadcast_slot.blk1.expect("PDCH network broadcast FN18 control").mac_block;
        broadcast_bits.seek(0);
        let broadcast_resource = MacResource::from_bitbuf(&mut broadcast_bits).expect("broadcast MAC-RESOURCE");
        assert_eq!(broadcast_resource.addr.map(|addr| addr.ssi), Some(broadcast_addr.ssi));
        assert!(sched.assoc_best_effort_queues[2].is_empty());
    }

    #[test]
    fn ordinary_hangtime_control_cancels_partial_best_effort_repeat() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 7,
                    direction,
                    ts: 3,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }
        sched.set_hangtime(3, true);

        let repeated_group = TetraAddress::new(92, SsiType::Gssi);
        let long_sdu = BitBuffer::from_bitstr(&"1".repeat(SCH_F_CAP * 2));
        sched.dl_enqueue_associated_best_effort_tma(
            3,
            10,
            BsChannelScheduler::dl_make_minimal_resource(&repeated_group, None, false),
            long_sdu,
            AieRequest::clear(AieSubject::Group { gssi: repeated_group.ssi }, AieScope::MacResource),
        );

        let first = TdmaTime { t: 3, f: 5, m: 2, h: 0 };
        sched.cur_dltime = first.add_timeslots(-1);
        let first_slot = sched.finalize_ts_for_tick();
        assert!(first_slot.blk1.is_some());
        assert!(matches!(
            sched.assoc_best_effort_queues[2].first(),
            Some(AssociatedBestEffortElem {
                kind: AssociatedBestEffortKind::CallRepeat(10),
                elem: DlSchedElem::FragBuf(..),
            })
        ));

        let sds_addr = TetraAddress::new(77_468, SsiType::Issi);
        sched.dl_enqueue_tma_on_timeslot(
            3,
            BsChannelScheduler::dl_make_minimal_resource(&sds_addr, None, false),
            BitBuffer::new(0),
            None,
            AieRequest::clear(AieSubject::Individual { issi: sds_addr.ssi }, AieScope::MacResource),
        );

        let second = first.add_timeslots(4);
        sched.cur_dltime = second.add_timeslots(-1);
        let second_slot = sched.finalize_ts_for_tick();
        let mut bits = second_slot.blk1.expect("ordinary hangtime control").mac_block;
        bits.seek(0);
        let resource = MacResource::from_bitbuf(&mut bits).expect("ordinary control resource");
        assert_eq!(resource.addr.map(|addr| addr.ssi), Some(sds_addr.ssi));
        assert!(
            sched.assoc_best_effort_queues[2].is_empty(),
            "a MAC-RESOURCE between MAC-FRAG and MAC-END must discard the expendable chain"
        );
    }

    #[test]
    fn test_associated_grant_request_reserves_after_actual_fn18() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        for direction in [Direction::Dl, Direction::Ul] {
            sched.create_circuit(
                direction,
                Circuit {
                    call_id: 1,
                    direction,
                    ts: 2,
                    usage: 6,
                    circuit_mode: CircuitModeType::TchS,
                    speech_service: Some(0),
                    etee_encrypted: false,
                },
            );
        }

        let addr = TetraAddress::new(1234, SsiType::Issi);
        sched.dl_enqueue_associated_grant_request(2, addr, ReservationRequirement::Req1Subslot);

        // The first candidate FN18 is mandatory BSCH. The request must stay
        // queued and must not reserve the target based on this skipped frame.
        let mandatory = TdmaTime { t: 2, f: 18, m: 1, h: 0 };
        assert!(mandatory.is_mandatory_bsch());
        sched.cur_dltime = mandatory.add_timeslots(-1);
        let mandatory_slot = sched.finalize_ts_for_tick();
        assert_eq!(mandatory_slot.blk1.unwrap().logical_channel, LogicalChannel::Bsch);
        assert_eq!(sched.assoc_dltx_queues[1].len(), 1);
        assert_eq!(
            sched.ul_get_slot_owner(mandatory.add_timeslots(18 * 4), PhyBlockNum::Block1),
            None,
            "a deferred request must not reserve from the skipped FN18"
        );

        // The next usable FN18 carries the grant and is reserved immediately
        // for the MS because the grant uses zero delay.
        let usable = TdmaTime { t: 2, f: 18, m: 2, h: 0 };
        sched.cur_dltime = usable.add_timeslots(-1);
        let usable_slot = sched.finalize_ts_for_tick();
        let blk1 = usable_slot.blk1.as_ref().expect("associated FN18 must contain SCH/F");
        let mut mac_block = blk1.mac_block.clone();
        mac_block.seek(0);
        let resource = MacResource::from_bitbuf(&mut mac_block).expect("valid associated grant resource");
        assert!(
            !resource.is_null_pdu(),
            "associated FN18 grant must not be overwritten by a Null PDU"
        );
        assert_eq!(
            resource.addr.map(|address| address.ssi),
            Some(addr.ssi),
            "associated FN18 grant must target the queued address"
        );
        let grant = resource.slot_granting_element.expect("grant must be built at actual FN18");
        let target = usable;
        let target_block = match grant.capacity_allocation {
            BasicSlotgrantCapAlloc::FirstSubslotGranted => PhyBlockNum::Block1,
            BasicSlotgrantCapAlloc::SecondSubslotGranted => PhyBlockNum::Block2,
            allocation => panic!("unexpected associated half-slot allocation: {:?}", allocation),
        };
        assert_eq!(
            sched.ul_get_slot_owner(target, target_block),
            Some(1234),
            "reservation must follow the FN18 that actually carried the grant"
        );
        assert!(sched.assoc_dltx_queues[1].is_empty());
    }

    #[test]
    fn test_dl_grant_and_ack_integration() {
        let mut sched = get_testing_slotter();
        let ts = TdmaTime::default();
        let addr = TetraAddress {
            ssi_type: SsiType::Issi,
            ssi: 1234,
        };
        let pdu = BsChannelScheduler::dl_make_minimal_resource(&addr, None, false);
        let sdu = BitBuffer::new(0);
        sched.dl_enqueue_tma(
            pdu,
            sdu,
            None,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        let grant = BasicSlotgrant {
            capacity_allocation: BasicSlotgrantCapAlloc::FirstSubslotGranted,
            granting_delay: BasicSlotgrantGrantingDelay::CapAllocAtNextOpportunity,
        };

        sched.dl_enqueue_grant(ts.t, addr, grant);
        sched.dl_enqueue_random_access_ack(
            ts.t,
            addr,
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacResource),
        );

        sched.dump_ul_schedule(true);
        sched.dump_dl_queue();

        assert!(sched.dltx_queues[ts.t as usize - 1].len() == 3);

        tracing::info!("Integrating queue");
        sched.dl_integrate_sched_elems_for_timeslot(ts);

        sched.dump_ul_schedule(true);
        sched.dump_dl_queue();

        assert!(sched.dltx_queues[ts.t as usize - 1].len() == 1);
    }

    fn decode_aach(sched: &BsChannelScheduler, ts: TdmaTime) -> AccessAssign {
        let bbk = sched.generate_bbk_block(ts);
        let mut buf = bbk.mac_block.clone();
        buf.seek(0);
        AccessAssign::from_bitbuf(&mut buf).expect("Failed to decode AACH block")
    }

    /// During hangtime the AACH must hold AssignedControl on every frame, including
    /// frames carrying a pending stolen block. If it flapped back to the traffic
    /// usage marker, the end-of-traffic detector (N.212 successive non-UMt
    /// ACCESS-ASSIGN PDUs, ETSI 23.8.2.3.2) would reset its count.
    #[test]
    fn test_hangtime_marker_does_not_flap_on_pending_stealing() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let ts = TdmaTime { t: 2, f: 1, m: 1, h: 0 };

        sched.create_circuit(
            Direction::Dl,
            Circuit {
                call_id: 1,
                direction: Direction::Dl,
                ts: 2,
                usage: 6,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );

        // Active over: traffic usage marker (UMt).
        assert!(
            decode_aach(&sched, ts).dl_is_traffic(),
            "active over should carry the traffic usage marker"
        );

        // Hangtime, no pending steal: AssignedControl, not traffic.
        sched.set_hangtime(2, true);
        let aach = decode_aach(&sched, ts);
        assert!(!aach.dl_is_traffic(), "hangtime should drop the traffic usage marker");
        assert!(
            matches!(
                aach,
                AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                    downlink_usage_marker: AccessAssignDlUsage::AssignedControl,
                    ..
                }
            ),
            "hangtime AACH should be AssignedControl, got {:?}",
            aach
        );

        // Hangtime with a pending stolen block: still AssignedControl, no flap to UMt.
        sched.dl_enqueue_stealing(
            2,
            BitBuffer::from_bitstr("10110000"),
            None,
            AieRequest::clear(AieSubject::System, AieScope::Facch),
            None,
        );
        assert!(sched.has_pending_stealing(2), "stealing block should be queued");
        let aach = decode_aach(&sched, ts);
        assert!(
            !aach.dl_is_traffic(),
            "hangtime marker must not flap back to traffic while a steal is pending, got {:?}",
            aach
        );
    }

    /// A grant carried in FACCH while downlink traffic remains active must
    /// close random access on the corresponding uplink slot.  ACCESS-ASSIGN
    /// has one assigned-only access field here, so reserving either half
    /// advertises both halves as reserved (23.5.1.4.2 and 23.5.2.2.7).
    #[test]
    fn test_assigned_aach_marks_granted_uplink_reserved() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let ts = TdmaTime { t: 2, f: 4, m: 1, h: 0 };

        sched.create_circuit(
            Direction::Dl,
            Circuit {
                call_id: 1,
                direction: Direction::Dl,
                ts: 2,
                usage: 6,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );

        let aach = decode_aach(&sched, ts);
        assert!(matches!(
            aach,
            AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                access_field: AccessField {
                    base_frame_len: DEFAULT_ACCESS_FRAME_MARKER,
                    ..
                },
                ..
            }
        ));

        let index = sched.ul_ts_to_sched_index(&ts);
        sched.ulsched[ts.t as usize - 1][index].ul1 = Some(77_468);

        let aach = decode_aach(&sched, ts);
        assert!(matches!(
            aach,
            AccessAssign::DownlinkDefinedUplinkAssignedOnly {
                downlink_usage_marker: AccessAssignDlUsage::Traffic(6),
                access_field: AccessField {
                    base_frame_len: BaseFrameLength::ReservedSubslot,
                    ..
                },
            }
        ));
    }

    #[test]
    fn test_frame18_aach_uses_assigned_only_for_active_sacch() {
        use tetra_saps::control::call_control::Circuit;
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let mut sched = get_testing_slotter();
        let ts = TdmaTime { t: 2, f: 18, m: 5, h: 0 };

        sched.create_circuit(
            Direction::Ul,
            Circuit {
                call_id: 1,
                direction: Direction::Ul,
                ts: 2,
                usage: 6,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );

        let bbk = sched.generate_bbk_block(ts);
        let mut buf = bbk.mac_block.clone();
        buf.seek(0);
        assert!(matches!(
            AccessAssignFr18::from_bitbuf(&mut buf).expect("valid active FN18 AACH"),
            AccessAssignFr18::UplinkAssignedOnly {
                access_field_1: AccessField {
                    base_frame_len: BaseFrameLength::CLCHSubslot,
                    ..
                },
                ..
            }
        ));

        sched.set_hangtime(2, true);
        let bbk = sched.generate_bbk_block(ts);
        let mut buf = bbk.mac_block.clone();
        buf.seek(0);
        assert!(matches!(
            AccessAssignFr18::from_bitbuf(&mut buf).expect("valid hangtime FN18 AACH"),
            AccessAssignFr18::UplinkAssignedOnly { .. }
        ));
    }

    #[test]
    fn test_dl_indicates_reserved_subslots() {
        let mut sched = get_testing_slotter();
        let mut ts = TdmaTime::default();

        // Add a reservation for TS1, both subslots in the third occurrence of TS1
        sched.ulsched[0][2] = TimeslotSchedule {
            ul1: Some(1),
            ul2: Some(1),
        };

        // Generate the next 4 frames to see how the reserved subslots are indicated in the BBK block
        for i in 0..4 {
            let bbk = sched.generate_bbk_block(ts);
            let mut aach_buf = bbk.mac_block.clone();
            aach_buf.seek(0);

            // Decode the AACH (which in this test will always be the F1-17 format)
            let access_assign = AccessAssign::from_bitbuf(&mut aach_buf).expect("Failed to decode AACH block");
            tracing::debug!("Decoded AACH: {:?}", access_assign);

            // Third occurrence should have both slots reserved
            let expected_subslot_bfl = if i == 2 {
                BaseFrameLength::ReservedSubslot
            } else {
                DEFAULT_ACCESS_FRAME_MARKER
            };

            match access_assign {
                AccessAssign::DownlinkCommonControlUplinkCommonOnly {
                    access_field_1,
                    access_field_2,
                } => {
                    assert_eq!(
                        access_field_1.base_frame_len,
                        expected_subslot_bfl,
                        "Unexpected base frame length for access field 1 on TS1 occurrence {}",
                        i + 1
                    );
                    assert_eq!(
                        access_field_2.base_frame_len,
                        expected_subslot_bfl,
                        "Unexpected base frame length for access field 2 on TS1 occurrence {}",
                        i + 1
                    );
                }
                _ => panic!("Expected DownlinkCommonControlUplinkCommonOnly format for TS1"),
            }

            // Move on to the next occurrence of TS1
            ts = ts.add_timeslots(4);
        }
    }

    #[test]
    fn test_dl_indicates_clch_opportunities() {
        let sched = get_testing_slotter();

        // Frame 18
        let mut ts = TdmaTime { t: 1, f: 18, m: 1, h: 0 };

        // Generate the next 4 frames to make sure CLCH is correctly indicated
        for _ in 0..4 {
            let bbk = sched.generate_bbk_block(ts);
            let mut aach_buf = bbk.mac_block.clone();
            aach_buf.seek(0);

            // Decode the AACH (which in this test will always be the frame 18 format)
            let access_assign = AccessAssignFr18::from_bitbuf(&mut aach_buf).expect("Failed to decode AACH block");
            tracing::debug!("Decoded AACH: {:?}", access_assign);

            // For MN=1, F=18, T=2, SSN1 should be CLCH (when F == 18 and T == 4 - ((M + 1) % 4), otherwise default
            let expected_subslot_bfl = if ts.t == 2 {
                BaseFrameLength::CLCHSubslot
            } else {
                DEFAULT_ACCESS_FRAME_MARKER
            };

            match access_assign {
                AccessAssignFr18::UplinkCommonOnly { access_field_1, .. } => {
                    assert_eq!(
                        access_field_1.base_frame_len, expected_subslot_bfl,
                        "Unexpected base frame length for access field 1 on frame 18"
                    );
                }
                _ => panic!("Expected AccessAssignFr18::UplinkCommonOnly format for frame 18"),
            }

            ts = ts.add_timeslots(1);
        }
    }

    #[test]
    fn packet_slots_are_assigned_channels_and_close_by_exact_generation() {
        let mut sched = get_testing_slotter();

        assert!(sched.open_packet_bearer(17, 3, 0b1100));
        assert!(sched.packet_bearer_is_active(3));
        assert!(sched.packet_bearer_is_active(4));
        assert!(sched.assigned_channel_is_active(3));

        assert!(!sched.close_packet_bearer(17, 2));
        assert!(sched.packet_bearer_is_active(3));
        assert!(sched.close_packet_bearer(17, 3));
        assert!(!sched.packet_bearer_is_active(3));
        assert!(!sched.packet_bearer_is_active(4));
    }

    #[test]
    fn idle_packet_slot_stays_schf_until_frame_18() {
        let mut sched = get_testing_slotter();
        assert!(sched.open_packet_bearer(17, 1, 0b1110));

        let packet_frame = sched.generate_default_blks(TdmaTime { t: 2, f: 5, m: 1, h: 0 });
        assert_eq!(packet_frame.logical_channel, LogicalChannel::SchF);
        let mut packet_bits = packet_frame.mac_block;
        packet_bits.seek(0);
        assert!(
            MacResource::from_bitbuf(&mut packet_bits)
                .expect("valid idle PDCH MAC block")
                .is_null_pdu()
        );

        let monitor_frame = sched.generate_default_blks(TdmaTime { t: 2, f: 18, m: 1, h: 0 });
        assert_eq!(monitor_frame.logical_channel, LogicalChannel::Bsch);

        assert!(sched.close_packet_bearer(17, 1));
        let released_frame = sched.generate_default_blks(TdmaTime { t: 2, f: 5, m: 1, h: 0 });
        assert_eq!(released_frame.logical_channel, LogicalChannel::Bsch);
    }

    #[test]
    fn final_sc3g_gck_immediate_uses_all_frame18_slots_and_keeps_sync() {
        let mut sched = get_testing_slotter();
        // TS1/FN1/MN2 makes the preceding FN18 a regular frame-18 across
        // all four physical timeslots while still exercising mandatory BSCH
        // and BNCH mapping selected by the multiframe counter.
        let activation = TdmaTime { t: 1, f: 1, m: 2, h: 0 };
        let address = TetraAddress::new(0x00ff_ffff, SsiType::Gssi);
        let mut resource = BsChannelScheduler::dl_make_minimal_resource(&address, None, false);
        resource.update_len_and_fill_ind(0);
        sched
            .reserve_gck_rollover_immediate(
                activation,
                resource,
                BitBuffer::new(0),
                AieRequest::clear(AieSubject::System, AieScope::MacResource),
            )
            .expect("reserve final Immediate");

        sched.cur_dltime = activation.add_timeslots(-5);
        for timeslot in 1..=4 {
            let output = sched.finalize_ts_for_tick();
            assert_eq!(output.ts.t, timeslot);
            assert_eq!(output.ts.f, 18);
            if output.ts.is_mandatory_bsch() {
                assert_eq!(output.blk1.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::Bsch));
                assert_eq!(output.blk2.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::SchHd));
            } else if output.ts.is_mandatory_bnch() {
                assert_eq!(output.blk1.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::SchHd));
                assert_eq!(output.blk2.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::Bnch));
            } else {
                assert_eq!(output.blk1.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::SchF));
                assert!(output.blk2.is_none());
            }
            sched.cur_dltime = output.ts;
        }
        assert!(sched.final_gck_rollover_immediate.iter().all(Option::is_none));

        // The reservation cannot bleed into a later multiframe.
        sched.cur_dltime = activation.add_timeslots(18 * 4 - 5);
        let later = sched.finalize_ts_for_tick();
        assert_ne!(later.ts, activation.add_timeslots(-4));
        assert!(sched.final_gck_rollover_immediate.iter().all(Option::is_none));
    }

    #[test]
    fn final_gck_immediate_on_group_tch_keeps_cmg_and_cck() {
        use tetra_config::bluestation::{RuntimeSc3Gck, RuntimeSc3TeaAlgorithm, SharedConfig};
        use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

        let parsed = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration");
        let config = SharedConfig::from_parts(parsed, None);
        let gssi = 1502;
        let activation = TdmaTime { t: 1, f: 1, m: 2, h: 0 };
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x35; 10], true, true);
        sc3.apply_sc3g_snapshot_with_rollover(
            1,
            true,
            10,
            vec![RuntimeSc3Gck::new(4, 10, [0x41; 10])],
            Some(11),
            vec![RuntimeSc3Gck::new(4, 11, [0x42; 10])],
            Some((1, 1)),
            vec![(gssi, 4)],
        )
        .expect("current and future group keys");
        assert_eq!(
            sc3.schedule_gck_rollover(1, activation.add_timeslots(-4)).map(|(_, at)| at),
            Some(activation)
        );
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let provider = BsAieKeyProvider::new(config);
        let mut sched = get_testing_slotter();
        sched.aie_provider = Some(provider.clone());
        sched.create_circuit(
            Direction::Dl,
            Circuit {
                call_id: 10,
                direction: Direction::Dl,
                ts: 2,
                usage: 6,
                circuit_mode: CircuitModeType::TchS,
                speech_service: Some(0),
                etee_encrypted: false,
            },
        );
        sched.set_traffic_aie(2, Some(AieRequest::sc3(AieSubject::Group { gssi }, AieScope::Traffic)));

        let cmg_gssi = 42_001;
        let cmg = TetraAddress::new(cmg_gssi, SsiType::Gssi);
        let mut sdu = BitBuffer::new_autoexpand(40);
        sdu.write_bits(0, 34);
        sdu.seek(0);
        let mut resource = BsChannelScheduler::dl_make_minimal_resource(&cmg, None, false);
        resource.update_len_and_fill_ind(sdu.get_len());
        sched
            .reserve_gck_rollover_immediate(
                activation,
                resource,
                sdu,
                AieRequest::sc3(AieSubject::Group { gssi: cmg_gssi }, AieScope::MacResource),
            )
            .expect("reserve CMG Immediate on all slots");
        sched.cur_dltime = activation.add_timeslots(-4);
        let output = sched.finalize_ts_for_tick();
        assert_eq!(output.ts.t, 2);
        assert_eq!(output.ts.f, 18);
        let mut block = [output.blk1, output.blk2]
            .into_iter()
            .flatten()
            .find(|block| matches!(block.logical_channel, LogicalChannel::SchHd | LogicalChannel::SchF))
            .expect("group Immediate")
            .mac_block;
        block.seek(0);
        let header = MacResource::from_bitbuf(&mut block).expect("Immediate MAC-RESOURCE");
        let address = header.addr.expect("encrypted CMG address");
        assert_ne!(address.ssi, cmg_gssi);
        // MAC-RESOURCE's SSI address field does not distinguish ISSI/GSSI.
        assert_eq!(address.ssi_type, SsiType::Ssi);
        assert_eq!(header.encryption_mode, 0b11);
        assert!(header.usage_marker.is_none());
    }

    #[test]
    fn final_sc3g_gck_immediate_replaces_stale_partial_reservation_atomically() {
        let mut sched = get_testing_slotter();
        let address = TetraAddress::new(0x00ff_ffff, SsiType::Gssi);
        let mut resource = BsChannelScheduler::dl_make_minimal_resource(&address, None, false);
        resource.update_len_and_fill_ind(0);
        let old_activation = TdmaTime { t: 1, f: 1, m: 1, h: 0 };
        let activation = TdmaTime { t: 1, f: 1, m: 2, h: 0 };
        sched
            .reserve_gck_rollover_immediate(
                old_activation,
                resource.clone(),
                BitBuffer::new(0),
                AieRequest::clear(AieSubject::System, AieScope::MacResource),
            )
            .expect("reserve stale Immediate");
        // Model the old error path: one reservation survived while the other
        // physical FN18 slots were no longer paired with it.
        sched.final_gck_rollover_immediate[1] = None;
        sched.final_gck_rollover_immediate[3] = None;

        sched
            .reserve_gck_rollover_immediate(
                activation,
                resource,
                BitBuffer::new(0),
                AieRequest::clear(AieSubject::System, AieScope::MacResource),
            )
            .expect("replace stale final Immediate");
        assert!(
            sched
                .final_gck_rollover_immediate
                .iter()
                .all(|entry| entry.as_ref().is_some_and(|item| item.activation == activation))
        );

        sched.cur_dltime = activation.add_timeslots(-5);
        for timeslot in 1..=4 {
            let output = sched.finalize_ts_for_tick();
            assert_eq!(output.ts.t, timeslot);
            assert_eq!(output.ts.f, 18);
            sched.cur_dltime = output.ts;
        }
        assert!(sched.final_gck_rollover_immediate.iter().all(Option::is_none));
    }

    #[test]
    fn stale_packet_open_cannot_resurrect_or_resize_new_generation() {
        let mut sched = get_testing_slotter();

        assert!(sched.open_packet_bearer(17, 4, 0b0010));
        assert!(sched.close_packet_bearer(17, 4));
        assert!(!sched.open_packet_bearer(17, 3, 0b1000));
        assert!(!sched.packet_bearers_match(17, 3));
        assert!(!sched.packet_bearer_is_active(4));

        assert!(sched.open_packet_bearer(17, 5, 0b0100));
        assert!(!sched.open_packet_bearer(17, 4, 0b1000));
        assert!(sched.packet_bearers_match(17, 5));
        assert!(sched.packet_bearer_is_active(3));
        assert!(!sched.packet_bearer_is_active(4));
    }
}
