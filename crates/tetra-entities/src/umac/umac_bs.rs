use std::{
    collections::{HashMap, HashSet, VecDeque},
    panic,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tetra_config::bluestation::{AieContextError, BsAieKeyProvider, RuntimeAieConfig, RuntimeSc3Aie, SharedConfig};
use tetra_core::freqs::FreqInfo;
use tetra_core::tetra_entities::TetraEntity;
use tetra_core::{
    AieCipherRegion, AieDirection, AieRequest, AieScope, AieSubject, BitBuffer, Direction, PhyBlockNum, Sap, Sc3KeyIdentifier, Sc3KeyType, SsiType, TdmaTime,
    TetraAddress, Todo, TxReporter,
};
use tetra_pdus::llc::enums::llc_pdu_type::LlcPduType;
use tetra_pdus::mle::fields::bs_service_details::BsServiceDetails;
use tetra_pdus::mle::pdus::d_mle_sync::DMleSync;
use tetra_pdus::mle::pdus::d_mle_sysinfo::DMleSysinfo;
use tetra_pdus::umac::enums::mac_pdu_type::MacPduType;
use tetra_pdus::umac::enums::reservation_requirement::ReservationRequirement;
use tetra_pdus::umac::enums::sysinfo_opt_field_flag::SysinfoOptFieldFlag;
use tetra_pdus::umac::fields::channel_allocation::ChanAllocElement;
use tetra_pdus::umac::fields::sysinfo_default_def_for_access_code_a::SysinfoDefaultDefForAccessCodeA;
use tetra_pdus::umac::fields::sysinfo_ext_services::SysinfoExtendedServices;
use tetra_pdus::umac::pdus::access_define::AccessDefine;
use tetra_pdus::umac::pdus::mac_access::MacAccess;
use tetra_pdus::umac::pdus::mac_data::MacData;
use tetra_pdus::umac::pdus::mac_end_hu::MacEndHu;
use tetra_pdus::umac::pdus::mac_end_ul::MacEndUl;
use tetra_pdus::umac::pdus::mac_frag_ul::MacFragUl;
use tetra_pdus::umac::pdus::mac_resource::MacResource;
use tetra_pdus::umac::pdus::mac_sync::MacSync;
use tetra_pdus::umac::pdus::mac_sysinfo::MacSysinfo;
use tetra_pdus::umac::pdus::mac_u_blck::MacUBlck;
use tetra_pdus::umac::pdus::mac_u_signal::MacUSignal;
use tetra_saps::control::call_control::{CallControl, Circuit};
use tetra_saps::control::packet_data::PacketBearerControl;
use tetra_saps::lcmc::enums::alloc_type::ChanAllocType;
use tetra_saps::lcmc::enums::ul_dl_assignment::UlDlAssignment;
use tetra_saps::lcmc::fields::chan_alloc_req::CmceChanAllocReq;
use tetra_saps::tma::{AssociatedChannel, TmaReport, TmaReportInd, TmaUnitdataInd};
use tetra_saps::tmv::TmvConfigureReq;
use tetra_saps::tmv::enums::logical_chans::LogicalChannel;
use tetra_saps::{SapMsg, SapMsgInner};
use tetra_swmi_protocol::{GroupProtection, SwmiMessage, TerminalSecurityClass, UplinkRfStats};

use crate::lmac::components::scrambler;
use crate::net_swmi::SwmiRfEndpoint;
use crate::umac::subcomp::bs_sched::{BsChannelScheduler, MACSCHED_TX_AHEAD, PrecomputedUmacPdus, TCH_S_CAP};
use crate::umac::subcomp::fillbits;
use crate::umac::subcomp::random_access::RandomAccessController;
use crate::{MessagePrio, MessageQueue, TetraEntityTrait};

use super::subcomp::bs_defrag::BsDefrag;
use super::subcomp::event_label_store::EventLabelStore;

pub struct UmacBs {
    self_component: TetraEntity,
    config: SharedConfig,
    dltime: TdmaTime,
    system_wide_services: bool,
    authentication_required: bool,
    aie: RuntimeAieConfig,
    /// BS-local SC2 provider for all uplink context resolution and ciphering.
    /// It is cloned into the downlink scheduler as well; both handles share
    /// the same authoritative runtime state and never expose SCK bytes.
    aie_provider: BsAieKeyProvider,
    /// Uplink traffic/FACCH policy per RF timeslot. LMAC needs a copy for
    /// speech decoding; UMAC retains it to decrypt MAC-U-SIGNAL after its
    /// clear three-bit header has been parsed.
    uplink_traffic_aie: [Option<AieRequest>; 4],
    /// CMCE call currently owning each physical traffic timeslot.  A call id
    /// is the generation token for the slot: teardown and floor/media events
    /// from an older call are ignored after the slot has been recycled.
    traffic_call_owner: [Option<u16>; 4],
    /// The GCK chosen when a group traffic channel opened remains in use
    /// until that call releases, even if the cell changes its current GCK.
    group_call_key: [Option<(u16, u32, Sc3KeyIdentifier)>; 4],
    /// First central downlink voice frame admitted to the RF scheduler for
    /// each traffic-slot call generation.  One log entry per call makes the
    /// media half of call restoration observable without per-frame logging.
    first_central_downlink_voice: [Option<u16>; 4],
    /// The current floor holder is the only identity available to an
    /// unaddressed U-TX CEASED MAC-U-SIGNAL. Keep it at the UMAC/CMCE
    /// boundary instead of forwarding a synthetic SSI 0.
    traffic_floor_holder: [Option<u32>; 4],
    random_access: RandomAccessController,

    /// This MAC's endpoint ID, for addressing by the higher layers
    /// When using only a single base radio, we can set this to a fixed value
    endpoint_id: u32,

    /// Subcomponents
    defrag: BsDefrag,
    /// Pending STCH MAC-DATA spanning block1+block2 (length_ind=0b111110), keyed by timeslot.
    pending_stch: Option<PendingStch>,
    event_label_store: EventLabelStore,
    /// Contains UL/DL scheduling logic
    /// Access to this field is used only by testing code
    pub channel_scheduler: BsChannelScheduler,
    // ulrx_scheduler: UlScheduler,
    /// Timestamp of last received UL voice frame per timeslot (0-indexed: ts1..ts4).
    /// Used to detect UL inactivity when a radio disappears mid-transmission.
    last_ul_voice: [Option<TdmaTime>; 4],
    /// P2P media is individually routed by SwmiMediaEntity.  Do not use the
    /// group-call same-timeslot UL loopback for these circuits: it returns a
    /// speaker's audio to the speaker instead of their private peer.
    private_media_timeslots: HashSet<u8>,
    /// Duplex private calls still use individually routed media, but unlike
    /// simplex calls both endpoints are expected to provide an uplink. Keep
    /// their radio-loss watchdog active so a vanished endpoint terminates the
    /// call instead of leaving a dead traffic circuit behind.
    duplex_private_media_timeslots: HashSet<u8>,
    /// MCCH resources held until an EE terminal's next monitoring occasion.
    /// Associated traffic-channel and FACCH paths never enter this queue.
    deferred_mcch: VecDeque<DeferredMcch>,
    /// Encrypted SC3 random-access bursts waiting for one on-demand DCK.
    /// They retain their original UL air time and are replayed only after the
    /// authenticated SwMI response has populated the bounded runtime cache.
    pending_sc3_access: VecDeque<PendingSc3Access>,
    /// Individually encrypted downlinks waiting for the same on-demand DCK
    /// path. This is required after state recovery: the SwMI can restore a
    /// subscriber before this BS has repopulated its ephemeral DCK cache.
    pending_sc3_downlink: VecDeque<PendingSc3Downlink>,
    swmi_rf: Option<SwmiRfEndpoint>,
    rf_windows: HashMap<u32, RfWindow>,
    pending_rf_reports: HashMap<u32, UplinkRfStats>,
}

struct RfWindow {
    started_at: Instant,
    measured_at_unix_ms: u64,
    seen_bursts: HashSet<(i32, u8)>,
    burst_count: u32,
    power_sum: f64,
    frequency_weighted_sum: f64,
    training_symbol_count: u32,
    training_error_bits: u32,
    training_bit_count: u32,
    block_error_count: u32,
    block_count: u32,
    evm_squared_weighted_sum: f64,
    arrival_sum: f64,
}

impl RfWindow {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            measured_at_unix_ms: 0,
            seen_bursts: HashSet::new(),
            burst_count: 0,
            power_sum: 0.0,
            frequency_weighted_sum: 0.0,
            training_symbol_count: 0,
            training_error_bits: 0,
            training_bit_count: 0,
            block_error_count: 0,
            block_count: 0,
            evm_squared_weighted_sum: 0.0,
            arrival_sum: 0.0,
        }
    }

    fn observe(&mut self, ul_time: TdmaTime, observation: tetra_core::UplinkRfObservation, block_ok: bool) {
        self.measured_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.block_count = self.block_count.saturating_add(1);
        self.block_error_count = self.block_error_count.saturating_add(u32::from(!block_ok));
        if !self.seen_bursts.insert((ul_time.to_int(), observation.burst_index)) {
            return;
        }
        self.burst_count = self.burst_count.saturating_add(1);
        self.power_sum += f64::from(observation.received_power_linear);
        let training_symbols = u32::from(observation.training_bit_count / 2);
        self.frequency_weighted_sum += f64::from(observation.frequency_offset_hz) * f64::from(training_symbols);
        self.training_symbol_count = self.training_symbol_count.saturating_add(training_symbols);
        self.training_error_bits = self.training_error_bits.saturating_add(u32::from(observation.training_error_bits));
        self.training_bit_count = self.training_bit_count.saturating_add(u32::from(observation.training_bit_count));
        self.evm_squared_weighted_sum += f64::from(observation.training_evm_percent).powi(2) * f64::from(training_symbols);
        self.arrival_sum += f64::from(observation.relative_arrival_symbols);
    }

    fn finish(self, issi: u32) -> Option<UplinkRfStats> {
        if self.burst_count == 0 || self.block_count == 0 || self.training_bit_count == 0 || self.training_symbol_count == 0 {
            return None;
        }
        let power_dbfs = 10.0 * (self.power_sum / f64::from(self.burst_count)).log10();
        let frequency_offset = self.frequency_weighted_sum / f64::from(self.training_symbol_count);
        let evm = (self.evm_squared_weighted_sum / f64::from(self.training_symbol_count)).sqrt();
        let arrival = self.arrival_sum / f64::from(self.burst_count);
        if [power_dbfs, frequency_offset, evm, arrival].iter().any(|value| !value.is_finite()) {
            return None;
        }
        Some(UplinkRfStats {
            issi,
            measured_at_unix_ms: self.measured_at_unix_ms,
            window_ms: 1_000,
            burst_count: self.burst_count.min(u32::from(u16::MAX)) as u16,
            received_power_dbfs_x100: scaled_i16(power_dbfs, 100.0),
            frequency_offset_hz_x100: scaled_i32(frequency_offset, 100.0),
            training_error_bits: self.training_error_bits.min(u32::from(u16::MAX)) as u16,
            training_bit_count: self.training_bit_count.min(u32::from(u16::MAX)) as u16,
            block_error_count: self.block_error_count.min(u32::from(u16::MAX)) as u16,
            block_count: self.block_count.min(u32::from(u16::MAX)) as u16,
            training_evm_percent_x100: (evm * 100.0).round().clamp(0.0, f64::from(u16::MAX)) as u16,
            relative_arrival_symbols_x1000: scaled_i32(arrival, 1_000.0),
        })
    }
}

fn scaled_i16(value: f64, scale: f64) -> i16 {
    (value * scale).round().clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
}

fn scaled_i32(value: f64, scale: f64) -> i32 {
    (value * scale).round().clamp(f64::from(i32::MIN), f64::from(i32::MAX)) as i32
}

struct PendingStch {
    addr: TetraAddress,
    scrambling_code: u32,
    encrypted: bool,
    fill_bits: bool,
    sdu_part: BitBuffer,
}

struct DeferredMcch {
    due: TdmaTime,
    pdu: MacResource,
    sdu: BitBuffer,
    tx_reporter: Option<TxReporter>,
    aie_request: AieRequest,
    ee_retry: Option<EeReplayRetry>,
}

/// A replay is useful only in the MS's one-frame EE reception window. If
/// SCH/F congestion displaces it, cancel the stale MAC resource and try the
/// next reception frame instead of transmitting while the MS is asleep.
struct EeReplayRetry {
    period_slots: i32,
    attempts_left: u8,
    cutoff: Option<TdmaTime>,
    in_flight: Option<TxReporter>,
}

struct PendingSc3Access {
    issi: u32,
    expires_at: TdmaTime,
    message: SapMsg,
}

struct PendingSc3Downlink {
    issi: u32,
    expires_at: TdmaTime,
    message: SapMsg,
}

impl UmacBs {
    fn apply_packet_event_label_addressing(
        &self,
        main_address: TetraAddress,
        associated_channel: Option<AssociatedChannel>,
        chan_alloc: Option<&CmceChanAllocReq>,
        sdu: &BitBuffer,
        pdu: &mut MacResource,
    ) {
        if main_address.ssi_type != SsiType::Issi {
            return;
        }
        let Some(event_label) = self.event_label_store.get_label_by_ssi(main_address.ssi) else {
            return;
        };
        let packet_assignment = chan_alloc.is_some_and(|allocation| {
            let mut assigned = allocation
                .timeslots
                .iter()
                .enumerate()
                .filter_map(|(index, assigned)| assigned.then_some(index as u8 + 1));
            let Some(first) = assigned.next() else {
                return false;
            };
            self.channel_scheduler.packet_bearer_is_active(first)
                && assigned.all(|timeslot| self.channel_scheduler.packet_bearer_is_active(timeslot))
        });
        if packet_assignment {
            // TTR 001-05 section 6.6 assigns the label with SSI + event label
            // in the MAC-RESOURCE carrying the PDCH allocation. A usage
            // marker cannot coexist with that address type and is not needed
            // for an assigned SCCH.
            pdu.addr = Some(main_address);
            pdu.event_label = Some(event_label);
            pdu.usage_marker = None;
            return;
        }
        let on_packet_bearer = associated_channel.is_some_and(|channel| self.channel_scheduler.packet_bearer_is_active(channel.timeslot));
        if !on_packet_bearer {
            return;
        }
        let mut header = sdu.clone();
        let Ok(raw_type) = header.read_field(4, "llc_pdu_type") else {
            return;
        };
        let advanced_link = matches!(
            LlcPduType::try_from(raw_type),
            Ok(LlcPduType::AlSetup
                | LlcPduType::AlDataAlFinal
                | LlcPduType::AlAlUdataAlUfinal
                | LlcPduType::AlAckAlRnr
                | LlcPduType::AlReconnect
                | LlcPduType::AlDisc)
        );
        if advanced_link {
            // Once assigned, the packet-data profile requires every advanced
            // link PDU to use the short event label. Basic-link SNDCP and SDS
            // continue to use the ISSI on the same PDCH.
            pdu.addr = None;
            pdu.event_label = Some(event_label);
            pdu.usage_marker = None;
        }
    }

    pub fn new(config: SharedConfig) -> Self {
        Self::new_with_swmi(config, None)
    }

    pub fn new_with_swmi(config: SharedConfig, swmi_rf: Option<SwmiRfEndpoint>) -> Self {
        let c = config.config();
        let scrambling_code = scrambler::tetra_scramb_get_init(c.net.mcc, c.net.mnc, c.cell.colour_code);
        let system_wide_services = Self::get_system_wide_services_state(&config);
        let authentication_required = Self::get_authentication_required_state(&config);
        let aie = Self::get_aie_config(&config);
        let aie_provider = BsAieKeyProvider::new(config.clone());
        let random_access = RandomAccessController::new(c.cell.random_access.clone());
        let precomps = Self::generate_precomps(&config);
        Self {
            self_component: TetraEntity::Umac,
            config,
            dltime: TdmaTime::default(),
            system_wide_services,
            authentication_required,
            aie,
            random_access,
            endpoint_id: 1,
            defrag: BsDefrag::new(),
            pending_stch: None,
            event_label_store: EventLabelStore::new(),
            channel_scheduler: BsChannelScheduler::new_with_aie_provider(scrambling_code, precomps, aie_provider.clone()),
            aie_provider,
            uplink_traffic_aie: [None; 4],
            traffic_call_owner: [None; 4],
            group_call_key: [None; 4],
            first_central_downlink_voice: [None; 4],
            traffic_floor_holder: [None; 4],
            last_ul_voice: [None; 4],
            private_media_timeslots: HashSet::new(),
            duplex_private_media_timeslots: HashSet::new(),
            deferred_mcch: VecDeque::new(),
            pending_sc3_access: VecDeque::new(),
            pending_sc3_downlink: VecDeque::new(),
            swmi_rf,
            rf_windows: HashMap::new(),
            pending_rf_reports: HashMap::new(),
        }
    }

    fn observe_terminal_rf(&mut self, issi: u32, ul_time: TdmaTime, observation: Option<tetra_core::UplinkRfObservation>, block_ok: bool) {
        let Some(observation) = observation.filter(|observation| {
            observation.received_power_linear.is_finite()
                && observation.received_power_linear > 0.0
                && observation.frequency_offset_hz.is_finite()
                && observation.training_evm_percent.is_finite()
                && observation.relative_arrival_symbols.is_finite()
                && observation.training_bit_count > 0
                && observation.training_error_bits <= observation.training_bit_count
        }) else {
            return;
        };
        self.rf_windows
            .entry(issi)
            .or_insert_with(RfWindow::new)
            .observe(ul_time, observation, block_ok);
    }

    fn observe_control_rf(
        &mut self,
        decoded_issi: Option<u32>,
        ul_time: TdmaTime,
        block_num: PhyBlockNum,
        observation: Option<tetra_core::UplinkRfObservation>,
        block_ok: bool,
    ) {
        let scheduled_issi = self.channel_scheduler.ul_get_slot_owner(ul_time, block_num);
        let issi = match (scheduled_issi, decoded_issi) {
            (Some(scheduled), Some(decoded)) if scheduled != decoded => {
                tracing::warn!(scheduled, decoded, %ul_time, ?block_num, "ignoring uplink RF observation with conflicting identities");
                return;
            }
            (Some(scheduled), _) => scheduled,
            (None, Some(decoded)) => decoded,
            (None, None) => return,
        };
        self.observe_terminal_rf(issi, ul_time, observation, block_ok);
    }

    fn flush_rf_windows(&mut self) {
        let expired = self
            .rf_windows
            .iter()
            .filter_map(|(issi, window)| (window.started_at.elapsed() >= Duration::from_secs(1)).then_some(*issi))
            .collect::<Vec<_>>();
        for issi in expired {
            if let Some(report) = self.rf_windows.remove(&issi).and_then(|window| window.finish(issi)) {
                self.pending_rf_reports.insert(issi, report);
            }
        }

        let Some(endpoint) = self.swmi_rf.as_ref().filter(|endpoint| endpoint.is_online()) else {
            return;
        };
        let pending = std::mem::take(&mut self.pending_rf_reports);
        for (issi, report) in pending {
            if let Err(SwmiMessage::UplinkRfStats(report)) = endpoint.submit(SwmiMessage::UplinkRfStats(report)) {
                self.pending_rf_reports.insert(issi, report);
            }
        }
    }

    /// Return the next MCCH TS1 monitoring opportunity for an individual
    /// terminal. ETSI TS 100 392-2 table 23.9 defines the sleep duration in
    /// TDMA frames; the reception period is one frame longer.
    fn next_energy_economy_mcch(&self, issi: u32) -> Option<TdmaTime> {
        let (mode, frame, multiframe) = self.config.state_read().subscribers.energy_economy(issi)?;
        self.next_energy_economy_mcch_for_assignment(mode, frame, multiframe)
    }

    fn energy_economy_period_frames(mode: u8) -> Option<i32> {
        match mode {
            1 => Some(2),
            2 => Some(3),
            3 => Some(6),
            4 => Some(9),
            5 => Some(18),
            6 => Some(72),
            7 => Some(360),
            _ => None,
        }
    }

    fn next_energy_economy_mcch_for_assignment(&self, mode: u8, frame: Option<u8>, multiframe: Option<u8>) -> Option<TdmaTime> {
        let period = Self::energy_economy_period_frames(mode)?;
        let (Some(frame), Some(multiframe)) = (frame, multiframe) else {
            tracing::warn!(mode, "invalid local EE assignment; falling back to immediate MCCH");
            return None;
        };
        if !(1..=18).contains(&frame) || !(1..=60).contains(&multiframe) {
            tracing::warn!(mode, frame, multiframe, "invalid local EE start point; falling back to immediate MCCH");
            return None;
        }
        let anchor = (i32::from(multiframe - 1) * 18 + i32::from(frame - 1)).rem_euclid(period);
        // The scheduler finalizes the air slot one tick ahead. Leave at
        // least one whole tick before the chosen reception slot so the
        // deferred resource can be released in time.
        // Every period divides the 1080-frame hyperframe.
        for offset in (MACSCHED_TX_AHEAD as i32 + 1)..=(360 * 4 + 4) {
            let candidate = self.dltime.add_timeslots(offset);
            let hyperframe_frame = i32::from(candidate.m - 1) * 18 + i32::from(candidate.f - 1);
            if candidate.t == 1 && hyperframe_frame.rem_euclid(period) == anchor {
                return Some(candidate);
            }
        }
        None
    }

    /// Precomputes SYNC, SYSINFO messages (and subfield variants) for faster TX msg building
    /// Precomputed PDUs are passed to scheduler
    /// Needs to be re-invoked if any network parameter changes
    pub fn generate_precomps(config: &SharedConfig) -> PrecomputedUmacPdus {
        let c = config.config();
        let aie = Self::get_aie_config(config);

        // TODO FIXME make more/all parameters configurable
        let ext_services = SysinfoExtendedServices {
            auth_required: Self::get_authentication_required_state(config),
            class1_supported: aie.enabled && aie.sc1_allowed,
            class2_supported: aie.enabled && aie.sc2.is_some(),
            class3_supported: aie.enabled && aie.sc3.is_some(),
            sck_n: aie.sc2.as_ref().map(|sc2| sc2.sckn),
            dck_retrieval_during_cell_select: aie.sc3.as_ref().map(|sc3| sc3.dck_retrieval_during_initial_cell_selection),
            dck_retrieval_during_cell_reselect: aie.sc3.as_ref().map(|sc3| sc3.dck_retrieval_during_cell_reselection),
            linked_gck_crypto_periods: aie.sc3.as_ref().map(|sc3| sc3.linked_gck_crypto_periods()),
            short_gck_vn: aie.sc3.as_ref().map(|sc3| (sc3.gck_vn() & 0x03) as u8),
            sdstl_addressing_method: 2,
            gck_supported: aie.sc3.as_ref().is_some_and(RuntimeSc3Aie::gck_supported),
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

        let access_define = c.cell.random_access.enabled.then(|| AccessDefine {
            common_or_assigned_control: false,
            access_code: 0,
            imm: def_access.imm,
            wt: def_access.wt,
            nu: def_access.nu,
            frame_len_factor: def_access.fl_factor,
            ts_pointer: def_access.ts_ptr,
            min_pdu_prio: def_access.min_pdu_prio,
            opt_field_flag: 0,
            subscriber_class: None,
            gssi: None,
        });

        let sysinfo1 = MacSysinfo {
            main_carrier: c.cell.main_carrier,
            freq_band: c.cell.freq_band,
            freq_offset_index: FreqInfo::freq_offset_hz_to_id(c.cell.freq_offset_hz).unwrap(),
            duplex_spacing: c.cell.duplex_spacing_id,
            reverse_operation: c.cell.reverse_operation,
            num_of_csch: 0, // Common secondary control channels
            ms_txpwr_max_cell: c.cell.ms_txpwr_max_cell,
            rxlev_access_min: c.cell.rxlev_access_min,
            access_parameter: c.cell.access_parameter,
            radio_dl_timeout: 3, // 432 timeslots (~6s radio link timeout)
            cipher_key_id_or_sck_vn: aie.sc3.as_ref().map(|sc3| sc3.cck_id),
            hyperframe_number: Some(0), // Updated dynamically in scheduler
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
            cipher_key_id_or_sck_vn: None,
            hyperframe_number: Some(0), // Updated dynamically in scheduler
            option_field: SysinfoOptFieldFlag::ExtServicesBroadcast,
            ts_common_frames: None,
            default_access_code: None,
            ext_services: Some(ext_services),
        };

        let system_wide_services = Self::get_system_wide_services_state(config);
        let mle_sysinfo_pdu = DMleSysinfo {
            location_area: c.cell.location_area,
            subscriber_class: c.cell.subscriber_class,
            bs_service_details: BsServiceDetails {
                registration: c.cell.registration,
                deregistration: c.cell.deregistration,
                priority_cell: c.cell.priority_cell,
                no_minimum_mode: c.cell.no_minimum_mode,
                migration: c.cell.migration,
                system_wide_services,
                voice_service: c.cell.voice_service,
                circuit_mode_data_service: c.cell.circuit_mode_data_service,
                sndcp_service: c.cell.sndcp_service,
                aie_service: aie.enabled,
                advanced_link: c.cell.advanced_link,
            },
        };

        let mac_sync_pdu = MacSync {
            system_code: c.cell.system_code,
            colour_code: c.cell.colour_code,
            time: TdmaTime::default(), // replaced dynamically in scheduler
            sharing_mode: c.cell.sharing_mode,
            ts_reserved_frames: c.cell.ts_reserved_frames,
            u_plane_dtx: c.cell.u_plane_dtx,
            frame_18_ext: c.cell.frame_18_ext,
        };

        let mle_sync_pdu = DMleSync {
            mcc: c.net.mcc,
            mnc: c.net.mnc,
            neighbor_cell_broadcast: 2, // Broadcast supported, but enquiry not supported
            cell_load_ca: 0,            // TODO implement dynamic setting. 0 = info unavailable
            late_entry_supported: c.cell.late_entry_supported,
        };

        PrecomputedUmacPdus {
            mac_sysinfo1: sysinfo1,
            mac_sysinfo2: sysinfo2,
            access_define,
            access_define_interval_multiframes: c.cell.random_access.update_interval_multiframes,
            mle_sysinfo: mle_sysinfo_pdu,
            mac_sync: mac_sync_pdu,
            mle_sync: mle_sync_pdu,
        }
    }

    /// Retrieve currently set value of system-wide services. If SwMI is active, this governs connection state
    /// Otherwise, value from config is used.
    fn get_system_wide_services_state(config: &SharedConfig) -> bool {
        let cfg = config.config();
        if cfg.swmi.is_some() {
            config.state_read().network_connected
        } else {
            cfg.cell.system_wide_services
        }
    }

    /// Retrieve the effective authentication policy.  A connected SwMI cell
    /// overrides the local fallback configuration at runtime.
    fn get_authentication_required_state(config: &SharedConfig) -> bool {
        let cfg = config.config();
        if cfg.swmi.is_some() {
            config.state_read().authentication_required
        } else {
            cfg.cell.authentication_required
        }
    }

    /// Bind a call leg to the currently installed SC2 identity.  This records
    /// only its public identifier; SCK bytes remain in the central runtime
    /// AIE provider state.  An unbound call is rejected by that provider,
    /// never treated as permission to fall back to clear traffic.
    fn bind_sc2_call(&self, subject: AieSubject) {
        let AieSubject::Call { call_id, .. } = subject else {
            return;
        };
        let mut state = self.config.state_write();
        if !state.aie.enabled {
            return;
        }
        let Some(sc2) = state.aie.sc2.clone() else {
            return;
        };
        if let AieSubject::Call { issi: Some(issi), .. } = subject
            && state.aie_sessions.terminal(issi).is_none()
        {
            tracing::warn!(
                call_id,
                issi,
                "refusing SC2 call binding for a terminal without an active SC2 session"
            );
            return;
        }
        state.aie_sessions.bind_call(call_id, subject, &sc2);
    }

    fn unbind_sc2_call(&self, call_id: u16) {
        self.config.state_write().aie_sessions.unbind_call(u32::from(call_id));
    }

    /// Install or remove the per-timeslot traffic policies at both sides of
    /// the UMAC/LMAC boundary.  The values are key-free and LMAC resolves
    /// them only using its exact TX/RX TDMA time.
    fn set_traffic_aie(&mut self, queue: &mut MessageQueue, ts: u8, downlink: Option<AieRequest>, uplink: Option<AieRequest>) {
        if !(1..=4).contains(&ts) {
            return;
        }
        self.channel_scheduler.set_traffic_aie(ts, downlink);
        self.uplink_traffic_aie[ts as usize - 1] = uplink;
        queue.push_prio(
            SapMsg {
                sap: Sap::TmvSap,
                src: self.self_component,
                dest: TetraEntity::Lmac,
                msg: SapMsgInner::TmvConfigureReq(TmvConfigureReq {
                    time: Some(self.dltime.forward_to_timeslot(ts)),
                    downlink_traffic_aie: Some(downlink),
                    uplink_traffic_aie: Some(uplink),
                    ..Default::default()
                }),
            },
            MessagePrio::Immediate,
        );
    }

    fn get_aie_config(config: &SharedConfig) -> RuntimeAieConfig {
        if config.config().swmi.is_some() {
            config.state_read().aie.clone()
        } else {
            RuntimeAieConfig::default()
        }
    }

    fn active_aie_request(&self, subject: AieSubject, scope: AieScope) -> Option<AieRequest> {
        if !self.aie.enabled {
            return None;
        }
        let state = self.config.state_read();
        let group = match subject {
            AieSubject::Group { gssi } | AieSubject::Call { gssi: Some(gssi), .. } => Some(gssi),
            _ => None,
        };
        if let Some(gssi) = group {
            let sc3g = self.aie.sc3.as_ref().is_some_and(|sc3| sc3.gckn_for_gssi(gssi).is_some());
            if !sc3g && state.aie_sessions.group_protection(gssi) == GroupProtection::Clear {
                return None;
            }
        }
        let terminal = match subject {
            AieSubject::Individual { issi } | AieSubject::Call { issi: Some(issi), .. } => Some(issi),
            _ => None,
        };
        if let Some(issi) = terminal {
            return match state.aie_sessions.terminal_class(issi) {
                TerminalSecurityClass::Sc1 => None,
                TerminalSecurityClass::Sc2 => Some(AieRequest::sc2(subject, scope)),
                TerminalSecurityClass::Sc3 => Some(AieRequest::sc3(subject, scope)),
                TerminalSecurityClass::Unknown => Some(if self.aie.sc3.is_some() {
                    AieRequest::sc3(subject, scope)
                } else {
                    AieRequest::sc2(subject, scope)
                }),
            };
        }
        Some(if self.aie.sc3.is_some() {
            AieRequest::sc3(subject, scope)
        } else {
            AieRequest::sc2(subject, scope)
        })
    }

    fn group_traffic_aie_for_call(&mut self, call_id: u16, gssi: u32, ts: u8) -> Option<AieRequest> {
        let request = self.active_aie_request(AieSubject::Group { gssi }, AieScope::Traffic)?;
        if !(1..=4).contains(&ts) {
            return Some(request);
        }
        if let Some((owner, group, key)) = self.group_call_key[ts as usize - 1]
            && owner == call_id && group == gssi
        {
            return Some(AieRequest::sc3_with_key(AieSubject::Group { gssi }, AieScope::Traffic, key));
        }
        if let AieRequest::Sc3 { .. } = request
            && let Ok(tetra_core::AieContext::Sc3 { key, .. }) =
                self.aie_provider.resolve(request, AieDirection::Downlink, self.dltime)
            && key.key_type == Sc3KeyType::Gck
        {
            self.group_call_key[ts as usize - 1] = Some((call_id, gssi, key));
            tracing::info!(call_id, ts, gssi, gck_vn = u16::from_be_bytes([key.context_id[14], key.context_id[15]]),
                "pinned GCK for group traffic until call release");
            return Some(AieRequest::sc3_with_key(AieSubject::Group { gssi }, AieScope::Traffic, key));
        }
        Some(request)
    }

    /// Resolve the cipher context of an event-label-addressed uplink.  The
    /// event label has already identified the terminal, so there is no ESI
    /// in this MAC header to invert.  Assigned-channel packet data still
    /// uses the terminal's normal SC2/SC3 policy and the exact uplink slot.
    fn resolve_assigned_uplink_context(
        &self,
        issi: u32,
        time: TdmaTime,
        scope: AieScope,
    ) -> Result<tetra_core::AieContext, AieContextError> {
        let request = self
            .active_aie_request(AieSubject::Individual { issi }, scope)
            .ok_or(AieContextError::InvalidContext)?;
        self.aie_provider.resolve(request, AieDirection::Uplink, time)
    }

    fn private_endpoint_traffic_subjects(call_id: u16, rf_endpoint_issi: u32) -> (AieSubject, AieSubject) {
        let endpoint = AieSubject::Call {
            call_id: u32::from(call_id),
            issi: Some(rf_endpoint_issi),
            gssi: None,
        };
        // Both directions on a dedicated endpoint circuit terminate at the
        // same MS and therefore use that MS's DCK.
        (endpoint, endpoint)
    }

    /// An EE replay must still be in the future and, during an AIE rollover,
    /// must use an opportunity strictly before the activation boundary.
    fn ee_replay_is_usable(due: TdmaTime, now: TdmaTime, rollover_activation: Option<TdmaTime>) -> bool {
        due.age(now) < 0 && rollover_activation.is_none_or(|activation| activation.diff(due) > 0)
    }

    fn shared_private_traffic_subjects(call_id: u16, source_issi: u32, destination_issi: u32) -> (AieSubject, AieSubject) {
        let downlink = AieSubject::Call {
            call_id: u32::from(call_id),
            issi: Some(destination_issi),
            gssi: None,
        };
        let uplink = AieSubject::Call {
            call_id: u32::from(call_id),
            issi: Some(source_issi),
            gssi: None,
        };
        (downlink, uplink)
    }

    fn refresh_random_access_control(&mut self, ts: TdmaTime) {
        let (pending_registrations, registration_delivery_failures) = {
            let mut state = self.config.state_write();
            (
                state.subscribers.pending_registration_count(),
                state.subscribers.take_registration_delivery_failures(),
            )
        };
        self.random_access.set_pending_registrations(pending_registrations);
        self.random_access
            .observe_registration_delivery_failures(registration_delivery_failures);
        let Some(update) = self.random_access.maybe_update(ts) else {
            return;
        };
        self.channel_scheduler
            .set_random_access_definition(update.parameters, update.frame_len);
        tracing::info!("UmacBs: updated common random-access parameters at {} after measured load", ts);
    }

    fn refresh_system_wide_services(&mut self) {
        let is_effective = Self::get_system_wide_services_state(&self.config);
        if is_effective != self.system_wide_services {
            self.system_wide_services = is_effective;
            self.channel_scheduler.set_system_wide_services_state(is_effective);

            // Should already be signalled at SwMI interface level
            tracing::debug!("UmacBs: system_wide_services {}", if is_effective { "ENABLED" } else { "DISABLED" });
        }
    }

    fn refresh_authentication_required(&mut self) {
        let required = Self::get_authentication_required_state(&self.config);
        if required != self.authentication_required {
            self.authentication_required = required;
            self.channel_scheduler.set_authentication_required(required);
        }
    }

    fn refresh_aie_config(&mut self) {
        let aie = Self::get_aie_config(&self.config);
        // The scheduler builds one future downlink slot. Select the SYSINFO
        // SCK identity for that air slot, not for this software tick, so its
        // broadcast changes on the same Absolute IV as traffic ciphering.
        self.channel_scheduler
            .set_aie_config_for_air_time(&aie, self.dltime.add_timeslots(MACSCHED_TX_AHEAD as i32));
        if aie != self.aie {
            self.aie = aie;
        }
    }

    fn cmce_to_mac_chanalloc(chan_alloc: &CmceChanAllocReq, default_carrier_num: u16) -> ChanAllocElement {
        // We grant clch permission for Replace and Additional allocations on the uplink
        let clch_permission = (chan_alloc.alloc_type == ChanAllocType::Replace || chan_alloc.alloc_type == ChanAllocType::Additional)
            && (chan_alloc.ul_dl_assigned == UlDlAssignment::Ul || chan_alloc.ul_dl_assigned == UlDlAssignment::Both);
        ChanAllocElement {
            alloc_type: chan_alloc.alloc_type,
            ts_assigned: chan_alloc.timeslots,
            ul_dl_assigned: chan_alloc.ul_dl_assigned,
            clch_permission,
            cell_change_flag: chan_alloc.cell_change_flag,
            // For an announced Type-1 handover the MAC header is emitted by
            // the old cell but must identify the target cell's carrier.
            carrier_num: chan_alloc.carrier.unwrap_or(default_carrier_num),
            ext: None,
            // Core TIP 14.1.6: a normal CCCH -> TCH allocation assigns all
            // three monitoring patterns.  The frame-18-only field is then
            // conditional absent, not a zero-valued field on the air.
            mon_pattern: 0b11,
            frame18_mon_pattern: None,
        }
    }

    /// Convenience function to send a TMA-REPORT.ind
    fn send_tma_report_ind(queue: &mut MessageQueue, handle: Todo, report: TmaReport) {
        let tma_report_ind = TmaReportInd {
            req_handle: handle,
            report,
        };
        let msg = SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Umac,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TmaReportInd(tma_report_ind),
        };
        queue.push_back(msg);
    }

    fn rx_tmv_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tmv_prim");
        match message.msg {
            SapMsgInner::TmvUnitdataInd(_) => {
                self.rx_tmv_unitdata_ind(queue, message);
            }
            SapMsgInner::TmvCrcInd(ind) => {
                self.observe_control_rf(None, ind.ul_time, ind.block_num, ind.rf_observation, false);
                if ind.common_control && ind.logical_channel == LogicalChannel::SchHu {
                    self.random_access.observe_crc_failure();
                    tracing::debug!("UmacBs: common random-access CRC failure block={:?}", ind.block_num);
                }
            }
            _ => {
                panic!();
            }
        }
    }

    pub fn rx_tmv_unitdata_ind(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        tracing::trace!("rx_tmv_unitdata_ind: {:?}", prim.logical_channel);

        match prim.logical_channel {
            LogicalChannel::SchF => {
                // Full slot signalling
                assert!(
                    prim.block_num == PhyBlockNum::Both,
                    "{:?} can't have block_num {:?}",
                    prim.logical_channel,
                    prim.block_num
                );
                self.rx_tmv_sch(queue, message);
            }
            LogicalChannel::Stch | LogicalChannel::SchHu => {
                // Half slot signalling
                assert!(
                    matches!(prim.block_num, PhyBlockNum::Block1 | PhyBlockNum::Block2),
                    "{:?} can't have block_num {:?}",
                    prim.logical_channel,
                    prim.block_num
                );
                self.rx_tmv_sch(queue, message);
            }
            _ => unreachable!("invalid channel: {:?}", prim.logical_channel),
        }
    }

    /// Receive signalling (SCH, or STCH / BNCH)
    pub fn rx_tmv_sch(&mut self, queue: &mut MessageQueue, mut message: SapMsg) {
        tracing::trace!("rx_tmv_sch");

        // Iterate until no more messages left in mac block
        loop {
            // let (lchan, block_num) = match &message.msg {
            //     SapMsgInner::TmvUnitdataInd(prim) => (prim.logical_channel, prim.block_num),
            //     _ => panic!(),
            // };

            // Handle STCH MAC-DATA spanning block1+block2 (length_ind=0b111110)
            // if lchan == LogicalChannel::Stch {
            //     if block_num == PhyBlockNum::Block2 {
            //         if let Some(pending) = self.pending_stch.take() {
            //             self.rx_stch_second_half(queue, &mut message, pending);
            //             break;
            //         }
            //     } else if self.pending_stch.is_some() {
            //         tracing::warn!(
            //             "rx_tmv_sch: pending STCH second-half but got {:?} on ts {}",
            //             block_num,
            //             message.dltime.t
            //         );
            //         self.pending_stch = None;
            //     }
            // }

            // Extract info from inner block
            let SapMsgInner::TmvUnitdataInd(prim) = &message.msg else {
                panic!()
            };
            let Some(bits) = prim.pdu.peek_bits(3) else {
                tracing::warn!("insufficient bits: {}", prim.pdu.dump_bin());
                break;
            };
            let orig_start = prim.pdu.get_raw_start();
            let lchan = prim.logical_channel;

            // Clause 21.4.1; handling differs between SCH_HU and others
            match lchan {
                LogicalChannel::SchF | LogicalChannel::Stch => {
                    // First two bits are MAC PDU type
                    let Ok(pdu_type) = MacPduType::try_from(bits >> 1) else {
                        tracing::warn!("invalid pdu type: {}", bits >> 1);
                        break;
                    };

                    match pdu_type {
                        MacPduType::MacResourceMacData => {
                            self.rx_mac_data(queue, &mut message);
                        }
                        MacPduType::MacFragMacEnd => {
                            // Also need third bit; designates mac-frag versus mac-end
                            if bits & 1 == 0 {
                                self.rx_mac_frag_ul(queue, &mut message);
                            } else {
                                self.rx_mac_end_ul(queue, &mut message);
                            }
                        }
                        MacPduType::SuppMacUSignal => {
                            // STCH determines which subtype is relevant
                            if lchan == LogicalChannel::Stch {
                                self.rx_ul_mac_u_signal(queue, &mut message);
                            } else {
                                // Supplementary MAC PDU type
                                if bits & 1 == 0 {
                                    self.rx_ul_mac_u_blck(queue, &mut message);
                                } else {
                                    tracing::warn!("unexpected supplementary PDU type")
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("unknown pdu type: {}", pdu_type);
                        }
                    }
                }
                LogicalChannel::SchHu => {
                    // Need only 1 bit for a single subtype distinction
                    let pdu_type = (bits >> 2) & 1;
                    match pdu_type {
                        0 => self.rx_mac_access(queue, &mut message),
                        1 => self.rx_mac_end_hu(queue, &mut message),
                        _ => panic!(),
                    }
                }

                _ => {
                    tracing::warn!("unknown logical channel: {:?}", lchan);
                }
            }

            // Check if end of message reached by re-borrowing inner
            // If start was not updated, we also consider it end of message
            // If 16 or more bits remain (len of null pdu), we continue parsing
            if let SapMsgInner::TmvUnitdataInd(prim) = &message.msg {
                if prim.pdu.get_raw_start() != orig_start && prim.pdu.get_len() >= 16 {
                    tracing::trace!("orig {} now {}", orig_start, prim.pdu.get_raw_start());
                    tracing::trace!(
                        "rx_tmv_unitdata_ind_sch: Remaining {} bits: {:?}",
                        prim.pdu.get_len_remaining(),
                        prim.pdu.dump_bin_full(true)
                    );
                } else {
                    tracing::trace!("rx_tmv_unitdata_ind_sch: End of message reached");
                    break;
                }
            }
        }

        let remaining_rf = match &mut message.msg {
            SapMsgInner::TmvUnitdataInd(prim) => prim
                .rf_observation
                .take()
                .map(|observation| (prim.ul_time, prim.block_num, prim.crc_pass, observation)),
            _ => None,
        };
        if let Some((ul_time, block_num, block_ok, observation)) = remaining_rf {
            self.observe_control_rf(None, ul_time, block_num, Some(observation), block_ok);
        }
    }

    fn handle_uplink_capacity_request(
        &mut self,
        ul_time: TdmaTime,
        addr: TetraAddress,
        res_req: ReservationRequirement,
        continues_fragment: bool,
    ) {
        if self
            .channel_scheduler
            .queue_packet_data_capacity_request(ul_time, addr, res_req, continues_fragment)
        {
            return;
        }

        let active_traffic_channel = self.channel_scheduler.circuit_is_active(Direction::Dl, ul_time.t)
            && !self.channel_scheduler.is_hangtime(ul_time.t)
            && (2..=4).contains(&ul_time.t);
        if active_traffic_channel {
            self.channel_scheduler.dl_enqueue_associated_grant_request(ul_time.t, addr, res_req);
            return;
        }

        let grant = if continues_fragment {
            self.channel_scheduler.ul_process_fragment_cap_req(ul_time.t, addr, &res_req)
        } else {
            self.channel_scheduler.ul_process_cap_req(ul_time.t, addr, &res_req)
        };
        if let Some(grant) = grant {
            self.channel_scheduler.dl_enqueue_grant(ul_time.t, addr, grant);
        } else {
            tracing::debug!(?addr, %ul_time, ?res_req, "no grant available for uplink capacity request");
        }
    }

    fn rx_mac_data(&mut self, queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_mac_data");
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        assert!(prim.pdu.get_pos() == 0); // We should be at the start of the MAC PDU
        let pdu = match MacData::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing MacData: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        // Get addr, either from pdu addr field or by resolving the event label
        let mut addr = if let Some(label) = pdu.event_label {
            let Some(address) = self.event_label_store.get_addr_by_label(label) else {
                tracing::warn!(label, "unknown packet-data event label in MAC-DATA");
                return;
            };
            address
        } else {
            pdu.addr.expect("MAC-DATA must carry an SSI or event label")
        };

        let (mut pdu_len_bits, is_frag_start, second_half_stolen, is_null_pdu) = {
            if let Some(len_ind) = pdu.length_ind {
                // We have a length ind, either clear length or a fragmentation start
                match len_ind {
                    0b000000 => {
                        // Null PDU
                        (if pdu.event_label.is_some() { 23 } else { 37 }, false, false, true)
                    }
                    0b000010..0b111000 => (len_ind as usize * 8, false, false, false),
                    0b111110 => {
                        // Second half stolen. Should be in STCH
                        (prim.pdu.get_len(), false, true, false)
                    }
                    0b111111 => {
                        // Start of fragmentation
                        (prim.pdu.get_len(), true, false, false)
                    }
                    _ => panic!("rx_mac_data: Invalid length_ind {}", len_ind),
                }
            } else {
                // We have a capacity request
                tracing::trace!(
                    "rx_mac_data: cap_req {}",
                    if pdu.frag_flag.unwrap() { "with frag_start" } else { "" }
                );
                (prim.pdu.get_len(), pdu.frag_flag.unwrap(), false, false)
            }
        };

        if second_half_stolen {
            tracing::debug!("rx_mac_data: STCH 2nd half stolen");
            self.signal_lmac_second_half_stolen(queue);
        }

        // Truncate len if past end (okay with standard)
        if pdu_len_bits > prim.pdu.get_len() {
            tracing::warn!("truncating MAC-DATA len from {} to {}", pdu_len_bits, prim.pdu.get_len());
            pdu_len_bits = prim.pdu.get_len() as usize;
        }

        // Strip fill bits. Maintain original end to allow for later parsing of a second mac block
        tracing::trace!("rx_mac_data: {}", prim.pdu.dump_bin_full(true));
        let num_fill_bits = {
            if pdu.fill_bits {
                fillbits::removal::get_num_fill_bits(&prim.pdu, pdu_len_bits, is_null_pdu)
            } else {
                0
            }
        };
        pdu_len_bits -= num_fill_bits;
        let orig_end = prim.pdu.get_raw_end();
        prim.pdu.set_raw_end(prim.pdu.get_raw_start() + pdu_len_bits);
        tracing::trace!(
            "rx_mac_data: pdu: {} sdu: {} fb: {}: {}",
            pdu_len_bits,
            prim.pdu.get_len_remaining(),
            num_fill_bits,
            prim.pdu.dump_bin_full(true)
        );

        if is_null_pdu {
            let decoded_issi = (addr.ssi_type == SsiType::Issi).then_some(addr.ssi);
            let rf_observation = prim.rf_observation.take();
            self.observe_control_rf(decoded_issi, prim.ul_time, prim.block_num, rf_observation, true);
            if self.channel_scheduler.packet_bearer_is_active(prim.ul_time.t) && addr.ssi_type == SsiType::Issi {
                self.channel_scheduler.clear_pending_packet_data_capacity(addr.ssi, prim.ul_time);
            }
            // TODO not sure if there is scenarios in which we want to pass a null pdu to the LLC
            // tracing::warn!("rx_mac_data: Null PDU not passed to LLC");
            return;
        }

        // Handle reservation if present
        let msg_dltime = prim.ul_time;
        let aie_request = if pdu.encrypted {
            // An event label identifies the assigned terminal directly; an
            // ordinary MAC-DATA header instead carries the reversible ESI.
            // In both cases only the remaining TM-SDU is ciphered.
            let (issi, context) = if pdu.event_label.is_some() {
                if addr.ssi_type != SsiType::Issi {
                    tracing::warn!(address_type = ?addr.ssi_type, "rejecting event-label MAC-DATA without an ISSI binding");
                    return;
                }
                let issi = addr.ssi;
                let context = match self.resolve_assigned_uplink_context(issi, msg_dltime, AieScope::MacData) {
                    Ok(context) => context,
                    Err(error) => {
                        if matches!(error, AieContextError::DckNotProvisioned(_) | AieContextError::DckExpired(_)) {
                            self.aie_provider.request_sc3_dck(issi);
                        }
                        tracing::warn!(
                            ?error,
                            issi,
                            "rejecting encrypted event-label MAC-DATA without an active cipher context"
                        );
                        return;
                    }
                };
                (issi, context)
            } else {
                if addr.ssi_type != SsiType::Esi {
                    tracing::warn!(address_type = ?addr.ssi_type, "rejecting encrypted MAC-DATA without an ESI");
                    return;
                }
                match self.aie_provider.resolve_uplink_esi(addr.ssi, msg_dltime, AieScope::MacData) {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(?error, "rejecting encrypted MAC-DATA with unknown or stale SC2 ESI");
                        return;
                    }
                }
            };
            addr = TetraAddress::issi(issi);
            let payload_start = prim.pdu.get_pos();
            let payload_len = prim.pdu.get_len_remaining();
            if let Err(error) = self
                .aie_provider
                .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
            {
                tracing::warn!(?error, issi, "rejecting MAC-DATA after SC2 context validation failed");
                return;
            }
            match context {
                tetra_core::AieContext::Sc3 { key, .. } => {
                    AieRequest::sc3_with_key(AieSubject::Individual { issi }, AieScope::MacData, key)
                }
                _ => AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacData),
            }
        } else {
            // The strict clear allow-list is applied after the LLC header is
            // available: a D-LOCATION UPDATE ACCEPT may still be confirmed
            // by its one matching clear BL-ACK after SC2 activation. LLC
            // accepts only that exact outstanding clear acknowledgement;
            // MLE/MM reject all other clear post-SC2 control traffic.
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData)
        };
        let decoded_issi = (addr.ssi_type == SsiType::Issi).then_some(addr.ssi);
        let rf_observation = prim.rf_observation.take();
        self.observe_control_rf(decoded_issi, msg_dltime, prim.block_num, rf_observation, true);
        if let Some(res_req) = pdu.reservation_req {
            self.handle_uplink_capacity_request(msg_dltime, addr, res_req, is_frag_start);
        } else if self.channel_scheduler.packet_bearer_is_active(msg_dltime.t) && addr.ssi_type == SsiType::Issi {
            self.channel_scheduler.clear_pending_packet_data_capacity(addr.ssi, msg_dltime);
        }

        tracing::debug!("rx_mac_data: {}", prim.pdu.dump_bin_full(true));
        if is_frag_start {
            // Fragmentation start, add to defragmenter
            self.defrag.insert_first(&mut prim.pdu, msg_dltime, addr, Some(aie_request));
        } else {
            // Pass directly to LLC
            let sdu = {
                if prim.pdu.get_len_remaining() == 0 {
                    None // No more data in this block
                } else {
                    // TODO FIXME should not copy here but take ownership
                    // Copy inner part, without MAC header or fill bits
                    Some(BitBuffer::from_bitbuffer_pos(&prim.pdu))
                }
            };

            if sdu.is_some() {
                // We have an SDU for the LLC, deliver it.
                let m = SapMsg {
                    sap: Sap::TmaSap,
                    src: TetraEntity::Umac,
                    dest: TetraEntity::Llc,

                    msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                        pdu: sdu,
                        main_address: addr,
                        scrambling_code: prim.scrambling_code,
                        endpoint_id: 0,        // TODO FIXME
                        new_endpoint_id: None, // TODO FIXME
                        css_endpoint_id: None, // TODO FIXME
                        air_interface_encryption: Some(aie_request),
                        chan_change_response_req: false,
                        chan_change_handle: None,
                        chan_info: None,
                    }),
                };
                queue.push_back(m);
            } else {
                // Either this is a null pdu or we are at the end of the block
                // For now, we don't deliver this. However, important data may need to be signalled upwards
                tracing::warn!("rx_mac_data: empty PDU not passed to LLC");
            }
        }

        // Since this is not a null pdu, more MAC PDUs may follow
        // This allows parent function to continue parsing
        prim.pdu.set_raw_end(orig_end);
        prim.pdu.set_raw_pos(prim.pdu.get_raw_start() + pdu_len_bits + num_fill_bits);
        prim.pdu.set_raw_start(prim.pdu.get_raw_pos());
    }

    fn rx_mac_access(&mut self, queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_mac_access");
        let retry_message = message.clone();
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        assert!(prim.pdu.get_pos() == 0); // We should be at the start of the MAC PDU
        let pdu = match MacAccess::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                self.random_access.observe_invalid_mac_access();
                tracing::warn!("Failed parsing MacAccess: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        // Resolve event label (if supplied)
        let mut addr = if let Some(label) = pdu.event_label {
            let Some(address) = self.event_label_store.get_addr_by_label(label) else {
                tracing::warn!(label, "unknown packet-data event label in MAC-ACCESS");
                return;
            };
            address
        } else if let Some(addr) = pdu.addr {
            addr
        } else {
            panic!()
        };

        let msg_dltime = prim.ul_time;

        // Compute len and extract flags
        let mut pdu_len_bits;
        if let Some(length_ind) = pdu.length_ind {
            if length_ind == 0 {
                // Null PDU
                if pdu.event_label.is_some() {
                    // Short event label present
                    pdu_len_bits = 22; // 22 bits for event label
                } else {
                    // SSI
                    pdu_len_bits = 36;
                }
            } else {
                // Full length ind
                pdu_len_bits = length_ind as usize * 8;
            }
        } else {
            // No length ind, we have capacity request. Fill slot.
            pdu_len_bits = prim.pdu.get_len();
        }
        if pdu_len_bits > prim.pdu.get_len() {
            tracing::warn!("truncating MAC-ACCESS len from {} to {}", pdu_len_bits, prim.pdu.get_len());
            pdu_len_bits = prim.pdu.get_len();
        }

        // Strip fill bits. Maintain original end to allow for later parsing of a second mac block
        // tracing::trace!("rx_mac_access: {}", prim.pdu.dump_bin_full(true));
        let num_fill_bits = if pdu.fill_bits {
            fillbits::removal::get_num_fill_bits(&prim.pdu, pdu_len_bits, pdu.is_null_pdu())
        } else {
            0
        };
        pdu_len_bits -= num_fill_bits;
        let orig_end = prim.pdu.get_raw_end();
        prim.pdu.set_raw_end(prim.pdu.get_raw_start() + pdu_len_bits);
        tracing::trace!(
            "rx_mac_access: pdu: {} sdu: {} fb: {}: {}",
            pdu_len_bits,
            prim.pdu.get_len_remaining(),
            num_fill_bits,
            prim.pdu.dump_bin_full(true)
        );

        if pdu.is_null_pdu() {
            let decoded_issi = (addr.ssi_type == SsiType::Issi).then_some(addr.ssi);
            let rf_observation = prim.rf_observation.take();
            self.observe_control_rf(decoded_issi, prim.ul_time, prim.block_num, rf_observation, true);
            if self.channel_scheduler.packet_bearer_is_active(prim.ul_time.t) && addr.ssi_type == SsiType::Issi {
                self.channel_scheduler.clear_pending_packet_data_capacity(addr.ssi, prim.ul_time);
            }
            // tracing::warn!("rx_mac_access: Null PDU not passed to LLC");
            return;
        }

        // An encrypted MAC-ACCESS has the same clear header/ESI and
        // TM-SDU-only cipher boundary as MAC-DATA (TS 100 392-7 clauses
        // 6.4.0, 6.4.2.2 and 6.5.2). TA61 is reversible, so an ESI identifies
        // its ISSI directly with the active SCK even before this BS has a
        // local subscriber session. Bind that key-free identity before the
        // first fragment is queued, otherwise a MAC-ACCESS ACK/grant cannot
        // be returned and the MS must retry the registration in clear.
        let aie_request = if pdu.encrypted {
            let payload_start = prim.pdu.get_pos();
            let payload_len = prim.pdu.get_len_remaining();
            let event_label_addressed = pdu.event_label.is_some();
            let resolved = if event_label_addressed {
                if addr.ssi_type != SsiType::Issi {
                    tracing::warn!(address_type = ?addr.ssi_type, "rejecting event-label MAC-ACCESS without an ISSI binding");
                    return;
                }
                let issi = addr.ssi;
                self.resolve_assigned_uplink_context(issi, msg_dltime, AieScope::MacData)
                    .map(|context| (issi, context))
            } else {
                if addr.ssi_type != SsiType::Esi {
                    tracing::warn!(address_type = ?addr.ssi_type, "rejecting encrypted MAC-ACCESS without an ESI");
                    return;
                }
                self.aie_provider.resolve_uplink_esi(addr.ssi, msg_dltime, AieScope::MacData)
            };
            match resolved {
                // Ordinary post-registration SC2: resolve the existing
                // session before forwarding its real ISSI to higher layers.
                // On a PDCH, the event-label binding already supplies ISSI.
                Ok((issi, context)) => {
                    if let Err(error) = self
                        .aie_provider
                        .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
                    {
                        tracing::warn!(?error, issi, "rejecting MAC-ACCESS after SC2 cipher failure");
                        return;
                    }
                    addr = TetraAddress::issi(issi);
                    match context {
                        tetra_core::AieContext::Sc3 { key, .. } => {
                            AieRequest::sc3_with_key(AieSubject::Individual { issi }, AieScope::MacData, key)
                        }
                        _ => AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacData),
                    }
                }
                // Only an unbound ESI may use the bootstrap path. Decode it
                // with inverse TA61 and establish a provisional cipher
                // binding; SwMI authentication/registration remains the
                // authority for access.
                Err(AieContextError::SubjectNotProvisioned) if !event_label_addressed => {
                    let (issi, context) = match self.aie_provider.bind_unbound_uplink_esi(addr.ssi, msg_dltime, AieScope::MacData) {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::warn!(?error, "rejecting MAC-ACCESS with undecodable SC2 ESI");
                            return;
                        }
                    };
                    if let Err(error) = self
                        .aie_provider
                        .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
                    {
                        tracing::warn!(?error, "rejecting MAC-ACCESS after SC2 bootstrap cipher failure");
                        return;
                    }
                    addr = TetraAddress::issi(issi);
                    AieRequest::sc2(AieSubject::Individual { issi }, AieScope::MacData)
                }
                Err(AieContextError::SubjectNotProvisioned) => {
                    tracing::warn!(
                        issi = addr.ssi,
                        "rejecting encrypted event-label MAC-ACCESS without an active terminal session"
                    );
                    return;
                }
                Err(AieContextError::DckNotProvisioned(issi) | AieContextError::DckExpired(issi)) => {
                    self.aie_provider.request_sc3_dck(issi);
                    if self.pending_sc3_access.len() >= 32 {
                        self.pending_sc3_access.pop_front();
                    }
                    if !self.pending_sc3_access.iter().any(|pending| pending.issi == issi) {
                        self.pending_sc3_access.push_back(PendingSc3Access {
                            issi,
                            expires_at: self.dltime.add_timeslots(4 * 18),
                            message: retry_message,
                        });
                    }
                    tracing::info!(issi, "deferred encrypted SC3 MAC-ACCESS pending on-demand DCK");
                    return;
                }
                Err(error) => {
                    tracing::warn!(?error, "rejecting encrypted MAC-ACCESS with invalid SC2 ESI context");
                    return;
                }
            }
        } else {
            AieRequest::clear(AieSubject::Individual { issi: addr.ssi }, AieScope::MacData)
        };

        let issi = (addr.ssi_type == SsiType::Issi).then_some(addr.ssi);
        let rf_observation = prim.rf_observation.take();
        self.observe_control_rf(issi, msg_dltime, prim.block_num, rf_observation, true);
        let (active, registration_pending) = issi
            .map(|issi| {
                let state = self.config.state_read();
                (state.subscribers.is_active(issi), state.subscribers.is_registration_pending(issi))
            })
            .unwrap_or((false, false));
        self.random_access.observe_access(issi, msg_dltime, active, registration_pending);

        if let Some(issi) = issi {
            // Preserve this context independently of the queued RA ACK. The
            // ACK itself is normally emitted before CMCE/SwMI has produced
            // D-CALL-PROCEEDING or D-CONNECT, so queue inspection alone is
            // too short-lived to protect the actual PTT response.
            self.config.state_write().subscribers.mark_direct_response_window(issi, self.dltime);
        }

        // Acknowledge the access, unless it is on a timeslot in an active over. During
        // traffic the uplink is reserved (ETSI 23.5.1.3), so the talker is not on random
        // access and acking it would steal an extra MAC-RESOURCE onto the traffic channel.
        // Hangtime and control-channel access (floor requests) are still acked.
        // Message on uplink was sent two timeslots ago.
        let in_active_over =
            self.channel_scheduler.circuit_is_active(Direction::Dl, msg_dltime.t) && !self.channel_scheduler.is_hangtime(msg_dltime.t);
        if !in_active_over && issi.is_some() {
            self.channel_scheduler.dl_enqueue_random_access_ack(msg_dltime.t, addr, aie_request);
        }

        // Handle reservation if present
        if let (Some(issi), Some(res_req)) = (issi, pdu.reservation_req) {
            let addr = TetraAddress::issi(issi);
            self.handle_uplink_capacity_request(msg_dltime, addr, res_req, pdu.is_frag_start());
        } else if let Some(issi) = issi
            && self.channel_scheduler.packet_bearer_is_active(msg_dltime.t)
        {
            self.channel_scheduler.clear_pending_packet_data_capacity(issi, msg_dltime);
        }

        // tracing::debug!("rx_mac_access: {}", prim.pdu.dump_bin_full(true));
        if pdu.is_frag_start() {
            // Fragmentation start, add to defragmenter
            self.defrag.insert_first(&mut prim.pdu, msg_dltime, addr, Some(aie_request));
        } else {
            // Pass directly to LLC
            if prim.pdu.get_len_remaining() == 0 {
                // Either this is a null pdu or we are at the end of the block
                // For now, we don't deliver this. However, important data may need to be signalled upwards
                tracing::warn!("rx_mac_access: empty PDU not passed to LLC");
                return;
            };

            // Pass directly to LLC
            let sdu = {
                if prim.pdu.get_len_remaining() == 0 {
                    None // No more data in this block
                } else {
                    // TODO FIXME check if there is a reasonable way to avoid copying here by taking ownership
                    Some(BitBuffer::from_bitbuffer_pos(&prim.pdu))
                }
            };

            if sdu.is_some() {
                // We have an SDU for the LLC, deliver it.
                let m = SapMsg {
                    sap: Sap::TmaSap,
                    src: TetraEntity::Umac,
                    dest: TetraEntity::Llc,
                    msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                        pdu: sdu,
                        main_address: addr,
                        scrambling_code: prim.scrambling_code,
                        endpoint_id: 0,        // TODO FIXME
                        new_endpoint_id: None, // TODO FIXME
                        css_endpoint_id: None, // TODO FIXME
                        air_interface_encryption: Some(aie_request),
                        chan_change_response_req: false,
                        chan_change_handle: None,
                        chan_info: None,
                    }),
                };
                queue.push_back(m);
            } else {
                // Either this is a null pdu or we are at the end of the block
                // For now, we don't deliver this. However, important data may need to be signalled upwards
                tracing::warn!("rx_mac_data: empty PDU not passed to LLC");
            }
        }

        // Since this is not a null pdu, more MAC PDUs may follow
        // This allows parent function to continue parsing
        prim.pdu.set_raw_end(orig_end);
        prim.pdu.set_raw_pos(prim.pdu.get_raw_start() + pdu_len_bits + num_fill_bits);
        prim.pdu.set_raw_start(prim.pdu.get_raw_pos());
    }

    fn rx_mac_frag_ul(&mut self, _queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_mac_frag_ul");
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        assert!(prim.pdu.get_pos() == 0); // We should be at the start of the MAC PDU

        // Parse header and optional ChanAlloc
        let pdu = match MacFragUl::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing MacFragUl: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        // Strip fill bits. This message is known to fill the slot.
        let mut pdu_len_bits = prim.pdu.get_len();
        let num_fill_bits = {
            if pdu.fill_bits {
                fillbits::removal::get_num_fill_bits(&prim.pdu, pdu_len_bits, false)
            } else {
                0
            }
        };
        pdu_len_bits -= num_fill_bits;
        prim.pdu.set_raw_end(prim.pdu.get_raw_start() + pdu_len_bits);
        tracing::debug!("rx_mac_frag_ul: pdu_len_bits: {} fill_bits: {}", pdu_len_bits, num_fill_bits);

        // Get slot owner from schedule
        let msg_dltime = prim.ul_time;
        let Some(slot_owner) = self.channel_scheduler.ul_get_slot_owner(msg_dltime, prim.block_num) else {
            tracing::warn!("rx_mac_frag_ul: Received MAC-FRAG-UL for unassigned block {:?}", prim.block_num);
            self.channel_scheduler.dump_ul_schedule_full(true);
            return;
        };

        if let Some(request) = self.defrag.get_aie_request(slot_owner, msg_dltime) {
            if request.with_scope(AieScope::MacFragment).is_encrypted() {
                let context = match self
                    .aie_provider
                    .resolve(request.with_scope(AieScope::MacFragment), AieDirection::Uplink, msg_dltime)
                {
                    Ok(context) => context,
                    Err(error) => {
                        tracing::warn!(?error, issi = slot_owner, "rejecting encrypted MAC-FRAG-UL with stale SC2 context");
                        return;
                    }
                };
                let payload_start = prim.pdu.get_pos();
                let payload_len = prim.pdu.get_len_remaining();
                if let Err(error) = self
                    .aie_provider
                    .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
                {
                    tracing::warn!(?error, issi = slot_owner, "rejecting MAC-FRAG-UL after SC2 cipher failure");
                    return;
                }
            }
        } else if !self.aie_provider.clear_uplink_allowed(slot_owner) {
            // No active fragment context must not create a clear fallback for
            // a bound SC2 terminal. insert_next will also reject the orphan.
            tracing::warn!(issi = slot_owner, "rejecting orphan clear MAC-FRAG-UL from SC2-bound terminal");
            return;
        }

        // Insert into defragmenter
        self.defrag.insert_next(&mut prim.pdu, slot_owner, msg_dltime);
    }

    fn rx_mac_end_ul(&mut self, queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_mac_end_ul");
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        assert!(prim.pdu.get_pos() == 0); // We should be at the start of the MAC PDU

        // Parse header and optional ChanAlloc
        let pdu = match MacEndUl::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing MacEndUl: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        // Will have either length_ind or reservation_req, never none or both
        let mut pdu_len_bits = if let Some(length_ind) = pdu.length_ind {
            length_ind as usize * 8
        } else {
            // No length ind, we have capacity request. Fill slot.
            prim.pdu.get_len()
        };
        if pdu_len_bits > prim.pdu.get_len() {
            tracing::warn!("truncating MAC-END-UL len from {} to {}", pdu_len_bits, prim.pdu.get_len());
            pdu_len_bits = prim.pdu.get_len();
        }

        // Strip fill bits if any
        let num_fill_bits = {
            if pdu.fill_bits {
                fillbits::removal::get_num_fill_bits(&prim.pdu, pdu_len_bits, false)
            } else {
                0
            }
        };
        pdu_len_bits -= num_fill_bits;
        let orig_end = prim.pdu.get_raw_end();
        prim.pdu.set_raw_end(prim.pdu.get_raw_start() + pdu_len_bits);
        tracing::trace!(
            "rx_mac_end_ul: pdu: {} sdu: {} fb: {}: {}",
            pdu_len_bits,
            prim.pdu.get_len_remaining(),
            num_fill_bits,
            prim.pdu.dump_bin_full(true)
        );

        // Get slot owner from schedule, decrypt if needed
        let msg_dltime = prim.ul_time;
        let Some(slot_owner) = self.channel_scheduler.ul_get_slot_owner(msg_dltime, prim.block_num) else {
            tracing::warn!("rx_mac_end_ul: Received MAC-END-UL for unassigned block {:?}", prim.block_num);
            self.channel_scheduler.dump_ul_schedule_full(true);
            return;
        };
        let aie_request = if let Some(request) = self.defrag.get_aie_request(slot_owner, msg_dltime) {
            if request.with_scope(AieScope::MacFragment).is_encrypted() {
                let context = match self
                    .aie_provider
                    .resolve(request.with_scope(AieScope::MacFragment), AieDirection::Uplink, msg_dltime)
                {
                    Ok(context) => context,
                    Err(error) => {
                        tracing::warn!(?error, issi = slot_owner, "rejecting encrypted MAC-END-UL with stale SC2 context");
                        return;
                    }
                };
                let payload_start = prim.pdu.get_pos();
                let payload_len = prim.pdu.get_len_remaining();
                if let Err(error) = self
                    .aie_provider
                    .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
                {
                    tracing::warn!(?error, issi = slot_owner, "rejecting MAC-END-UL after SC2 cipher failure");
                    return;
                }
                request
            } else {
                // The MAC header cannot identify the encapsulated protocol.
                // Retain an in-progress clear bootstrap PDU until LLC/MLE/MM
                // can apply their exact MM and OTAR allow-lists. In
                // particular, this admits the clear U-OTAR GSKO DEMAND that
                // follows a clear D-LOCATION UPDATE ACCEPT.
                request
            }
        } else {
            if !self.aie_provider.clear_uplink_allowed(slot_owner) {
                tracing::warn!(issi = slot_owner, "rejecting orphan clear MAC-END-UL from SC2-bound terminal");
                return;
            }
            AieRequest::clear(AieSubject::Individual { issi: slot_owner }, AieScope::MacFragment)
        };

        // Insert last fragment and retrieve finalized block
        let defragbuf = self.defrag.insert_last(&mut prim.pdu, slot_owner, msg_dltime);
        let Some(defragbuf) = defragbuf else {
            tracing::warn!("rx_mac_end_ul: could not obtain defragged buf");
            return;
        };

        // Handle reservation if present
        if let Some(res_req) = pdu.reservation_req {
            self.handle_uplink_capacity_request(msg_dltime, defragbuf.addr, res_req, false);
        } else if self.channel_scheduler.packet_bearer_is_active(msg_dltime.t) && defragbuf.addr.ssi_type == SsiType::Issi {
            self.channel_scheduler
                .clear_pending_packet_data_capacity(defragbuf.addr.ssi, msg_dltime);
        }

        // Pass completed block to LLC
        tracing::debug!("rx_mac_end_ul: sdu: {:?}", defragbuf.buffer.dump_bin());

        let m = SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Umac,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                pdu: Some(defragbuf.buffer),
                main_address: defragbuf.addr,
                scrambling_code: prim.scrambling_code,
                endpoint_id: 0,        // TODO FIXME
                new_endpoint_id: None, // TODO FIXME
                css_endpoint_id: None, // TODO FIXME
                air_interface_encryption: Some(aie_request),
                chan_change_response_req: false,
                chan_change_handle: None,
                chan_info: None,
            }),
        };
        queue.push_back(m);

        // Since this is not a null pdu, more MAC PDUs may follow
        // This allows parent function to continue parsing
        prim.pdu.set_raw_end(orig_end);
        prim.pdu.set_raw_pos(prim.pdu.get_raw_start() + pdu_len_bits + num_fill_bits);
        prim.pdu.set_raw_start(prim.pdu.get_raw_pos());
    }

    fn rx_mac_end_hu(&mut self, queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_mac_end_hu");
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };
        assert!(prim.pdu.get_pos() == 0); // We should be at the start of the MAC PDU

        // Parse header and optional ChanAlloc
        let pdu = match MacEndHu::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing MacEndHu: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        // Will have either length_ind or reservation_req, never none or both
        let mut pdu_len_bits = if let Some(length_ind) = pdu.length_ind {
            if length_ind == 0 {
                // Table 21.44: length indication 0 is reserved, discard PDU
                tracing::debug!("rx_mac_end_hu: discarding PDU with reserved length indication 0");
                return;
            }
            let len = length_ind as usize * 8;
            if len > prim.pdu.get_len() { prim.pdu.get_len() } else { len }
        } else {
            // No length ind, we have capacity request. Fill slot.
            prim.pdu.get_len()
        };
        if pdu_len_bits > prim.pdu.get_len() {
            tracing::warn!("truncating MAC-END-HU len from {} to {}", pdu_len_bits, prim.pdu.get_len());
            pdu_len_bits = prim.pdu.get_len();
        }

        // Strip fill bits if any
        let num_fill_bits = {
            if pdu.fill_bits {
                fillbits::removal::get_num_fill_bits(&prim.pdu, pdu_len_bits, false)
            } else {
                0
            }
        };
        pdu_len_bits -= num_fill_bits;
        let orig_end = prim.pdu.get_raw_end();
        prim.pdu.set_raw_end(prim.pdu.get_raw_start() + pdu_len_bits);

        // set to trace
        tracing::trace!(
            "rx_mac_end_hu: pdu: {} sdu: {} fb: {}: {}",
            pdu_len_bits,
            prim.pdu.get_len_remaining(),
            num_fill_bits,
            prim.pdu.dump_bin_full(true)
        );

        // Get slot owner from schedule, decrypt if needed
        let msg_dltime = prim.ul_time;
        let Some(slot_owner) = self.channel_scheduler.ul_get_slot_owner(msg_dltime, prim.block_num) else {
            tracing::warn!("rx_mac_end_hu: Received MAC-END-HU for unassigned block {:?}", prim.block_num);
            self.channel_scheduler.dump_ul_schedule_full(true);
            return;
        };
        // MAC-END-HU has no encryption-mode bit of its own. Its payload
        // inherits the policy of the preceding MAC-ACCESS/MAC-DATA fragment;
        // decrypt only the remaining TM-SDU region with the exact UL slot
        // IV. The short MAC-END-HU header and fill bits stay clear.
        let aie_request = if let Some(request) = self.defrag.get_aie_request(slot_owner, msg_dltime) {
            let request = request.with_scope(AieScope::MacFragment);
            if request.is_encrypted() {
                let context = match self.aie_provider.resolve(request, AieDirection::Uplink, msg_dltime) {
                    Ok(context) => context,
                    Err(error) => {
                        tracing::warn!(?error, issi = slot_owner, "rejecting encrypted MAC-END-HU with stale SC2 context");
                        return;
                    }
                };
                let payload_start = prim.pdu.get_pos();
                let payload_len = prim.pdu.get_len_remaining();
                if let Err(error) = self
                    .aie_provider
                    .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
                {
                    tracing::warn!(?error, issi = slot_owner, "rejecting MAC-END-HU after SC2 cipher failure");
                    return;
                }
            }
            request
        } else {
            if !self.aie_provider.clear_uplink_allowed(slot_owner) {
                tracing::warn!(issi = slot_owner, "rejecting orphan clear MAC-END-HU from SC2-bound terminal");
                return;
            }
            AieRequest::clear(AieSubject::Individual { issi: slot_owner }, AieScope::MacFragment)
        };

        // Insert last fragment and retrieve finalized block
        let defragbuf = self.defrag.insert_last(&mut prim.pdu, slot_owner, msg_dltime);
        let Some(defragbuf) = defragbuf else {
            tracing::warn!("rx_mac_end_hu: could not obtain defragged buf");
            return;
        };

        // Handle reservation if present
        if let Some(res_req) = pdu.reservation_req {
            self.handle_uplink_capacity_request(msg_dltime, defragbuf.addr, res_req, false);
        } else if self.channel_scheduler.packet_bearer_is_active(msg_dltime.t) && defragbuf.addr.ssi_type == SsiType::Issi {
            self.channel_scheduler
                .clear_pending_packet_data_capacity(defragbuf.addr.ssi, msg_dltime);
        }

        // Pass completed block to LLC
        tracing::debug!("rx_mac_end_hu: sdu: {:?}", defragbuf.buffer.dump_bin());

        let m = SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Umac,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                pdu: Some(defragbuf.buffer),
                main_address: defragbuf.addr,
                scrambling_code: prim.scrambling_code,
                endpoint_id: 0,        // TODO FIXME
                new_endpoint_id: None, // TODO FIXME
                css_endpoint_id: None, // TODO FIXME
                air_interface_encryption: Some(aie_request),
                chan_change_response_req: false,
                chan_change_handle: None,
                chan_info: None,
            }),
        };
        queue.push_back(m);

        // Since this is not a null pdu, more MAC PDUs may follow
        // This allows parent function to continue parsing
        // tracing::trace!("rx_mac_end_hu: orig_end {} raw_start {} num_fill_bits {} curr_pos {}", orig_end, prim.pdu.get_raw_start(), num_fill_bits, prim.pdu.get_raw_pos());
        prim.pdu.set_raw_end(orig_end);
        prim.pdu.set_raw_pos(prim.pdu.get_raw_start() + pdu_len_bits + num_fill_bits);
        prim.pdu.set_raw_start(prim.pdu.get_raw_pos());
    }

    /// UL MAC-U-SIGNAL on STCH: extract TM-SDU and forward to LLC → MLE → CMCE.
    /// This carries signaling like U-TX CEASED / U-TX DEMAND on the traffic channel.
    fn rx_ul_mac_u_signal(&self, queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_ul_mac_u_signal");

        // Extract sdu and parse pdu
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let pdu = match MacUSignal::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing MacUSignal: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        if pdu.second_half_stolen {
            tracing::warn!("rx_ul_mac_u_signal: second_half_stolen not implemented");
            return;
        }

        // The remaining bits after the MAC-U-SIGNAL header are the TM-SDU (LLC PDU)
        if prim.pdu.get_len_remaining() == 0 {
            tracing::trace!("rx_ul_mac_u_signal: empty TM-SDU");
            return;
        }

        // MAC-U-SIGNAL has no address field. Its three-bit header remains
        // clear, while the TM-SDU is protected with the active traffic/FACCH
        // context. The floor holder supplied by CMCE is therefore the only
        // valid identity to attach to U-TX CEASED; forwarding SSI 0 caused
        // CMCE to discard a genuine PTT release and wait for the UL timeout.
        let ts = prim.ul_time.t;
        if !(1..=4).contains(&ts) {
            tracing::warn!(ts, "discarding MAC-U-SIGNAL on an invalid timeslot");
            return;
        }
        let Some(issi) = self.traffic_floor_holder.get(ts as usize - 1).copied().flatten() else {
            tracing::warn!(ts, "discarding MAC-U-SIGNAL without a current floor-holder identity");
            return;
        };
        let request = self
            .uplink_traffic_aie
            .get(ts as usize - 1)
            .copied()
            .flatten()
            .unwrap_or_else(|| AieRequest::clear(AieSubject::Individual { issi }, AieScope::Facch));
        let payload_start = prim.pdu.get_pos();
        let payload_len = prim.pdu.get_len_remaining();
        if request.is_encrypted() {
            let context = match self
                .aie_provider
                .resolve(request.with_scope(AieScope::Facch), AieDirection::Uplink, prim.ul_time)
            {
                Ok(context) => context,
                Err(error) => {
                    tracing::warn!(?error, ts, ul_time = %prim.ul_time, "discarding encrypted MAC-U-SIGNAL without a valid SC2 context");
                    return;
                }
            };
            if let Err(error) = self
                .aie_provider
                .cipher_uplink_mac(context, &mut prim.pdu, payload_start, payload_len)
            {
                tracing::warn!(?error, ts, issi, "discarding encrypted MAC-U-SIGNAL after SC2 decrypt failure");
                return;
            }
        }

        let sdu = BitBuffer::from_bitbuffer_pos(&prim.pdu);
        tracing::debug!("rx_ul_mac_u_signal: forwarding {} bit TM-SDU to LLC", sdu.get_len());

        // Forward to LLC via TMA-SAP, same path as MAC-DATA.
        // Address is not carried in MAC-U-SIGNAL, so carry the currently
        // assigned floor-holder identity that scoped the traffic context.
        let m = SapMsg {
            sap: Sap::TmaSap,
            src: TetraEntity::Umac,
            dest: TetraEntity::Llc,
            msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
                pdu: Some(sdu),
                main_address: TetraAddress::issi(issi),
                scrambling_code: prim.scrambling_code,
                endpoint_id: 0,
                new_endpoint_id: None,
                css_endpoint_id: None,
                air_interface_encryption: Some(request.with_scope(AieScope::Facch)),
                chan_change_response_req: false,
                chan_change_handle: None,
                chan_info: None,
            }),
        };
        queue.push_back(m);
    }

    /// TMA-SAP MAC-U-BLCK
    fn rx_ul_mac_u_blck(&self, _queue: &mut MessageQueue, message: &mut SapMsg) {
        tracing::trace!("rx_ul_mac_u_blck");

        // Extract sdu and parse pdu
        let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
            panic!()
        };

        let _pdu = match MacUBlck::from_bitbuf(&mut prim.pdu) {
            Ok(pdu) => {
                tracing::debug!("<- {:?}", pdu);
                pdu
            }
            Err(e) => {
                tracing::warn!("Failed parsing MacUBlck: {:?} {}", e, prim.pdu.dump_bin());
                return;
            }
        };

        // Handle reservation if present
        // TODO implement slightly different handling since enum is not the same.
        unimplemented!();
    }

    fn rx_ul_tma_unitdata_req(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_ul_tma_unitdata_req");

        let missing_downlink_dck = match &message.msg {
            SapMsgInner::TmaUnitdataReq(prim) => match prim.air_interface_encryption {
                Some(AieRequest::Sc3 {
                    subject: AieSubject::Individual { issi },
                    key: None,
                    ..
                }) if !self.aie_provider.has_sc3_dck(issi) => Some(issi),
                _ => None,
            },
            _ => None,
        };
        if let Some(issi) = missing_downlink_dck {
            self.aie_provider.request_sc3_dck(issi);
            if self.pending_sc3_downlink.len() >= 64
                && let Some(expired) = self.pending_sc3_downlink.pop_front()
            {
                Self::discard_pending_downlink(expired.message);
            }
            self.pending_sc3_downlink.push_back(PendingSc3Downlink {
                issi,
                expires_at: self.dltime.add_timeslots(4 * 18),
                message,
            });
            tracing::info!(issi, "deferred encrypted SC3 downlink pending on-demand DCK");
            return;
        }

        // Extract sdu
        let SapMsgInner::TmaUnitdataReq(mut prim) = message.msg else { panic!() };
        // Group-addressed control on this call's assigned channel must use
        // the same GCK as its speech. FACCH carries the traffic slot in the
        // channel allocation rather than associated_channel, so cover both.
        let call_channel = prim.associated_channel.map(|channel| (channel.timeslot, Some(channel.call_id)))
            .or_else(|| prim.stealing_permission.then(|| {
                prim.chan_alloc.as_ref().and_then(|allocation| allocation.timeslots.iter().position(|&set| set))
                    .map(|index| ((index + 1) as u8, None))
            }).flatten());
        if let Some((ts, call_id)) = call_channel
            && (1..=4).contains(&ts)
            && let Some((owner, group, key)) = self.group_call_key[ts as usize - 1]
            && call_id.is_none_or(|call_id| call_id == owner)
            && prim.main_address.ssi_type == SsiType::Gssi
            && let Some(AieRequest::Sc3 { subject: AieSubject::Group { gssi }, scope, .. }) = prim.air_interface_encryption
            && gssi == group && gssi == prim.main_address.ssi
        {
            prim.air_interface_encryption = Some(AieRequest::sc3_with_key(AieSubject::Group { gssi }, scope, key));
        }
        if let Some(activation) = prim.frame18_rollover_activation {
            // EN 300 392-7 4.5.5.6 defines Immediate as the first TS of the
            // next downlink multiframe.  The MM emits the marker two UMAC
            // scheduler ticks before the four preceding FN18 resources are
            // built, allowing for MM -> MLE -> LLC -> UMAC routing. It is
            // deliberately not eligible for normal all-MS traffic fan-out:
            // UMAC reserves all four physical FN18 resources itself.
            let final_frame18 = activation.add_timeslots(-4);
            if prim.main_address.ssi != 0x00ff_ffff
                || prim.main_address.ssi_type != SsiType::Gssi
                || prim.associated_channel.is_some()
                || prim.chan_alloc.is_some()
                || activation.t != 1
                || activation.f != 1
                || final_frame18 != self.dltime.add_timeslots(2)
            {
                tracing::error!(
                    dltime = %self.dltime,
                    activation = %activation,
                    address = ?prim.main_address,
                    "discarding invalid or late final SC3G GCK rollover Immediate request"
                );
                return;
            }
            let aie_request = prim
                .air_interface_encryption
                .unwrap_or_else(|| AieRequest::clear(AieSubject::System, AieScope::MacResource));
            let mut pdu = MacResource {
                fill_bits: false,
                pos_of_grant: 0,
                encryption_mode: 0,
                random_access_flag: false,
                length_ind: 0,
                addr: Some(prim.main_address),
                event_label: None,
                usage_marker: None,
                power_control_element: None,
                slot_granting_element: None,
                chan_alloc_element: None,
            };
            pdu.update_len_and_fill_ind(prim.pdu.get_len());
            if let Err(error) = self
                .channel_scheduler
                .reserve_gck_rollover_immediate(activation, pdu, prim.pdu, aie_request)
            {
                tracing::error!(dltime = %self.dltime, activation = %activation, error, "cannot reserve final SC3G GCK rollover Immediate resources");
            } else {
                tracing::info!(dltime = %self.dltime, activation = %activation, "reserved final all-timeslot SC3G GCK rollover Immediate resources");
            }
            return;
        }
        let all_ms_traffic_broadcast = prim.stealing_permission
            && prim.main_address.ssi == 0x00ff_ffff
            && prim.main_address.ssi_type == SsiType::Gssi
            && prim.associated_channel.is_none()
            && prim.chan_alloc.is_none();
        if all_ms_traffic_broadcast {
            let channels = self.channel_scheduler.active_downlink_traffic_channels();
            for (timeslot, usage) in &channels {
                let mut copy = prim.clone();
                // Keep the all-MS broadcast address on assigned channels.
                // TTR 001-11 §6.2.7.1 permits a broadcast CK change on any
                // channel. Its §6.2.10 reserves CMG GSSIs for group-addressed
                // security signalling; the active *talkgroup* is not a CMG.
                // Readdressing this MM PDU to the talkgroup made it invisible
                // to MS-MM during the observed in-call GCK rollover.
                // The synthetic association is routing-only. call_id zero is
                // never exposed on air; timeslot selects the TCH. Its usage
                // marker is route metadata, not part of this broadcast PDU.
                copy.associated_channel = Some(AssociatedChannel {
                    call_id: 0,
                    timeslot: *timeslot,
                    usage: *usage,
                    best_effort_key: None,
                });
                self.rx_ul_tma_unitdata_req(
                    queue,
                    SapMsg::new(Sap::TmaSap, TetraEntity::Llc, TetraEntity::Umac, SapMsgInner::TmaUnitdataReq(copy)),
                );
            }
            tracing::info!(
                channels = channels.len(),
                "fanned all-MS D-CK CHANGE broadcast out over active traffic channels"
            );
            return;
        }
        let mut sdu = prim.pdu;
        let associated_channel = prim.associated_channel;
        let assigned_channel_frame18_broadcast = prim.assigned_channel_frame18_broadcast;
        let aie_request = prim.air_interface_encryption.unwrap_or_else(|| {
            AieRequest::clear(
                AieSubject::Individual {
                    issi: prim.main_address.ssi,
                },
                AieScope::MacResource,
            )
        });

        // ── FACCH/Stealing path ──────────────────────────────────────────
        // stealing_permission → STCH on traffic channel for time-critical signaling
        // (D-TX CEASED, D-TX GRANTED) per EN 300 392-2, clause 23.5.
        // CRITICAL: DL STCH uses MAC-RESOURCE (124-bit half-slot), NOT MAC-U-SIGNAL (UL-only).
        if prim.stealing_permission {
            // Determine the target traffic timeslot for FACCH stealing.
            // If chan_alloc specifies a timeslot, use it; otherwise fall back to first active DL circuit.
            let traffic_ts = associated_channel
                .map(|channel| channel.timeslot)
                .or_else(|| {
                    prim.chan_alloc
                        .as_ref()
                        .and_then(|ca| ca.timeslots.iter().enumerate().find(|&(_, &set)| set).map(|(i, _)| (i + 1) as u8))
                })
                .or_else(|| (2..=4u8).find(|&t| self.channel_scheduler.circuit_is_active(Direction::Dl, t)));

            if let Some(ts) = traffic_ts {
                // Build MAC-RESOURCE PDU for the STCH half-slot (124 type1 bits).
                // Same format as MCCH signaling, just in 124 bits instead of 268.
                const STCH_CAP: usize = 124;
                const NULL_PDU_LEN_BITS: usize = 16;

                let all_ms_address = prim.main_address.ssi == 0x00ff_ffff && prim.main_address.ssi_type == SsiType::Gssi;
                // The traffic bearer identifies the associated call. The
                // synthetic call_id 0 is used for the all-MS fan-out, even
                // when its on-air copy is addressed to the actual group. A
                // usage marker adds six bits and makes the Absolute-IV PDU
                // overflow this 124-bit STCH half-slot after octet fill.
                let broadcast_copy = associated_channel.is_some_and(|channel| channel.call_id == 0);
                let usage_marker = if all_ms_address || broadcast_copy {
                    None
                } else {
                    associated_channel
                        .map(|channel| channel.usage)
                        .or_else(|| prim.chan_alloc.as_ref().and_then(|ca| ca.usage))
                };
                // Per ETSI 21.4.3.1: "The random access flag shall be used for the BS to
                // acknowledge a successful random access so as to prevent the MS sending
                // further random access requests."
                // Set the flag if this address has a pending RA (dropped by
                // dl_drop_all_except_stolen when leaving hangtime), or if the address
                // is ISSI (direct CC-level response to a MAC-ACCESS).
                let has_pending_ra = self.channel_scheduler.take_pending_ra_ack(ts, prim.main_address.ssi);
                let is_random_access_response = has_pending_ra || prim.main_address.ssi_type == SsiType::Issi;
                let mut mac_pdu = MacResource {
                    fill_bits: false,
                    pos_of_grant: 0,
                    encryption_mode: 0,
                    random_access_flag: is_random_access_response,
                    length_ind: 0,
                    addr: Some(prim.main_address),
                    event_label: None,
                    usage_marker,
                    power_control_element: None,
                    slot_granting_element: None,
                    chan_alloc_element: None,
                };
                // FACCH has the same SC2 MAC-RESOURCE addressing rules as
                // an SCH/F resource, but its payload ciphering is deferred
                // to LMAC where the actual burst time is known.  Resolving
                // here is used only to validate the key identity and derive
                // an encrypted short identity (IESI/GESI); no keystream is
                // generated at this layer.
                if let AieRequest::Sc2 { subject, .. } | AieRequest::Sc3 { subject, .. } = aie_request {
                    let context = match self.aie_provider.resolve(aie_request, AieDirection::Downlink, self.dltime) {
                        Ok(context) => context,
                        Err(error) => {
                            tracing::warn!(?error, ts, "dropping FACCH without a valid SC2 context");
                            return;
                        }
                    };
                    let Some(address) = mac_pdu.addr.as_mut() else {
                        tracing::warn!(ts, "dropping SC2 FACCH without a MAC address");
                        return;
                    };
                    let compatible = match subject {
                        AieSubject::Individual { .. } => matches!(address.ssi_type, SsiType::Issi | SsiType::Ssi),
                        AieSubject::Group { .. } => address.ssi_type == SsiType::Gssi,
                        _ => false,
                    };
                    if !compatible {
                        tracing::warn!(ts, address_type = ?address.ssi_type, "dropping FACCH with an incompatible SC2 address");
                        return;
                    }
                    match self.aie_provider.encrypted_short_identity(context, address.ssi) {
                        Ok(esi) => {
                            address.ssi = esi;
                            address.ssi_type = SsiType::Esi;
                        }
                        Err(error) => {
                            tracing::warn!(?error, ts, "dropping FACCH with an invalid SC2 encrypted short identity");
                            return;
                        }
                    }
                    mac_pdu.encryption_mode = match context {
                        tetra_core::AieContext::Sc2 { key, .. } => 0b10 | (key.sck_vn as u8 & 1),
                        tetra_core::AieContext::Sc3 { key, .. } => 0b10 | (key.cck_id as u8 & 1),
                        tetra_core::AieContext::Clear { .. } => 0,
                    };
                }
                let sdu_len = sdu.get_len();
                let num_fill_bits = mac_pdu.update_len_and_fill_ind(sdu_len);
                let header_len = mac_pdu.compute_header_len();
                let encoded_len = header_len + sdu_len + num_fill_bits;
                if encoded_len > STCH_CAP {
                    tracing::warn!(
                        ts,
                        address = ?prim.main_address,
                        header_bits = header_len,
                        sdu_bits = sdu_len,
                        fill_bits = num_fill_bits,
                        encoded_bits = encoded_len,
                        capacity_bits = STCH_CAP,
                        "dropping signalling PDU that does not fit in one STCH half-slot"
                    );
                    return;
                }
                let cipher_region = aie_request.is_encrypted().then(|| {
                    // STCH begins directly with MAC-RESOURCE on downlink.
                    AieCipherRegion::new(header_len, sdu_len)
                });

                let mut stch_block = BitBuffer::new(STCH_CAP);
                mac_pdu.to_bitbuf(&mut stch_block);

                // Copy LLC PDU (BL-DATA) directly — no conversion needed.
                // Both BL-DATA and BL-UDATA are valid D-LLC-PDU types per the spec.
                sdu.seek(0);
                stch_block.copy_bits(&mut sdu, sdu_len);

                // ETSI 23.4.3.1 fill bit addition: a '1' immediately after the TM-SDU,
                // then zeros up to the indicated length. Without the leading '1', a
                // receiver performing the mandated fill bit deletion (23.4.3.2) strips
                // backwards past the fill region into the PDU and corrupts its tail.
                fillbits::addition::write(&mut stch_block, Some(num_fill_bits));

                // Complete the remaining half-slot capacity with a Null PDU followed by
                // a '1' and zeros (ETSI 23.4.2.2), instead of leaving raw zeros.
                if stch_block.get_len_remaining() >= NULL_PDU_LEN_BITS {
                    let mut null_pdu = MacResource::null_pdu();
                    let _ = null_pdu.update_len_and_fill_ind(0);
                    null_pdu.to_bitbuf(&mut stch_block);
                }
                if stch_block.get_len_remaining() > 0 {
                    stch_block.write_bit(1);
                    // Rest of the buffer is already zeroed.
                }

                tracing::info!(
                    dltime = %self.dltime,
                    ts,
                    address = ?prim.main_address,
                    random_access_flag = is_random_access_response,
                    associated_channel = ?associated_channel,
                    sdu_bits = sdu_len,
                    stch_bits = stch_block.get_len(),
                    "queueing FACCH/STCH floor-control block"
                );

                self.channel_scheduler
                    .dl_enqueue_stealing(ts, stch_block, prim.tx_reporter, aie_request, cipher_region);

                return;
            } else {
                tracing::warn!("rx_ul_tma_unitdata_req: stealing requested but no active DL circuit, falling back to MCCH");
                // Fall through to normal MCCH path below
            }
        }

        // ── Normal signaling path (MCCH / SCH/F) ────────────────────────
        // Every group-addressed MCCH resource (including D-SETUP and SDS)
        // needs one replay per distinct EE monitoring phase. Associated
        // traffic-channel delivery remains a bypass: the MS listens there on
        // every frame and must not get MCCH duplicates.
        let group_ee_replay = associated_channel.is_none() && prim.main_address.ssi_type == SsiType::Gssi;
        let (usage_marker, mac_chan_alloc) = if let Some(chan_alloc) = prim.chan_alloc.as_ref() {
            (
                chan_alloc.usage,
                Some(Self::cmce_to_mac_chanalloc(&chan_alloc, self.config.config().cell.main_carrier)),
            )
        } else {
            (None, None)
        };
        // Build MAC-RESOURCE optimistically (as if it would always fit in one slot).
        // This is not, merely by being ISSI-addressed, an answer to a random
        // access request.  In particular SDS and private-call signalling to a
        // listening terminal are unsolicited.  Marking those resources as a
        // random-access response makes an MS that did not request access drop
        // them.  The scheduler sets this flag only when it integrates a real
        // queued RandomAccessAck for the same address.
        let is_random_access_response = false;
        let mut pdu = MacResource {
            fill_bits: false, // Updated later
            pos_of_grant: 0,
            encryption_mode: 0,
            random_access_flag: is_random_access_response,
            length_ind: 0, // Updated later
            addr: Some(prim.main_address),
            event_label: None,
            usage_marker,
            power_control_element: None,
            slot_granting_element: None,
            chan_alloc_element: mac_chan_alloc,
        };
        self.apply_packet_event_label_addressing(prim.main_address, associated_channel, prim.chan_alloc.as_ref(), &sdu, &mut pdu);
        pdu.update_len_and_fill_ind(sdu.get_len());

        if group_ee_replay {
            let all_ms = prim.main_address.ssi == 0x00ff_ffff && prim.main_address.ssi_type == SsiType::Gssi;
            let (assignments, rollover_activation, all_ms_rollover) = {
                let state = self.config.state_read();
                // The all-ones broadcast address has no group affiliates.
                // Full GCK-VN advertisements (TTR 001-11 table 1) must also
                // reach sleeping MSs when no SCK rollover is pending.
                // Respect their negotiated reception pattern, TS 100 392-2
                // 23.7.6, rather than looking up a fictitious talkgroup.
                let rollover = all_ms.then(|| {
                    state.aie.rollover_notification().map(|(_, activation)| activation)
                        .or_else(|| state.aie.sc3.as_ref()?.gck_rollover_notification()
                            .map(|(_, _, activation)| activation))
                }).flatten();
                let assignments = if all_ms_traffic_broadcast {
                    // MM also sends an MCCH copy of these TCH/STCH notices.
                    // Replay that copy once per listening phase, not both.
                    Vec::new()
                } else if all_ms {
                    state.subscribers.active_energy_economies()
                } else {
                    state.subscribers.group_energy_economies(prim.main_address.ssi)
                };
                (
                    assignments,
                    rollover.flatten(),
                    rollover.is_some(),
                )
            };
            // `(time, copy)` de-duplicates terminals sharing one EE phase,
            // while retaining both independently decodable rollover copies.
            let mut scheduled: Vec<(TdmaTime, usize)> = Vec::new();
            for (issi, mode, frame, multiframe) in assignments {
                let Some(due) = self.next_energy_economy_mcch_for_assignment(mode, frame, multiframe) else {
                    continue;
                };
                if !Self::ee_replay_is_usable(due, self.dltime, rollover_activation) {
                    continue;
                }

                let period_frames = Self::energy_economy_period_frames(mode).expect("valid EE assignment");
                let second = due.add_timeslots(period_frames * 4);
                let second = if rollover_activation.is_none_or(|activation| activation.diff(second) > 0) {
                    second
                } else {
                    // If only one EE occasion remains, put two all-MS PDUs in
                    // that reception window instead of leaking an obsolete
                    // Absolute-IV demand past cutover.
                    due
                };
                let opportunities = if all_ms_rollover { vec![due, second] } else { vec![due] };
                for (copy, opportunity) in opportunities.into_iter().enumerate() {
                    if scheduled.contains(&(opportunity, copy)) {
                        continue;
                    }
                    tracing::debug!(
                        gssi = prim.main_address.ssi,
                        issi,
                        due = %opportunity,
                        copy = copy + 1,
                        rollover = all_ms_rollover,
                        "queuing EE-aligned group-MCCH broadcast replay"
                    );
                    scheduled.push((opportunity, copy));
                    self.deferred_mcch.push_back(DeferredMcch {
                        due: opportunity,
                        pdu: pdu.clone(),
                        sdu: sdu.clone(),
                        tx_reporter: None,
                        aie_request,
                        ee_retry: all_ms.then_some(EeReplayRetry {
                            period_slots: period_frames * 4,
                            attempts_left: 4,
                            cutoff: rollover_activation,
                            in_flight: None,
                        }),
                    });
                }
            }
        }

        // Ordinary individually addressed MCCH signalling is sent only at a
        // terminal's EE monitoring opportunity. A known associated channel
        // means the terminal is on TCH and listens continuously, so it is an
        // explicit bypass (as are FACCH resources handled above).
        if associated_channel.is_none() && prim.main_address.ssi_type == SsiType::Issi {
            // ETSI TS 100 392-2 §21.4.3.1 requires the random-access flag to
            // stop retransmissions. The matching response is therefore sent
            // immediately while that acknowledgement remains queued, rather
            // than waiting for a later EE monitoring occasion.
            let random_access_response = self.channel_scheduler.has_pending_random_access_ack(prim.main_address.ssi);
            let (activation_response, direct_response_window) = {
                let mut state = self.config.state_write();
                (
                    state.subscribers.take_energy_economy_activation_pending(prim.main_address.ssi),
                    state.subscribers.direct_response_window_active(prim.main_address.ssi, self.dltime),
                )
            };
            if direct_response_window {
                tracing::debug!(
                    issi = prim.main_address.ssi,
                    "sending correlated MAC-ACCESS response without EE deferral"
                );
            }
            if !activation_response && !random_access_response && !direct_response_window {
                if let Some(due) = self.next_energy_economy_mcch(prim.main_address.ssi) {
                    tracing::debug!(issi = prim.main_address.ssi, due = %due, "deferring MCCH resource for EE monitoring occasion");
                    self.deferred_mcch.push_back(DeferredMcch {
                        due,
                        pdu,
                        sdu,
                        tx_reporter: prim.tx_reporter,
                        aie_request,
                        ee_retry: None,
                    });
                    return;
                }
            }
        }

        // // Per ETSI EN 300 392-2 Clause 23.3.1.1.2: idle MSes monitor the MCCH (slot 1)
        // // for signaling. Without common SCCHs, all MSes listen on slot 1.
        // // All signaling on the normal path (non-FACCH) must go to the MCCH.
        // if message.dltime.t != 1 {
        //     tracing::warn!("rx_ul_tma_unitdata_req: signaling scheduled for non-MCCH {}", message.dltime.t);
        // }
        // self.channel_scheduler.dl_enqueue_tma(message.dltime.t, pdu, sdu, prim.tx_reporter);

        if assigned_channel_frame18_broadcast {
            let valid_broadcast = associated_channel.is_none()
                && prim.chan_alloc.is_none()
                && prim.main_address.ssi == 0x00ff_ffff
                && prim.main_address.ssi_type == SsiType::Gssi;
            if valid_broadcast {
                let channels = self.channel_scheduler.active_assigned_channels();
                for timeslot in channels.iter().copied() {
                    self.channel_scheduler
                        .dl_enqueue_associated_frame18_broadcast(timeslot, pdu.clone(), sdu.clone(), aie_request);
                }
                tracing::debug!(
                    channels = channels.len(),
                    "queued D-NWRK-BROADCAST for free FN18 slots on active assigned channels"
                );
            } else {
                tracing::warn!(
                    address = ?prim.main_address,
                    ?associated_channel,
                    has_channel_allocation = prim.chan_alloc.is_some(),
                    "ignoring invalid assigned-channel frame-18 broadcast marker"
                );
            }
        }

        if let Some(channel) = associated_channel {
            // A late-entry D-SETUP is transmitted where the target MS is
            // believed to be listening, while its channel allocation points
            // at the *new* call.  Do not discard that association merely
            // because the MAC-RESOURCE carries a channel allocation.
            if (2..=4).contains(&channel.timeslot) && self.channel_scheduler.assigned_channel_is_active(channel.timeslot) {
                if let Some(key) = channel.best_effort_key {
                    // Periodic cross-call D-SETUP copies are expendable and
                    // coalesced separately from all ordinary signalling.
                    self.channel_scheduler
                        .dl_enqueue_associated_best_effort_tma(channel.timeslot, key, pdu, sdu, aie_request);
                } else if self.channel_scheduler.packet_bearer_is_active(channel.timeslot) {
                    let mut packet_data_slots = [false; 4];
                    if let Some(routes) = self
                        .config
                        .state_read()
                        .subscriber_packet_delivery_routes
                        .get(&prim.main_address.ssi)
                    {
                        for route in routes.iter().filter(|route| route.call_id == channel.call_id) {
                            if (2..=4).contains(&route.timeslot) && self.channel_scheduler.packet_bearer_is_active(route.timeslot) {
                                packet_data_slots[route.timeslot as usize - 1] = true;
                            }
                        }
                    }
                    // Keep a valid single-slot route during the brief state
                    // propagation window in which LLC already knows the
                    // associated bearer but the shared route set is not yet
                    // complete.
                    packet_data_slots[channel.timeslot as usize - 1] = true;
                    tracing::debug!(
                        ?channel,
                        ?packet_data_slots,
                        "routing SNDCP signalling through assigned packet channel"
                    );
                    self.channel_scheduler.dl_enqueue_packet_tma_on_timeslot(
                        channel.timeslot,
                        pdu,
                        sdu,
                        prim.tx_reporter,
                        aie_request,
                        packet_data_slots,
                    );
                } else {
                    let hangtime = self.channel_scheduler.is_hangtime(channel.timeslot);
                    let ul_active = self.channel_scheduler.circuit_is_active(Direction::Ul, channel.timeslot);
                    if !hangtime && ul_active {
                        // Keep the PDU grant-free until the scheduler knows which
                        // FN18 will actually transmit it. A mandatory BSCH/BNCH
                        // can defer this queue entry by one or more multiframes.
                        tracing::debug!(?channel, "routing ordinary signalling through associated FN18 control queue");
                        self.channel_scheduler
                            .dl_enqueue_associated_tma(channel.timeslot, pdu, sdu, prim.tx_reporter, aie_request);
                    } else {
                        tracing::debug!(
                            ?channel,
                            hangtime,
                            ul_active,
                            "routing ordinary signalling through associated non-traffic signalling queue"
                        );
                        self.channel_scheduler
                            .dl_enqueue_tma_on_timeslot(channel.timeslot, pdu, sdu, prim.tx_reporter, aie_request);
                    }
                }
            } else if channel.best_effort_key.is_some() {
                // The normal MCCH late-entry copy is already queued. A stale
                // expendable cross-call route must not create another MCCH PDU.
                tracing::debug!(?channel, "dropping stale best-effort associated repeat");
            } else {
                tracing::warn!(?channel, "invalid or stale associated-channel context; using MCCH");
                self.channel_scheduler.dl_enqueue_tma(pdu, sdu, prim.tx_reporter, aie_request);
            }
        } else {
            self.channel_scheduler.dl_enqueue_tma(pdu, sdu, prim.tx_reporter, aie_request);
        }

        // let enqueue_ts = 1;
        // self.channel_scheduler.dl_enqueue_tma(enqueue_ts, pdu, sdu, prim.tx_reporter);
    }

    fn discard_pending_downlink(message: SapMsg) {
        if let SapMsgInner::TmaUnitdataReq(prim) = message.msg
            && let Some(reporter) = prim.tx_reporter
            && reporter.get_state() == tetra_core::TxState::Pending
        {
            reporter.mark_discarded();
        }
    }

    fn rx_tma_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tma_prim");
        match message.msg {
            SapMsgInner::TmaUnitdataReq(_) => {
                self.rx_ul_tma_unitdata_req(queue, message);
            }
            _ => panic!(),
        }
    }

    fn rx_tlmb_prim(&mut self, _queue: &mut MessageQueue, _message: SapMsg) {
        tracing::trace!("rx_tlmb_prim");
        panic!()
    }

    fn rx_tmd_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_tmd_prim");

        let src = message.src;
        match message.msg {
            // DL voice from Brew/upper layer → schedule for DL transmission
            SapMsgInner::TmdCircuitDataReq(prim) => {
                let ts = prim.ts;
                // Network-originated group audio has no local UL speaker, so
                // it keeps the group-call watchdog alive. Never use private
                // duplex downlink audio as evidence of its endpoint's UL: it
                // can be the surviving peer talking to a vanished terminal.
                if (1..=4).contains(&ts)
                    && self.channel_scheduler.circuit_is_active(Direction::Ul, ts)
                    && !self.duplex_private_media_timeslots.contains(&ts)
                {
                    self.last_ul_voice[ts as usize - 1] = Some(self.dltime);
                }
                if self.channel_scheduler.circuit_is_active(Direction::Dl, ts) {
                    if (1..=4).contains(&ts)
                        && src == TetraEntity::Swmi
                        && let Some(call_id) = self.traffic_call_owner[ts as usize - 1]
                        && self.first_central_downlink_voice[ts as usize - 1] != Some(call_id)
                    {
                        self.first_central_downlink_voice[ts as usize - 1] = Some(call_id);
                        tracing::info!(
                            call_id,
                            ts,
                            dltime = %self.dltime,
                            "first central voice frame admitted to RF traffic scheduler"
                        );
                    }
                    self.channel_scheduler.dl_schedule_tmd(ts, prim.data);
                } else {
                    tracing::warn!(
                        "rx_tmd_prim: dropping DL voice on inactive circuit ts={} src={:?} dltime={}",
                        ts,
                        src,
                        self.dltime
                    );
                }
            }
            // UL voice from LMAC → forward to Brew + optional loopback to DL
            SapMsgInner::TmdCircuitDataInd(prim) => {
                let ts = prim.ts;
                let data = prim.data;
                if (1..=4).contains(&ts)
                    && let Some(issi) = self.traffic_floor_holder[ts as usize - 1]
                {
                    self.observe_terminal_rf(issi, prim.ul_time, prim.rf_observation, prim.block_ok);
                }
                if data.is_empty() {
                    return;
                }

                // Track last UL voice frame time for inactivity detection
                if (1..=4).contains(&ts) {
                    self.last_ul_voice[ts as usize - 1] = Some(self.dltime);
                }

                // Forward UL voice to configured network user-plane bridges.
                // SwMI receives the native TMD boundary and authorizes it
                // against its central call/floor state before redistribution.
                if self.config.config().brew.is_some() {
                    if self.channel_scheduler.circuit_is_active(Direction::Ul, ts) {
                        let msg = SapMsg {
                            sap: Sap::TmdSap,
                            src: TetraEntity::Umac,
                            dest: TetraEntity::Brew,
                            msg: SapMsgInner::TmdCircuitDataInd(tetra_saps::tmd::TmdCircuitDataInd {
                                ts,
                                ul_time: prim.ul_time,
                                data: data.clone(),
                                block_ok: true,
                                rf_observation: None,
                            }),
                        };
                        queue.push_back(msg);
                    } else {
                        tracing::trace!("rx_tmd_prim: no active UL circuit on ts={}, dropping UL voice to Brew", ts);
                    }
                }

                if self.config.config().swmi.is_some() {
                    if self.channel_scheduler.circuit_is_active(Direction::Ul, ts) {
                        queue.push_back(SapMsg {
                            sap: Sap::TmdSap,
                            src: TetraEntity::Umac,
                            dest: TetraEntity::Swmi,
                            msg: SapMsgInner::TmdCircuitDataInd(tetra_saps::tmd::TmdCircuitDataInd {
                                ts,
                                ul_time: prim.ul_time,
                                data: data.clone(),
                                block_ok: true,
                                rf_observation: None,
                            }),
                        });
                    }
                }

                // Loopback only if there's an active DL circuit on this timeslot
                if self.channel_scheduler.circuit_is_active(Direction::Dl, ts) && !self.private_media_timeslots.contains(&ts) {
                    tracing::trace!("rx_tmd_prim: loopback UL voice on ts={}", ts);
                    if let Some(packed) = pack_ul_acelp_bits(&data) {
                        self.channel_scheduler.dl_schedule_tmd(ts, packed);
                    } else {
                        tracing::warn!(
                            "rx_tmd_prim: unsupported UL voice length {} on ts={}, skipping loopback",
                            data.len(),
                            ts
                        );
                    }
                } else if self.private_media_timeslots.contains(&ts) {
                    tracing::trace!(
                        "rx_tmd_prim: private voice is routed to peer circuit, skipping local loopback on ts={}",
                        ts
                    );
                } else {
                    tracing::trace!("rx_tmd_prim: no active DL circuit on ts={}, skipping loopback", ts);
                }
            }
            _ => {
                tracing::warn!("rx_tmd_prim: unexpected message type");
            }
        }
    }

    fn signal_lmac_second_half_stolen(&mut self, queue: &mut MessageQueue) {
        // Signal LMAC that Block2 is also stolen (STCH, not TCH).
        // Must be Immediate priority so LMAC sees it before processing Block2.
        let m = SapMsg {
            sap: Sap::TmvSap,
            src: self.self_component,
            dest: TetraEntity::Lmac,
            msg: SapMsgInner::TmvConfigureReq(TmvConfigureReq {
                blk2_stolen: Some(true),
                ..Default::default()
            }),
        };
        queue.push_prio(m, MessagePrio::Immediate);
    }

    // fn rx_stch_second_half(&mut self, queue: &mut MessageQueue, message: &mut SapMsg, pending: PendingStch) {
    //     let SapMsgInner::TmvUnitdataInd(prim) = &mut message.msg else {
    //         panic!()
    //     };

    //     // Sanity checks
    //     assert!(prim.logical_channel == LogicalChannel::Stch, "rx_stch_second_half: expected STCH logical channel, got {:?}", prim.logical_channel);
    //     assert!(prim.block_num == PhyBlockNum::Block2, "rx_stch_second_half: expected Block2, got {:?}", prim.block_num);
    //     assert!(self.pending_stch.is_some(), "rx_stch_second_half: no pending STCH, cannot process second half");

    //     let mut first = pending.sdu_part;
    //     first.seek(0);
    //     let first_len = first.get_len_remaining();
    //     prim.pdu.seek(0);
    //     let second_len = prim.pdu.get_len_remaining();

    //     self.rx_mac_access(queue, message);

    //     let mut combined = BitBuffer::new(first_len + second_len);
    //     combined.copy_bits(&mut first, first_len);
    //     combined.copy_bits(&mut prim.pdu, second_len);
    //     combined.seek(0);

    //     if pending.fill_bits {
    //         let total_len = combined.get_len();
    //         let num_fill_bits = fillbits::removal::get_num_fill_bits(&combined, total_len, false);
    //         if num_fill_bits > 0 {
    //             combined.set_raw_end(total_len - num_fill_bits);
    //         }
    //         combined.seek(0);
    //     }

    //     let m = SapMsg {
    //         sap: Sap::TmaSap,
    //         src: TetraEntity::Umac,
    //         dest: TetraEntity::Llc,
    //         dltime: message.dltime,
    //         msg: SapMsgInner::TmaUnitdataInd(TmaUnitdataInd {
    //             pdu: Some(combined),
    //             main_address: pending.addr,
    //             scrambling_code: pending.scrambling_code,
    //             endpoint_id: 0,
    //             new_endpoint_id: None,
    //             css_endpoint_id: None,
    //             air_interface_encryption: pending.encrypted as Todo,
    //             chan_change_response_req: false,
    //             chan_change_handle: None,
    //             chan_info: None,
    //         }),
    //     };
    //     queue.push_back(m);
    // }

    fn owns_traffic_slot(&self, call_id: u16, ts: u8) -> bool {
        (1..=4).contains(&ts) && self.traffic_call_owner[ts as usize - 1] == Some(call_id)
    }

    fn rx_control_circuit_open(&mut self, queue: &mut MessageQueue, prim: CallControl) {
        let CallControl::Open(circuit) = prim else { panic!() };
        let call_id = circuit.call_id;
        let ts = circuit.ts;
        let dir = circuit.direction;

        if !(1..=4).contains(&ts) {
            tracing::warn!(call_id, ts, "ignoring circuit open for invalid traffic timeslot");
            return;
        }

        let previous_owner = self.traffic_call_owner[ts as usize - 1];
        if previous_owner != Some(call_id) {
            // Do not carry either the previous group's GCK policy or queued
            // private-call state into the next generation of this slot.
            self.set_traffic_aie(queue, ts, None, None);
            self.group_call_key[ts as usize - 1] = None;
            self.channel_scheduler.set_hangtime(ts, false);
            self.first_central_downlink_voice[ts as usize - 1] = None;
            self.traffic_floor_holder[ts as usize - 1] = None;
            self.last_ul_voice[ts as usize - 1] = None;
            self.private_media_timeslots.remove(&ts);
            self.duplex_private_media_timeslots.remove(&ts);
        }

        // Direction::Both needs to be split into separate DL and UL operations
        // because the UMAC circuit manager tracks them independently.
        let dirs: Vec<Direction> = match dir {
            Direction::Both => vec![Direction::Dl, Direction::Ul],
            d @ (Direction::Dl | Direction::Ul) => vec![d],
            Direction::None => {
                tracing::warn!("rx_control_circuit_open: Direction::None, ignoring");
                return;
            }
        };

        for d in dirs {
            // See if pre-existing circuit somehow needs to be closed
            if self.channel_scheduler.circuit_is_active(d, ts) {
                tracing::warn!("rx_control_circuit_open: Circuit already exists for {:?} {}, closing first", d, ts);
                self.channel_scheduler.close_circuit(d, ts);
            }

            let c = Circuit {
                call_id,
                direction: d,
                ts: circuit.ts,
                usage: circuit.usage,
                circuit_mode: circuit.circuit_mode,
                speech_service: circuit.speech_service,
                etee_encrypted: circuit.etee_encrypted,
            };
            self.channel_scheduler.create_circuit(d, c);

            // Start UL inactivity timer when opening a UL circuit
            if d == Direction::Ul && (1..=4).contains(&ts) {
                self.last_ul_voice[ts as usize - 1] = Some(self.dltime);
            }

            tracing::debug!("  rx_control_circuit_open: Setup {:?} circuit for ts {}", d, ts);
        }
        self.traffic_call_owner[ts as usize - 1] = Some(call_id);
        tracing::info!(call_id, ts, ?previous_owner, "traffic timeslot owner installed");
    }

    fn rx_control_circuit_close(&mut self, queue: &mut MessageQueue, prim: CallControl) {
        let CallControl::Close {
            call_id,
            direction: dir,
            ts,
        } = prim
        else {
            panic!()
        };

        if !self.owns_traffic_slot(call_id, ts) {
            tracing::warn!(
                call_id,
                ts,
                current_owner = ?self.traffic_call_owner.get(ts.saturating_sub(1) as usize).copied().flatten(),
                "ignoring stale circuit close after traffic-timeslot recycling"
            );
            return;
        }

        // Direction::Both needs to be split into separate DL and UL close operations
        let dirs: Vec<Direction> = match dir {
            Direction::Both => vec![Direction::Dl, Direction::Ul],
            d @ (Direction::Dl | Direction::Ul) => vec![d],
            Direction::None => {
                tracing::warn!("rx_control_circuit_close: Direction::None, ignoring");
                return;
            }
        };

        for d in dirs {
            match self.channel_scheduler.close_circuit(d, ts) {
                Some(_) => {
                    // Clear UL inactivity timer when closing a UL circuit
                    if d == Direction::Ul && (1..=4).contains(&ts) {
                        self.last_ul_voice[ts as usize - 1] = None;
                    }
                    tracing::info!("  rx_control_circuit_close: Closed {:?} circuit for ts {}", d, ts);
                }
                None => {
                    tracing::warn!("  rx_control_circuit_close: No {:?} circuit to close for ts {}", d, ts);
                }
            }
        }
        self.set_traffic_aie(queue, ts, None, None);
        if (1..=4).contains(&ts) {
            self.traffic_call_owner[ts as usize - 1] = None;
            self.group_call_key[ts as usize - 1] = None;
            self.first_central_downlink_voice[ts as usize - 1] = None;
            self.traffic_floor_holder[ts as usize - 1] = None;
            self.last_ul_voice[ts as usize - 1] = None;
            self.private_media_timeslots.remove(&ts);
            self.duplex_private_media_timeslots.remove(&ts);
        }
        self.channel_scheduler.set_hangtime(ts, false);
    }

    /// Check for UL inactivity on traffic timeslots. If no voice frames have arrived
    /// for UL_INACTIVITY_TIMESLOTS on a timeslot with an active UL circuit (and not in
    /// hangtime), send UlInactivityTimeout to CMCE.
    fn check_ul_inactivity(&mut self, queue: &mut MessageQueue) {
        // 3 multiframes ~ 3s. Above T.213 (1s) to tolerate DTX and brief RF fading.
        const UL_INACTIVITY_TIMESLOTS: i32 = 3 * 18 * 4;

        for ts in 1..=4u8 {
            let idx = ts as usize - 1;

            // A simplex private call is floor controlled and one endpoint is
            // normally silent, so it must not use the radio-loss watchdog.
            // Duplex calls use distinct traffic circuits per endpoint and are
            // intentionally kept under this guard.
            if self.private_media_timeslots.contains(&ts) && !self.duplex_private_media_timeslots.contains(&ts) {
                continue;
            }

            // Only check timeslots with an active UL circuit
            if !self.channel_scheduler.circuit_is_active(Direction::Ul, ts) {
                continue;
            }

            // Skip if in hangtime (no voice expected)
            if self.channel_scheduler.is_hangtime(ts) {
                continue;
            }

            // Check if we've exceeded the inactivity threshold
            let timed_out = match self.last_ul_voice[idx] {
                Some(t) => t.age(self.dltime) > UL_INACTIVITY_TIMESLOTS,
                None => false, // Initialized at circuit open; shouldn't be None here
            };

            if timed_out {
                tracing::warn!("UL inactivity timeout on ts={}, sending notification to CMCE", ts);
                self.last_ul_voice[idx] = None;

                queue.push_back(SapMsg {
                    sap: Sap::Control,
                    src: TetraEntity::Umac,
                    dest: TetraEntity::Cmce,
                    msg: SapMsgInner::CmceCallControl(CallControl::UlInactivityTimeout { ts }),
                });
            }
        }
    }

    fn rx_control(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        tracing::trace!("rx_control");
        let prim = match message.msg {
            SapMsgInner::CmceCallControl(prim) => prim,
            SapMsgInner::PacketBearerControl(prim) => {
                self.rx_packet_bearer_control(prim);
                return;
            }
            other => panic!("unexpected UMAC control primitive: {other:?}"),
        };

        match prim {
            CallControl::Open(_) => {
                self.rx_control_circuit_open(queue, prim);
            }
            CallControl::Close { .. } => {
                self.rx_control_circuit_close(queue, prim);
            }
            CallControl::ConfigureGroupTrafficAie { call_id, gssi, ts } => {
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::warn!(
                        call_id,
                        ts,
                        gssi,
                        "ignoring stale group traffic AIE configuration after traffic-timeslot recycling"
                    );
                    return;
                }
                let downlink = self.group_traffic_aie_for_call(call_id, gssi, ts);
                self.set_traffic_aie(queue, ts, downlink, None);
                tracing::info!(
                    call_id,
                    ts,
                    gssi,
                    downlink_policy = ?downlink,
                    "installed floorless group downlink traffic AIE context"
                );
            }
            // Floor-control signals drive traffic↔signalling transitions during hangtime.
            CallControl::FloorReleased { call_id, ts } => {
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::warn!(call_id, ts, "ignoring stale floor release after traffic-timeslot recycling");
                    return;
                }
                self.channel_scheduler.set_hangtime(ts, true);
                // Stop checking UL inactivity during hangtime
                if (1..=4).contains(&ts) {
                    self.last_ul_voice[ts as usize - 1] = None;
                }
            }
            CallControl::FloorGranted {
                call_id,
                source_issi,
                dest_gssi,
                ts,
            } => {
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::warn!(
                        call_id,
                        ts,
                        dest_gssi,
                        "ignoring stale floor grant after traffic-timeslot recycling"
                    );
                    return;
                }
                if (1..=4).contains(&ts) {
                    self.traffic_floor_holder[ts as usize - 1] = Some(source_issi);
                }
                let subject = AieSubject::Call {
                    call_id: u32::from(call_id),
                    issi: Some(source_issi),
                    gssi: Some(dest_gssi),
                };
                self.bind_sc2_call(subject);
                // SC2 group traffic uses the active TMO SCK. GSKO/GCK remain
                // separate OTAR/key-management flows; their absence must not
                // cause an active SC2 group call to leak traffic in clear.
                let downlink = self.group_traffic_aie_for_call(call_id, dest_gssi, ts);
                let uplink = self.active_aie_request(subject, AieScope::Traffic);
                self.set_traffic_aie(queue, ts, downlink, uplink);
                tracing::info!(
                    call_id,
                    ts,
                    gssi = dest_gssi,
                    source_issi,
                    downlink_policy = ?downlink,
                    uplink_policy = ?uplink,
                    "installed group traffic AIE contexts for current timeslot owner"
                );
                self.channel_scheduler.begin_floor_grant_transition(ts, source_issi);
                // Restart UL inactivity timer when new speaker gets floor
                if (1..=4).contains(&ts) {
                    self.last_ul_voice[ts as usize - 1] = Some(self.dltime);
                }
            }
            CallControl::CallEnded { call_id, ts } => {
                self.unbind_sc2_call(call_id);
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::debug!(
                        call_id,
                        ts,
                        current_owner = ?self.traffic_call_owner.get(ts.saturating_sub(1) as usize).copied().flatten(),
                        "ignoring stale call-ended slot cleanup"
                    );
                    return;
                }
                self.set_traffic_aie(queue, ts, None, None);
                self.channel_scheduler.set_hangtime(ts, false);
                if (1..=4).contains(&ts) {
                    self.traffic_call_owner[ts as usize - 1] = None;
                    self.group_call_key[ts as usize - 1] = None;
                    self.first_central_downlink_voice[ts as usize - 1] = None;
                    self.traffic_floor_holder[ts as usize - 1] = None;
                    self.last_ul_voice[ts as usize - 1] = None;
                    self.duplex_private_media_timeslots.remove(&ts);
                }
            }
            CallControl::PrivateCallTrafficActive { call_id, ts } => {
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::warn!(call_id, ts, "ignoring stale private traffic activation after timeslot recycling");
                    return;
                }
                // Full-duplex P2P has no simplex floor or hangtime.  A
                // restore must therefore keep its traffic slot active even
                // though the central private floor holder is zero. It does
                // still require the UL inactivity guard for a lost endpoint.
                self.channel_scheduler.set_hangtime(ts, false);
                if (1..=4).contains(&ts) {
                    self.last_ul_voice[ts as usize - 1] = Some(self.dltime);
                    self.duplex_private_media_timeslots.insert(ts);
                }
            }
            CallControl::PrivateFloorGranted {
                call_id,
                source_issi,
                destination_issi,
                ts,
            } => {
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::warn!(call_id, ts, "ignoring stale private floor grant after timeslot recycling");
                    return;
                }
                if (1..=4).contains(&ts) {
                    self.traffic_floor_holder[ts as usize - 1] = Some(source_issi);
                }

                // A same-cell simplex call may deliberately share one RF
                // circuit. SC2 can use its common SCK in both directions,
                // but SC3 cannot: the uplink is protected with the floor
                // holder's DCK and the downlink with the listening peer's
                // DCK. Separate endpoint circuits already received their
                // own bidirectional DCK binding through PrivateMediaStart.
                if let Some(destination_issi) = destination_issi {
                    let (downlink_subject, uplink_subject) = Self::shared_private_traffic_subjects(call_id, source_issi, destination_issi);
                    self.bind_sc2_call(uplink_subject);
                    self.bind_sc2_call(downlink_subject);
                    self.set_traffic_aie(
                        queue,
                        ts,
                        self.active_aie_request(downlink_subject, AieScope::Traffic),
                        self.active_aie_request(uplink_subject, AieScope::Traffic),
                    );
                    tracing::info!(
                        call_id,
                        ts,
                        uplink_issi = source_issi,
                        downlink_issi = destination_issi,
                        "installed shared private traffic AIE contexts"
                    );
                }
                self.channel_scheduler.begin_floor_grant_transition(ts, source_issi);
                if (1..=4).contains(&ts) {
                    self.last_ul_voice[ts as usize - 1] = Some(self.dltime);
                }
            }
            CallControl::PrivateMediaStart {
                call_id,
                source_issi,
                destination_issi,
                ts,
            } => {
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::warn!(call_id, ts, "ignoring stale private-media start after timeslot recycling");
                    return;
                }
                let (downlink_subject, uplink_subject) = Self::private_endpoint_traffic_subjects(call_id, source_issi);
                let destination = AieSubject::Call {
                    call_id: u32::from(call_id),
                    issi: Some(destination_issi),
                    gssi: None,
                };
                self.bind_sc2_call(uplink_subject);
                self.bind_sc2_call(destination);
                self.set_traffic_aie(
                    queue,
                    ts,
                    // `source_issi` is the terminal attached to this RF
                    // circuit. Incoming peer audio is transmitted on this
                    // circuit and must therefore use that local endpoint's
                    // DCK, not the remote media destination's DCK.
                    self.active_aie_request(downlink_subject, AieScope::Traffic),
                    self.active_aie_request(uplink_subject, AieScope::Traffic),
                );
                tracing::info!(
                    call_id,
                    ts,
                    rf_endpoint_issi = source_issi,
                    media_peer_issi = destination_issi,
                    "installed dedicated private traffic AIE contexts"
                );
                self.private_media_timeslots.insert(ts);
            }
            CallControl::PrivateMediaStop { call_id, ts } => {
                self.unbind_sc2_call(call_id);
                if !self.owns_traffic_slot(call_id, ts) {
                    tracing::debug!(call_id, ts, "ignoring stale private-media stop slot cleanup");
                    return;
                }
                self.set_traffic_aie(queue, ts, None, None);
                self.traffic_call_owner[ts as usize - 1] = None;
                self.first_central_downlink_voice[ts as usize - 1] = None;
                self.private_media_timeslots.remove(&ts);
                self.duplex_private_media_timeslots.remove(&ts);
                if (1..=4).contains(&ts) {
                    self.traffic_floor_holder[ts as usize - 1] = None;
                }
            }

            // UlInactivityTimeout is UMAC→CMCE only, UMAC won't receive it back
            CallControl::UlInactivityTimeout { .. } => {}

            // NetworkCall* and liveliness checks are for other entities.
            CallControl::NetworkCallStart { .. }
            | CallControl::NetworkCallReady { .. }
            | CallControl::NetworkCallEnd { .. }
            | CallControl::NetworkTalkingPartyProfile { .. }
            | CallControl::LivelinessCheckRequest { .. }
            | CallControl::LivelinessCheckReady { .. } => {
                tracing::trace!("rx_control: ignoring CMCE-Brew notification (not for UMAC)");
            }
        }
    }

    fn rx_packet_bearer_control(&mut self, control: PacketBearerControl) {
        match control {
            PacketBearerControl::Open {
                bearer_id,
                generation,
                timeslot_bitmap,
            } => {
                if !self.channel_scheduler.open_packet_bearer(bearer_id, generation, timeslot_bitmap) {
                    tracing::warn!(bearer_id, generation, "ignoring stale packet bearer activation");
                    return;
                }
                tracing::info!(bearer_id, generation, timeslot_bitmap, "packet bearer active");
            }
            PacketBearerControl::Resize {
                bearer_id,
                generation,
                timeslot_bitmap,
            } => {
                if !self.channel_scheduler.open_packet_bearer(bearer_id, generation, timeslot_bitmap) {
                    tracing::warn!(bearer_id, generation, "ignoring stale packet bearer resize");
                    return;
                }
                tracing::info!(bearer_id, generation, timeslot_bitmap, "packet bearer resized");
            }
            PacketBearerControl::Attach {
                bearer_id,
                generation,
                issi,
                event_label,
            } => {
                if !self.channel_scheduler.packet_bearers_match(bearer_id, generation) {
                    tracing::warn!(bearer_id, generation, issi, "ignoring stale packet event-label binding");
                    return;
                }
                if !self.event_label_store.bind(event_label, TetraAddress::issi(issi)) {
                    tracing::warn!(event_label, issi, "invalid packet event-label binding");
                }
            }
            PacketBearerControl::Detach {
                bearer_id,
                generation,
                event_label,
            } => {
                if self.channel_scheduler.packet_bearers_match(bearer_id, generation) {
                    if let Some(addr) = self.event_label_store.get_addr_by_label(event_label)
                        && addr.ssi_type == SsiType::Issi
                    {
                        self.channel_scheduler.detach_packet_data_terminal(addr.ssi);
                    }
                    self.event_label_store.remove(event_label);
                }
            }
            PacketBearerControl::Drain { bearer_id, generation } => {
                self.channel_scheduler.set_packet_bearer_draining(bearer_id, generation);
                tracing::info!(bearer_id, generation, "packet bearer draining; new packet grants disabled");
            }
            PacketBearerControl::Close {
                bearer_id,
                generation,
                forced,
            } => {
                if self.channel_scheduler.close_packet_bearer(bearer_id, generation) {
                    tracing::info!(bearer_id, generation, forced, "packet bearer closed");
                } else {
                    tracing::warn!(bearer_id, generation, forced, "ignoring stale packet bearer close");
                }
            }
        }
    }
}

impl TetraEntityTrait for UmacBs {
    fn entity(&self) -> TetraEntity {
        TetraEntity::Umac
    }

    fn set_config(&mut self, config: SharedConfig) {
        self.config = config;
    }

    fn rx_prim(&mut self, queue: &mut MessageQueue, message: SapMsg) {
        // tracing::debug!("rx_prim: {:?}", message);
        // tracing::debug!(ts=%message.dltime, "rx_prim: {:?}", message);

        match message.sap {
            Sap::TmvSap => {
                self.rx_tmv_prim(queue, message);
            }
            Sap::TmaSap => {
                self.rx_tma_prim(queue, message);
            }
            Sap::TmdSap => {
                self.rx_tmd_prim(queue, message);
            }
            Sap::TlmbSap => {
                self.rx_tlmb_prim(queue, message);
            }
            Sap::TlmcSap => {
                unimplemented!();
            }
            Sap::Control => {
                self.rx_control(queue, message);
            }
            _ => {
                panic!()
            }
        }
    }

    fn tick_start(&mut self, queue: &mut MessageQueue, ts: TdmaTime) {
        self.dltime = ts;
        self.refresh_system_wide_services();
        self.refresh_authentication_required();
        self.refresh_aie_config();
        self.refresh_random_access_control(ts);
        self.flush_rf_windows();

        if self.channel_scheduler.cur_dltime != ts && self.channel_scheduler.cur_dltime == (TdmaTime { t: 0, f: 0, m: 0, h: 0 }) {
            // Upon start of the system, we need to set the dl time for the channel scheduler
            self.channel_scheduler.set_dl_time(ts);
        } else {
            // When running, we adopt the new time and check for desync
            self.channel_scheduler.tick_start(ts);
        }

        // The scheduler finalizes the following air slot on this tick. Feed
        // EE-gated resources into its queue on the tick before the MS's TS1
        // reception occasion; releasing at TS1 itself transmits at TS1 of
        // the next frame and systematically misses the listening window.
        let air_time = ts.add_timeslots(MACSCHED_TX_AHEAD as i32);
        let mut retained = VecDeque::new();
        while let Some(mut resource) = self.deferred_mcch.pop_front() {
            if resource.tx_reporter.as_ref().is_some_and(TxReporter::is_discarded) {
                tracing::debug!(due = %resource.due, "dropping cancelled deferred MCCH copy");
                continue;
            }
            if let Some(retry) = resource.ee_retry.as_mut() {
                if let Some(reporter) = retry.in_flight.as_ref() {
                    if reporter.is_transmitted() {
                        tracing::debug!(due = %resource.due, "EE replay transmitted in reception frame");
                        continue;
                    }
                    if resource.due.age(air_time) > 0 {
                        if !reporter.is_discarded() {
                            reporter.mark_discarded();
                        }
                        tracing::debug!(due = %resource.due, "EE replay missed its reception frame; retrying on next phase");
                        retry.in_flight = None;
                        resource.due = resource.due.add_timeslots(retry.period_slots);
                    }
                }
                if retry.in_flight.is_none() && resource.due.age(air_time) >= 0 {
                    if retry.attempts_left == 0
                        || retry.cutoff.is_some_and(|cutoff| cutoff.diff(resource.due) <= 0)
                    {
                        continue;
                    }
                    let reporter = TxReporter::new_unacked();
                    self.channel_scheduler.dl_enqueue_ee_mcch_tma(
                        resource.pdu.clone(), resource.sdu.clone(), reporter.clone(), resource.aie_request,
                    );
                    retry.in_flight = Some(reporter);
                    retry.attempts_left -= 1;
                }
                retained.push_back(resource);
                continue;
            }
            if resource.due.age(air_time) >= 0 {
                self.channel_scheduler
                    .dl_enqueue_tma(resource.pdu, resource.sdu, resource.tx_reporter, resource.aie_request);
            } else {
                retained.push_back(resource);
            }
        }
        self.deferred_mcch = retained;

        let mut waiting = VecDeque::new();
        let mut ready = Vec::new();
        while let Some(pending) = self.pending_sc3_access.pop_front() {
            if self.aie_provider.has_sc3_dck(pending.issi) {
                ready.push(pending.message);
            } else if pending.expires_at.age(ts) < 0 {
                waiting.push_back(pending);
            } else {
                tracing::warn!(issi = pending.issi, "expired deferred SC3 MAC-ACCESS without a DCK response");
            }
        }
        self.pending_sc3_access = waiting;
        for message in ready {
            self.rx_tmv_prim(queue, message);
        }

        let mut waiting = VecDeque::new();
        let mut ready = Vec::new();
        while let Some(pending) = self.pending_sc3_downlink.pop_front() {
            if self.aie_provider.has_sc3_dck(pending.issi) {
                ready.push(pending.message);
            } else if pending.expires_at.age(ts) < 0 {
                waiting.push_back(pending);
            } else {
                tracing::warn!(issi = pending.issi, "expired deferred SC3 downlink without a DCK response");
                Self::discard_pending_downlink(pending.message);
            }
        }
        self.pending_sc3_downlink = waiting;
        for message in ready {
            self.rx_tma_prim(queue, message);
        }

        // Check for UL inactivity (stuck transmitter detection)
        self.check_ul_inactivity(queue);

        // Collect/construct traffic that should be sent down to the LMAC
        // This is basically the _previous_ timeslot
        let elem = self.channel_scheduler.finalize_ts_for_tick();
        let s = SapMsg {
            sap: Sap::TmvSap,
            src: self.self_component,
            dest: TetraEntity::Lmac,
            msg: SapMsgInner::TmvUnitdataReq(elem),
        };
        tracing::trace!("UmacBs tick: Pushing finalized timeslot to LMAC: {:?}", s);
        queue.push_back(s);
    }
}

/// Pack UL ACELP voice bits (274 bits, one-bit-per-byte) into packed byte array for DL transmission.
/// Handles both already-packed (35 bytes) and unpacked (274 bytes) formats.
fn pack_ul_acelp_bits(bits: &[u8]) -> Option<Vec<u8>> {
    const PACKED_TCH_S_BYTES: usize = (TCH_S_CAP + 7) / 8;

    // Already packed format — pass through
    if bits.len() == PACKED_TCH_S_BYTES {
        return Some(bits.to_vec());
    }
    // Insufficient data
    if bits.len() < TCH_S_CAP {
        return None;
    }

    // Pack 274 one-bit-per-byte into 35 bytes (last byte has 2 padding bits)
    let mut out = Vec::with_capacity(PACKED_TCH_S_BYTES);
    for chunk_idx in 0..PACKED_TCH_S_BYTES {
        let mut byte = 0u8;
        for bit in 0..8 {
            let bit_idx = chunk_idx * 8 + bit;
            if bit_idx < TCH_S_CAP {
                byte |= (bits[bit_idx] & 1) << (7 - bit);
            }
        }
        out.push(byte);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tetra_saps::control::enums::circuit_mode_type::CircuitModeType;

    fn rf_observation(burst_index: u8, power: f32, offset: f32) -> tetra_core::UplinkRfObservation {
        tetra_core::UplinkRfObservation {
            burst_index,
            received_power_linear: power,
            frequency_offset_hz: offset,
            training_error_bits: 1,
            training_bit_count: 22,
            training_evm_percent: 5.0,
            relative_arrival_symbols: 0.25,
        }
    }

    #[test]
    fn rf_window_deduplicates_physical_bursts_but_counts_blocks() {
        let time = TdmaTime::default();
        let mut window = RfWindow::new();
        window.observe(time, rf_observation(0, 0.01, 10.0), true);
        window.observe(time, rf_observation(0, 0.01, 10.0), false);
        window.observe(time.add_timeslots(1), rf_observation(0, 0.1, -10.0), true);
        let stats = window.finish(1001).expect("RF stats");
        assert_eq!(stats.burst_count, 2);
        assert_eq!(stats.block_count, 3);
        assert_eq!(stats.block_error_count, 1);
        assert_eq!(stats.training_bit_count, 44);
        assert_eq!(stats.training_error_bits, 2);
        assert_eq!(stats.frequency_offset_hz_x100, 0);
        assert_eq!(stats.received_power_dbfs_x100, -1_260);
    }

    fn test_circuit(call_id: u16, ts: u8) -> Circuit {
        Circuit {
            call_id,
            direction: Direction::Both,
            ts,
            usage: 4,
            circuit_mode: CircuitModeType::TchS,
            speech_service: Some(0),
            etee_encrypted: false,
        }
    }

    fn deliver_control(umac: &mut UmacBs, queue: &mut MessageQueue, control: CallControl) {
        umac.rx_control(
            queue,
            SapMsg::new(
                Sap::Control,
                TetraEntity::Cmce,
                TetraEntity::Umac,
                SapMsgInner::CmceCallControl(control),
            ),
        );
    }

    #[test]
    fn stale_teardown_cannot_clear_recycled_slots_group_key_policy() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let mut queue = MessageQueue::new();
        let ts = 2;

        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(10, ts)));
        umac.set_traffic_aie(
            &mut queue,
            ts,
            Some(AieRequest::sc3(AieSubject::Group { gssi: 1202 }, AieScope::Traffic)),
            None,
        );

        // Recycle TS2 for TG91 before delayed lifecycle messages of call 10
        // arrive. Both Close and CallEnded must be generation-aware.
        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(11, ts)));
        let tg91 = AieRequest::sc3(AieSubject::Group { gssi: 91 }, AieScope::Traffic);
        umac.set_traffic_aie(&mut queue, ts, Some(tg91), None);
        deliver_control(
            &mut umac,
            &mut queue,
            CallControl::Close {
                call_id: 10,
                direction: Direction::Both,
                ts,
            },
        );
        deliver_control(&mut umac, &mut queue, CallControl::CallEnded { call_id: 10, ts });

        assert_eq!(umac.traffic_call_owner[ts as usize - 1], Some(11));
        assert_eq!(umac.channel_scheduler.traffic_aie(ts), Some(tg91));
        assert!(umac.channel_scheduler.circuit_is_active(Direction::Dl, ts));
        assert!(umac.channel_scheduler.circuit_is_active(Direction::Ul, ts));
    }

    #[test]
    fn floorless_group_call_installs_only_downlink_traffic_aie() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let config = SharedConfig::from_parts(config, None);
        let gssi = 204;
        {
            let mut state = config.state_write();
            state.aie = RuntimeAieConfig {
                enabled: true,
                sc1_allowed: false,
                sc2: None,
                sc3: Some(RuntimeSc3Aie::new(
                    tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea1,
                    1,
                    [0x6c; 10],
                    true,
                    true,
                )),
                rollover: None,
            };
        }
        let mut umac = UmacBs::new(config.clone());
        // The example configuration does not enable a SwMI endpoint.  Mirror
        // the live endpoint update so this focused test exercises the active
        // traffic-AIE policy path.
        umac.aie = config.state_read().aie.clone();
        let mut queue = MessageQueue::new();
        let call_id = 12;
        let ts = 2;

        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(call_id, ts)));
        assert_eq!(umac.channel_scheduler.traffic_aie(ts), None);

        deliver_control(&mut umac, &mut queue, CallControl::ConfigureGroupTrafficAie { call_id, gssi, ts });

        assert_eq!(
            umac.channel_scheduler.traffic_aie(ts),
            Some(AieRequest::sc3(AieSubject::Group { gssi }, AieScope::Traffic))
        );
        assert_eq!(umac.uplink_traffic_aie[ts as usize - 1], None);
        assert_eq!(umac.traffic_floor_holder[ts as usize - 1], None);
    }

    #[test]
    fn group_traffic_keeps_its_gck_across_rollover_until_call_end() {
        use tetra_config::bluestation::{RuntimeSc3Gck, RuntimeSc3TeaAlgorithm};

        let parsed = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"
        ))).unwrap();
        let config = SharedConfig::from_parts(parsed, None);
        let gssi = 1502;
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x35; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 7,
            vec![RuntimeSc3Gck::new(4, 7, [0x47; 10])], vec![(gssi, 4)]).unwrap();
        config.state_write().aie = RuntimeAieConfig {
            enabled: true, sc1_allowed: false, sc2: None, sc3: Some(sc3), rollover: None,
        };
        let mut umac = UmacBs::new(config.clone());
        umac.aie = config.state_read().aie.clone();
        let mut queue = MessageQueue::new();
        let ts = 2;
        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(11, ts)));
        deliver_control(&mut umac, &mut queue, CallControl::ConfigureGroupTrafficAie { call_id: 11, gssi, ts });
        let old_key = umac.group_call_key[ts as usize - 1].expect("original group key").2;
        assert_eq!(u16::from_be_bytes([old_key.context_id[14], old_key.context_id[15]]), 7);

        config.state_write().aie.sc3.as_mut().unwrap().apply_sc3g_snapshot(2, true, 8,
            vec![RuntimeSc3Gck::new(4, 8, [0x48; 10])], vec![(gssi, 4)]).unwrap();
        deliver_control(&mut umac, &mut queue, CallControl::FloorGranted {
            call_id: 11, source_issi: 77_479, dest_gssi: gssi, ts,
        });
        assert_eq!(
            umac.channel_scheduler.traffic_aie(ts),
            Some(AieRequest::sc3_with_key(AieSubject::Group { gssi }, AieScope::Traffic, old_key))
        );
        // Floor control on FACCH carries its traffic slot in chan_alloc,
        // not associated_channel. It must also retain the call's old key.
        let mut timeslots = [false; 4];
        timeslots[ts as usize - 1] = true;
        umac.rx_ul_tma_unitdata_req(&mut queue, SapMsg::new(
            Sap::TmaSap, TetraEntity::Llc, TetraEntity::Umac,
            SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                req_handle: 0,
                pdu: BitBuffer::from_bitstr("0000000000000000"),
                main_address: TetraAddress::new(gssi, SsiType::Gssi),
                endpoint_id: 0,
                stealing_permission: true,
                subscriber_class: 0,
                air_interface_encryption: Some(AieRequest::sc3(AieSubject::Group { gssi }, AieScope::MacResource)),
                stealing_repeats_flag: None,
                data_category: None,
                chan_alloc: Some(CmceChanAllocReq {
                    usage: None, carrier: None, timeslots,
                    alloc_type: ChanAllocType::Replace, cell_change_flag: false,
                    ul_dl_assigned: UlDlAssignment::Both,
                }),
                associated_channel: None,
                assigned_channel_frame18_broadcast: false,
                frame18_rollover_activation: None,
                tx_reporter: None,
            }),
        ));
        umac.channel_scheduler.cur_dltime = TdmaTime { t: 1, f: 5, m: 1, h: 0 };
        let stch = umac.channel_scheduler.finalize_ts_for_tick().blk1.expect("group FACCH");
        assert_eq!(stch.logical_channel, LogicalChannel::Stch);
        assert_eq!(stch.air_interface_encryption,
            Some(AieRequest::sc3_with_key(AieSubject::Group { gssi }, AieScope::Facch, old_key)));

        deliver_control(&mut umac, &mut queue, CallControl::CallEnded { call_id: 11, ts });
        assert!(umac.group_call_key[ts as usize - 1].is_none());
        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(12, ts)));
        deliver_control(&mut umac, &mut queue, CallControl::ConfigureGroupTrafficAie { call_id: 12, gssi, ts });
        let new_key = umac.group_call_key[ts as usize - 1].expect("new group key").2;
        assert_eq!(u16::from_be_bytes([new_key.context_id[14], new_key.context_id[15]]), 8);
    }

    #[test]
    fn type_one_channel_allocation_keeps_target_carrier_and_cell_change() {
        let allocation = CmceChanAllocReq {
            usage: Some(17),
            carrier: Some(1521),
            timeslots: [false, false, true, false],
            alloc_type: ChanAllocType::Replace,
            cell_change_flag: true,
            ul_dl_assigned: UlDlAssignment::Both,
        };
        let mac = UmacBs::cmce_to_mac_chanalloc(&allocation, 1000);
        assert_eq!(mac.carrier_num, 1521);
        assert!(mac.cell_change_flag);
        assert_eq!(mac.ts_assigned, [false, false, true, false]);
    }

    #[test]
    fn private_dedicated_circuit_uses_the_rf_endpoints_dck_in_both_directions() {
        let call_id = 23;
        let endpoint = 430_892;
        let (downlink, uplink) = UmacBs::private_endpoint_traffic_subjects(call_id, endpoint);
        let expected = AieSubject::Call {
            call_id: u32::from(call_id),
            issi: Some(endpoint),
            gssi: None,
        };
        assert_eq!(downlink, expected);
        assert_eq!(uplink, expected);
    }

    #[test]
    fn private_shared_simplex_circuit_uses_listener_dck_downlink_and_speaker_dck_uplink() {
        let call_id = 23;
        let speaker = 430_892;
        let listener = 430_905;
        let (downlink, uplink) = UmacBs::shared_private_traffic_subjects(call_id, speaker, listener);
        assert!(matches!(downlink, AieSubject::Call { issi: Some(found), .. } if found == listener));
        assert!(matches!(uplink, AieSubject::Call { issi: Some(found), .. } if found == speaker));
    }

    #[test]
    fn marked_broadcast_keeps_mcch_and_fans_out_to_tch_and_pdch() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let mut queue = MessageQueue::new();
        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(10, 2)));
        assert!(umac.channel_scheduler.open_packet_bearer(83, 1, 0b0100));

        umac.rx_ul_tma_unitdata_req(
            &mut queue,
            SapMsg::new(
                Sap::TmaSap,
                TetraEntity::Llc,
                TetraEntity::Umac,
                SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                    req_handle: 0,
                    pdu: BitBuffer::from_bitstr("0000"),
                    main_address: TetraAddress::new(0x00ff_ffff, SsiType::Gssi),
                    endpoint_id: 0,
                    stealing_permission: false,
                    subscriber_class: 0,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    associated_channel: None,
                    assigned_channel_frame18_broadcast: true,
                    frame18_rollover_activation: None,
                    tx_reporter: None,
                }),
            ),
        );

        let mcch_time = TdmaTime { t: 1, f: 5, m: 1, h: 0 };
        umac.channel_scheduler.cur_dltime = mcch_time.add_timeslots(-1);
        let mcch = umac.channel_scheduler.finalize_ts_for_tick();
        let mut mcch_bits = mcch.blk1.expect("original MCCH broadcast").mac_block;
        mcch_bits.seek(0);
        let mcch_resource = MacResource::from_bitbuf(&mut mcch_bits).expect("MCCH MAC-RESOURCE");
        assert_eq!(mcch_resource.addr.map(|addr| addr.ssi), Some(0x00ff_ffff));

        let tch_time = TdmaTime { t: 2, f: 18, m: 2, h: 0 };
        assert!(!tch_time.is_mandatory_bsch() && !tch_time.is_mandatory_bnch());
        umac.channel_scheduler.cur_dltime = tch_time.add_timeslots(-1);
        let tch = umac.channel_scheduler.finalize_ts_for_tick();
        assert_eq!(tch.blk1.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::SchF));
        let mut tch_bits = tch.blk1.expect("TCH FN18 broadcast").mac_block;
        tch_bits.seek(0);
        let tch_resource = MacResource::from_bitbuf(&mut tch_bits).expect("TCH MAC-RESOURCE");
        assert_eq!(tch_resource.addr.map(|addr| addr.ssi), Some(0x00ff_ffff));

        let pdch_time = TdmaTime { t: 3, f: 18, m: 3, h: 0 };
        assert!(!pdch_time.is_mandatory_bsch() && !pdch_time.is_mandatory_bnch());
        umac.channel_scheduler.cur_dltime = pdch_time.add_timeslots(-1);
        let pdch = umac.channel_scheduler.finalize_ts_for_tick();
        assert_eq!(pdch.blk1.as_ref().map(|block| block.logical_channel), Some(LogicalChannel::SchF));
        let mut pdch_bits = pdch.blk1.expect("PDCH FN18 broadcast").mac_block;
        pdch_bits.seek(0);
        let pdch_resource = MacResource::from_bitbuf(&mut pdch_bits).expect("PDCH MAC-RESOURCE");
        assert_eq!(pdch_resource.addr.map(|addr| addr.ssi), Some(0x00ff_ffff));
    }

    #[test]
    fn absolute_iv_notice_on_group_tch_is_clear_and_fits_stch() {
        use tetra_config::bluestation::{RuntimeSc3Gck, RuntimeSc3TeaAlgorithm};

        let parsed = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration");
        let config = SharedConfig::from_parts(parsed, None);
        let gssi = 1502;
        let mut sc3 = RuntimeSc3Aie::new(RuntimeSc3TeaAlgorithm::Tea1, 1, [0x35; 10], true, true);
        sc3.apply_sc3g_snapshot(1, true, 10, vec![RuntimeSc3Gck::new(4, 10, [0x41; 10])], vec![(gssi, 4)])
            .expect("group key");
        config.state_write().aie = RuntimeAieConfig {
            enabled: true,
            sc1_allowed: false,
            sc2: None,
            sc3: Some(sc3),
            rollover: None,
        };
        let mut umac = UmacBs::new(config);
        let mut queue = MessageQueue::new();
        deliver_control(&mut umac, &mut queue, CallControl::Open(test_circuit(10, 2)));
        umac.set_traffic_aie(
            &mut queue,
            2,
            Some(AieRequest::sc3(AieSubject::Group { gssi }, AieScope::Traffic)),
            None,
        );

        // A linked-GCK Absolute-IV demand plus BL-UDATA is 74 bits. It must
        // survive the fan-out and mandatory octet fill in a 124-bit STCH.
        let mut sdu = BitBuffer::new_autoexpand(74);
        sdu.write_bits(0, 64);
        sdu.write_bits(0, 10);
        sdu.seek(0);
        umac.rx_ul_tma_unitdata_req(
            &mut queue,
            SapMsg::new(
                Sap::TmaSap,
                TetraEntity::Llc,
                TetraEntity::Umac,
                SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                    req_handle: 0,
                    pdu: sdu,
                    main_address: TetraAddress::new(0x00ff_ffff, SsiType::Gssi),
                    endpoint_id: 0,
                    stealing_permission: true,
                    subscriber_class: 0,
                    air_interface_encryption: Some(AieRequest::clear(AieSubject::System, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    associated_channel: None,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: None,
                    tx_reporter: None,
                }),
            ),
        );

        umac.channel_scheduler.cur_dltime = TdmaTime { t: 1, f: 5, m: 1, h: 0 };
        let output = umac.channel_scheduler.finalize_ts_for_tick();
        assert_eq!(output.ts.t, 2);
        let mut stch = output.blk1.expect("broadcast rollover STCH");
        assert_eq!(stch.logical_channel, LogicalChannel::Stch);
        assert_eq!(
            stch.air_interface_encryption,
            Some(AieRequest::clear(AieSubject::System, AieScope::Facch))
        );
        stch.mac_block.seek(0);
        let resource = MacResource::from_bitbuf(&mut stch.mac_block).expect("valid STCH MAC-RESOURCE");
        assert_eq!(resource.addr.expect("broadcast address").ssi, 0x00ff_ffff);
        assert_eq!(resource.encryption_mode, 0);
        assert!(resource.usage_marker.is_none());
    }

    #[test]
    fn early_final_sc3g_marker_reaches_every_frame18_timeslot() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let activation = TdmaTime { t: 1, f: 1, m: 2, h: 0 };
        // MM -> MLE -> LLC -> UMAC needs one scheduler tick before UMAC
        // builds TS1/FN18.  The marker therefore arrives while TS4/FN17 is
        // being finalized, rather than after TS1/FN18 has already gone out.
        umac.dltime = activation.add_timeslots(-6);
        umac.channel_scheduler.cur_dltime = umac.dltime;
        let mut queue = MessageQueue::new();
        umac.rx_ul_tma_unitdata_req(
            &mut queue,
            SapMsg::new(
                Sap::TmaSap,
                TetraEntity::Llc,
                TetraEntity::Umac,
                SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                    req_handle: 0,
                    pdu: BitBuffer::new(0),
                    main_address: TetraAddress::new(0x00ff_ffff, SsiType::Gssi),
                    endpoint_id: 0,
                    stealing_permission: false,
                    subscriber_class: 0,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    associated_channel: None,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: Some(activation),
                    tx_reporter: None,
                }),
            ),
        );

        assert_eq!(umac.channel_scheduler.pending_final_gck_rollover_count(), 4);
        let preceding = umac.channel_scheduler.finalize_ts_for_tick();
        assert_eq!(preceding.ts, activation.add_timeslots(-5));
        assert_eq!(umac.channel_scheduler.pending_final_gck_rollover_count(), 4);

        umac.channel_scheduler.cur_dltime = preceding.ts;
        for timeslot in 1..=4 {
            let output = umac.channel_scheduler.finalize_ts_for_tick();
            assert_eq!(output.ts.t, timeslot);
            assert_eq!(output.ts.f, 18);
            umac.channel_scheduler.cur_dltime = output.ts;
        }
        assert_eq!(umac.channel_scheduler.pending_final_gck_rollover_count(), 0);
    }

    #[test]
    fn ee_group_replay_accepts_only_a_future_pre_rollover_opportunity() {
        let now = TdmaTime::default().add_timeslots(100);
        let due = now.add_timeslots(20);
        let activation = now.add_timeslots(40);

        assert!(UmacBs::ee_replay_is_usable(due, now, None));
        assert!(UmacBs::ee_replay_is_usable(due, now, Some(activation)));
        assert!(!UmacBs::ee_replay_is_usable(now, now, None));
        assert!(!UmacBs::ee_replay_is_usable(now.add_timeslots(-1), now, None));
        assert!(!UmacBs::ee_replay_is_usable(activation, now, Some(activation)));
        assert!(!UmacBs::ee_replay_is_usable(activation.add_timeslots(1), now, Some(activation)));
    }

    #[test]
    fn ee_reception_follows_table_23_9_across_multiframe_and_hyperframe_boundaries() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        for (mode, period) in [(1, 2), (2, 3), (3, 6), (4, 9), (5, 18), (6, 72), (7, 360)] {
            let anchor = TdmaTime { t: 1, f: 17, m: 60, h: 2 };
            umac.dltime = anchor;
            let due = umac
                .next_energy_economy_mcch_for_assignment(mode, Some(anchor.f), Some(anchor.m))
                .expect("valid EE assignment has a reception opportunity");
            assert_eq!(due, anchor.add_timeslots(period * 4), "EG{mode} must use the spec frame period");
            umac.dltime = due;
            let next = umac
                .next_energy_economy_mcch_for_assignment(mode, Some(anchor.f), Some(anchor.m))
                .expect("EE cycle continues after hyperframe rollover");
            assert_eq!(next, due.add_timeslots(period * 4), "EG{mode} must keep its phase");
        }
    }

    #[test]
    fn all_ms_broadcast_reaches_distinct_ee_frames_without_group_affiliation() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let config = SharedConfig::from_parts(config, None);
        for (issi, frame) in [(430_893, 2), (430_905, 5), (77_480, 5)] {
            let mut state = config.state_write();
            state.subscribers.register(issi);
            assert!(state.subscribers.set_energy_economy(issi, 5, Some(frame), Some(1)));
            state.subscribers.mark_active(issi);
        }
        let mut umac = UmacBs::new(config);
        let mut queue = MessageQueue::new();
        umac.rx_ul_tma_unitdata_req(
            &mut queue,
            SapMsg::new(
                Sap::TmaSap,
                TetraEntity::Llc,
                TetraEntity::Umac,
                SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                    req_handle: 0,
                    pdu: BitBuffer::from_bitstr("0010000100000000000000100111"),
                    main_address: TetraAddress::new(0x00ff_ffff, SsiType::Gssi),
                    endpoint_id: 0,
                    stealing_permission: false,
                    subscriber_class: 0,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    associated_channel: None,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: None,
                    tx_reporter: None,
                }),
            ),
        );
        let mut due = umac.deferred_mcch.iter().map(|replay| replay.due).collect::<Vec<_>>();
        due.sort_by_key(|time| time.to_int());
        assert_eq!(
            due,
            vec![TdmaTime { t: 1, f: 2, m: 1, h: 0 }, TdmaTime { t: 1, f: 5, m: 1, h: 0 }],
            "each listening phase gets one copy, including the unassociated all-MS address"
        );
    }

    #[test]
    fn ee_replay_is_finalized_on_the_terminal_reception_slot() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let due = TdmaTime { t: 1, f: 5, m: 2, h: 0 };
        umac.deferred_mcch.push_back(DeferredMcch {
            due,
            pdu: BsChannelScheduler::dl_make_minimal_resource(
                &TetraAddress::new(0x00ff_ffff, SsiType::Gssi),
                None,
                false,
            ),
            sdu: BitBuffer::from_bitstr("00100010010000100000000000000100111"),
            tx_reporter: None,
            aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
            ee_retry: None,
        });
        umac.channel_scheduler.cur_dltime = due.add_timeslots(-3);
        let mut queue = MessageQueue::new();

        umac.tick_start(&mut queue, due.add_timeslots(-2));
        assert_eq!(umac.deferred_mcch.len(), 1, "the replay must not be released two ticks early");
        queue.pop_front().expect("preceding slot is finalized");

        umac.tick_start(&mut queue, due.add_timeslots(-1));
        assert!(umac.deferred_mcch.is_empty());
        let output = queue.pop_front().expect("reception slot is finalized");
        let SapMsgInner::TmvUnitdataReq(slot) = output.msg else { panic!("expected downlink slot") };
        assert_eq!(slot.ts, due);
        let mut bits = slot.blk1.expect("GCK broadcast on SCH/F").mac_block;
        bits.seek(0);
        let resource = MacResource::from_bitbuf(&mut bits).expect("broadcast MAC-RESOURCE");
        let address = resource.addr.expect("all-MS broadcast address");
        assert_eq!(address.ssi, 0x00ff_ffff);
    }

    #[test]
    fn cancelled_concurrent_copy_leaves_deferred_mcch_queue() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let reporter = TxReporter::new();
        let tick = TdmaTime::default().add_timeslots(1);
        umac.deferred_mcch.push_back(DeferredMcch {
            due: tick.add_timeslots(20),
            pdu: BsChannelScheduler::dl_make_minimal_resource(&TetraAddress::issi(77_468), None, false),
            sdu: BitBuffer::from_bitstr("1010"),
            tx_reporter: Some(reporter.clone()),
            aie_request: AieRequest::clear(AieSubject::Individual { issi: 77_468 }, AieScope::MacResource),
            ee_retry: None,
        });

        reporter.mark_discarded();
        umac.tick_start(&mut MessageQueue::new(), tick);

        assert!(umac.deferred_mcch.is_empty());
    }

    #[test]
    fn missed_all_ms_ee_frame_is_cancelled_and_retried_in_next_window() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let due = TdmaTime { t: 1, f: 5, m: 2, h: 0 };
        let missed = TxReporter::new_unacked();
        umac.deferred_mcch.push_back(DeferredMcch {
            due,
            pdu: BsChannelScheduler::dl_make_minimal_resource(&TetraAddress::new(0x00ff_ffff, SsiType::Gssi), None, false),
            sdu: BitBuffer::from_bitstr("00100010010000100000000000000100111"),
            tx_reporter: None,
            aie_request: AieRequest::clear(AieSubject::System, AieScope::MacResource),
            ee_retry: Some(EeReplayRetry {
                period_slots: 4 * 18,
                attempts_left: 1,
                cutoff: None,
                in_flight: Some(missed.clone()),
            }),
        });

        umac.channel_scheduler.cur_dltime = due;
        umac.tick_start(&mut MessageQueue::new(), due.add_timeslots(1));
        assert!(missed.is_discarded(), "stale copy must never be emitted in a frame the MS does not hear");
        let next = due.add_timeslots(4 * 18);
        assert_eq!(umac.deferred_mcch.front().expect("retry retained").due, next);

        umac.channel_scheduler.cur_dltime = next.add_timeslots(-2);
        let mut queue = MessageQueue::new();
        umac.tick_start(&mut queue, next.add_timeslots(-1));
        let retry = umac.deferred_mcch.front().expect("retry receipt retained");
        assert!(retry.ee_retry.as_ref().expect("EE state").in_flight.as_ref().expect("sent copy").is_transmitted());
        let output = queue.pop_front().expect("reception slot finalized");
        let SapMsgInner::TmvUnitdataReq(slot) = output.msg else { panic!("expected downlink slot") };
        assert_eq!(slot.ts, next);
    }

    #[test]
    fn missing_sc3_dck_defers_downlink_until_key_arrives() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let config = SharedConfig::from_parts(config, None);
        let issi = 430_904;
        config.state_write().aie.sc3 = Some(tetra_config::bluestation::RuntimeSc3Aie::new(
            tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea1,
            1,
            [0x11; 10],
            true,
            true,
        ));
        let mut umac = UmacBs::new(config.clone());
        let reporter = TxReporter::new();
        let mut queue = MessageQueue::new();
        umac.rx_tma_prim(
            &mut queue,
            SapMsg::new(
                Sap::TmaSap,
                TetraEntity::Llc,
                TetraEntity::Umac,
                SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                    req_handle: 0,
                    pdu: BitBuffer::from_bitstr("00010010"),
                    main_address: TetraAddress::issi(issi),
                    endpoint_id: 0,
                    stealing_permission: false,
                    subscriber_class: 0,
                    air_interface_encryption: Some(AieRequest::sc3(AieSubject::Individual { issi }, AieScope::MacResource)),
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    associated_channel: None,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: None,
                    tx_reporter: Some(reporter.clone()),
                }),
            ),
        );

        assert_eq!(umac.pending_sc3_downlink.len(), 1);
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert!(!umac.aie_provider.request_sc3_dck(issi), "DCK request must be coalesced");

        config.state_write().aie.sc3.as_mut().expect("SC3 configured").install_dck(
            issi,
            tetra_config::bluestation::RuntimeSc3Dck::new([0x22; 16], [0x33; 10], true, None),
        );
        let tick = TdmaTime::default().add_timeslots(1);
        umac.tick_start(&mut queue, tick);

        assert!(umac.pending_sc3_downlink.is_empty());
        assert_eq!(reporter.get_state(), tetra_core::TxState::Pending);
        assert!(
            umac.channel_scheduler
                .dl_take_prioritized_sched_item(TdmaTime { t: 1, f: 2, m: 1, h: 0 })
                .is_some()
        );
    }

    #[test]
    fn group_mcch_for_an_active_affiliated_ee_terminal_queues_a_future_replay() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let config = SharedConfig::from_parts(config, None);
        let mut umac = UmacBs::new(config.clone());
        let issi = 430_905;
        let gssi = 91;
        {
            let mut state = config.state_write();
            state.subscribers.register(issi);
            state.subscribers.affiliate(issi, gssi);
            assert!(state.subscribers.set_energy_economy(issi, 1, Some(2), Some(1)));
            state.subscribers.mark_active(issi);
        }

        let mut queue = MessageQueue::new();
        umac.rx_ul_tma_unitdata_req(
            &mut queue,
            SapMsg::new(
                Sap::TmaSap,
                TetraEntity::Llc,
                TetraEntity::Umac,
                SapMsgInner::TmaUnitdataReq(tetra_saps::tma::TmaUnitdataReq {
                    req_handle: 0,
                    pdu: BitBuffer::from_bitstr("00000000"),
                    main_address: TetraAddress {
                        ssi_type: SsiType::Gssi,
                        ssi: gssi,
                    },
                    endpoint_id: 0,
                    stealing_permission: false,
                    subscriber_class: 0,
                    air_interface_encryption: None,
                    stealing_repeats_flag: None,
                    data_category: None,
                    chan_alloc: None,
                    associated_channel: None,
                    assigned_channel_frame18_broadcast: false,
                    frame18_rollover_activation: None,
                    tx_reporter: None,
                }),
            ),
        );

        assert_eq!(umac.deferred_mcch.len(), 1);
        let replay = umac
            .deferred_mcch
            .front()
            .expect("TG91 must be replayed at the EE monitoring occasion");
        assert!(replay.due.age(umac.dltime) < 0, "queued EE replay must lie in the future");
    }

    #[test]
    fn packet_assignment_assigns_event_label_without_usage_marker() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let issi = 77_479;
        assert!(umac.channel_scheduler.open_packet_bearer(83, 1, 0b1110));
        assert!(umac.event_label_store.bind(3, TetraAddress::issi(issi)));
        let allocation = CmceChanAllocReq {
            usage: Some(51),
            carrier: None,
            timeslots: [false, true, true, true],
            alloc_type: ChanAllocType::Replace,
            cell_change_flag: false,
            ul_dl_assigned: UlDlAssignment::Both,
        };
        let mut pdu = MacResource {
            addr: Some(TetraAddress::issi(issi)),
            usage_marker: Some(51),
            ..MacResource::default()
        };

        umac.apply_packet_event_label_addressing(
            TetraAddress::issi(issi),
            None,
            Some(&allocation),
            &BitBuffer::from_bitstr("0101"),
            &mut pdu,
        );

        assert_eq!(pdu.addr.map(|address| address.ssi), Some(issi));
        assert_eq!(pdu.event_label, Some(3));
        assert_eq!(pdu.usage_marker, None);
    }

    #[test]
    fn packet_event_label_resolves_the_assigned_terminals_uplink_dck() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let config = SharedConfig::from_parts(config, None);
        let issi = 77_479;
        {
            let mut state = config.state_write();
            state.aie.enabled = true;
            state.aie.sc3 = Some(tetra_config::bluestation::RuntimeSc3Aie::new(
                tetra_config::bluestation::RuntimeSc3TeaAlgorithm::Tea1,
                1,
                [0x11; 10],
                true,
                true,
            ));
            state.aie.sc3.as_mut().expect("SC3 configured").install_dck(
                issi,
                tetra_config::bluestation::RuntimeSc3Dck::new([0x22; 16], [0x33; 10], true, None),
            );
            state.aie_sessions.set_terminal_class(issi, TerminalSecurityClass::Sc3, None);
        }
        let mut umac = UmacBs::new(config);
        assert!(umac.event_label_store.bind(4, TetraAddress::issi(issi)));

        let address = umac.event_label_store.get_addr_by_label(4).expect("assigned label");
        let context = umac
            .resolve_assigned_uplink_context(address.ssi, TdmaTime::default(), AieScope::MacData)
            .expect("assigned SC3 uplink context");

        assert!(matches!(
            context,
            tetra_core::AieContext::Sc3 {
                subject: AieSubject::Individual { issi: found },
                direction: AieDirection::Uplink,
                scope: AieScope::MacData,
                ..
            } if found == issi
        ));
    }

    #[test]
    fn packet_advanced_link_uses_event_label_while_basic_link_keeps_issi() {
        let config = tetra_config::bluestation::from_toml_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../example_config/config.toml"
        )))
        .expect("example configuration must remain valid");
        let mut umac = UmacBs::new(SharedConfig::from_parts(config, None));
        let issi = 77_479;
        assert!(umac.channel_scheduler.open_packet_bearer(83, 1, 0b1110));
        assert!(umac.event_label_store.bind(3, TetraAddress::issi(issi)));
        let route = Some(AssociatedChannel {
            call_id: 83,
            timeslot: 2,
            usage: 51,
            best_effort_key: None,
        });
        let mut advanced = MacResource {
            addr: Some(TetraAddress::issi(issi)),
            ..MacResource::default()
        };
        umac.apply_packet_event_label_addressing(
            TetraAddress::issi(issi),
            route,
            None,
            &BitBuffer::from_bitstr("10010000000000000"),
            &mut advanced,
        );
        assert!(advanced.addr.is_none());
        assert_eq!(advanced.event_label, Some(3));

        let mut basic = MacResource {
            addr: Some(TetraAddress::issi(issi)),
            ..MacResource::default()
        };
        umac.apply_packet_event_label_addressing(
            TetraAddress::issi(issi),
            route,
            None,
            &BitBuffer::from_bitstr("01010000"),
            &mut basic,
        );
        assert_eq!(basic.addr.map(|address| address.ssi), Some(issi));
        assert_eq!(basic.event_label, None);
    }
}
