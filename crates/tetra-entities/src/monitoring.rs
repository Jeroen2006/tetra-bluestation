//! Read-only, bounded snapshots for the embedded BS dashboard. Never put an
//! HTTP request or a blocking send on the TDMA thread.
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[derive(Clone, Default, Serialize)]
pub struct RaParameters {
    pub imm: u8,
    pub wt: u8,
    pub nu: u8,
    pub frame_len: u8,
    pub frame_len_factor: bool,
    pub ts_pointer: u8,
    pub min_pdu_prio: u8,
}

#[derive(Clone, Default, Serialize)]
pub struct RaLimits {
    pub imm: [u8; 2],
    pub wt: [u8; 2],
    pub nu: [u8; 2],
    pub frame_len: [u8; 2],
}

#[derive(Clone, Default, Serialize)]
pub struct RaWindow {
    pub first_attempts: u16,
    pub retry_attempts: u16,
    pub followup_attempts: u16,
    pub invalid_mac_access: u16,
    pub crc_failures: u16,
    pub pending_registrations: u16,
    pub registration_delivery_failures: u16,
    pub sample_score: u32,
    pub ewma_score: f64,
}

#[derive(Clone, Default, Serialize)]
pub struct RaSnapshot {
    pub dynamic: bool,
    pub load: String,
    pub current: RaParameters,
    pub limits: RaLimits,
    pub low_threshold: u8,
    pub high_threshold: u8,
    pub window: Option<RaWindow>,
}

#[derive(Clone, Default, Serialize)]
pub struct RfSnapshot {
    pub measured_at_ms: u64,
    pub rssi_dbfs: f64,
    pub frequency_offset_hz: f64,
    pub evm_percent: f64,
    pub block_errors: u16,
    pub block_count: u16,
}

#[derive(Clone, Default, Serialize)]
pub struct PdpSnapshot {
    pub created_at_ms: u64,
    pub nsapi: u8,
    pub session: bool,
    pub bearer: bool,
    pub timeslots: Vec<u8>,
    pub ipv4: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct TerminalSnapshot {
    pub issi: u32,
    pub registration: String,
    pub common_scch_supported: Option<bool>,
    pub ms_scch: Option<u8>,
    pub control_timeslot: u8,
    pub talkgroups: Vec<u32>,
    pub last_seen_ms: Option<u64>,
    pub rf: Option<RfSnapshot>,
    pub pdp: Option<PdpSnapshot>,
}

#[derive(Clone, Default, Serialize)]
pub struct RadioSnapshot {
    pub measured_at_ms: u64,
    pub cell: Option<CellSnapshot>,
    pub ra: RaSnapshot,
    pub terminals: Vec<TerminalSnapshot>,
    pub timeslots: [String; 4],
    pub common_scch_requested: u8,
    pub common_scch_active: u8,
    pub common_scch_transition: bool,
    pub control_channel_loads: [u32; 4],
    pub network_connected: bool,
    pub radio_tx_allowed: bool,
    pub radio_tx_enabled: bool,
    pub radio_tx_active: bool,
    pub provisioned_once: bool,
    pub advertisement_accepted: bool,
    pub recovery_ready: bool,
}

#[derive(Clone, Default, Serialize)]
pub struct SwmiSnapshot {
    pub phase: String,
    pub connected: bool,
    pub rtt_ms: Option<f64>,
    pub rtt_measured_at_ms: Option<u64>,
    pub connected_at_ms: Option<u64>,
    pub last_receive_ms: Option<u64>,
    pub reconnects: u64,
    pub last_error: Option<String>,
}

pub enum EntitySnapshot {
    Umac { cell: CellSnapshot, ra: RaSnapshot, rf: HashMap<u32, RfSnapshot>, last_seen: HashMap<u32, u64> },
    Sndcp(HashMap<u32, PdpSnapshot>),
}

#[derive(Default)]
pub struct MonitorState {
    pub radio: RwLock<RadioSnapshot>,
    pub swmi: RwLock<SwmiSnapshot>,
}

pub type SharedMonitor = Arc<MonitorState>;

/// Public broadcast metadata only: never expose AIE keys or provisioning secrets.
#[derive(Clone, Serialize)]
pub struct CellSnapshot {
    pub time: tetra_core::TdmaTime,
    pub mcc: u16,
    pub mnc: u16,
    pub location_area: u16,
    pub colour_code: u8,
    pub system_code: u8,
    pub sharing_mode: u8,
    pub main_carrier: u16,
    pub frequency_band: u8,
    pub offset_hz: i16,
    pub duplex_spacing: u8,
    pub reverse_operation: bool,
    pub frequencies_hz: Option<(u32, u32)>,
    pub secondary_control_channels: u8,
    pub ms_txpwr_max_cell: u8,
    pub rxlev_access_min: u8,
    pub access_parameter: u8,
    pub radio_dl_timeout: u8,
    pub subscriber_class: u16,
    pub services: Vec<(String, bool)>,
}

impl CellSnapshot {
    pub fn from_broadcast(p: &crate::umac::subcomp::bs_sched::PrecomputedUmacPdus, time: tetra_core::TdmaTime, custom_split: Option<u32>) -> Self {
        let mac = &p.mac_sysinfo1;
        let service = &p.mle_sysinfo.bs_service_details;
        let offset_hz = tetra_core::freqs::FreqInfo::freq_offset_id_to_hz(mac.freq_offset_index).unwrap_or_default();
        let frequencies_hz = tetra_core::freqs::checked_freq_info(
            mac.freq_band, mac.main_carrier, offset_hz, mac.reverse_operation, mac.duplex_spacing, custom_split,
        ).ok().map(|info| info.get_freqs());
        let ext = p.mac_sysinfo2.ext_services.as_ref();
        Self {
            time, mcc: p.mle_sync.mcc, mnc: p.mle_sync.mnc, location_area: p.mle_sysinfo.location_area,
            colour_code: p.mac_sync.colour_code,
            system_code: p.mac_sync.system_code, sharing_mode: p.mac_sync.sharing_mode,
            main_carrier: mac.main_carrier, frequency_band: mac.freq_band, offset_hz,
            duplex_spacing: mac.duplex_spacing, reverse_operation: mac.reverse_operation, frequencies_hz,
            secondary_control_channels: mac.num_of_csch,
            ms_txpwr_max_cell: mac.ms_txpwr_max_cell, rxlev_access_min: mac.rxlev_access_min,
            access_parameter: mac.access_parameter, radio_dl_timeout: mac.radio_dl_timeout,
            subscriber_class: p.mle_sysinfo.subscriber_class,
            services: [
                ("Registration", service.registration), ("Deregistration", service.deregistration),
                ("Voice", service.voice_service), ("Packet data (SNDCP)", service.sndcp_service),
                ("Circuit mode data", service.circuit_mode_data_service), ("System-wide services", service.system_wide_services),
                ("Migration", service.migration), ("Priority cell", service.priority_cell),
                ("Minimum mode allowed", !service.no_minimum_mode), ("Advanced link", service.advanced_link),
                ("Late entry", p.mle_sync.late_entry_supported), ("Air-interface encryption", service.aie_service),
                ("U-plane DTX allowed", p.mac_sync.u_plane_dtx), ("Frame 18 extension", p.mac_sync.frame_18_ext),
                ("Authentication required", ext.is_some_and(|e| e.auth_required)),
                ("Security class 1", ext.is_some_and(|e| e.class1_supported)),
                ("Security class 2", ext.is_some_and(|e| e.class2_supported)),
                ("Security class 3", ext.is_some_and(|e| e.class3_supported)),
            ].into_iter().map(|(label, enabled)| (label.to_owned(), enabled)).collect(),
        }
    }
}

#[derive(Clone, Default, Serialize)]
pub struct SlotCounts {
    pub control: u8,
    pub voice: u8,
    pub packet: u8,
    pub network: u8,
    pub free: u8,
}

impl RadioSnapshot {
    pub fn slot_counts(&self) -> SlotCounts {
        let mut counts = SlotCounts::default();
        for slot in &self.timeslots {
            match slot.as_str() {
                "Control" | "Common SCCH" => counts.control += 1,
                "Voice" => counts.voice += 1,
                "Packet data" => counts.packet += 1,
                "Network" => counts.network += 1,
                "Free" => counts.free += 1,
                _ => {},
            }
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_history_tracks_all_owners_and_released_capacity() {
        let mut radio = RadioSnapshot {
            timeslots: ["Control".into(), "Voice".into(), "Packet data".into(), "Network".into()],
            ..Default::default()
        };
        let counts = radio.slot_counts();
        assert_eq!((counts.control, counts.voice, counts.packet, counts.network, counts.free), (1, 1, 1, 1, 0));
        radio.timeslots[1] = "Free".into();
        radio.timeslots[2] = "Free".into();
        let counts = radio.slot_counts();
        assert_eq!((counts.control, counts.voice, counts.packet, counts.network, counts.free), (1, 0, 0, 1, 2));
    }
}
