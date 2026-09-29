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
    pub talkgroups: Vec<u32>,
    pub last_seen_ms: Option<u64>,
    pub rf: Option<RfSnapshot>,
    pub pdp: Option<PdpSnapshot>,
}

#[derive(Clone, Default, Serialize)]
pub struct RadioSnapshot {
    pub measured_at_ms: u64,
    pub ra: RaSnapshot,
    pub terminals: Vec<TerminalSnapshot>,
    pub timeslots: [String; 4],
    pub network_connected: bool,
    pub radio_tx_allowed: bool,
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
    Umac { ra: RaSnapshot, rf: HashMap<u32, RfSnapshot>, last_seen: HashMap<u32, u64> },
    Sndcp(HashMap<u32, PdpSnapshot>),
}

#[derive(Default)]
pub struct MonitorState {
    pub radio: RwLock<RadioSnapshot>,
    pub swmi: RwLock<SwmiSnapshot>,
}

pub type SharedMonitor = Arc<MonitorState>;
