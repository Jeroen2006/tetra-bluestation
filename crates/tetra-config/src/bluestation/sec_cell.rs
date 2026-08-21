use serde::Deserialize;
use std::collections::HashMap;

use tetra_core::ranges::{SortedDisjointSsiRanges, SsiRange};
use toml::Value;

/// Dynamic common-channel random-access control for access code A.
#[derive(Debug, Clone)]
pub struct CfgRandomAccess {
    pub enabled: bool,
    pub update_interval_multiframes: u8,
    pub startup_grace_multiframes: u8,
    pub recovery_step_multiframes: u8,
    pub low_load_threshold: u8,
    pub high_load_threshold: u8,
    pub imm_min: u8,
    pub imm_max: u8,
    pub wt_min: u8,
    pub wt_max: u8,
    pub nu_min: u8,
    pub nu_max: u8,
    pub frame_len_min: u8,
    pub frame_len_max: u8,
    pub retry_window_multiframes: u8,
    pub retry_weight_percent: u8,
    pub ewma_alpha_percent: u8,
    pub frame_factor_activation_windows: u8,
    pub frame_factor_release_windows: u8,
}

impl Default for CfgRandomAccess {
    fn default() -> Self {
        Self {
            enabled: true,
            update_interval_multiframes: 1,
            startup_grace_multiframes: 5,
            recovery_step_multiframes: 3,
            low_load_threshold: 2,
            high_load_threshold: 8,
            imm_min: 0,
            imm_max: 15,
            wt_min: 3,
            wt_max: 8,
            nu_min: 3,
            nu_max: 5,
            frame_len_min: 2,
            frame_len_max: 8,
            retry_window_multiframes: 30,
            retry_weight_percent: 33,
            ewma_alpha_percent: 50,
            frame_factor_activation_windows: 3,
            frame_factor_release_windows: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CfgCellInfo {
    // 2 bits, from 18.4.2.1 D-MLE-SYNC
    pub neighbor_cell_broadcast: u8,
    // 2 bits, from 18.4.2.1 D-MLE-SYNC
    pub late_entry_supported: bool,

    /// 12 bits, from MAC SYSINFO
    pub main_carrier: u16,
    /// 4 bits, from MAC SYSINFO
    pub freq_band: u8,
    /// Offset in Hz from 25kHz aligned carrier. Options: 0, 6250, -6250, 12500 Hz
    /// Represented as 0-3 in SYSINFO
    pub freq_offset_hz: i16,
    /// Index in duplex setting table. Sent in SYSINFO. Maps to a specific duplex spacing in Hz.
    /// Custom spacing can be provided optionally by setting
    pub duplex_spacing_id: u8,
    /// Custom duplex spacing in Hz, for users that use a modified, non-standard duplex spacing table.
    pub custom_duplex_spacing: Option<u32>,
    /// 1 bits, from MAC SYSINFO
    pub reverse_operation: bool,

    // 14 bits, from 18.4.2.2 D-MLE-SYSINFO
    pub location_area: u16,
    /// Advertise that authentication is required on this serving cell.
    pub authentication_required: bool,
    // 16 bits, from 18.4.2.2 D-MLE-SYSINFO
    pub subscriber_class: u16,

    // 1-bit service flags
    pub registration: bool,
    pub deregistration: bool,
    pub priority_cell: bool,
    pub no_minimum_mode: bool,
    pub migration: bool,
    pub system_wide_services: bool,
    pub voice_service: bool,
    pub circuit_mode_data_service: bool,
    pub sndcp_service: bool,
    pub aie_service: bool,
    pub advanced_link: bool,

    // From SYNC
    pub system_code: u8,
    pub colour_code: u8,
    pub sharing_mode: u8,
    pub ts_reserved_frames: u8,
    pub u_plane_dtx: bool,
    pub frame_18_ext: bool,

    pub ms_txpwr_max_cell: u8,

    pub rxlev_access_min: u8,
    pub access_parameter: u8,

    pub random_access: CfgRandomAccess,

    pub local_ssi_ranges: SortedDisjointSsiRanges,

    /// IANA timezone name (e.g. "Europe/Amsterdam"). When set, enables D-NWRK-BROADCAST
    /// time broadcasting so MSs can synchronize their clocks.
    pub timezone: Option<String>,
}

#[derive(Default, Deserialize)]
pub struct CellInfoDto {
    pub main_carrier: u16,
    pub freq_band: u8,
    pub freq_offset: i16,
    pub duplex_spacing: u8,
    pub reverse_operation: bool,
    pub custom_duplex_spacing: Option<u32>,

    pub location_area: u16,
    pub authentication_required: Option<bool>,

    pub neighbor_cell_broadcast: Option<u8>,
    pub late_entry_supported: Option<bool>,
    pub subscriber_class: Option<u16>,
    pub registration: Option<bool>,
    pub deregistration: Option<bool>,
    pub priority_cell: Option<bool>,
    pub no_minimum_mode: Option<bool>,
    pub migration: Option<bool>,
    pub system_wide_services: Option<bool>,
    pub voice_service: Option<bool>,
    pub circuit_mode_data_service: Option<bool>,
    pub sndcp_service: Option<bool>,
    pub aie_service: Option<bool>,
    pub advanced_link: Option<bool>,

    pub system_code: Option<u8>,
    pub colour_code: Option<u8>,
    pub sharing_mode: Option<u8>,
    pub ts_reserved_frames: Option<u8>,
    pub u_plane_dtx: Option<bool>,
    pub frame_18_ext: Option<bool>,

    pub ms_txpwr_max_cell: Option<u8>,
    pub rxlev_access_min: Option<u8>,
    pub access_parameter: Option<u8>,

    #[serde(default)]
    pub random_access: Option<RandomAccessDto>,

    pub local_ssi_ranges: Option<Vec<(u32, u32)>>,

    pub timezone: Option<String>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Default, Deserialize)]
pub struct RandomAccessDto {
    pub enabled: Option<bool>,
    pub update_interval_multiframes: Option<u8>,
    pub startup_grace_multiframes: Option<u8>,
    pub recovery_step_multiframes: Option<u8>,
    pub low_load_threshold: Option<u8>,
    pub high_load_threshold: Option<u8>,
    pub imm_min: Option<u8>,
    pub imm_max: Option<u8>,
    pub wt_min: Option<u8>,
    pub wt_max: Option<u8>,
    pub nu_min: Option<u8>,
    pub nu_max: Option<u8>,
    pub frame_len_min: Option<u8>,
    pub frame_len_max: Option<u8>,
    pub retry_window_multiframes: Option<u8>,
    pub retry_weight_percent: Option<u8>,
    pub ewma_alpha_percent: Option<u8>,
    pub frame_factor_activation_windows: Option<u8>,
    pub frame_factor_release_windows: Option<u8>,
}

pub fn cell_dto_to_cfg(ci: CellInfoDto) -> CfgCellInfo {
    let random_access = ci
        .random_access
        .map(|dto| CfgRandomAccess {
            enabled: dto.enabled.unwrap_or(true),
            update_interval_multiframes: dto.update_interval_multiframes.unwrap_or(1),
            startup_grace_multiframes: dto.startup_grace_multiframes.unwrap_or(5),
            recovery_step_multiframes: dto.recovery_step_multiframes.unwrap_or(3),
            low_load_threshold: dto.low_load_threshold.unwrap_or(2),
            high_load_threshold: dto.high_load_threshold.unwrap_or(8),
            imm_min: dto.imm_min.unwrap_or(0),
            imm_max: dto.imm_max.unwrap_or(15),
            wt_min: dto.wt_min.unwrap_or(3),
            wt_max: dto.wt_max.unwrap_or(8),
            nu_min: dto.nu_min.unwrap_or(3),
            nu_max: dto.nu_max.unwrap_or(5),
            frame_len_min: dto.frame_len_min.unwrap_or(2),
            frame_len_max: dto.frame_len_max.unwrap_or(8),
            retry_window_multiframes: dto.retry_window_multiframes.unwrap_or(30),
            retry_weight_percent: dto.retry_weight_percent.unwrap_or(33),
            ewma_alpha_percent: dto.ewma_alpha_percent.unwrap_or(50),
            frame_factor_activation_windows: dto.frame_factor_activation_windows.unwrap_or(3),
            frame_factor_release_windows: dto.frame_factor_release_windows.unwrap_or(3),
        })
        .unwrap_or_default();

    CfgCellInfo {
        main_carrier: ci.main_carrier,
        freq_band: ci.freq_band,
        freq_offset_hz: ci.freq_offset,
        duplex_spacing_id: ci.duplex_spacing,
        reverse_operation: ci.reverse_operation,
        custom_duplex_spacing: ci.custom_duplex_spacing,
        location_area: ci.location_area,
        authentication_required: ci.authentication_required.unwrap_or(false),
        neighbor_cell_broadcast: ci.neighbor_cell_broadcast.unwrap_or(0),
        late_entry_supported: ci.late_entry_supported.unwrap_or(false),
        subscriber_class: ci.subscriber_class.unwrap_or(65535), // All subscriber classes allowed
        registration: ci.registration.unwrap_or(true),
        deregistration: ci.deregistration.unwrap_or(true),
        priority_cell: ci.priority_cell.unwrap_or(false),
        no_minimum_mode: ci.no_minimum_mode.unwrap_or(false),
        migration: ci.migration.unwrap_or(false),
        system_wide_services: ci.system_wide_services.unwrap_or(false),
        voice_service: ci.voice_service.unwrap_or(true),
        circuit_mode_data_service: ci.circuit_mode_data_service.unwrap_or(false),
        sndcp_service: ci.sndcp_service.unwrap_or(false),
        aie_service: ci.aie_service.unwrap_or(false),
        advanced_link: ci.advanced_link.unwrap_or(false),
        system_code: ci.system_code.unwrap_or(3), // 3 = ETSI EN 300 392-2 V3.1.1
        colour_code: ci.colour_code.unwrap_or(0),
        sharing_mode: ci.sharing_mode.unwrap_or(0),
        ts_reserved_frames: ci.ts_reserved_frames.unwrap_or(0),
        u_plane_dtx: ci.u_plane_dtx.unwrap_or(false),
        frame_18_ext: ci.frame_18_ext.unwrap_or(false),
        ms_txpwr_max_cell: ci.ms_txpwr_max_cell.unwrap_or(4), // 30 dBm (1W), Table 18.57
        rxlev_access_min: ci.rxlev_access_min.unwrap_or(3),   // -110 dBm, Table 21.64
        access_parameter: ci.access_parameter.unwrap_or(7),   // -39 dBm, Table 21.65
        random_access,
        local_ssi_ranges: ci
            .local_ssi_ranges
            .map(SortedDisjointSsiRanges::from_vec_tuple)
            .unwrap_or(default_tetrapack_local_ranges()),
        timezone: ci.timezone,
    }
}

/// Default local SSI ranges are defined as 0-90 (inclusive), which fits the TetraPack configuration.
/// This helps prevent excessive flows of unroutable traffic to TetraPack, and can be overridden
/// by users if needed.
fn default_tetrapack_local_ranges() -> SortedDisjointSsiRanges {
    SortedDisjointSsiRanges::from_vec_ssirange(vec![SsiRange::new(0, 90)])
}
