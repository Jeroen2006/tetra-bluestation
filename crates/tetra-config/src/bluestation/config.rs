use serde::Deserialize;
use std::sync::{Arc, RwLock};
use tetra_core::freqs::FreqInfo;

use crate::bluestation::{
    CfgCellInfo, CfgControl, CfgNeighbourCells, CfgNetInfo, CfgNetworkBroadcast, CfgPhyIo, CfgRandomAccess, CfgRua, PhyBackend,
    RuntimeNetworkBroadcast, StackState,
};

use super::sec_brew::CfgBrew;
use super::sec_swmi::CfgSwmi;
use super::sec_telemetry::CfgTelemetry;
use super::sec_web::CfgWeb;

/// Wrapper for a string that should be treated as a secret. Display and Debug will redact the actual value,
/// to prevent accidental logging of secrets.
#[derive(Clone)]
pub struct SecretField {
    pub val: String,
}

impl From<String> for SecretField {
    fn from(val: String) -> Self {
        Self { val }
    }
}

impl From<SecretField> for String {
    fn from(secret: SecretField) -> Self {
        secret.val
    }
}

impl AsRef<str> for SecretField {
    fn as_ref(&self) -> &str {
        &self.val
    }
}

impl std::fmt::Display for SecretField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "********")
    }
}

impl std::fmt::Debug for SecretField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretField").field("val", &"********").finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum StackMode {
    Bs,
    Ms,
    Mon,
}

#[derive(Debug, Clone)]
pub struct StackConfig {
    pub stack_mode: StackMode,
    pub debug_log: Option<String>,

    pub phy_io: CfgPhyIo,
    pub net: CfgNetInfo,
    pub cell: CfgCellInfo,
    pub neighbour_cells: CfgNeighbourCells,
    pub network_broadcast: CfgNetworkBroadcast,

    /// TTR 001-17 Radio User Assignment policy for the air interface.
    pub rua: CfgRua,

    /// Brew protocol (TetraPack/BrandMeister) configuration
    pub brew: Option<CfgBrew>,

    /// Native central SwMI connection. This supersedes Brew for new deployments.
    pub swmi: Option<CfgSwmi>,

    /// Telemetry endpoint configuration
    pub telemetry: Option<CfgTelemetry>,

    /// Control endpoint configuration
    pub control: Option<CfgControl>,
    /// Embedded, read-only BS dashboard.
    pub web: CfgWeb,
}

impl StackConfig {
    /// Validate that all required configuration fields are properly set.
    pub fn validate(&self) -> Result<(), &str> {
        // Check input device settings
        match self.phy_io.backend {
            PhyBackend::SoapySdr => {
                if self.phy_io.soapysdr.is_none() {
                    return Err("soapysdr configuration must be provided for Soapysdr backend");
                };
            }
            PhyBackend::None => {} // For testing
            PhyBackend::Undefined => {
                return Err("phy_io backend must be defined");
            }
        };

        // Sanity check on main carrier property fields in SYSINFO
        if self.phy_io.backend == PhyBackend::SoapySdr {
            let soapy_cfg = self
                .phy_io
                .soapysdr
                .as_ref()
                .expect("SoapySdr config must be set for SoapySdr PhyIo");

            let Ok(freq_info) = FreqInfo::from_components(
                self.cell.freq_band,
                self.cell.main_carrier,
                self.cell.freq_offset_hz,
                self.cell.reverse_operation,
                self.cell.duplex_spacing_id,
                self.cell.custom_duplex_spacing,
            ) else {
                return Err("Invalid cell info frequency settings");
            };

            let (dlfreq, ulfreq) = freq_info.get_freqs();

            println!("    {:?}", freq_info);
            println!("    Derived DL freq: {} Hz, UL freq: {} Hz\n", dlfreq, ulfreq);

            if soapy_cfg.dl_freq as u32 != dlfreq {
                return Err("PhyIo DlFrequency does not match computed FreqInfo");
            };
            if soapy_cfg.ul_freq as u32 != ulfreq {
                return Err("PhyIo UlFrequency does not match computed FreqInfo");
            };
        }

        if self.cell.ms_txpwr_max_cell > 7 {
            return Err("ms_txpwr_max_cell must be 0-7 (3 bits)");
        }
        if self.cell.rxlev_access_min > 15 {
            return Err("rxlev_access_min must be 0-15 (4 bits)");
        }
        if self.cell.access_parameter > 15 {
            return Err("access_parameter must be 0-15 (4 bits)");
        }
        if self.cell.tdma_frame_offset > 63 {
            return Err("tdma_frame_offset must be 0-63 (6 bits)");
        }

        let random_access = &self.cell.random_access;
        if !(1..=60).contains(&random_access.update_interval_multiframes) {
            return Err("cell.random_access.update_interval_multiframes must be 1-60");
        }
        if random_access.startup_grace_multiframes > 60 {
            return Err("cell.random_access.startup_grace_multiframes must be 0-60");
        }
        if !(1..=60).contains(&random_access.recovery_step_multiframes) {
            return Err("cell.random_access.recovery_step_multiframes must be 1-60");
        }
        if random_access.low_load_threshold >= random_access.high_load_threshold {
            return Err("cell.random_access.low_load_threshold must be lower than high_load_threshold");
        }
        if random_access.imm_min > random_access.imm_max || random_access.imm_max > 15 {
            return Err("cell.random_access IMM limits must be ordered and 0-15");
        }
        if random_access.wt_min == 0 || random_access.wt_min > random_access.wt_max || random_access.wt_max > 15 {
            return Err("cell.random_access WT limits must be ordered and 1-15");
        }
        if random_access.nu_min == 0 || random_access.nu_min > random_access.nu_max || random_access.nu_max > 15 {
            return Err("cell.random_access Nu limits must be ordered and 1-15");
        }
        if random_access.frame_len_min == 0 || random_access.frame_len_min > random_access.frame_len_max || random_access.frame_len_max > 15
        {
            return Err("cell.random_access frame length limits must be ordered and 1-15");
        }
        if !(1..=60).contains(&random_access.retry_window_multiframes) {
            return Err("cell.random_access.retry_window_multiframes must be 1-60");
        }
        if !(1..=100).contains(&random_access.retry_weight_percent) {
            return Err("cell.random_access.retry_weight_percent must be 1-100");
        }
        if !(1..=100).contains(&random_access.ewma_alpha_percent) {
            return Err("cell.random_access.ewma_alpha_percent must be 1-100");
        }
        if !(1..=60).contains(&random_access.frame_factor_activation_windows) {
            return Err("cell.random_access.frame_factor_activation_windows must be 1-60");
        }
        if !(1..=60).contains(&random_access.frame_factor_release_windows) {
            return Err("cell.random_access.frame_factor_release_windows must be 1-60");
        }

        // Validate timezone if configured
        if let Some(ref tz) = self.cell.timezone {
            if tz.parse::<chrono_tz::Tz>().is_err() {
                return Err("Invalid IANA timezone name in cell.timezone");
            }
        }
        if self.neighbour_cells.ids.len() > 31 {
            return Err("neighbour_cells.ids may contain at most 31 CA cells");
        }
        let mut neighbour_ids = std::collections::HashSet::new();
        for id in &self.neighbour_cells.ids {
            if id.trim().is_empty() {
                return Err("neighbour_cells.ids may not contain an empty ID");
            }
            if !neighbour_ids.insert(id) {
                return Err("neighbour_cells.ids must be unique");
            }
        }
        if self.network_broadcast.cell_load_ca > 3 {
            return Err("network_broadcast.cell_load_ca must be 0-3");
        }
        if self.network_broadcast.time_enabled {
            let Some(tz) = &self.network_broadcast.timezone else {
                return Err("network_broadcast.timezone is required when time_enabled is true");
            };
            if tz.parse::<chrono_tz::Tz>().is_err() {
                return Err("Invalid IANA timezone name in network_broadcast.timezone");
            }
        }
        if !self.neighbour_cells.ids.is_empty() && !self.network_broadcast.time_enabled {
            return Err("network_broadcast.time_enabled must be true when neighbour cells are configured");
        }

        Ok(())
    }
}

/// The operator-editable fields consumed by the running radio and SwMI worker.
#[derive(Debug, Clone)]
pub struct RuntimeOperatorSettings {
    pub version: u64,
    pub random_access: CfgRandomAccess,
    pub ms_txpwr_max_cell: u8,
    pub rxlev_access_min: u8,
    pub access_parameter: u8,
    pub allow_lst: bool,
}

impl Default for RuntimeOperatorSettings {
    fn default() -> Self {
        Self {
            version: 0,
            random_access: CfgRandomAccess::default(),
            ms_txpwr_max_cell: 4,
            rxlev_access_min: 3,
            access_parameter: 7,
            allow_lst: false,
        }
    }
}

/// Global shared configuration: immutable startup config + mutable state.
#[derive(Clone)]
pub struct SharedConfig {
    /// Read-only configuration (immutable after construction).
    cfg: Arc<StackConfig>,
    /// Mutable state guarded with RwLock (write by the stack, read by others).
    state: Arc<RwLock<StackState>>,
}

impl SharedConfig {
    pub fn from_parts(cfg: StackConfig, state: Option<StackState>) -> Self {
        // Check config for validity before returning the SharedConfig object
        match cfg.validate() {
            Ok(_) => {}
            Err(e) => panic!("Invalid stack configuration: {}", e),
        }

        let mut state = state.unwrap_or_default();
        // Central provisioning supplies this before the radio can transmit.
        state.authentication_required = false;
        state.network_broadcast = RuntimeNetworkBroadcast {
            version: 1,
            neighbours: cfg.neighbour_cells.clone(),
            broadcast: cfg.network_broadcast.clone(),
        };
        state.operator_settings = RuntimeOperatorSettings {
            version: 1,
            random_access: cfg.cell.random_access.clone(),
            ms_txpwr_max_cell: cfg.cell.ms_txpwr_max_cell,
            rxlev_access_min: cfg.cell.rxlev_access_min,
            access_parameter: cfg.cell.access_parameter,
            allow_lst: cfg.swmi.as_ref().is_some_and(|swmi| swmi.allow_lst),
        };

        Self {
            cfg: Arc::new(cfg),
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Access immutable config.
    pub fn config(&self) -> Arc<StackConfig> {
        Arc::clone(&self.cfg)
    }

    /// Read guard for mutable state.
    pub fn state_read(&self) -> std::sync::RwLockReadGuard<'_, StackState> {
        self.state.read().expect("StackState RwLock blocked")
    }

    /// Write guard for mutable state.
    pub fn state_write(&self) -> std::sync::RwLockWriteGuard<'_, StackState> {
        self.state.write().expect("StackState RwLock blocked")
    }

    /// Publish validated web-editable settings without replacing startup-only
    /// radio or network configuration. One version change is observed at the
    /// next UMAC tick; advertisement changes are reported to the SwMI.
    pub fn apply_live_editable_settings(&self, previous: &StackConfig, next: &StackConfig) -> bool {
        let previous_lst = previous.swmi.as_ref().is_some_and(|swmi| swmi.allow_lst);
        let next_lst = next.swmi.as_ref().is_some_and(|swmi| swmi.allow_lst);
        let operator_requested = previous.cell.random_access != next.cell.random_access
            || previous.cell.ms_txpwr_max_cell != next.cell.ms_txpwr_max_cell
            || previous.cell.rxlev_access_min != next.cell.rxlev_access_min
            || previous.cell.access_parameter != next.cell.access_parameter
            || previous_lst != next_lst;
        let broadcast_requested = previous.neighbour_cells.ids != next.neighbour_cells.ids
            || previous.network_broadcast.cell_reselect_parameters != next.network_broadcast.cell_reselect_parameters
            || previous.network_broadcast.time_enabled != next.network_broadcast.time_enabled
            || previous.network_broadcast.timezone != next.network_broadcast.timezone;
        if !operator_requested && !broadcast_requested {
            return false;
        }
        let mut state = self.state_write();
        let cell_changed = operator_requested && (state.operator_settings.ms_txpwr_max_cell != next.cell.ms_txpwr_max_cell
            || state.operator_settings.rxlev_access_min != next.cell.rxlev_access_min
            || state.operator_settings.access_parameter != next.cell.access_parameter);
        let operator_changed = operator_requested && (cell_changed
            || state.operator_settings.random_access != next.cell.random_access
            || state.operator_settings.allow_lst != next_lst);
        let lst_changed = state.operator_settings.allow_lst != next_lst;
        let broadcast_changed = broadcast_requested && (state.network_broadcast.neighbours.ids != next.neighbour_cells.ids
            || state.network_broadcast.broadcast.cell_reselect_parameters != next.network_broadcast.cell_reselect_parameters
            || state.network_broadcast.broadcast.time_enabled != next.network_broadcast.time_enabled
            || state.network_broadcast.broadcast.timezone != next.network_broadcast.timezone);
        if operator_changed {
            state.operator_settings.version = state.operator_settings.version.saturating_add(1);
            state.operator_settings.random_access = next.cell.random_access.clone();
            state.operator_settings.ms_txpwr_max_cell = next.cell.ms_txpwr_max_cell;
            state.operator_settings.rxlev_access_min = next.cell.rxlev_access_min;
            state.operator_settings.access_parameter = next.cell.access_parameter;
            state.operator_settings.allow_lst = next_lst;
            if lst_changed {
                let ready = state.station_provisioning.is_some()
                    && state.advertisement_accepted
                    && state.neighbours_ready
                    && state.recovery_ready
                    && state.sc3g_ready
                    && state.network_connected;
                state.radio_tx_allowed = ready || (next_lst && state.provisioned_once);
            }
        }
        if broadcast_changed {
            state.network_broadcast.neighbours = next.neighbour_cells.clone();
            state.network_broadcast.broadcast.cell_reselect_parameters = next.network_broadcast.cell_reselect_parameters;
            state.network_broadcast.broadcast.time_enabled = next.network_broadcast.time_enabled;
            state.network_broadcast.broadcast.timezone = next.network_broadcast.timezone.clone();
        }
        if broadcast_changed || cell_changed {
            state.network_broadcast.version = state.network_broadcast.version.saturating_add(1);
        }
        operator_changed || broadcast_changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_editable_settings_update_runtime_without_replacing_startup_config() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));
        let original = crate::bluestation::parsing::from_toml_str(source).unwrap();
        let shared = SharedConfig::from_parts(original.clone(), None);
        let mut edited = original.clone();
        edited.cell.random_access.high_load_threshold += 1;
        edited.cell.ms_txpwr_max_cell = 5;
        edited.cell.rxlev_access_min = 4;
        edited.cell.access_parameter = 8;
        edited.network_broadcast.cell_reselect_parameters = 0x1234;
        edited.network_broadcast.time_enabled = true;
        edited.network_broadcast.timezone = Some("Europe/Amsterdam".to_owned());
        edited.neighbour_cells.ids = vec!["other-bs".to_owned()];
        edited.swmi.as_mut().unwrap().allow_lst = false;
        edited.validate().unwrap();

        assert!(shared.apply_live_editable_settings(&original, &edited));
        let state = shared.state_read();
        assert_eq!(state.operator_settings.version, 2);
        assert_eq!(state.operator_settings.random_access.high_load_threshold, edited.cell.random_access.high_load_threshold);
        assert_eq!(state.operator_settings.ms_txpwr_max_cell, 5);
        assert_eq!(state.operator_settings.rxlev_access_min, 4);
        assert_eq!(state.operator_settings.access_parameter, 8);
        assert!(!state.operator_settings.allow_lst);
        assert_eq!(state.network_broadcast.version, 2);
        assert_eq!(state.network_broadcast.neighbours.ids, vec!["other-bs".to_owned()]);
        assert_eq!(state.network_broadcast.broadcast.cell_reselect_parameters, 0x1234);
        assert_eq!(state.network_broadcast.broadcast.timezone.as_deref(), Some("Europe/Amsterdam"));
        drop(state);
        assert_eq!(shared.config().cell.ms_txpwr_max_cell, original.cell.ms_txpwr_max_cell);
        assert!(!shared.apply_live_editable_settings(&edited, &edited));
        assert_eq!(shared.state_read().operator_settings.version, 2);
    }

    #[test]
    fn allow_lst_takes_effect_while_swmi_is_disconnected() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));
        let original = crate::bluestation::parsing::from_toml_str(source).unwrap();
        let shared = SharedConfig::from_parts(original.clone(), None);
        {
            let mut state = shared.state_write();
            state.provisioned_once = true;
            state.network_connected = false;
            state.radio_tx_allowed = true;
        }
        let mut edited = original.clone();
        edited.swmi.as_mut().unwrap().allow_lst = false;
        assert!(shared.apply_live_editable_settings(&original, &edited));
        assert!(!shared.state_read().radio_tx_allowed);
        assert!(shared.apply_live_editable_settings(&edited, &original));
        assert!(shared.state_read().radio_tx_allowed);
    }

    #[test]
    fn random_access_edit_preserves_swmi_broadcast_update() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));
        let original = crate::bluestation::parsing::from_toml_str(source).unwrap();
        let shared = SharedConfig::from_parts(original.clone(), None);
        shared.state_write().network_broadcast.neighbours.ids = vec!["swmi-neighbour".to_owned()];
        let mut edited = original.clone();
        edited.cell.random_access.high_load_threshold += 1;
        assert!(shared.apply_live_editable_settings(&original, &edited));
        assert_eq!(shared.state_read().network_broadcast.neighbours.ids, vec!["swmi-neighbour".to_owned()]);
    }
}
