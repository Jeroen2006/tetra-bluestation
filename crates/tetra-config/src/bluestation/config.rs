use serde::Deserialize;
use std::sync::{Arc, RwLock};
use tetra_core::freqs::FreqInfo;

use crate::bluestation::{CfgCellInfo, CfgControl, CfgNetInfo, CfgPhyIo, PhyBackend, StackState};

use super::sec_brew::CfgBrew;
use super::sec_swmi::CfgSwmi;
use super::sec_telemetry::CfgTelemetry;

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

    /// Brew protocol (TetraPack/BrandMeister) configuration
    pub brew: Option<CfgBrew>,

    /// Native central SwMI connection. This supersedes Brew for new deployments.
    pub swmi: Option<CfgSwmi>,

    /// Telemetry endpoint configuration
    pub telemetry: Option<CfgTelemetry>,

    /// Control endpoint configuration
    pub control: Option<CfgControl>,
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

        Ok(())
    }
}

/// Global shared configuration: immutable config + mutable state.
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
        // Use the local value until a connected SwMI provides the authoritative
        // serving-cell policy.  The SwMI worker overwrites this when CellConfig
        // arrives, so SYSINFO can follow central policy at runtime.
        state.authentication_required = cfg.cell.authentication_required;

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
}
