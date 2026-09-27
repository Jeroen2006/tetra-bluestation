use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use serde::Deserialize;
use toml::Value;

use crate::bluestation::{
    CellInfoDto, CfgControlDto, CfgNetInfo, CfgRua, NetworkBroadcastDto, RandomAccessDto, apply_control_patch,
    cell_dto_to_cfg, neighbour_cells_dto_to_cfg, network_broadcast_dto_to_cfg,
};

use super::config::{StackConfig, StackMode};
use super::sec_brew::CfgBrewDto;
use super::sec_swmi::{CfgSwmiDto, apply_swmi_patch};
use super::sec_telemetry::{CfgTelemetryDto, apply_telemetry_patch};
use super::{PhyIoDto, phy_dto_to_cfg};

/// Build `StackConfig` from a TOML configuration file
pub fn from_toml_str(toml_str: &str) -> Result<StackConfig, Box<dyn std::error::Error>> {
    let root: TomlConfigRoot = toml::from_str(toml_str)?;

    // Various sanity checks
    let expected_config_version = "0.7";
    if !root.config_version.eq(expected_config_version) {
        return Err(format!(
            "Unrecognized config_version: {}, expect {}",
            root.config_version, expected_config_version
        )
        .into());
    }
    if !root.extra.is_empty() {
        return Err(format!("Unrecognized top-level fields: {:?}", sorted_keys(&root.extra)).into());
    }

    if !root.phy_io.extra.is_empty() {
        return Err(format!("Unrecognized fields: phy_io::{:?}", sorted_keys(&root.phy_io.extra)).into());
    }
    if let Some(ref soapy) = root.phy_io.soapysdr {
        let extra_keys = sorted_keys(&soapy.extra);
        let extra_keys_filtered = extra_keys
            .iter()
            .filter(|key| !(key.starts_with("rx_gain_") || key.starts_with("tx_gain_")))
            .collect::<Vec<&&str>>();
        if !extra_keys_filtered.is_empty() {
            return Err(format!("Unrecognized fields: phy_io.soapysdr::{:?}", extra_keys_filtered).into());
        }
    }
    if !root.cell_info.extra.is_empty() {
        return Err(format!("Unrecognized fields in cell_info: {:?}", sorted_keys(&root.cell_info.extra)).into());
    }

    // The old Brew configuration is retained as an internal compatibility type
    // while the entities are being migrated, but new BlueStation configs must
    // use the native SwMI section.
    if let Some(ref brew) = root.brew {
        if !brew.extra.is_empty() {
            return Err(format!("Unrecognized fields in brew config: {:?}", sorted_keys(&brew.extra)).into());
        }
        return Err("[brew] has been removed; configure the central connection with [swmi]".into());
    }
    if !root.network_broadcast.neighbour_cells.extra.is_empty() {
        return Err(format!(
            "Unrecognized fields in network_broadcast.neighbour_cells: {:?}",
            sorted_keys(&root.network_broadcast.neighbour_cells.extra)
        )
        .into());
    }
    if !root.random_access.extra.is_empty() {
        return Err(format!("Unrecognized fields in random_access: {:?}", sorted_keys(&root.random_access.extra)).into());
    }
    if !root.network_broadcast.extra.is_empty() {
        return Err(format!(
            "Unrecognized fields in network_broadcast: {:?}",
            sorted_keys(&root.network_broadcast.extra)
        )
        .into());
    }
    if let Some(cell_reselect) = &root.network_broadcast.cell_reselect
        && !cell_reselect.extra.is_empty()
    {
        return Err(format!(
            "Unrecognized fields in network_broadcast.cell_reselect: {:?}",
            sorted_keys(&cell_reselect.extra)
        )
        .into());
    }
    if root.cell_info.timezone.is_some() && root.network_broadcast.timezone.is_some() {
        return Err("configure timezone in either cell_info (legacy) or network_broadcast, not both".into());
    }
    if let Some(ref swmi) = root.swmi {
        if !swmi.extra.is_empty() {
            return Err(format!("Unrecognized fields in swmi config: {:?}", sorted_keys(&swmi.extra)).into());
        }
    }

    // Optional telemetry section
    if let Some(ref telemetry) = root.telemetry {
        if !telemetry.extra.is_empty() {
            return Err(format!("Unrecognized fields in telemetry config: {:?}", sorted_keys(&telemetry.extra)).into());
        }
    }

    // Build config from required and optional values
    let legacy_timezone = root.cell_info.timezone.clone();
    let mut network_broadcast = root.network_broadcast;
    let neighbours = neighbour_cells_dto_to_cfg(std::mem::take(&mut network_broadcast.neighbour_cells));
    let mut cfg = StackConfig {
        stack_mode: root.stack_mode,
        debug_log: root.debug_log,
        phy_io: phy_dto_to_cfg(root.phy_io),
        net: CfgNetInfo { mcc: 0, mnc: 0 },
        cell: cell_dto_to_cfg(root.cell_info, root.random_access),
        neighbour_cells: neighbours,
        network_broadcast: network_broadcast_dto_to_cfg(network_broadcast, legacy_timezone)?,
        rua: CfgRua::default(),
        brew: None,
        swmi: None,
        telemetry: None,
        control: None,
    };

    cfg.swmi = Some(apply_swmi_patch(root.swmi.ok_or("[swmi] is required")?)?);

    if let Some(telemetry) = root.telemetry {
        cfg.telemetry = Some(apply_telemetry_patch(telemetry)?);
    }

    if let Some(command) = root.command {
        cfg.control = Some(apply_control_patch(command)?);
    }

    Ok(cfg)
}

/// Build `SharedConfig` from any reader.
pub fn from_reader<R: Read>(reader: R) -> Result<StackConfig, Box<dyn std::error::Error>> {
    let mut contents = String::new();
    let mut reader = BufReader::new(reader);
    reader.read_to_string(&mut contents)?;
    from_toml_str(&contents)
}

/// Build `SharedConfig` from a file path.
pub fn from_file<P: AsRef<Path>>(path: P) -> Result<StackConfig, Box<dyn std::error::Error>> {
    let f = File::open(path)?;
    let r = BufReader::new(f);
    let cfg = from_reader(r)?;
    Ok(cfg)
}

fn sorted_keys(map: &HashMap<String, Value>) -> Vec<&str> {
    let mut v: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
    v.sort_unstable();
    v
}

/// ----------------------- DTOs for input shape -----------------------

#[derive(Deserialize)]
struct TomlConfigRoot {
    config_version: String,
    stack_mode: StackMode,
    debug_log: Option<String>,

    phy_io: PhyIoDto,
    cell_info: CellInfoDto,
    #[serde(default)]
    network_broadcast: NetworkBroadcastDto,
    #[serde(default)]
    random_access: RandomAccessDto,

    brew: Option<CfgBrewDto>,
    swmi: Option<CfgSwmiDto>,
    telemetry: Option<CfgTelemetryDto>,
    command: Option<CfgControlDto>,

    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::from_toml_str;

    const EXAMPLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));

    #[test]
    fn central_fields_are_not_accepted_locally() {
        assert!(from_toml_str(&format!("{EXAMPLE}\n[net_info]\nmcc = 204\nmnc = 2671\n")).is_err());
        assert!(from_toml_str(&EXAMPLE.replace("[cell_info]", "[cell_info]\nlocation_area = 101")).is_err());
        assert!(from_toml_str(&EXAMPLE.replace("[swmi]", "[rua]\nrequested_rui_type = \"alpha_tag\"\n[swmi]")).is_err());
        assert!(from_toml_str(&EXAMPLE.replace("[random_access]", "[random_access]\nunknown_parameter = 1")).is_err());
    }

    #[test]
    fn neighbours_require_time_broadcast() {
        let mut cfg = from_toml_str(EXAMPLE).expect("new example is valid");
        cfg.neighbour_cells.ids.push("bs-neighbour".to_owned());
        assert!(cfg.validate().is_err());
        cfg.network_broadcast.time_enabled = true;
        cfg.network_broadcast.timezone = Some("Europe/Amsterdam".to_owned());
        assert!(cfg.validate().is_ok());
    }
}
