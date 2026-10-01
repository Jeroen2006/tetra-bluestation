use std::fs::{self, OpenOptions, Permissions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use serde::{Deserialize, Serialize};
use tetra_config::bluestation::{CfgRandomAccess, StackConfig, parsing};
use toml_edit::{Array, DocumentMut, Item, Table, value};

use super::AppState;

#[path = "web_frequency.rs"]
mod frequency;
use frequency::{FrequencyBandOption, FrequencySettings};

type ApiResult<T> = Result<([(header::HeaderName, HeaderValue); 1], Json<T>), (StatusCode, Json<ApiError>)>;

#[derive(Debug, Serialize)]
pub(super) struct ApiError {
    error: String,
}

fn error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: message.into() }))
}

fn no_store<T>(data: T) -> ([(header::HeaderName, HeaderValue); 1], Json<T>) {
    ([(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))], Json(data))
}

#[derive(Serialize, Deserialize)]
struct CellReselectSettings {
    slow_reselect_threshold_above_fast_db: u8,
    fast_reselect_threshold_db: u8,
    slow_reselect_hysteresis_db: u8,
    fast_reselect_hysteresis_db: u8,
}

#[derive(Serialize, Deserialize)]
struct CellSettings {
    #[serde(default)]
    colour_code: Option<u8>,
    ms_txpwr_max_cell_dbm: Option<i16>,
    rxlev_access_min_dbm: i16,
    access_parameter_dbm: i16,
}

#[derive(Serialize, Deserialize)]
struct EditableSettings {
    #[serde(default)]
    frequency: Option<FrequencySettings>,
    random_access: CfgRandomAccess,
    neighbour_cells: Vec<String>,
    cell_reselect: CellReselectSettings,
    timezone: Option<String>,
    time_enabled: bool,
    cell_info: CellSettings,
    allow_lst: bool,
    #[serde(default = "default_tx_enabled")]
    tx_enabled: bool,
}

fn default_tx_enabled() -> bool { true }

impl EditableSettings {
    fn from_config(config: &StackConfig) -> Self {
        let packed = config.network_broadcast.cell_reselect_parameters;
        Self {
            frequency: Some(FrequencySettings::from_config(config)),
            random_access: config.cell.random_access.clone(),
            neighbour_cells: config.neighbour_cells.ids.clone(),
            cell_reselect: CellReselectSettings {
                slow_reselect_threshold_above_fast_db: ((packed >> 12) as u8 & 15) * 2,
                fast_reselect_threshold_db: ((packed >> 8) as u8 & 15) * 2,
                slow_reselect_hysteresis_db: ((packed >> 4) as u8 & 15) * 2,
                fast_reselect_hysteresis_db: (packed as u8 & 15) * 2,
            },
            timezone: config.network_broadcast.timezone.clone(),
            time_enabled: config.network_broadcast.time_enabled,
            cell_info: CellSettings {
                colour_code: Some(config.cell.colour_code),
                ms_txpwr_max_cell_dbm: (config.cell.ms_txpwr_max_cell != 0).then(|| 10 + i16::from(config.cell.ms_txpwr_max_cell) * 5),
                rxlev_access_min_dbm: -125 + i16::from(config.cell.rxlev_access_min) * 5,
                access_parameter_dbm: -53 + i16::from(config.cell.access_parameter) * 2,
            },
            allow_lst: config.swmi.as_ref().is_some_and(|swmi| swmi.allow_lst),
            tx_enabled: config.phy_io.tx_enabled,
        }
    }
}

#[derive(Serialize)]
pub(super) struct ConfigResponse {
    revision: String,
    settings: EditableSettings,
    frequency_bands: Vec<FrequencyBandOption>,
}

#[derive(Deserialize)]
pub(super) struct ConfigUpdate {
    revision: String,
    settings: EditableSettings,
}

#[derive(Serialize)]
pub(super) struct SaveResponse {
    applied: bool,
    changed: bool,
    restarting: bool,
    run_id: String,
}

fn revision(contents: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    contents.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub(super) async fn get_config(State(app): State<AppState>) -> ApiResult<ConfigResponse> {
    let _guard = app
        .config_lock
        .lock()
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Configuration lock unavailable"))?;
    let contents =
        fs::read_to_string(&app.config_path).map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not read configuration"))?;
    let config =
        parsing::from_toml_str(&contents).map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not parse configuration"))?;
    Ok(no_store(ConfigResponse {
        revision: revision(&contents),
        settings: EditableSettings::from_config(&config),
        frequency_bands: frequency::band_options(),
    }))
}

pub(super) async fn put_config(State(app): State<AppState>, Json(update): Json<ConfigUpdate>) -> ApiResult<SaveResponse> {
    let _guard = app
        .config_lock
        .lock()
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Configuration lock unavailable"))?;
    if app.restart_scheduled.load(Ordering::SeqCst) {
        return Err(error(StatusCode::SERVICE_UNAVAILABLE, "Radio restart already scheduled"));
    }
    let current =
        fs::read_to_string(&app.config_path).map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not read configuration"))?;
    if revision(&current) != update.revision {
        return Err(error(
            StatusCode::CONFLICT,
            "Configuration changed on disk. Reload it before saving.",
        ));
    }
    let mut document = current
        .parse::<DocumentMut>()
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not parse configuration"))?;
    let previous = parsing::from_toml_str(&current)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not parse current configuration"))?;
    apply_settings(&mut document, &update.settings).map_err(|message| error(StatusCode::BAD_REQUEST, message))?;
    let candidate = document.to_string();
    let parsed =
        parsing::from_toml_str(&candidate).map_err(|_| error(StatusCode::BAD_REQUEST, "Resulting configuration could not be parsed"))?;
    parsed.validate().map_err(|message| error(StatusCode::BAD_REQUEST, message))?;
    let restarting = FrequencySettings::from_config(&previous) != FrequencySettings::from_config(&parsed)
        || previous.cell.colour_code != parsed.cell.colour_code;
    let permissions = fs::metadata(&app.config_path)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not inspect configuration permissions"))?
        .permissions();
    let backup_path = app
        .config_path
        .with_file_name(format!("{}.web-backup", app.config_path.file_name().unwrap().to_string_lossy()));
    atomic_write(&backup_path, current.as_bytes(), permissions.clone())
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not save configuration backup"))?;
    atomic_write(&app.config_path, candidate.as_bytes(), permissions)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "Could not save configuration"))?;
    if restarting {
        app.restart_scheduled.store(true, Ordering::SeqCst);
        let running = app.running.clone();
        std::thread::spawn(move || {
            // Allow the response to reach the browser before the normal stack
            // shutdown closes the SDR. The service manager starts the new config.
            std::thread::sleep(std::time::Duration::from_millis(800));
            running.store(false, Ordering::SeqCst);
        });
        Ok(no_store(SaveResponse { applied: false, changed: true, restarting: true, run_id: app.run_id.clone() }))
    } else {
        let changed = app.config.apply_live_editable_settings(&previous, &parsed);
        Ok(no_store(SaveResponse { applied: true, changed, restarting: false, run_id: app.run_id.clone() }))
    }
}

fn table_mut<'a>(document: &'a mut DocumentMut, path: &[&str]) -> Result<&'a mut Table, String> {
    let mut table = document.as_table_mut();
    for key in path {
        if !table.contains_key(key) {
            table.insert(key, Item::Table(Table::new()));
        }
        table = table
            .get_mut(key)
            .and_then(Item::as_table_mut)
            .ok_or_else(|| format!("{key} must be a TOML table"))?;
    }
    Ok(table)
}

fn encoded_dbm(value: i16, first: i16, last: i16, step: i16, label: &str) -> Result<i64, String> {
    if !(first..=last).contains(&value) || (value - first) % step != 0 {
        return Err(format!("{label} must be {first}..{last} dBm in {step} dB steps"));
    }
    Ok(i64::from((value - first) / step))
}

fn apply_settings(document: &mut DocumentMut, settings: &EditableSettings) -> Result<(), String> {
    if settings.cell_info.colour_code.is_some_and(|code| code > 63) {
        return Err("Colour code must be 0-63 (6 bits)".to_owned());
    }
    if let Some(frequency) = &settings.frequency {
        frequency.apply(document)?;
    }
    let tx_power = match settings.cell_info.ms_txpwr_max_cell_dbm {
        None => 0,
        Some(dbm) => encoded_dbm(dbm, 15, 45, 5, "Maximum MS transmit power")? + 1,
    };
    let rx_min = encoded_dbm(settings.cell_info.rxlev_access_min_dbm, -125, -50, 5, "Minimum RX access level")?;
    let access = encoded_dbm(settings.cell_info.access_parameter_dbm, -53, -23, 2, "Access parameter")?;
    let reselect = &settings.cell_reselect;
    for (label, db) in [
        ("Slow threshold above fast", reselect.slow_reselect_threshold_above_fast_db),
        ("Fast threshold", reselect.fast_reselect_threshold_db),
        ("Slow hysteresis", reselect.slow_reselect_hysteresis_db),
        ("Fast hysteresis", reselect.fast_reselect_hysteresis_db),
    ] {
        if db > 30 || db % 2 != 0 {
            return Err(format!("{label} must be 0..30 dB in 2 dB steps"));
        }
    }
    let timezone = settings.timezone.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let ra = table_mut(document, &["random_access"])?;
    ra.insert("enabled", value(settings.random_access.enabled));
    macro_rules! ra_numbers {
        ($($field:ident),+ $(,)?) => { $(ra.insert(stringify!($field), value(i64::from(settings.random_access.$field)));)+ };
    }
    ra_numbers!(
        update_interval_multiframes,
        startup_grace_multiframes,
        recovery_step_multiframes,
        low_load_threshold,
        high_load_threshold,
        imm_min,
        imm_max,
        wt_min,
        wt_max,
        nu_min,
        nu_max,
        frame_len_min,
        frame_len_max,
        retry_window_multiframes,
        retry_weight_percent,
        ewma_alpha_percent,
        frame_factor_activation_windows,
        frame_factor_release_windows
    );
    let mut ids = Array::new();
    for id in &settings.neighbour_cells {
        ids.push(id.trim());
    }
    table_mut(document, &["network_broadcast", "neighbour_cells"])?.insert("ids", value(ids));
    let broadcast = table_mut(document, &["network_broadcast"])?;
    broadcast.remove("cell_reselect_parameters");
    broadcast.insert("time_enabled", value(settings.time_enabled));
    if let Some(timezone) = timezone {
        broadcast.insert("timezone", value(timezone));
    } else {
        broadcast.remove("timezone");
    }
    let cell_reselect = table_mut(document, &["network_broadcast", "cell_reselect"])?;
    cell_reselect.insert(
        "slow_reselect_threshold_above_fast_db",
        value(i64::from(reselect.slow_reselect_threshold_above_fast_db)),
    );
    cell_reselect.insert("fast_reselect_threshold_db", value(i64::from(reselect.fast_reselect_threshold_db)));
    cell_reselect.insert(
        "slow_reselect_hysteresis_db",
        value(i64::from(reselect.slow_reselect_hysteresis_db)),
    );
    cell_reselect.insert(
        "fast_reselect_hysteresis_db",
        value(i64::from(reselect.fast_reselect_hysteresis_db)),
    );
    let cell = table_mut(document, &["cell_info"])?;
    if let Some(code) = settings.cell_info.colour_code {
        cell.insert("colour_code", value(i64::from(code)));
    }
    cell.remove("timezone"); // Migrate the legacy location before writing network_broadcast.timezone.
    cell.insert("ms_txpwr_max_cell", value(tx_power));
    cell.insert("rxlev_access_min", value(rx_min));
    cell.insert("access_parameter", value(access));
    table_mut(document, &["swmi"])?.insert("allow_lst", value(settings.allow_lst));
    table_mut(document, &["phy_io"])?.insert("tx_enabled", value(settings.tx_enabled));
    Ok(())
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn atomic_write(path: &Path, bytes: &[u8], permissions: Permissions) -> std::io::Result<()> {
    let name = path.file_name().unwrap().to_string_lossy();
    let temporary = path.with_file_name(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.set_permissions(permissions)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_only_restarts_for_radio_changes_and_blocks_a_second_save() {
        check_radio_restart(false);
        check_radio_restart(true);
    }

    fn check_radio_restart(change_colour_code: bool) {
        use std::sync::{Arc, Mutex, RwLock, atomic::AtomicBool};
        use tetra_config::bluestation::SharedConfig;
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));
        let original = parsing::from_toml_str(source).unwrap();
        let folder = std::env::temp_dir().join(format!("bs-radio-save-{}-{}", std::process::id(), NEXT_TEMP.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&folder).unwrap();
        let path = folder.join("test.toml");
        fs::write(&path, source).unwrap();
        let app = Arc::new(super::super::AppData {
            run_id: "test-run".to_owned(), monitor: Default::default(),
            system: RwLock::new(Default::default()), history: RwLock::new(Default::default()),
            swmi_host: String::new(), swmi_port: 0, swmi_tls: false,
            config_path: path.clone(), config_lock: Mutex::new(()),
            config: SharedConfig::from_parts(original.clone(), None),
            restart_scheduled: AtomicBool::new(false), running: Arc::new(AtomicBool::new(true)),
        });
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut settings = EditableSettings::from_config(&original);
        // Older clients omit CC; saving must preserve it without a restart.
        settings.cell_info.colour_code = None;
        let update = ConfigUpdate { revision: revision(source), settings };
        let (_, Json(saved)) = runtime.block_on(put_config(State(app.clone()), Json(update))).unwrap();
        assert!(saved.applied);
        assert!(!saved.changed);
        assert!(!saved.restarting);
        assert!(app.running.load(Ordering::SeqCst));
        assert_eq!(parsing::from_toml_str(&fs::read_to_string(&path).unwrap()).unwrap().cell.colour_code, original.cell.colour_code);

        let contents = fs::read_to_string(&path).unwrap();
        let mut settings = EditableSettings::from_config(&original);
        settings.tx_enabled = false;
        let update = ConfigUpdate { revision: revision(&contents), settings };
        let (_, Json(saved)) = runtime.block_on(put_config(State(app.clone()), Json(update))).unwrap();
        assert!(saved.applied && saved.changed && !saved.restarting);
        assert!(app.running.load(Ordering::SeqCst));
        assert!(!app.config.state_read().operator_tx_enabled);
        let saved_config = parsing::from_toml_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(!saved_config.phy_io.tx_enabled);

        let contents = fs::read_to_string(&path).unwrap();
        let mut settings = EditableSettings::from_config(&original);
        if change_colour_code {
            settings.cell_info.colour_code = Some(original.cell.colour_code + 1);
        } else {
            settings.frequency.as_mut().unwrap().main_carrier += 1;
        }
        let update = ConfigUpdate { revision: revision(&contents), settings };
        let (_, Json(saved)) = runtime.block_on(put_config(State(app.clone()), Json(update))).unwrap();
        assert!(!saved.applied);
        assert!(saved.changed && saved.restarting);
        assert_eq!(saved.run_id, "test-run");
        let candidate = fs::read_to_string(&path).unwrap();
        let parsed = parsing::from_toml_str(&candidate).unwrap();
        parsed.validate().unwrap();
        if change_colour_code {
            assert_eq!(parsed.cell.colour_code, original.cell.colour_code + 1);
            assert_eq!(parsed.cell.main_carrier, original.cell.main_carrier);
            assert_eq!(app.config.config().cell.colour_code, original.cell.colour_code);
        } else {
            assert_eq!(parsed.cell.main_carrier, original.cell.main_carrier + 1);
        }
        assert_eq!(app.config.config().cell.main_carrier, original.cell.main_carrier);
        let second = ConfigUpdate { revision: revision(&candidate), settings: EditableSettings::from_config(&parsed) };
        let rejected = runtime.block_on(put_config(State(app.clone()), Json(second))).err().unwrap();
        assert_eq!(rejected.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(fs::read_to_string(&path).unwrap(), candidate);
        // This exercises the normal stop signal, without starting a radio or BS.
        for _ in 0..30 {
            if !app.running.load(Ordering::SeqCst) { break; }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(!app.running.load(Ordering::SeqCst));
        fs::remove_file(path).unwrap();
        fs::remove_file(folder.join("test.toml.web-backup")).unwrap();
        fs::remove_dir(folder).unwrap();
    }

    fn settings() -> EditableSettings {
        EditableSettings {
            frequency: None,
            random_access: CfgRandomAccess::default(),
            neighbour_cells: vec!["bs-neighbour".into()],
            cell_reselect: CellReselectSettings {
                slow_reselect_threshold_above_fast_db: 6,
                fast_reselect_threshold_db: 8,
                slow_reselect_hysteresis_db: 10,
                fast_reselect_hysteresis_db: 12,
            },
            timezone: Some("Europe/Amsterdam".into()),
            time_enabled: true,
            cell_info: CellSettings {
                colour_code: Some(2),
                ms_txpwr_max_cell_dbm: Some(30),
                rxlev_access_min_dbm: -110,
                access_parameter_dbm: -39,
            },
            allow_lst: true,
            tx_enabled: true,
        }
    }

    #[test]
    fn edits_preserve_unrelated_fields_and_secrets() {
        let source = "# operator comment\n[cell_info]\nmain_carrier = 864\nrxlev_access_min = 3\n[network_broadcast]\ncell_reselect_parameters = 1\n[swmi]\npassword = \"secret\"\n";
        let mut document = source.parse::<DocumentMut>().unwrap();
        apply_settings(&mut document, &settings()).unwrap();
        let output = document.to_string();
        assert!(output.contains("# operator comment"));
        assert!(output.contains("main_carrier = 864"));
        assert!(output.contains("password = \"secret\""));
        assert!(output.contains("rxlev_access_min = 3"));
        assert!(output.contains("ms_txpwr_max_cell = 4"));
        assert!(!output.contains("cell_reselect_parameters"));
        assert!(output.contains("slow_reselect_threshold_above_fast_db = 6"));
    }

    #[test]
    fn colour_code_boundaries_and_older_clients() {
        let source = "[cell_info]\ncolour_code = 17\n";
        let mut input = settings();
        let older = serde::de::value::MapDeserializer::<_, serde::de::value::Error>::new(
            [("rxlev_access_min_dbm", -110_i16), ("access_parameter_dbm", -39)].into_iter(),
        );
        input.cell_info = CellSettings::deserialize(older).unwrap();
        let mut document = source.parse::<DocumentMut>().unwrap();
        apply_settings(&mut document, &input).unwrap();
        assert_eq!(document["cell_info"]["colour_code"].as_integer(), Some(17));
        for code in [0, 63] {
            input.cell_info.colour_code = Some(code);
            apply_settings(&mut document, &input).unwrap();
            assert_eq!(document["cell_info"]["colour_code"].as_integer(), Some(i64::from(code)));
        }
        let before = document.to_string();
        input.cell_info.colour_code = Some(64);
        assert!(apply_settings(&mut document, &input).is_err());
        assert_eq!(document.to_string(), before);
    }

    #[test]
    fn rejects_non_etsi_steps() {
        let mut document = "[cell_info]\n[network_broadcast]\n[swmi]\n".parse::<DocumentMut>().unwrap();
        let mut input = settings();
        input.cell_info.rxlev_access_min_dbm = -111;
        assert!(apply_settings(&mut document, &input).is_err());
        input.cell_info.rxlev_access_min_dbm = -110;
        input.cell_reselect.fast_reselect_hysteresis_db = 3;
        assert!(apply_settings(&mut document, &input).is_err());
    }
}
