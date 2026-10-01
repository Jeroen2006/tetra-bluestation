use clap::Parser;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tetra_core::tetra_entities::TetraEntity;
use tetra_entities::net_control::channel::build_all_control_links;
use tetra_entities::net_control::{
    CONTROL_HEARTBEAT_INTERVAL, CONTROL_HEARTBEAT_TIMEOUT, CONTROL_PROTOCOL_VERSION, CommandDispatcher, ControlWorker,
};

use tetra_config::bluestation::{PhyBackend, SharedConfig, StackConfig, parsing};
use tetra_core::{TdmaTime, debug};
use tetra_entities::MessageRouter;
use tetra_entities::net_swmi;
use tetra_entities::net_swmi::entity::SwmiMediaEntity;
use tetra_entities::net_telemetry::worker::TelemetryWorker;
use tetra_entities::net_telemetry::{
    TELEMETRY_HEARTBEAT_INTERVAL, TELEMETRY_HEARTBEAT_TIMEOUT, TELEMETRY_PROTOCOL_VERSION, TelemetrySource, telemetry_channel,
};
use tetra_entities::network::transports::websocket::{WebSocketTransport, WebSocketTransportConfig};
use tetra_entities::{
    cmce::cmce_bs::CmceBs,
    llc::llc_bs_ms::Llc,
    lmac::lmac_bs::LmacBs,
    mle::mle_bs::MleBs,
    mm::mm_bs::MmBs,
    phy::{
        components::{soapy_calibration::calibrate_tx, soapy_dev::RxTxDevSoapySdr},
        phy_bs::PhyBs,
    },
    sndcp::sndcp_bs::Sndcp,
    umac::umac_bs::UmacBs,
};

mod web;

/// Load configuration file
fn load_config_from_toml(cfg_path: &str) -> StackConfig {
    match parsing::from_file(cfg_path) {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to load configuration from {}: {}", cfg_path, e);
            std::process::exit(1);
        }
    }
}

fn persist_calibrated_tx(config_path: &str, tx_dc_i: f32, tx_dc_q: f32, tx_iq_gain_db: f32, tx_iq_phase_deg: f32) -> Result<(), String> {
    let path = Path::new(config_path);
    let original = fs::read_to_string(path).map_err(|err| format!("Failed to read config '{}': {err}", path.display()))?;
    let updated = render_config_with_calibrated_tx(&original, tx_dc_i, tx_dc_q, tx_iq_gain_db, tx_iq_phase_deg)?;
    if updated == original {
        return Ok(());
    }

    let metadata = fs::metadata(path).map_err(|err| format!("Failed to inspect config '{}': {err}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("Config path '{}' has no file name", path.display()))?
        .to_string_lossy();
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let temp_path = path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));

    let write_result = (|| -> Result<(), String> {
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|err| format!("Failed to create temporary config '{}': {err}", temp_path.display()))?;
        temp_file
            .write_all(updated.as_bytes())
            .map_err(|err| format!("Failed to write temporary config '{}': {err}", temp_path.display()))?;
        temp_file
            .sync_all()
            .map_err(|err| format!("Failed to sync temporary config '{}': {err}", temp_path.display()))?;
        fs::set_permissions(&temp_path, metadata.permissions()).map_err(|err| format!("Failed to preserve config permissions: {err}"))?;
        fs::rename(&temp_path, path).map_err(|err| format!("Failed to replace config '{}': {err}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

fn render_config_with_calibrated_tx(
    original: &str,
    tx_dc_i: f32,
    tx_dc_q: f32,
    tx_iq_gain_db: f32,
    tx_iq_phase_deg: f32,
) -> Result<String, String> {
    let mut document = original
        .parse::<toml_edit::DocumentMut>()
        .map_err(|err| format!("Failed to parse config for calibration update: {err}"))?;

    let phy_io = document
        .get_mut("phy_io")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or_else(|| "Config is missing the [phy_io] table".to_string())?;
    let soapy = phy_io
        .get_mut("soapysdr")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or_else(|| "Config is missing the [phy_io.soapysdr] table".to_string())?;
    set_toml_float_preserving_decor(soapy, "tx_dc_i", tx_dc_i as f64)?;
    set_toml_float_preserving_decor(soapy, "tx_dc_q", tx_dc_q as f64)?;
    set_toml_float_preserving_decor(soapy, "tx_iq_gain_db", tx_iq_gain_db as f64)?;
    set_toml_float_preserving_decor(soapy, "tx_iq_phase_deg", tx_iq_phase_deg as f64)?;
    Ok(document.to_string())
}

fn set_toml_float_preserving_decor(table: &mut toml_edit::Table, key: &str, number: f64) -> Result<(), String> {
    if let Some(item) = table.get_mut(key) {
        let Some(value) = item.as_value_mut() else {
            return Err(format!("Config field '{key}' must be a number"));
        };
        let decor = value.decor().clone();
        let mut replacement = toml_edit::Value::from(number);
        *replacement.decor_mut() = decor;
        *value = replacement;
    } else {
        table.insert(key, toml_edit::value(number));
    }
    Ok(())
}

#[cfg(test)]
mod config_persistence_tests {
    use super::render_config_with_calibrated_tx;

    #[test]
    fn calibration_update_preserves_comments_and_unrelated_config() {
        let original = r#"[phy_io]
backend = "SoapySdr"

[phy_io.soapysdr]
rx_freq = 433025000
tx_dc_i = 0.0 # retain I note
tx_dc_q = 0.0 # retain Q note
tx_iq_gain_db = 0.0 # retain gain note
tx_iq_phase_deg = 0.0 # retain phase note

[other]
label = "keep me" # retain section
"#;
        let updated = render_config_with_calibrated_tx(original, 0.019, -0.016, -0.03, 0.38).expect("valid config updates");

        assert!(updated.contains("# retain I note"), "{updated}");
        assert!(updated.contains("# retain Q note"), "{updated}");
        assert!(updated.contains("# retain gain note"), "{updated}");
        assert!(updated.contains("# retain phase note"), "{updated}");
        assert!(updated.contains("label = \"keep me\" # retain section"));
        assert!(updated.contains("rx_freq = 433025000"));
        let parsed = updated
            .parse::<toml_edit::DocumentMut>()
            .expect("updated config remains valid TOML");
        let soapy = parsed["phy_io"]["soapysdr"].as_table().expect("Soapy config remains a table");
        assert!((soapy["tx_dc_i"].as_float().expect("I value remains numeric") - 0.019).abs() < 1e-7);
        assert!((soapy["tx_dc_q"].as_float().expect("Q value remains numeric") + 0.016).abs() < 1e-7);
        assert!((soapy["tx_iq_gain_db"].as_float().expect("gain remains numeric") + 0.03).abs() < 1e-7);
        assert!((soapy["tx_iq_phase_deg"].as_float().expect("phase remains numeric") - 0.38).abs() < 1e-7);
    }
}

fn start_telemetry_worker(cfg: SharedConfig, telemetry_source: TelemetrySource) -> thread::JoinHandle<()> {
    let config = cfg.config();
    let tcfg = config.telemetry.as_ref().unwrap();

    let custom_root_certs = tcfg.ca_cert.as_ref().map(|path| {
        let der_bytes = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read CA certificate from '{}': {}", path, e);
            std::process::exit(1);
        });
        vec![rustls::pki_types::CertificateDer::from(der_bytes)]
    });

    let ws_config = WebSocketTransportConfig {
        host: tcfg.host.clone(),
        port: tcfg.port,
        use_tls: tcfg.use_tls,
        digest_auth_credentials: None,
        basic_auth_credentials: tcfg.credentials.clone(),
        endpoint_path: "/".to_string(),
        subprotocol: Some(TELEMETRY_PROTOCOL_VERSION.to_string()),
        user_agent: format!("BlueStation/{}", tetra_core::STACK_VERSION),
        heartbeat_interval: TELEMETRY_HEARTBEAT_INTERVAL,
        heartbeat_timeout: TELEMETRY_HEARTBEAT_TIMEOUT,
        custom_root_certs,
        extra_headers: Vec::new(),
    };

    thread::spawn(move || {
        let transport = WebSocketTransport::new(ws_config);
        let mut worker = TelemetryWorker::new(telemetry_source, transport);
        worker.run();
    })
}

fn start_control_worker(cfg: SharedConfig, command_dispatchers: HashMap<TetraEntity, CommandDispatcher>) -> thread::JoinHandle<()> {
    let config = cfg.config();
    let ccfg = config.control.as_ref().unwrap();

    let custom_root_certs = ccfg.ca_cert.as_ref().map(|path| {
        let der_bytes = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read CA certificate from '{}': {}", path, e);
            std::process::exit(1);
        });
        vec![rustls::pki_types::CertificateDer::from(der_bytes)]
    });

    let ws_config = WebSocketTransportConfig {
        host: ccfg.host.clone(),
        port: ccfg.port,
        use_tls: ccfg.use_tls,
        digest_auth_credentials: None,
        basic_auth_credentials: ccfg.credentials.clone(),
        endpoint_path: "/".to_string(),
        subprotocol: Some(CONTROL_PROTOCOL_VERSION.to_string()),
        user_agent: format!("BlueStation/{}", tetra_core::STACK_VERSION),
        heartbeat_interval: CONTROL_HEARTBEAT_INTERVAL,
        heartbeat_timeout: CONTROL_HEARTBEAT_TIMEOUT,
        custom_root_certs,
        extra_headers: Vec::new(),
    };

    thread::spawn(move || {
        let transport = WebSocketTransport::new(ws_config);
        let mut worker = ControlWorker::new(command_dispatchers, transport);
        worker.run();
    })
}

/// Start base station stack
fn build_bs_stack(
    cfg: &mut SharedConfig,
    swmi_mm: Option<net_swmi::SwmiMmEndpoint>,
    swmi_cmce: Option<net_swmi::SwmiCmceEndpoint>,
    swmi_mle: Option<net_swmi::SwmiMleEndpoint>,
    swmi_media: Option<net_swmi::SwmiMediaEndpoint>,
    swmi_rf: Option<net_swmi::SwmiRfEndpoint>,
    swmi_packet: Option<net_swmi::SwmiPacketEndpoint>,
) -> (MessageRouter, Option<TelemetrySource>, HashMap<TetraEntity, CommandDispatcher>) {
    let mut router = MessageRouter::new(cfg.clone());

    // Add suitable Phy component based on PhyIo type
    match cfg.config().phy_io.backend {
        PhyBackend::SoapySdr => {
            let rxdev = RxTxDevSoapySdr::new(cfg);
            let phy = PhyBs::new(cfg.clone(), rxdev);
            router.register_entity(Box::new(phy));
        }
        _ => {
            panic!("Unsupported PhyIo type: {:?}", cfg.config().phy_io.backend);
        }
    }

    // Build telemetry sink/source, if enabled
    let (tsink, tsource) = if cfg.config().telemetry.is_some() {
        let (a, b) = telemetry_channel();
        (Some(a), Some(b))
    } else {
        (None, None)
    };

    // Build control links, if enabled
    let (mut c_d, mut c_e) = if cfg.config().control.is_some() {
        build_all_control_links()
    } else {
        (HashMap::new(), HashMap::new())
    };

    // Add remaining components
    let lmac = LmacBs::new(cfg.clone());
    let umac = UmacBs::new_with_swmi(cfg.clone(), swmi_rf);
    let llc = Llc::new(cfg.clone());
    let mle = MleBs::new(cfg.clone(), swmi_mle, c_e.remove(&TetraEntity::Mle));
    let mm = MmBs::new(cfg.clone(), tsink.clone(), c_e.remove(&TetraEntity::Mm), swmi_mm);
    let sndcp = Sndcp::new(cfg.clone(), swmi_packet);
    let cmce = CmceBs::new(cfg.clone(), tsink.clone(), c_e.remove(&TetraEntity::Cmce), swmi_cmce);
    router.register_entity(Box::new(lmac));
    router.register_entity(Box::new(umac));
    router.register_entity(Box::new(llc));
    router.register_entity(Box::new(mle));
    router.register_entity(Box::new(mm));
    router.register_entity(Box::new(sndcp));
    router.register_entity(Box::new(cmce));
    if let Some(swmi_media) = swmi_media {
        router.register_entity(Box::new(SwmiMediaEntity::new(swmi_media)));
    }

    // Drop all command links that were not given to a TetraEntity
    for (entity, dispatcher) in c_e.into_iter() {
        drop(dispatcher);
        c_d.remove(&entity);
    }

    // Init network time
    router.set_dl_time(TdmaTime::default());

    (router, tsource, c_d)
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "TETRA BlueStation base station stack",
    long_about = "Runs the TETRA BlueStation base station stack using the provided TOML configuration files"
)]

struct Args {
    /// Config file (required)
    #[arg(help = "TOML config with network/cell parameters")]
    config: String,
    /// Validate configuration and exit without opening the radio.
    #[arg(long)]
    check_config: bool,
}

fn main() {
    eprintln!("░▀█▀░█▀▀░▀█▀░█▀▄░█▀█░░░░░█▀▄░█░░░█░█░█▀▀░█▀▀░▀█▀░█▀█░▀█▀░▀█▀░█▀█░█▀█");
    eprintln!("░░█░░█▀▀░░█░░█▀▄░█▀█░▄▄▄░█▀▄░█░░░█░█░█▀▀░▀▀█░░█░░█▀█░░█░░░█░░█░█░█░█");
    eprintln!("░░▀░░▀▀▀░░▀░░▀░▀░▀░▀░░░░░▀▀░░▀▀▀░▀▀▀░▀▀▀░▀▀▀░░▀░░▀░▀░░▀░░▀▀▀░▀▀▀░▀░▀\n");
    eprintln!("  Wouter Bokslag / Midnight Blue");
    eprintln!("  https://github.com/MidnightBlueLabs/tetra-bluestation");
    eprintln!("  Version: {}", tetra_core::STACK_VERSION);

    // Parse command-line arguments
    let args = Args::parse();

    let mut stack_cfg = load_config_from_toml(&args.config);
    if let Err(err) = stack_cfg.validate() {
        eprintln!("Invalid configuration: {err}");
        std::process::exit(1);
    }
    if args.check_config {
        println!("Configuration valid");
        return;
    }

    let _log_guards = debug::setup_logging_default(stack_cfg.debug_log.clone());
    let stack_mode = stack_cfg.stack_mode;
    if let Some(soapy_cfg) = stack_cfg.phy_io.soapysdr.as_mut()
        && soapy_cfg.tx_dc_calibration_on_startup
    {
        eprintln!("Starting opt-in SX1255 TX DC and I/Q calibration for SXceiver/MuCell before the BS stack");
        let (tx_dc_i, tx_dc_q, tx_iq_gain_db, tx_iq_phase_deg) = calibrate_tx(soapy_cfg, stack_mode).unwrap_or_else(|err| {
            eprintln!("SX1255 startup TX calibration failed: {err}");
            std::process::exit(1);
        });
        persist_calibrated_tx(&args.config, tx_dc_i, tx_dc_q, tx_iq_gain_db, tx_iq_phase_deg).unwrap_or_else(|err| {
            eprintln!("Failed to save SX1255 TX calibration: {err}");
            std::process::exit(1);
        });
        soapy_cfg.tx_dc_i = tx_dc_i;
        soapy_cfg.tx_dc_q = tx_dc_q;
        soapy_cfg.tx_iq_gain_db = tx_iq_gain_db;
        soapy_cfg.tx_iq_phase_deg = tx_iq_phase_deg;
    }

    // Build immutable, cheaply clonable SharedConfig only after applying the
    // calibration values that this run will use.
    let mut cfg = SharedConfig::from_parts(stack_cfg, None);
    let (swmi_worker, swmi_mm, _swmi_cmce, swmi_mle, swmi_media, swmi_rf, swmi_packet) = if cfg.config().swmi.is_some() {
        let (worker, mm, cmce, mle, media, rf, packet) = net_swmi::channel();
        (Some(worker), Some(mm), Some(cmce), Some(mle), Some(media), Some(rf), Some(packet))
    } else {
        (None, None, None, None, None, None, None)
    };
    let is_running = Arc::new(AtomicBool::new(true));
    let is_running_clone = is_running.clone();
    ctrlc::set_handler(move || {
        is_running_clone.store(false, Ordering::SeqCst);
    })
    .expect("failed to set Ctrl+C handler");

    let requested_monitor = cfg.config().web.enabled.then(|| Arc::new(tetra_entities::monitoring::MonitorState::default()));
    let web_server = requested_monitor.as_ref().and_then(|monitor| {
        let settings = cfg.config();
        let swmi = settings.swmi.as_ref().map(|s| (s.host.as_str(), s.port, s.tls));
        match web::start(&settings.web, &args.config, swmi, monitor.clone(), cfg.clone(), is_running.clone()) {
            Ok(server) => Some(server),
            Err(error) => {
                tracing::error!(%error, "BS dashboard unavailable");
                None
            }
        }
    });
    let monitor = requested_monitor.filter(|_| web_server.is_some());

    if let Some(swmi_worker) = swmi_worker {
        net_swmi::start_with_monitor(cfg.clone(), swmi_worker, monitor.clone());
        while is_running.load(Ordering::Relaxed) && cfg.state_read().station_provisioning.is_none() {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !is_running.load(Ordering::Relaxed) {
            if let Some(server) = web_server { server.join(); }
            return;
        }
    }
    let (mut router, tsource, cdispatchers) = build_bs_stack(&mut cfg, swmi_mm, _swmi_cmce, swmi_mle, swmi_media, swmi_rf, swmi_packet);
    if let Some(monitor) = monitor { router.set_monitor(monitor); }

    // Start Telemetry and Control threads, if enabled
    if let Some(telemetry_source) = tsource {
        start_telemetry_worker(cfg.clone(), telemetry_source);
    };
    if cfg.config().control.is_some() {
        start_control_worker(cfg.clone(), cdispatchers);
    };
    // Start the stack
    router.run_stack(None, Some(is_running));
    if let Some(server) = web_server { server.join(); }

    // router drops here → entities are dropped, networked entities disconnect.
}
