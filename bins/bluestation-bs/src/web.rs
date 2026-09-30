use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sysinfo::{Components, Pid, ProcessesToUpdate, System};
use tetra_config::bluestation::{CfgWeb, SharedConfig};
use tetra_entities::monitoring::{RadioSnapshot, SharedMonitor, SwmiSnapshot, unix_ms};

#[path = "web_config.rs"]
mod config;

const HISTORY_CAPACITY: usize = 900;
const INDEX: &str = include_str!("../assets/index.html");
const CSS: &str = include_str!("../assets/dashboard.css");
const JS: &str = include_str!("../assets/dashboard.js");
const CONFIG_JS: &str = include_str!("../assets/config.js");
const FREQUENCY_JS: &str = include_str!("../assets/frequency.js");
const BOOTSTRAP: &str = include_str!("../assets/vendor/bootstrap.min.css");
const BOOTSTRAP_JS: &str = include_str!("../assets/vendor/bootstrap.min.js");
const CHART: &str = include_str!("../assets/vendor/chart.umd.min.js");
const LOGO: &str = include_str!("../../../contrib/logo/bluestation_noname.svg");

#[derive(Clone, Default, Serialize)]
struct Temperature {
    label: String,
    celsius: f32,
}

#[derive(Clone, Default, Serialize)]
struct NetworkInterface {
    name: String,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_errors: u64,
    tx_errors: u64,
    rx_drops: u64,
    tx_drops: u64,
    rx_bytes_per_sec: Option<f64>,
    tx_bytes_per_sec: Option<f64>,
}

#[derive(Clone, Default, Serialize)]
struct SystemSnapshot {
    measured_at_ms: u64,
    hostname: Option<String>,
    model: Option<String>,
    cpu_model: Option<String>,
    cpu_cores: usize,
    linux_version: Option<String>,
    kernel_version: Option<String>,
    architecture: Option<String>,
    host_uptime_sec: u64,
    process_uptime_sec: u64,
    cpu_percent: f32,
    process_cpu_percent: Option<f32>,
    ram_used_bytes: u64,
    ram_total_bytes: u64,
    process_ram_bytes: Option<u64>,
    cpu_temperature_c: Option<f32>,
    temperature_measured_at_ms: Option<u64>,
    temperatures: Vec<Temperature>,
    network: Vec<NetworkInterface>,
}

#[derive(Clone, Serialize)]
struct HistoryPoint {
    seq: u64,
    at_ms: u64,
    cpu_percent: Option<f32>,
    ram_percent: Option<f64>,
    cpu_temperature_c: Option<f32>,
    temperatures: Vec<Temperature>,
    rx_bytes_per_sec: Option<f64>,
    tx_bytes_per_sec: Option<f64>,
    interfaces: Vec<InterfaceRate>,
    ra_score: Option<f64>,
    ra_load: Option<String>,
    rtt_ms: Option<f64>,
    terminal_count: Option<usize>,
}

#[derive(Clone, Serialize)]
struct InterfaceRate {
    name: String,
    rx_bytes_per_sec: Option<f64>,
    tx_bytes_per_sec: Option<f64>,
}

struct AppData {
    run_id: String,
    monitor: SharedMonitor,
    system: RwLock<SystemSnapshot>,
    history: RwLock<VecDeque<HistoryPoint>>,
    swmi_host: String,
    swmi_port: u16,
    swmi_tls: bool,
    config_path: PathBuf,
    config_lock: Mutex<()>,
    config: SharedConfig,
    restart_scheduled: AtomicBool,
    running: Arc<AtomicBool>,
}

type AppState = Arc<AppData>;

#[derive(Serialize)]
struct SnapshotResponse {
    run_id: String,
    sample_seq: u64,
    latest_point: Option<HistoryPoint>,
    server_time_ms: u64,
    system: SystemSnapshot,
    radio: RadioSnapshot,
    swmi: SwmiSnapshot,
    swmi_host: String,
    swmi_port: u16,
    swmi_tls: bool,
}

#[derive(Serialize)]
struct HistoryResponse {
    run_id: String,
    points: Vec<HistoryPoint>,
}

async fn snapshot(State(app): State<AppState>) -> impl IntoResponse {
    let system = app.system.read().unwrap().clone();
    let radio = app.monitor.radio.read().unwrap().clone();
    let swmi = app.monitor.swmi.read().unwrap().clone();
    let latest_point = app.history.read().unwrap().back().cloned();
    let sample_seq = latest_point.as_ref().map_or(0, |point| point.seq);
    ([(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))], Json(SnapshotResponse {
        run_id: app.run_id.clone(), sample_seq, latest_point, server_time_ms: unix_ms(), system, radio, swmi,
        swmi_host: app.swmi_host.clone(), swmi_port: app.swmi_port, swmi_tls: app.swmi_tls,
    }))
}

async fn history(State(app): State<AppState>) -> impl IntoResponse {
    ([(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(HistoryResponse { run_id: app.run_id.clone(), points: app.history.read().unwrap().iter().cloned().collect() }))
}

fn static_asset(body: &'static str, content_type: &'static str) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
         (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
         (header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"))],
        body,
    )
}

fn read_model() -> Option<String> {
    ["/proc/device-tree/model", "/sys/devices/virtual/dmi/id/product_name"]
        .into_iter().find_map(|path| std::fs::read_to_string(path).ok())
        .map(|value| value.trim_matches(['\0', '\n', ' ']).to_owned())
}

fn read_os_release() -> Option<String> {
    std::fs::read_to_string("/etc/os-release").ok()?.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim_matches('"').to_owned())
}

/// /proc/net/dev includes drops and errors, which sysinfo's network API does not expose.
fn read_network() -> Vec<NetworkInterface> {
    let Ok(data) = std::fs::read_to_string("/proc/net/dev") else { return Vec::new(); };
    let mut out = Vec::new();
    for line in data.lines().skip(2) {
        let Some((name, values)) = line.split_once(':') else { continue; };
        let n = values.split_whitespace().filter_map(|v| v.parse::<u64>().ok()).collect::<Vec<_>>();
        if n.len() < 16 { continue; }
        out.push(NetworkInterface {
            name: name.trim().to_owned(), rx_bytes: n[0], rx_packets: n[1], rx_errors: n[2], rx_drops: n[3],
            tx_bytes: n[8], tx_packets: n[9], tx_errors: n[10], tx_drops: n[11],
            rx_bytes_per_sec: None, tx_bytes_per_sec: None,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn read_thermal_fallback() -> Vec<Temperature> {
    let mut result = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/thermal") else { return result; };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("thermal_zone") { continue; }
        let label = std::fs::read_to_string(entry.path().join("type")).unwrap_or_default().trim().to_owned();
        let Ok(value) = std::fs::read_to_string(entry.path().join("temp")) else { continue; };
        let Ok(millidegrees) = value.trim().parse::<f32>() else { continue; };
        let celsius = millidegrees / 1000.0;
        if celsius.is_finite() && (-30.0..=150.0).contains(&celsius) {
            result.push(Temperature { label, celsius });
        }
    }
    result.sort_by(|a, b| a.label.cmp(&b.label));
    result.truncate(32);
    result
}

fn sample_loop(app: AppState, running: Arc<AtomicBool>) {
    set_normal_priority();
    let mut system = System::new_all();
    let mut components = Components::new_with_refreshed_list();
    let pid = Pid::from_u32(std::process::id());
    let started = Instant::now();
    let model = read_model();
    let os = read_os_release().or_else(System::name);
    let mut previous_network: HashMap<String, NetworkInterface> = HashMap::new();
    let mut previous_time: Option<Instant> = None;
    let mut last_temperature = Instant::now() - Duration::from_secs(5);
    let mut temperatures: Vec<Temperature> = Vec::new();
    let mut temperature_measured_at_ms = None;
    let mut last_rtt_at = None;
    while running.load(Ordering::Relaxed) {
        let cycle = Instant::now();
        system.refresh_cpu_usage();
        system.refresh_memory();
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        if last_temperature.elapsed() >= Duration::from_secs(5) {
            components.refresh(true);
            temperatures = components.iter().filter_map(|c| c.temperature().map(|temperature| Temperature {
                label: c.label().to_owned(), celsius: temperature,
            })).filter(|c| c.celsius.is_finite()).collect();
            let fallback = read_thermal_fallback();
            let sensor_key = |label: &str| {
                label.chars().filter(char::is_ascii_alphanumeric).collect::<String>()
                    .to_ascii_lowercase().trim_end_matches("temp1").to_owned()
            };
            for sensor in fallback {
                if !temperatures.iter().any(|existing| sensor_key(&existing.label) == sensor_key(&sensor.label)) {
                    temperatures.push(sensor);
                }
            }
            temperatures.truncate(32);
            temperature_measured_at_ms = Some(unix_ms());
            last_temperature = Instant::now();
        }
        let cpu_temperature_c = temperatures.iter()
            .find(|t| ["cpu", "package", "core", "soc"].iter().any(|term| t.label.to_lowercase().contains(term)))
            .map(|t| t.celsius);
        let mut network = read_network();
        let seconds = previous_time.map(|then| cycle.duration_since(then).as_secs_f64()).filter(|v| *v > 0.0);
        for interface in &mut network {
            if let (Some(old), Some(seconds)) = (previous_network.get(&interface.name), seconds) {
                interface.rx_bytes_per_sec = interface.rx_bytes.checked_sub(old.rx_bytes).map(|delta| delta as f64 / seconds);
                interface.tx_bytes_per_sec = interface.tx_bytes.checked_sub(old.tx_bytes).map(|delta| delta as f64 / seconds);
            }
        }
        previous_network = network.iter().map(|item| (item.name.clone(), item.clone())).collect();
        previous_time = Some(cycle);
        let cpu_cores = system.cpus().len();
        let data = SystemSnapshot {
            measured_at_ms: unix_ms(),
            hostname: System::host_name(), model: model.clone(),
            cpu_model: system.cpus().first().map(|cpu| cpu.brand().to_owned()), cpu_cores,
            linux_version: os.clone(), kernel_version: System::kernel_version(),
            architecture: Some(System::cpu_arch()), host_uptime_sec: System::uptime(),
            process_uptime_sec: started.elapsed().as_secs(),
            cpu_percent: system.global_cpu_usage(),
            process_cpu_percent: system.process(pid).map(|p| p.cpu_usage() / cpu_cores.max(1) as f32),
            ram_used_bytes: system.used_memory(), ram_total_bytes: system.total_memory(),
            process_ram_bytes: system.process(pid).map(|p| p.memory()),
            cpu_temperature_c, temperature_measured_at_ms, temperatures: temperatures.clone(), network,
        };
        *app.system.write().unwrap() = data.clone();
        let radio = app.monitor.radio.read().unwrap();
        let swmi = app.monitor.swmi.read().unwrap();
        let radio_fresh = radio.measured_at_ms != 0 && data.measured_at_ms.saturating_sub(radio.measured_at_ms) <= 5_000;
        let rtt_fresh = swmi.connected && swmi.rtt_measured_at_ms.is_some_and(|at| data.measured_at_ms.saturating_sub(at) <= 5_000);
        let rtt_changed = rtt_fresh && swmi.rtt_measured_at_ms != last_rtt_at;
        if rtt_changed { last_rtt_at = swmi.rtt_measured_at_ms; }
        let mut history = app.history.write().unwrap();
        let point = HistoryPoint {
            seq: history.back().map_or(1, |last| last.seq + 1), at_ms: data.measured_at_ms,
            cpu_percent: Some(data.cpu_percent),
            ram_percent: (data.ram_total_bytes > 0).then(|| data.ram_used_bytes as f64 * 100.0 / data.ram_total_bytes as f64),
            cpu_temperature_c: data.cpu_temperature_c,
            temperatures: data.temperatures.clone(),
            rx_bytes_per_sec: data.network.iter().filter_map(|n| n.rx_bytes_per_sec).reduce(|a, b| a + b),
            tx_bytes_per_sec: data.network.iter().filter_map(|n| n.tx_bytes_per_sec).reduce(|a, b| a + b),
            interfaces: data.network.iter().take(32).map(|n| InterfaceRate {
                name: n.name.clone(), rx_bytes_per_sec: n.rx_bytes_per_sec, tx_bytes_per_sec: n.tx_bytes_per_sec,
            }).collect(),
            ra_score: radio_fresh.then(|| radio.ra.window.as_ref().map(|w| w.ewma_score)).flatten(),
            ra_load: radio_fresh.then(|| radio.ra.load.clone()),
            rtt_ms: rtt_changed.then_some(swmi.rtt_ms).flatten(),
            terminal_count: radio_fresh.then_some(radio.terminals.len()),
        };
        history.push_back(point);
        if history.len() > HISTORY_CAPACITY { history.pop_front(); }
        drop(history);
        drop(swmi);
        drop(radio);
        let remaining = Duration::from_secs(1).saturating_sub(cycle.elapsed());
        if !remaining.is_zero() { thread::sleep(remaining); }
    }
}

#[cfg(unix)]
fn set_normal_priority() {
    let param = libc::sched_param { sched_priority: 0 };
    let result = unsafe { libc::sched_setscheduler(0, libc::SCHED_OTHER, &param) };
    if result != 0 { tracing::warn!(error = %std::io::Error::last_os_error(), "could not set dashboard thread to normal priority"); }
}

#[cfg(not(unix))]
fn set_normal_priority() {}

pub struct WebServer {
    server: thread::JoinHandle<()>,
    sampler: thread::JoinHandle<()>,
}

impl WebServer {
    pub fn join(self) {
        let _ = self.server.join();
        let _ = self.sampler.join();
    }
}

pub fn start(
    config: &CfgWeb,
    config_path: &str,
    swmi: Option<(&str, u16, bool)>,
    monitor: SharedMonitor,
    stack_config: SharedConfig,
    running: Arc<AtomicBool>,
) -> Result<WebServer, String> {
    let address = SocketAddr::new(config.bind_address, config.port);
    let listener = TcpListener::bind(address).map_err(|e| format!("cannot bind dashboard at {address}: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let app = Arc::new(AppData {
        run_id: format!("{}-{}", unix_ms(), std::process::id()),
        monitor, system: RwLock::new(SystemSnapshot::default()), history: RwLock::new(VecDeque::with_capacity(HISTORY_CAPACITY)),
        swmi_host: swmi.map_or("".to_owned(), |s| s.0.to_owned()),
        swmi_port: swmi.map_or(0, |s| s.1), swmi_tls: swmi.is_some_and(|s| s.2),
        config_path: std::fs::canonicalize(config_path).map_err(|e| format!("cannot resolve configuration path: {e}"))?,
        config_lock: Mutex::new(()), config: stack_config,
        restart_scheduled: AtomicBool::new(false), running: running.clone(),
    });
    let sampler_app = app.clone();
    let sampler_running = running.clone();
    let sampler = thread::Builder::new().name("bs-web-sampler".to_owned())
        .spawn(move || sample_loop(sampler_app, sampler_running)).map_err(|e| e.to_string())?;
    let server = thread::Builder::new().name("bs-web-http".to_owned()).spawn(move || {
        set_normal_priority();
        let router = Router::new()
            .route("/", get(|| async { ([(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))], Html(INDEX)) }))
            .route("/api/v1/snapshot", get(snapshot))
            .route("/api/v1/history", get(history))
            .route("/api/v1/config", get(config::get_config).put(config::put_config))
            .route("/assets/bootstrap.min.css", get(|| async { static_asset(BOOTSTRAP, "text/css; charset=utf-8") }))
            .route("/assets/bootstrap.min.js", get(|| async { static_asset(BOOTSTRAP_JS, "text/javascript; charset=utf-8") }))
            .route("/assets/chart.umd.min.js", get(|| async { static_asset(CHART, "text/javascript; charset=utf-8") }))
            .route("/assets/dashboard.css", get(|| async { static_asset(CSS, "text/css; charset=utf-8") }))
            .route("/assets/dashboard.js", get(|| async { static_asset(JS, "text/javascript; charset=utf-8") }))
            .route("/assets/config.js", get(|| async { static_asset(CONFIG_JS, "text/javascript; charset=utf-8") }))
            .route("/assets/frequency.js", get(|| async { static_asset(FREQUENCY_JS, "text/javascript; charset=utf-8") }))
            .route("/assets/logo.svg", get(|| async { static_asset(LOGO, "image/svg+xml") }))
            .fallback(|| async { StatusCode::NOT_FOUND })
            .layer(DefaultBodyLimit::max(64 * 1024))
            .with_state(app);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("dashboard runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("dashboard listener");
            tracing::info!(%address, "BS dashboard listening");
            let shutdown = async move {
                while running.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(200)).await; }
            };
            if let Err(error) = axum::serve(listener, router).with_graceful_shutdown(shutdown).await {
                tracing::error!(%error, "dashboard server stopped");
            }
        });
    }).map_err(|e| e.to_string())?;
    Ok(WebServer { server, sampler })
}
