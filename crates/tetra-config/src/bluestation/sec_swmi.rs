use std::{collections::HashMap, time::Duration};

use serde::Deserialize;
use toml::Value;

use crate::bluestation::SecretField;

/// Connection settings for the native central SwMI.
///
/// MCC, MNC and Location Area deliberately do not live here. They are supplied
/// by the authenticated SwMI as a versioned CellConfig and cached for LST.
#[derive(Debug, Clone)]
pub struct CfgSwmi {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// Optional PEM CA certificate used exclusively for the SwMI WSS server.
    /// This is the explicit trust anchor for a self-signed deployment.
    pub ca_certificate: Option<String>,
    pub username: String,
    pub password: SecretField,
    pub reconnect_delay: Duration,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
}

#[derive(Default, Deserialize)]
pub struct CfgSwmiDto {
    pub host: String,
    #[serde(default = "default_swmi_port")]
    pub port: u16,
    #[serde(default = "default_tls")]
    pub tls: bool,
    #[serde(default)]
    pub ca_certificate: Option<String>,
    pub username: String,
    pub password: String,
    #[serde(default = "default_reconnect_delay_secs")]
    pub reconnect_delay_secs: u64,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

fn default_swmi_port() -> u16 {
    443
}
fn default_tls() -> bool {
    true
}
fn default_reconnect_delay_secs() -> u64 {
    5
}
fn default_heartbeat_interval_secs() -> u64 {
    2
}
fn default_heartbeat_timeout_secs() -> u64 {
    10
}

pub fn apply_swmi_patch(src: CfgSwmiDto) -> Result<CfgSwmi, &'static str> {
    if src.host.trim().is_empty() || src.username.trim().is_empty() || src.password.is_empty() {
        return Err("swmi host, username and password must be set");
    }
    if src.heartbeat_interval_secs == 0 || src.heartbeat_timeout_secs <= src.heartbeat_interval_secs {
        return Err("swmi heartbeat_timeout_secs must be greater than heartbeat_interval_secs");
    }
    if !src.tls && src.ca_certificate.is_some() {
        return Err("swmi ca_certificate requires tls = true");
    }
    Ok(CfgSwmi {
        host: src.host,
        port: src.port,
        tls: src.tls,
        ca_certificate: src.ca_certificate,
        username: src.username,
        password: SecretField::from(src.password),
        reconnect_delay: Duration::from_secs(src.reconnect_delay_secs),
        heartbeat_interval: Duration::from_secs(src.heartbeat_interval_secs),
        heartbeat_timeout: Duration::from_secs(src.heartbeat_timeout_secs),
    })
}
