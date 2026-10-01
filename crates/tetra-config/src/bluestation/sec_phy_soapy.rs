use serde::Deserialize;
use std::collections::HashMap;
use toml::Value;

/// SoapySDR configuration
#[derive(Debug, Clone)]
pub struct CfgSoapySdr {
    /// Uplink frequency in Hz
    pub ul_freq: f64,
    /// Downlink frequency in Hz
    pub dl_freq: f64,
    /// RX LO offset from the selected carrier in Hz. Positive values place the LO above the carrier.
    pub rx_lo_offset_hz: i64,
    /// TX LO offset from the selected carrier in Hz. Positive values place the LO above the carrier.
    pub tx_lo_offset_hz: i64,
    /// TX baseband DC correction added to active I samples, in normalized sample units.
    pub tx_dc_i: f32,
    /// TX baseband DC correction added to active Q samples, in normalized sample units.
    pub tx_dc_q: f32,
    /// Relative TX Q-path gain correction in dB.
    pub tx_iq_gain_db: f32,
    /// TX I/Q quadrature phase correction in degrees.
    pub tx_iq_phase_deg: f32,
    /// Run SXceiver/MuCell SX1255 RF-loopback TX DC and I/Q calibration before starting the BS stack.
    pub tx_dc_calibration_on_startup: bool,
    /// PPM frequency error correction
    pub ppm_err: f64,
    /// Argument string to select a specific SDR device.
    /// If None, devices will be enumerated until the first supported device is found.
    pub device: Option<String>,
    /// RX antenna. Device specific default will be used if None.
    pub rx_ant: Option<String>,
    /// TX antenna. Device specific default will be used if None.
    pub tx_ant: Option<String>,
    /// RX gain values.
    /// Device specific defaults will be used for gains that are not set.
    pub rx_gains: HashMap<String, f64>,
    /// TX gain values.
    /// Device specific defaults will be used for gains that are not set.
    pub tx_gains: HashMap<String, f64>,
    /// RX and TX sample rate. Device specific default will be used if None.
    pub fs: Option<f64>,
    /// RX channel number
    pub rx_ch: Option<usize>,
    /// TX channel number
    pub tx_ch: Option<usize>,
}

impl CfgSoapySdr {
    /// Get corrected UL frequency with PPM error applied
    pub fn ul_freq_corrected(&self) -> (f64, f64) {
        let ppm = self.ppm_err;
        let err = (self.ul_freq / 1_000_000.0) * ppm;
        (self.ul_freq + err, err)
    }

    /// Get corrected DL frequency with PPM error applied
    pub fn dl_freq_corrected(&self) -> (f64, f64) {
        let ppm = self.ppm_err;
        let err = (self.dl_freq / 1_000_000.0) * ppm;
        (self.dl_freq + err, err)
    }
}

#[derive(Deserialize)]
pub struct SoapySdrDto {
    pub rx_freq: f64,
    pub tx_freq: f64,
    pub rx_lo_offset_hz: Option<i64>,
    pub tx_lo_offset_hz: Option<i64>,
    pub tx_dc_i: Option<f32>,
    pub tx_dc_q: Option<f32>,
    pub tx_iq_gain_db: Option<f32>,
    pub tx_iq_phase_deg: Option<f32>,
    pub tx_dc_calibration_on_startup: Option<bool>,
    pub ppm_err: Option<f64>,

    pub device: Option<String>,

    pub rx_antenna: Option<String>,
    pub tx_antenna: Option<String>,

    pub sample_rate: Option<f64>,
    pub rx_channel: Option<usize>,
    pub tx_channel: Option<usize>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
