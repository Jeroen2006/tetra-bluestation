use soapysdr;
use tetra_config::bluestation::{SharedConfig, StackMode, sec_phy_soapy::CfgSoapySdr};

use tetra_pdus::phy::traits::rxtx_dev::RxTxDevError;

use super::dsp_types::*;
use super::soapy_settings;
use super::soapy_settings::{SdrSettings, SupportedDevice};
use super::soapy_time::{ticks_to_time_ns, time_ns_to_ticks};

type StreamType = ComplexSample;
const CHANNEL_HALF_BANDWIDTH_GUARD_HZ: f64 = 20_000.0;

fn validate_lo_offset(offset_hz: i64, sample_rate: f64, direction: &str) -> Result<(), soapysdr::Error> {
    let half_bandwidth = (offset_hz as f64).abs() + CHANNEL_HALF_BANDWIDTH_GUARD_HZ;
    if !sample_rate.is_finite() || sample_rate <= 0.0 || half_bandwidth >= sample_rate / 2.0 {
        return Err(soapysdr::Error {
            code: soapysdr::ErrorCode::Other,
            message: format!("{direction} LO offset {offset_hz} Hz exceeds the available baseband range at {sample_rate} S/s"),
        });
    }
    Ok(())
}

fn apply_tx_dc_offset(samples: &[StreamType], dc_i: f32, dc_q: f32) -> Vec<StreamType> {
    let correction = ComplexSample::new(dc_i, dc_q);
    samples
        .iter()
        .map(|sample| {
            if *sample == ComplexSample::ZERO {
                *sample
            } else {
                *sample + correction
            }
        })
        .collect()
}

pub struct RxResult {
    /// Number of samples read
    pub len: usize,
    /// Sample counter for the first sample read
    pub count: SampleCount,
}

pub struct SoapyIo {
    rx_ch: usize,
    tx_ch: usize,
    rx_fs: f64,
    tx_fs: f64,
    tx_dc_i: f32,
    tx_dc_q: f32,
    /// Timestamp for the first sample read from SDR.
    /// This is subtracted from all following timestamps,
    /// so that sample counter startsB210 from 0 even if timestamp does not.
    initial_time: Option<i64>,
    rx_next_count: SampleCount,
    prev_time_ns: i64,

    /// If false, timestamp of latest RX read is used to estimate
    /// current hardware time. This is used in case get_hardware_time
    /// is unacceptably slow or not supported.
    use_get_hardware_time: bool,

    dev: soapysdr::Device,
    /// Receive stream. None if receiving is disabled.
    rx: Option<soapysdr::RxStream<StreamType>>,
    /// Transmit stream. None if transmitting is disabled.
    tx: Option<soapysdr::TxStream<StreamType>>,
    tx_active: bool,
}

/// Soapy/Lime timestamps can occasionally jitter by a single sample.
/// Treat tiny deltas as contiguous to avoid triggering large block realignments downstream.
const RX_TIMESTAMP_JITTER_TOLERANCE_SAMPLES: SampleCount = 1;

/// It is annoying to repeat error handling so do that in a macro.
/// ? could be used but then it could not print which SoapySDR call failed.
macro_rules! soapycheck {
    ($text:literal, $soapysdr_call:expr) => {
        match $soapysdr_call {
            Ok(ret) => ret,
            Err(err) => {
                tracing::error!("SoapySDR: Failed to {}: {}", $text, err);
                return Err(err);
            }
        }
    };
}

impl SoapyIo {
    pub fn new(cfg: &SharedConfig) -> Result<Self, soapysdr::Error> {
        let binding = cfg.config();
        let soapy_cfg = binding
            .phy_io
            .soapysdr
            .as_ref()
            .expect("SoapySdr config must be set for SoapySdr PhyIo");

        let mode = cfg.config().stack_mode;

        let (dev, sdr_settings) = open_device(&soapy_cfg, mode)?;

        let rx_ch = sdr_settings.rx_ch;
        let tx_ch = sdr_settings.tx_ch;

        // Get PPM corrected freqs
        let (dl_corrected, _) = soapy_cfg.dl_freq_corrected();
        let (ul_corrected, _) = soapy_cfg.ul_freq_corrected();

        let (rx_freq, tx_freq) = match mode {
            StackMode::Bs => (
                Some(ul_corrected + soapy_cfg.rx_lo_offset_hz as f64),
                Some(dl_corrected + soapy_cfg.tx_lo_offset_hz as f64),
            ),
            StackMode::Ms => (
                Some(dl_corrected + soapy_cfg.rx_lo_offset_hz as f64),
                Some(ul_corrected + soapy_cfg.tx_lo_offset_hz as f64),
            ),
            StackMode::Mon => {
                unimplemented!("Monitor mode not implemented yet");
            }
        };

        let rx_enabled = rx_freq.is_some();
        let tx_enabled = tx_freq.is_some();

        let mut rx_fs: f64 = 0.0;
        if rx_enabled {
            soapycheck!(
                "set RX sample rate",
                dev.set_sample_rate(soapysdr::Direction::Rx, rx_ch, sdr_settings.fs)
            );
            // Read the actual sample rate obtained and store it
            // to avoid having to read it again every time it is needed.
            rx_fs = soapycheck!("get RX sample rate", dev.sample_rate(soapysdr::Direction::Rx, rx_ch));
            validate_lo_offset(soapy_cfg.rx_lo_offset_hz, rx_fs, "RX")?;
        }
        let mut tx_fs: f64 = 0.0;
        if tx_enabled {
            soapycheck!(
                "set TX sample rate",
                dev.set_sample_rate(soapysdr::Direction::Tx, tx_ch, sdr_settings.fs)
            );
            tx_fs = soapycheck!("get TX sample rate", dev.sample_rate(soapysdr::Direction::Tx, tx_ch));
            validate_lo_offset(soapy_cfg.tx_lo_offset_hz, tx_fs, "TX")?;
        }

        if rx_enabled {
            // If rx_enabled is true, we already know rx_freq is not None,
            // so unwrap is fine here.
            soapycheck!(
                "set RX center frequency",
                dev.set_frequency(soapysdr::Direction::Rx, rx_ch, rx_freq.unwrap(), soapysdr::Args::new())
            );

            if let Some(ref ant) = sdr_settings.rx_ant {
                soapycheck!("set RX antenna", dev.set_antenna(soapysdr::Direction::Rx, rx_ch, ant.as_str()));
            }

            for (name, gain) in &sdr_settings.rx_gain {
                soapycheck!(
                    "set RX gain",
                    dev.set_gain_element(soapysdr::Direction::Rx, rx_ch, name.as_str(), *gain)
                );
            }
        }

        if tx_enabled {
            soapycheck!(
                "set TX center frequency",
                dev.set_frequency(soapysdr::Direction::Tx, tx_ch, tx_freq.unwrap(), soapysdr::Args::new())
            );

            if let Some(ref ant) = sdr_settings.tx_ant {
                soapycheck!("set TX antenna", dev.set_antenna(soapysdr::Direction::Tx, tx_ch, ant.as_str()));
            }

            for (name, gain) in &sdr_settings.tx_gain {
                soapycheck!(
                    "set TX gain",
                    dev.set_gain_element(soapysdr::Direction::Tx, tx_ch, name.as_str(), *gain)
                );
            }
        }

        let mut rx_args = soapysdr::Args::new();
        for (key, value) in sdr_settings.rx_args {
            rx_args.set(key, value);
        }

        let mut tx_args = soapysdr::Args::new();
        for (key, value) in sdr_settings.tx_args {
            tx_args.set(key, value);
        }

        let mut rx = if rx_enabled {
            Some(soapycheck!("setup RX stream", dev.rx_stream_args(&[rx_ch], rx_args)))
        } else {
            None
        };
        let tx = if tx_enabled {
            Some(soapycheck!("setup TX stream", dev.tx_stream_args(&[tx_ch], tx_args)))
        } else {
            None
        };
        if let Some(rx) = &mut rx {
            soapycheck!("activate RX stream", rx.activate(None));
        }
        Ok(Self {
            rx_ch,
            tx_ch,
            rx_fs,
            tx_fs,
            tx_dc_i: soapy_cfg.tx_dc_i,
            tx_dc_q: soapy_cfg.tx_dc_q,
            initial_time: None,
            rx_next_count: 0,
            prev_time_ns: -1,
            use_get_hardware_time: sdr_settings.use_get_hardware_time,
            dev,
            rx,
            tx,
            tx_active: false,
        })
    }

    /// Switch the physical transmitter without disturbing the receive clock.
    pub fn set_tx_active(&mut self, active: bool) -> Result<(), soapysdr::Error> {
        if self.tx_active == active {
            return Ok(());
        }
        if let Some(tx) = &mut self.tx {
            if active { tx.activate(None)?; } else { tx.deactivate(None)?; }
            self.tx_active = active;
        }
        Ok(())
    }

    pub fn receive(&mut self, buffer: &mut [StreamType]) -> Result<RxResult, RxTxDevError> {
        if let Some(rx) = &mut self.rx {
            // RX is enabled
            match rx.read(&mut [buffer], 1000000) {
                Ok(len) => {
                    // Get timestamp, set initial time if not yet set
                    let time = rx.time_ns();
                    // rust-soapysdr does not let us if a timestamp was available
                    // so we have to guess by checking whether it has changed from its previous value.
                    let timestamp_available = time != self.prev_time_ns;
                    self.prev_time_ns = time;

                    if self.initial_time.is_none() && timestamp_available {
                        self.initial_time = Some(time - ticks_to_time_ns(self.rx_next_count, self.rx_fs));
                        tracing::trace!("Set initial_time to {} ns", self.initial_time.unwrap());
                    };

                    // Re-compute total count from timestamp (gracefully handles lost samples).
                    let mut count = if timestamp_available {
                        time_ns_to_ticks(time - self.initial_time.unwrap(), self.rx_fs)
                    } else {
                        // If timestamp was not available,
                        // assume the read continues right after the previous read.
                        // Some drivers, particularly SoapyRemote,
                        // may provide a timestamp only in some of the reads.
                        self.rx_next_count
                    };

                    // Smooth tiny timestamp jitter (e.g. +/-1 sample) to keep counters monotonic
                    // This is known to happen for LimeSDR Mini v2 after some time
                    let delta_from_expected = count - self.rx_next_count;
                    if delta_from_expected.abs() <= RX_TIMESTAMP_JITTER_TOLERANCE_SAMPLES {
                        if delta_from_expected != 0 {
                            // Re-anchor phase so persistent +/-1 sample offset is corrected
                            let initial_time = self.initial_time.unwrap() + ticks_to_time_ns(delta_from_expected, self.rx_fs); // unwrap never fails
                            self.initial_time = Some(initial_time);
                            tracing::debug!(
                                "RX timestamp jitter {} sample(s); re-anchoring initial_time by {} ns",
                                delta_from_expected,
                                ticks_to_time_ns(delta_from_expected, self.rx_fs)
                            );
                        }
                        count = self.rx_next_count;
                    }

                    // Store expected sample count for the next sample to be read.
                    // This is used in case timestamp is missing.
                    self.rx_next_count = count + len as SampleCount;

                    Ok(RxResult { len, count })
                }
                Err(_) => Err(RxTxDevError::RxReadError),
            }
        } else {
            // RX is disabled
            Err(RxTxDevError::RxReadError)
        }
    }

    pub fn transmit(&mut self, buffer: &[StreamType], count: Option<SampleCount>) -> Result<(), RxTxDevError> {
        if !self.tx_active {
            return Err(RxTxDevError::RxReadError);
        }
        let corrected_buffer = if self.tx_dc_i == 0.0 && self.tx_dc_q == 0.0 {
            None
        } else {
            Some(apply_tx_dc_offset(buffer, self.tx_dc_i, self.tx_dc_q))
        };
        let samples = corrected_buffer.as_deref().unwrap_or(buffer);
        if let Some(tx) = &mut self.tx {
            if let Some(initial_time) = self.initial_time {
                tx.write_all(
                    &[samples],
                    count.map(|count| initial_time + ticks_to_time_ns(count, self.tx_fs)),
                    false,
                    1000000,
                )
                .map_err(|_| RxTxDevError::RxReadError)
            } else {
                // initial_time is not available, so TX is not possible yet
                Err(RxTxDevError::RxReadError)
            }
        } else {
            // TX is disabled
            Err(RxTxDevError::RxReadError)
        }
    }

    pub fn current_time(&self) -> Result<i64, RxTxDevError> {
        self.dev.get_hardware_time(None).map_err(|_| RxTxDevError::RxReadError)
    }

    /// Current hardware time as RX sample count
    pub fn rx_current_count(&self) -> Result<SampleCount, RxTxDevError> {
        if !self.rx_enabled() {
            return Ok(0);
        }
        if self.use_get_hardware_time {
            Ok(time_ns_to_ticks(self.current_time()? - self.initial_time.unwrap_or(0), self.rx_fs))
        } else {
            Ok(self.rx_next_count - 1)
        }
    }

    /// Current hardware time as TX sample count
    pub fn tx_current_count(&self) -> Result<SampleCount, RxTxDevError> {
        if !self.tx_enabled() {
            return Ok(0);
        }
        if self.use_get_hardware_time {
            Ok(time_ns_to_ticks(self.current_time()? - self.initial_time.unwrap_or(0), self.tx_fs))
        } else {
            // Assumes equal RX and TX sample rates
            // and does not work if RX is disabled.
            // This is not a problem right now but could be fixed if needed.
            Ok(self.rx_next_count - 1)
        }
    }

    pub fn tx_possible(&self) -> bool {
        // initial_time is obtained from the first RX read (that includes a timestamp),
        // so prevent TX before it is available.
        self.tx_enabled() && self.tx_active && self.initial_time.is_some()
    }

    pub fn rx_sample_rate(&self) -> f64 {
        self.rx_fs
    }

    pub fn tx_sample_rate(&self) -> f64 {
        self.tx_fs
    }

    pub fn rx_center_frequency(&self) -> Result<f64, soapysdr::Error> {
        self.dev.frequency(soapysdr::Direction::Rx, self.rx_ch)
    }

    pub fn tx_center_frequency(&self) -> Result<f64, soapysdr::Error> {
        self.dev.frequency(soapysdr::Direction::Tx, self.tx_ch)
    }

    pub fn rx_enabled(&self) -> bool {
        self.rx.is_some()
    }

    pub fn tx_enabled(&self) -> bool {
        self.tx.is_some()
    }
}

// Messy logic related to opening a device follows...

/// Struct to temporarily hold stuff related to opening and detecting a device
struct OpenedDevice {
    dev_args: soapysdr::Args,
    dev: soapysdr::Device,
    driver_key: String,
    hardware_key: String,
    detected_device: SupportedDevice,
    soapyremote_used: bool,
}

fn open_given_device(dev_args: soapysdr::Args) -> Result<OpenedDevice, soapysdr::Error> {
    let soapyremote_used = match dev_args.get("driver") {
        Some("remote") => true,
        _ => false,
    };
    tracing::info!("Trying to open a device with arguments: {}", dev_args);

    let dev_args_copy: soapysdr::Args = dev_args.iter().collect();
    let dev = match soapysdr::Device::new(dev_args_copy) {
        Ok(dev) => dev,
        Err(err) => {
            tracing::info!("Skipping a SoapySDR device because opening failed: {}", err);
            return Err(err);
        }
    };
    let driver_key = dev.driver_key().unwrap_or_default();
    let hardware_key = dev.hardware_key().unwrap_or_default();

    // Check whether the device is supported
    if let Some(detected_device) = SupportedDevice::detect(&driver_key, &hardware_key) {
        tracing::info!(
            "Found supported device with driver_key '{}' hardware_key '{}'",
            driver_key,
            hardware_key
        );
        Ok(OpenedDevice {
            dev_args,
            dev,
            driver_key,
            hardware_key,
            detected_device,
            soapyremote_used,
        })
    } else {
        tracing::info!(
            "Skipping unsupported device with driver_key '{}' hardware_key '{}'",
            driver_key,
            hardware_key
        );
        Err(soapysdr::Error {
            code: soapysdr::ErrorCode::NotSupported,
            message: "Unsupported device".to_string(),
        })
    }
}

/// Enumerate devices and find the first supported device
fn find_supported_device(filter_args: soapysdr::Args) -> Result<OpenedDevice, soapysdr::Error> {
    for dev_args in soapycheck!("Enumerate SoapySDR devices", soapysdr::enumerate(filter_args)) {
        //tracing::info!("Trying to open a device with arguments: {}", args_formatted);
        match open_given_device(dev_args) {
            Ok(opened_device) => return Ok(opened_device),
            Err(_) => {}
        }
    }
    return Err(soapysdr::Error {
        code: soapysdr::ErrorCode::NotSupported,
        message: "No supported devices found".to_string(),
    });
}

/// Open a given device if argument string is given,
/// automatically find the first supported device if not.
fn open_device(soapy_cfg: &CfgSoapySdr, mode: StackMode) -> Result<(soapysdr::Device, SdrSettings), soapysdr::Error> {
    let mut opened_device = if let Some(arg_string) = &soapy_cfg.device {
        open_given_device(arg_string.as_str().into())
    } else {
        find_supported_device(soapysdr::Args::new())
    }?;

    let mut sdr_settings = match SdrSettings::get_settings(&soapy_cfg, opened_device.detected_device, mode) {
        Ok(sdr_settings) => sdr_settings,
        Err(soapy_settings::Error::InvalidConfiguration) => {
            return Err(soapysdr::Error {
                code: soapysdr::ErrorCode::Other,
                message: "Invalid SDR device configuration".to_string(),
            });
        }
    };

    if opened_device.soapyremote_used {
        // Getting hardware time may be too slow over SoapyRemote
        tracing::info!("SoapyRemote detected, forcing use_get_hardware_time=false");
        sdr_settings.use_get_hardware_time = false;
    }

    tracing::info!("Using settings: {:?}", sdr_settings);

    // If additional driver arguments are needed, reopen the device with them
    if sdr_settings.dev_args.len() > 0 {
        // Append additional arguments from settings
        for (key, value) in &sdr_settings.dev_args {
            opened_device.dev_args.set(key.as_str(), value.as_str());
        }

        tracing::info!("Reopening device with additional arguments: {}", opened_device.dev_args);

        // Make sure device gets closed first. Not sure if needed.
        std::mem::drop(opened_device.dev);
        opened_device.dev = soapycheck!(
            "open SoapySDR device with additional arguments",
            soapysdr::Device::new(opened_device.dev_args)
        );
        // Make sure it is still the same device.
        // Unlikely to change, but who knows if a device got connected just in between,
        // or if the device broke from first opening attempt and something else got opened
        // because device arguments were not precise enough to guarantee a specific device.
        let new_driver_key = opened_device.dev.driver_key().unwrap_or_default();
        let new_hardware_key = opened_device.dev.hardware_key().unwrap_or_default();
        if new_driver_key != opened_device.driver_key || new_hardware_key != opened_device.hardware_key {
            tracing::info!(
                "Expected the same driver_key='{}' hardware_key='{}' after reopen, got driver_key='{}' hardware_key='{}'",
                opened_device.driver_key,
                opened_device.hardware_key,
                new_driver_key,
                new_hardware_key
            );
            return Err(soapysdr::Error {
                code: soapysdr::ErrorCode::Other,
                message: "Reopened a different device".to_string(),
            });
        }
    }

    Ok((opened_device.dev, sdr_settings))
}

#[cfg(test)]
mod tests {
    use super::{apply_tx_dc_offset, validate_lo_offset};
    use crate::phy::components::dsp_types::ComplexSample;

    #[test]
    fn tx_dc_offset_changes_signal_samples_and_preserves_silence() {
        let input = [ComplexSample::ZERO, ComplexSample::new(0.25, -0.5), ComplexSample::ZERO];

        let output = apply_tx_dc_offset(&input, 0.01, -0.02);

        assert_eq!(output[0], ComplexSample::ZERO);
        assert_eq!(output[1], ComplexSample::new(0.26, -0.52));
        assert_eq!(output[2], ComplexSample::ZERO);
    }

    #[test]
    fn zero_tx_dc_offset_preserves_samples() {
        let input = [ComplexSample::ZERO, ComplexSample::new(0.25, -0.5)];
        assert_eq!(apply_tx_dc_offset(&input, 0.0, 0.0), input);
    }

    #[test]
    fn lo_offset_must_leave_room_for_the_tetra_channel() {
        assert!(validate_lo_offset(-50_000, 600_000.0, "TX").is_ok());
        assert!(validate_lo_offset(-280_000, 600_000.0, "TX").is_err());
        assert!(validate_lo_offset(-20_000, f64::NAN, "RX").is_err());
    }
}
