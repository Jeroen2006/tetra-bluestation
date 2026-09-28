//! Startup TX DC calibration for SXceiver radios with SX1255 RF loopback.

use soapysdr::{Args, Direction, Error, ErrorCode};
use tetra_config::bluestation::{StackMode, sec_phy_soapy::CfgSoapySdr};

use super::dsp_types::ComplexSample;
use super::soapy_settings::SdrSettings;
use super::soapyio::open_device;

const TX_PILOT_HZ: f64 = 100_000.0;
const RX_LO_OFFSET_HZ: f64 = 25_000.0;
const TX_PILOT_AMPLITUDE: f32 = 0.02;
const MAX_TX_DC_CORRECTION: f32 = 0.05;
const TX_BLOCK_SAMPLES: usize = 4096;
const MEASURED_BLOCKS: usize = 4;

/// Calibrate TX baseband DC through the SX1255's RF loopback and return the
/// values to persist in the station configuration.
pub fn calibrate_tx_dc(cfg: &CfgSoapySdr, mode: StackMode) -> Result<(f32, f32), Error> {
    if mode != StackMode::Bs {
        return Err(calibration_error("SXceiver TX DC calibration requires BS mode"));
    }

    if cfg.tx_dc_i.abs() > MAX_TX_DC_CORRECTION || cfg.tx_dc_q.abs() > MAX_TX_DC_CORRECTION {
        return Err(calibration_error(format!(
            "Configured TX DC correction is outside the automatic calibration range (+/-{MAX_TX_DC_CORRECTION})"
        )));
    }

    // RF loopback is selected on RX while the normal TX antenna setting is
    // retained. This config clone is used only while the temporary radio is open.
    let mut loopback_cfg = cfg.clone();
    loopback_cfg.rx_ant = Some("LB".to_string());
    let (dev, settings, is_sxceiver) = open_device(&loopback_cfg, mode)?;
    if !is_sxceiver {
        return Err(calibration_error(
            "Startup TX DC calibration is only supported by the SXceiver driver",
        ));
    }

    let rx_ch = settings.rx_ch;
    let tx_ch = settings.tx_ch;
    let operation = run_calibration(&dev, &settings, cfg, rx_ch, tx_ch);

    // Force the physical PA off and leave RX antenna selection in its normal
    // position even when stream setup or a measurement failed.
    let tx_cleanup = dev.set_antenna(Direction::Tx, tx_ch, "NONE");
    let rx_cleanup = dev.set_antenna(Direction::Rx, rx_ch, "RX");

    match operation {
        Err(err) => Err(err),
        Ok(values) => {
            tx_cleanup?;
            rx_cleanup?;
            Ok(values)
        }
    }
}

fn run_calibration(
    dev: &soapysdr::Device,
    settings: &SdrSettings,
    cfg: &CfgSoapySdr,
    rx_ch: usize,
    tx_ch: usize,
) -> Result<(f32, f32), Error> {
    dev.set_antenna(Direction::Tx, tx_ch, "NONE")?;

    dev.set_sample_rate(Direction::Rx, rx_ch, settings.fs)?;
    let rx_fs = dev.sample_rate(Direction::Rx, rx_ch)?;
    dev.set_sample_rate(Direction::Tx, tx_ch, settings.fs)?;
    let tx_fs = dev.sample_rate(Direction::Tx, tx_ch)?;
    if !rx_fs.is_finite() || !tx_fs.is_finite() || rx_fs <= 0.0 || tx_fs <= 0.0 || (rx_fs - tx_fs).abs() > 1.0 {
        return Err(calibration_error(format!(
            "Unsupported SXceiver sample rates RX={rx_fs}, TX={tx_fs}"
        )));
    }
    if TX_PILOT_HZ + RX_LO_OFFSET_HZ + 20_000.0 >= rx_fs / 2.0 {
        return Err(calibration_error(format!(
            "Sample rate {rx_fs} S/s is too low for SXceiver TX DC calibration"
        )));
    }

    let (tx_lo_hz, _) = cfg.dl_freq_corrected();
    let tx_lo_hz = tx_lo_hz + cfg.tx_lo_offset_hz as f64;
    // Moving the RX LO below the TX LO brings TX LO leakage away from DC,
    // where receiver DC removal could hide it. The pilot lands at a separate IF.
    let rx_lo_hz = tx_lo_hz - RX_LO_OFFSET_HZ;
    dev.set_frequency(Direction::Rx, rx_ch, rx_lo_hz, Args::new())?;
    dev.set_frequency(Direction::Tx, tx_ch, tx_lo_hz, Args::new())?;

    let rx_antennas = dev.antennas(Direction::Rx, rx_ch)?;
    if !rx_antennas.iter().any(|antenna| antenna == "LB") {
        return Err(calibration_error("SXceiver driver does not expose the RF loopback antenna (LB)"));
    }
    dev.set_antenna(Direction::Rx, rx_ch, "LB")?;

    // The SX1255 loopback enters at the receiver mixer. Keep RX gain low so a
    // loopback signal cannot clip the ADC; TX gains remain the normal configured gains.
    dev.set_gain_element(Direction::Rx, rx_ch, "LNA", 0.0)?;
    dev.set_gain_element(Direction::Rx, rx_ch, "PGA", 0.0)?;
    for (name, gain) in &settings.tx_gain {
        dev.set_gain_element(Direction::Tx, tx_ch, name.as_str(), *gain)?;
    }

    let mut rx_args = Args::new();
    for (key, value) in &settings.rx_args {
        rx_args.set(key.as_str(), value.as_str());
    }
    let mut tx_args = Args::new();
    for (key, value) in &settings.tx_args {
        tx_args.set(key.as_str(), value.as_str());
    }

    let mut rx = dev.rx_stream_args(&[rx_ch], rx_args)?;
    let mut tx = dev.tx_stream_args(&[tx_ch], tx_args)?;
    rx.activate(None)?;
    tx.activate(None)?;
    dev.set_antenna(Direction::Tx, tx_ch, "TX")?;

    tracing::info!("Measuring SXceiver TX LO leakage through RF loopback; startup may take several seconds");
    let (tx_dc_i, tx_dc_q, before, after, pilot_power) = minimize_tx_dc(cfg.tx_dc_i, cfg.tx_dc_q, |i, q| {
        measure_loopback(&mut tx, &mut rx, tx_fs, RX_LO_OFFSET_HZ, TX_PILOT_HZ + RX_LO_OFFSET_HZ, i, q)
    })?;

    tx.deactivate(None)?;
    rx.deactivate(None)?;
    tracing::info!(
        "SXceiver TX DC calibration complete: TX DC I={tx_dc_i:.5}, TX DC Q={tx_dc_q:.5}; LO leakage relative to pilot {:.1} dBc -> {:.1} dBc",
        ratio_db(before, pilot_power),
        ratio_db(after, pilot_power),
    );
    Ok((tx_dc_i, tx_dc_q))
}

fn measure_loopback(
    tx: &mut soapysdr::TxStream<ComplexSample>,
    rx: &mut soapysdr::RxStream<ComplexSample>,
    sample_rate: f64,
    leakage_if_hz: f64,
    pilot_if_hz: f64,
    tx_dc_i: f32,
    tx_dc_q: f32,
) -> Result<(f64, f64), Error> {
    let phase_step = std::f64::consts::TAU * TX_PILOT_HZ / sample_rate;
    let mut tx_phase = 0.0_f64;
    let mut leakage_power = 0.0;
    let mut pilot_power = 0.0;
    let mut peak = 0.0_f32;
    let mut tx_samples = vec![ComplexSample::ZERO; TX_BLOCK_SAMPLES];
    let mut rx_samples = vec![ComplexSample::ZERO; TX_BLOCK_SAMPLES];

    // One block lets the stream and RF loopback settle after changing DC; the
    // following blocks provide averaged measurements at the LO and pilot IFs.
    for block in 0..=MEASURED_BLOCKS {
        for sample in &mut tx_samples {
            *sample = ComplexSample::new(
                (TX_PILOT_AMPLITUDE as f64 * tx_phase.cos()) as f32 + tx_dc_i,
                (TX_PILOT_AMPLITUDE as f64 * tx_phase.sin()) as f32 + tx_dc_q,
            );
            tx_phase = (tx_phase + phase_step).rem_euclid(std::f64::consts::TAU);
        }
        tx.write_all(&[tx_samples.as_slice()], None, false, 1_000_000)?;

        let mut filled = 0;
        while filled < rx_samples.len() {
            let received = rx.read(&mut [&mut rx_samples[filled..]], 1_000_000)?;
            if received == 0 {
                return Err(calibration_error("SXceiver returned an empty RX loopback buffer"));
            }
            filled += received;
        }

        if block == 0 {
            continue;
        }
        let (leakage, pilot, block_peak) = measure_spectrum_bins(&rx_samples, sample_rate, leakage_if_hz, pilot_if_hz);
        leakage_power += leakage;
        pilot_power += pilot;
        peak = peak.max(block_peak);
    }

    if peak > 0.95 {
        return Err(calibration_error(format!(
            "SXceiver RX loopback is clipping (peak sample {peak:.3})"
        )));
    }
    let pilot_power = pilot_power / MEASURED_BLOCKS as f64;
    if !pilot_power.is_finite() || pilot_power < 1e-12 {
        return Err(calibration_error(format!(
            "No usable TX pilot was detected through SXceiver RF loopback (power {pilot_power:.3e})"
        )));
    }
    Ok((leakage_power / MEASURED_BLOCKS as f64, pilot_power))
}

fn measure_spectrum_bins(samples: &[ComplexSample], sample_rate: f64, leakage_if_hz: f64, pilot_if_hz: f64) -> (f64, f64, f32) {
    let mut leakage = ComplexSample::ZERO;
    let mut pilot = ComplexSample::ZERO;
    let mut weight_sum = 0.0_f64;
    let mut peak = 0.0_f32;
    let last = samples.len().saturating_sub(1).max(1) as f64;

    for (index, sample) in samples.iter().enumerate() {
        let index_f = index as f64;
        let weight = 0.5 - 0.5 * (std::f64::consts::TAU * index_f / last).cos();
        let lo_phase = -std::f64::consts::TAU * leakage_if_hz * index_f / sample_rate;
        let pilot_phase = -std::f64::consts::TAU * pilot_if_hz * index_f / sample_rate;
        let lo_rotator = ComplexSample::new(lo_phase.cos() as f32, lo_phase.sin() as f32);
        let pilot_rotator = ComplexSample::new(pilot_phase.cos() as f32, pilot_phase.sin() as f32);
        leakage += *sample * lo_rotator * weight as f32;
        pilot += *sample * pilot_rotator * weight as f32;
        weight_sum += weight;
        peak = peak.max(sample.norm());
    }

    let scale = weight_sum.max(1.0).powi(2);
    ((leakage.norm_sqr() as f64) / scale, (pilot.norm_sqr() as f64) / scale, peak)
}

fn minimize_tx_dc<E, F>(start_i: f32, start_q: f32, mut measure: F) -> Result<(f32, f32, f64, f64, f64), E>
where
    F: FnMut(f32, f32) -> Result<(f64, f64), E>,
{
    let (mut current_i, mut current_q) = (start_i, start_q);
    let (mut current_score, mut pilot_power) = measure(current_i, current_q)?;
    let initial_score = current_score;

    for step in [0.02_f32, 0.01, 0.005, 0.002, 0.001, 0.0005, 0.0002] {
        loop {
            let mut best = (current_i, current_q, current_score, pilot_power);
            for (i, q) in [
                (current_i + step, current_q),
                (current_i - step, current_q),
                (current_i, current_q + step),
                (current_i, current_q - step),
            ] {
                if i.abs() > MAX_TX_DC_CORRECTION || q.abs() > MAX_TX_DC_CORRECTION {
                    continue;
                }
                let (score, pilot) = measure(i, q)?;
                let minimum_improvement = (best.2 * 0.002).max(1e-14);
                if score + minimum_improvement < best.2 {
                    best = (i, q, score, pilot);
                }
            }
            if best.0 == current_i && best.1 == current_q {
                break;
            }
            (current_i, current_q, current_score, pilot_power) = best;
        }
    }

    Ok((current_i, current_q, initial_score, current_score, pilot_power))
}

fn ratio_db(numerator: f64, denominator: f64) -> f64 {
    10.0 * (numerator.max(1e-20) / denominator.max(1e-20)).log10()
}

fn calibration_error(message: impl Into<String>) -> Error {
    Error {
        code: ErrorCode::Other,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TX_DC_CORRECTION, minimize_tx_dc};

    #[test]
    fn coordinate_search_finds_dc_minimum_and_stays_in_bounds() {
        let target = (0.019_f32, -0.016_f32);
        let (i, q, before, after, _) = minimize_tx_dc(0.0, 0.0, |i, q| {
            let error_i = i - target.0;
            let error_q = q - target.1;
            Ok::<_, ()>(((error_i * error_i + error_q * error_q) as f64, 1.0))
        })
        .expect("deterministic measurement succeeds");

        assert!((i - target.0).abs() <= 0.0002);
        assert!((q - target.1).abs() <= 0.0002);
        assert!(after < before * 1e-5);
        assert!(i.abs() <= MAX_TX_DC_CORRECTION);
        assert!(q.abs() <= MAX_TX_DC_CORRECTION);
    }
}
