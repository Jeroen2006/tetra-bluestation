use serde::{Deserialize, Serialize};
use tetra_config::bluestation::StackConfig;
use tetra_core::freqs::{FreqInfo, checked_freq_info};
use toml_edit::{DocumentMut, value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct FrequencySettings {
    pub frequency_band: u8,
    pub main_carrier: u16,
    pub offset_hz: i16,
    pub duplex_spacing: u8,
    pub custom_split_mhz: Option<f64>,
    pub reverse_operation: bool,
}

impl FrequencySettings {
    pub fn from_config(config: &StackConfig) -> Self {
        let cell = &config.cell;
        Self {
            frequency_band: cell.freq_band,
            main_carrier: cell.main_carrier,
            offset_hz: cell.freq_offset_hz,
            duplex_spacing: cell.duplex_spacing_id,
            custom_split_mhz: cell.custom_duplex_spacing.map(|hz| f64::from(hz) / 1_000_000.0),
            reverse_operation: cell.reverse_operation,
        }
    }

    fn frequency_info(&self) -> Result<FreqInfo, String> {
        let custom = self.custom_split_mhz.map(|mhz| {
            let hz = mhz * 1_000_000.0;
            if !hz.is_finite() || !(0.0..=f64::from(u32::MAX)).contains(&hz) || (hz - hz.round()).abs() > 0.000_01 {
                return Err("Custom split must be 0..4294.967295 MHz, with at most six decimal places".to_owned());
            }
            Ok(hz.round() as u32)
        }).transpose()?;
        checked_freq_info(self.frequency_band, self.main_carrier, self.offset_hz, self.reverse_operation, self.duplex_spacing, custom)
    }

    pub fn apply(&self, document: &mut DocumentMut) -> Result<(), String> {
        let info = self.frequency_info()?;
        let (dl, ul) = info.get_freqs();
        let cell = super::table_mut(document, &["cell_info"])?;
        cell.insert("freq_band", value(i64::from(info.band)));
        cell.insert("main_carrier", value(i64::from(info.carrier)));
        cell.insert("freq_offset", value(i64::from(info.freq_offset_hz)));
        cell.insert("duplex_spacing", value(i64::from(info.duplex_spacing_id)));
        cell.insert("reverse_operation", value(info.reverse_operation));
        if self.custom_split_mhz.is_some() {
            cell.insert("custom_duplex_spacing", value(i64::from(info.duplex_spacing_val)));
        } else {
            cell.remove("custom_duplex_spacing");
        }
        if document.get("phy_io").and_then(|phy| phy.get("soapysdr")).is_some() {
            let soapy = super::table_mut(document, &["phy_io", "soapysdr"])?;
            soapy.insert("tx_freq", value(f64::from(dl)));
            soapy.insert("rx_freq", value(f64::from(ul)));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct FrequencyBandOption {
    pub value: u8,
    pub base_mhz: u16,
    pub duplex_spacings: Vec<DuplexSpacingOption>,
}

#[derive(Serialize)]
pub(super) struct DuplexSpacingOption {
    pub value: u8,
    pub spacing_mhz: f64,
}

pub(super) fn band_options() -> Vec<FrequencyBandOption> {
    (1..=9).map(|band| FrequencyBandOption {
        value: band,
        base_mhz: u16::from(band) * 100,
        duplex_spacings: (0..=5).filter_map(|entry| FreqInfo::get_default_duplex_spacing(band, entry).map(|hz| DuplexSpacingOption {
            value: entry, spacing_mhz: f64::from(hz) / 1_000_000.0,
        })).collect(),
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_keep_radio_and_on_air_frequencies_in_sync() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));
        let original = tetra_config::bluestation::parsing::from_toml_str(source).unwrap();
        let mut settings = FrequencySettings::from_config(&original);
        settings.frequency_band = 9;
        settings.main_carrier = 600;
        settings.offset_hz = 0;
        settings.duplex_spacing = 1;
        let mut doc = source.parse::<DocumentMut>().unwrap();
        settings.apply(&mut doc).unwrap();
        let parsed = tetra_config::bluestation::parsing::from_toml_str(&doc.to_string()).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.phy_io.soapysdr.as_ref().unwrap().dl_freq, 915_000_000.0);
        assert_eq!(parsed.phy_io.soapysdr.as_ref().unwrap().ul_freq, 870_000_000.0);
        settings.duplex_spacing = 7;
        settings.custom_split_mhz = Some(7.6);
        settings.reverse_operation = true;
        settings.apply(&mut doc).unwrap();
        let parsed = tetra_config::bluestation::parsing::from_toml_str(&doc.to_string()).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.cell.custom_duplex_spacing, Some(7_600_000));
        assert_eq!(parsed.phy_io.soapysdr.as_ref().unwrap().ul_freq, 922_600_000.0);
        settings.custom_split_mhz = None;
        settings.duplex_spacing = 1;
        settings.apply(&mut doc).unwrap();
        assert!(doc["cell_info"].get("custom_duplex_spacing").is_none());
    }

    #[test]
    fn invalid_custom_split_is_rejected() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../example_config/config.toml"));
        let original = tetra_config::bluestation::parsing::from_toml_str(source).unwrap();
        let mut settings = FrequencySettings::from_config(&original);
        settings.duplex_spacing = 7;
        for split in [f64::NAN, -1.0, 7.6000001, 500.0] {
            settings.custom_split_mhz = Some(split);
            assert!(settings.frequency_info().is_err());
        }
    }
}
