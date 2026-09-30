//! Compatibility re-export of the shared TETRA frequency helpers.

pub use tetra_air_interface::freqs::*;

/// Validate operator input before using the shared frequency helper, whose
/// legacy constructor asserts on invalid input and excludes the 900 MHz band.
pub fn checked_freq_info(
    band: u8,
    carrier: u16,
    offset_hz: i16,
    reverse_operation: bool,
    duplex_spacing_id: u8,
    custom_spacing_hz: Option<u32>,
) -> Result<FreqInfo, String> {
    if !(1..=9).contains(&band) {
        return Err("Frequency band must have a base frequency of 100..900 MHz".into());
    }
    if carrier >= 4000 {
        return Err("Main carrier must be 0..3999".into());
    }
    if FreqInfo::freq_offset_hz_to_id(offset_hz).is_none() {
        return Err("Frequency offset must be -6.25, 0, +6.25 or +12.5 kHz".into());
    }
    if duplex_spacing_id > 7 {
        return Err("Duplex spacing entry must be 0..7".into());
    }
    let spacing = custom_spacing_hz
        .or_else(|| FreqInfo::get_default_duplex_spacing(band, duplex_spacing_id))
        .ok_or("No standard duplex spacing exists for this frequency band and entry")?;
    let dl = (i64::from(band) * 100_000_000 + i64::from(carrier) * 25_000 + i64::from(offset_hz)) as u32;
    let ul = if reverse_operation { dl.checked_add(spacing) } else { dl.checked_sub(spacing) };
    if ul.is_none_or(|hz| hz == 0) {
        return Err("The duplex settings produce an invalid uplink frequency".into());
    }
    Ok(FreqInfo {
        band,
        carrier,
        freq_offset_hz: offset_hz,
        duplex_spacing_id,
        duplex_spacing_val: spacing,
        reverse_operation,
    })
}

#[cfg(test)]
mod checked_tests {
    use super::*;

    #[test]
    fn standard_reverse_and_custom_spacing() {
        assert_eq!(checked_freq_info(4, 864, 6250, false, 0, None).unwrap().get_freqs(), (421_606_250, 411_606_250));
        assert_eq!(checked_freq_info(9, 600, 0, false, 1, None).unwrap().get_freqs(), (915_000_000, 870_000_000));
        assert_eq!(checked_freq_info(4, 864, -6250, true, 7, Some(7_600_000)).unwrap().get_freqs(), (421_593_750, 429_193_750));
    }

    #[test]
    fn malformed_input_returns_errors_without_panicking() {
        for (band, carrier, offset, entry, split) in [
            (255, 0, 0, 0, None), (4, 4000, 0, 0, None),
            (4, 864, 1, 0, None), (4, 864, 0, 255, None),
            (4, 864, 0, 6, None), (4, 864, 0, 7, Some(500_000_000)),
        ] {
            assert!(checked_freq_info(band, carrier, offset, false, entry, split).is_err());
        }
        assert!(checked_freq_info(4, 864, 0, true, 7, Some(u32::MAX)).is_err());
    }
}
