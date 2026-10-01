//! CA common SCCH configuration and population assignment.
//! TS 100 392-2 23.3.1.2.1.2; TIP Core 6.3.
use tetra_core::TdmaTime;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommonControlAssignment {
    pub supported: Option<bool>,
    pub ms_scch: Option<u8>,
    /// The request/accept exchange remains on this CCCH until its BL-ACK.
    pub registration_slot: Option<u8>,
    pub last_uplink_slot: Option<u8>,
}

pub fn common_control_slot(ms_scch: Option<u8>, count: u8) -> u8 {
    1 + ms_scch.filter(|value| *value < 12).unwrap_or(0) % (count.min(2) + 1)
}

pub fn ee_period_frames(mode: u8) -> u32 {
    match mode { 1 => 2, 2 => 3, 3 => 6, 4 => 9, 5 => 18, 6 => 72, 7 => 360, _ => 1 }
}

/// Advertised configuration and the temporarily wider physical configuration.
/// A decrease keeps the old CCCH resources until sleeping radios had a chance
/// to read SYSINFO and previously announced uplink reservations have drained.
#[derive(Debug, Clone, Default)]
pub struct CommonControlChannels {
    pub advertised_count: u8,
    pub physical_count: u8,
    pub drain_until: Option<TdmaTime>,
    pub advertised_frame18_slots: u8,
}

impl CommonControlChannels {
    pub fn is_common(&self, slot: u8) -> bool { (1..=self.physical_count + 1).contains(&slot) }
    pub fn advertised_slots(&self) -> std::ops::RangeInclusive<u8> { 1..=self.advertised_count + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn population_mapping_follows_the_air_interface_formula() {
        for count in 0..=2 {
            let mut loads = [0; 3];
            for value in 0..12 { loads[(common_control_slot(Some(value), count) - 1) as usize] += 1; }
            for slot in 0..=count as usize { assert_eq!(loads[slot], 12 / (count + 1)); }
        }
        assert_eq!(common_control_slot(None, 2), 1);
        assert_eq!(common_control_slot(Some(7), 1), 2);
        assert_eq!(common_control_slot(Some(7), 2), 2);
    }
    #[test]
    fn ee_cycles_use_tdmas_not_exponential_multiframes() {
        assert_eq!(ee_period_frames(6), 72);
        assert_eq!(ee_period_frames(7), 360);
    }
}
