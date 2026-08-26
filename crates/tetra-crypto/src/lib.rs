//! TETRA air-interface cryptographic primitives.
//!
//! This crate contains no key storage, protocol state machine, randomness
//! source, or over-the-air transport. Callers own those responsibilities.
//!
//! The TEA1, TEA3, HURDLE and TAA1-family implementations are a Rust port of
//! the Apache-2.0 licensed reference implementation from Midnight Blue Labs:
//! <https://github.com/MidnightBlueLabs/TETRA_crypto> (commit `defed03`).

#![forbid(unsafe_code)]

mod hurdle;
mod taa1;
mod tea1;
mod tea3;

pub use taa1::{
    AuthResult, KeyUnsealResult, SealResult10, ta11_ta41, ta12_ta22, ta21, ta31, ta32, ta51, ta52, ta61, ta61_inverse, ta71, ta81, ta82,
    ta91, ta92, tb4, tb5, tb6, tb7,
};
pub use tea1::tea1;
pub use tea3::tea3;

/// Errors returned when a value cannot be represented in the TETRA bit field
/// required by a primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    CarrierNumberOutOfRange,
    LocationAreaOutOfRange,
    ColourCodeOutOfRange,
    KeyNumberOutOfRange,
}

/// Build the 32-bit air-interface IV used by TEA algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameNumbers {
    /// TDMA timeslot, in the range 1..=4.
    pub timeslot: u8,
    /// Frame number, in the range 1..=18.
    pub frame: u8,
    /// Multiframe number, in the range 1..=60.
    pub multiframe: u8,
    /// Hyperframe number; only its low 15 bits enter the IV.
    pub hyperframe: u16,
    /// `false` for downlink, `true` for uplink.
    pub uplink: bool,
}

impl FrameNumbers {
    /// Return the packed air-interface IV.
    #[must_use]
    pub const fn iv(self) -> u32 {
        assert!(self.timeslot >= 1 && self.timeslot <= 4);
        assert!(self.frame >= 1 && self.frame <= 18);
        assert!(self.multiframe >= 1 && self.multiframe <= 60);
        (self.timeslot as u32 - 1)
            | ((self.frame as u32) << 2)
            | ((self.multiframe as u32) << 7)
            | (((self.hyperframe as u32) & 0x7fff) << 13)
            | ((self.uplink as u32) << 28)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_numbers_pack_like_reference() {
        assert_eq!(
            FrameNumbers {
                timeslot: 4,
                frame: 18,
                multiframe: 60,
                hyperframe: 0xffff,
                uplink: true,
            }
            .iv(),
            0x1fff_fe4b
        );
    }

    #[test]
    fn sc2_tmo_eck_iv_and_kss_mapping_vector() {
        let sck = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xaa, 0xbb];
        let eck = tb5(0x02bc, 0x1dcc, 0x05, &sck).unwrap();
        let time = FrameNumbers {
            timeslot: 3,
            frame: 17,
            multiframe: 59,
            hyperframe: 0x1234,
            uplink: false,
        };
        let downlink_iv = time.iv();
        let uplink_iv = FrameNumbers { uplink: true, ..time }.iv();
        let mut tea1_downlink = [0; 54];
        let mut tea3_downlink = [0; 54];
        let mut tea1_uplink = [0; 54];
        tea1(downlink_iv, &eck, &mut tea1_downlink);
        tea3(downlink_iv, &eck, &mut tea3_downlink);
        tea1(uplink_iv, &eck, &mut tea1_uplink);
        assert_eq!(eck, [0x76, 0x13, 0xea, 0x62, 0xa2, 0x6a, 0x87, 0x1f, 0xf8, 0x07]);
        assert_eq!(downlink_iv, 0x0246_9dc6);
        assert_eq!(uplink_iv, 0x1246_9dc6);
        assert_eq!(
            tea1_downlink,
            [
                0x73, 0x5b, 0xf4, 0x3d, 0xea, 0x69, 0x1a, 0xdd, 0x23, 0xae, 0xc3, 0x50, 0x24, 0x7f, 0x72, 0xdf, 0xb6, 0x9d, 0xb7, 0xe4,
                0xa1, 0xe7, 0xe5, 0xf9, 0x30, 0x2c, 0x11, 0xb1, 0xd5, 0x04, 0xca, 0x3e, 0x5a, 0x8e, 0x92, 0xc2, 0xa5, 0x04, 0x7a, 0x21,
                0xae, 0xa5, 0xbe, 0xcb, 0x29, 0xcf, 0xe3, 0xcc, 0x04, 0x04, 0xc1, 0x6b, 0x59, 0x98,
            ]
        );
        assert_eq!(
            tea3_downlink,
            [
                0xcd, 0x46, 0x95, 0x7c, 0xaf, 0x85, 0x1f, 0xc2, 0x59, 0x70, 0xcd, 0x24, 0x29, 0x91, 0xcd, 0xb2, 0x2a, 0xee, 0x77, 0x4a,
                0x76, 0x3d, 0xd7, 0x82, 0x91, 0x28, 0xad, 0xb6, 0x01, 0x8b, 0x8f, 0x3a, 0xe2, 0x20, 0xe5, 0x39, 0x3b, 0x4b, 0x46, 0x9b,
                0x59, 0xd4, 0xfa, 0xe1, 0x73, 0x2b, 0xdd, 0x61, 0x19, 0xca, 0x24, 0x4e, 0xe4, 0xc3,
            ]
        );
        assert_eq!(
            tea1_uplink,
            [
                0x3c, 0x9a, 0x23, 0xe9, 0x2b, 0xde, 0xb7, 0x09, 0xe1, 0xc5, 0x99, 0xf1, 0xe5, 0x18, 0x95, 0xbb, 0x6e, 0xaa, 0xd8, 0x0a,
                0x2f, 0xf0, 0x80, 0x3c, 0x99, 0x86, 0x96, 0xd9, 0xd3, 0x30, 0x9b, 0xdc, 0x89, 0x51, 0x3c, 0xe3, 0x2c, 0x63, 0xe8, 0x13,
                0x7b, 0xb5, 0x6b, 0xee, 0xd7, 0xe8, 0xf5, 0xa9, 0x04, 0xd1, 0xf8, 0x2d, 0xb5, 0xc8,
            ]
        );
    }
}
