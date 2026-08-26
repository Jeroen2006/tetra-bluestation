// Derived from Midnight Blue Labs' TETRA_crypto (Apache-2.0).

use crate::{
    InputError,
    hurdle::{Hurdle, dec_cts, enc_cbc, inverse_sbox, sbox},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub response: [u8; 4],
    pub derived_cipher_key: [u8; 10],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealResult10 {
    pub key: [u8; 10],
    pub malformed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUnsealResult {
    pub key: [u8; 10],
    pub key_number: u8,
    pub malformed: bool,
}

/// TA11 / TA41: derive KS from K and the 80-bit RS challenge.
pub fn ta11_ta41(key: &[u8; 16], challenge: &[u8; 10]) -> [u8; 16] {
    enc_cbc(&expand_80_to_128_alt(challenge), key)
}

/// TA12 / TA22: calculate RES and DCK from KS and RAND.
pub fn ta12_ta22(key: &[u8; 16], random: &[u8; 10]) -> AuthResult {
    let encrypted = enc_cbc(&expand_80_to_128_alt(random), key);
    AuthResult {
        response: [
            encrypted[0] ^ encrypted[3],
            encrypted[6],
            encrypted[9],
            encrypted[12] ^ encrypted[15],
        ],
        derived_cipher_key: [
            encrypted[1],
            encrypted[2],
            encrypted[4],
            encrypted[5],
            encrypted[7],
            encrypted[8],
            encrypted[10],
            encrypted[11],
            encrypted[13],
            encrypted[14],
        ],
    }
}

/// TA21: derive KSP from K and the reversed 80-bit RS challenge.
pub fn ta21(key: &[u8; 16], challenge: &[u8; 10]) -> [u8; 16] {
    let mut reversed = *challenge;
    reversed.reverse();
    enc_cbc(&expand_80_to_128_alt(&reversed), key)
}

/// TA31: seal a CCK using CCK ID and DCK.
pub fn ta31(unsealed_cck: &[u8; 10], cck_id: &[u8; 2], dck: &[u8; 10]) -> [u8; 15] {
    let mut plaintext = [0; 16];
    plaintext[..15].copy_from_slice(&expand_80_to_120_alt(unsealed_cck));
    let key = adjusted_key_80(dck, cck_id);
    steal(&enc_cbc(&plaintext, &key))
}

/// TA32: unseal a CCK. `malformed` reports a failed integrity check.
pub fn ta32(sealed_cck: &[u8; 15], cck_id: &[u8; 2], dck: &[u8; 10]) -> SealResult10 {
    let decrypted = dec_cts(sealed_cck, &adjusted_key_80(dck, cck_id));
    SealResult10 {
        key: shrink_120_to_80_alt(&decrypted),
        malformed: !check_80_alt(&decrypted),
    }
}

/// TA51: seal an 80-bit key and a five-bit key number.
pub fn ta51(unsealed: &[u8; 10], version: &[u8; 2], key: &[u8; 16], key_number: u8) -> Result<[u8; 15], InputError> {
    if key_number > 31 {
        return Err(InputError::KeyNumberOutOfRange);
    }
    let mut source = [0; 11];
    source[..10].copy_from_slice(unsealed);
    source[10] = key_number;
    let mut plaintext = [0; 16];
    plaintext[..15].copy_from_slice(&expand_88_to_120(&source));
    Ok(steal(&enc_cbc(&plaintext, &adjusted_key_128(key, version))))
}

/// TA52: unseal an 80-bit key and its key number. `malformed` includes an invalid key number.
pub fn ta52(sealed: &[u8; 15], key: &[u8; 16], version: &[u8; 2]) -> KeyUnsealResult {
    let decrypted = dec_cts(sealed, &adjusted_key_128(key, version));
    let unsealed = shrink_120_to_88(&decrypted);
    KeyUnsealResult {
        key: unsealed[..10].try_into().unwrap(),
        key_number: unsealed[10],
        malformed: !check_88(&decrypted) || unsealed[10] > 31,
    }
}

/// TA61: encrypt a three-octet SSI segment.
pub fn ta61(key: &[u8; 10], identity: &[u8; 3]) -> [u8; 3] {
    ta61_inner(&ta61_compute_c(key), identity)
}
/// Inverse TA61 operation.
pub fn ta61_inverse(key: &[u8; 10], encrypted_identity: &[u8; 3]) -> [u8; 3] {
    ta61_inner_inverse(&ta61_compute_c(key), encrypted_identity)
}

/// TA71: derive MGCK from GCK and CCK.
pub fn ta71(gck: &[u8; 10], cck: &[u8; 10]) -> [u8; 10] {
    let mut plaintext = [0; 10];
    for index in 0..10 {
        plaintext[index] = gck[index] ^ cck[index];
    }
    let mut key = [0; 16];
    key[..6].copy_from_slice(&gck[..6]);
    for index in 0..4 {
        key[6 + index] = gck[6 + index] ^ cck[index];
    }
    key[10..].copy_from_slice(&cck[4..]);
    enc_cbc(&expand_80_to_128_alt(&plaintext), &key)[3..13].try_into().unwrap()
}

/// TA81: seal a GCK and its two-octet GCK number.
pub fn ta81(unsealed_gck: &[u8; 10], version: &[u8; 2], gck_number: &[u8; 2], key: &[u8; 16]) -> [u8; 15] {
    let plaintext = expand_gck(unsealed_gck, gck_number);
    steal(&enc_cbc(&plaintext, &adjusted_key_128(key, version)))
}

/// TA82: unseal a GCK. The returned key number is valid only when `malformed` is false.
pub fn ta82(sealed_gck: &[u8; 15], version: &[u8; 2], key: &[u8; 16]) -> ([u8; 10], [u8; 2], bool) {
    let plain = dec_cts(sealed_gck, &adjusted_key_128(key, version));
    let gck = [
        plain[0], plain[1], plain[2], plain[3], plain[5], plain[6], plain[7], plain[8], plain[10], plain[11],
    ];
    let number = [plain[12], plain[13]];
    let malformed = plain[14] != plain[10] ^ plain[11] ^ plain[12] ^ plain[13]
        || plain[9] != plain[5] ^ plain[6] ^ plain[7] ^ plain[8]
        || plain[4] != plain[0] ^ plain[1] ^ plain[2] ^ plain[3];
    (gck, number, malformed)
}

/// TA91: seal the 12-octet GSKO form.
pub fn ta91(unsealed_gsko: &[u8; 12], version: &[u8; 2], key: &[u8; 16]) -> [u8; 15] {
    let key_number: [u8; 2] = unsealed_gsko[10..12].try_into().unwrap();
    ta81(&unsealed_gsko[..10].try_into().unwrap(), version, &key_number, key)
}

/// TA92: unseal the 12-octet GSKO form.
pub fn ta92(sealed_gsko: &[u8; 15], version: &[u8; 2], key: &[u8; 16]) -> ([u8; 12], bool) {
    let (value, number, malformed) = ta82(sealed_gsko, version, key);
    let mut result = [0; 12];
    result[..10].copy_from_slice(&value);
    result[10..].copy_from_slice(&number);
    (result, malformed)
}

/// TB4: XOR two DCKs.
pub fn tb4(first: &[u8; 10], second: &[u8; 10]) -> [u8; 10] {
    core::array::from_fn(|index| first[index] ^ second[index])
}

/// TB5: derive an ECK from a CK, carrier number, location area and colour code.
pub fn tb5(carrier_number: u16, location_area: u16, colour_code: u8, ck: &[u8; 10]) -> Result<[u8; 10], InputError> {
    if carrier_number > 0x0fff {
        return Err(InputError::CarrierNumberOutOfRange);
    }
    if location_area > 0x3fff {
        return Err(InputError::LocationAreaOutOfRange);
    }
    if colour_code > 0x3f {
        return Err(InputError::ColourCodeOutOfRange);
    }
    let input = u80_words(ck);
    let masks = [
        (u32::from(location_area) << 2) | (u32::from(carrier_number) >> 10),
        (u32::from(carrier_number) << 22)
            | (u32::from(colour_code) << 16)
            | (u32::from(carrier_number) << 4)
            | (u32::from(colour_code) >> 2),
        (u32::from(colour_code) << 30) | (u32::from(carrier_number) << 18) | (u32::from(colour_code) << 12) | u32::from(carrier_number),
    ];
    Ok(words_u80([input[0] ^ masks[0], input[1] ^ masks[1], input[2] ^ masks[2]]))
}

/// TB6: derive an ECK from an SCK, carrier number and 24-bit SSI.
pub fn tb6(sck: &[u8; 10], carrier_number: u16, ssi: &[u8; 3]) -> Result<[u8; 10], InputError> {
    if carrier_number > 0x0fff {
        return Err(InputError::CarrierNumberOutOfRange);
    }
    let ssi = u32::from_be_bytes([0, ssi[0], ssi[1], ssi[2]]);
    let input = u80_words(sck);
    let carrier_number = u32::from(carrier_number);
    let masks = [
        (carrier_number << 4) | (ssi >> 20),
        (ssi << 12) | carrier_number,
        (ssi << 8) | (ssi & 0xff),
    ];
    Ok(words_u80([input[0] ^ masks[0], input[1] ^ masks[1], input[2] ^ masks[2]]))
}

/// TB7: expand the 12-octet GSKO to the 16-octet EGSKO.
pub fn tb7(gsko: &[u8; 12]) -> [u8; 16] {
    let mut out = [0; 16];
    for group in 0..4 {
        let source = group * 3;
        let destination = group * 4;
        out[destination..destination + 3].copy_from_slice(&gsko[source..source + 3]);
        out[destination + 3] = gsko[source] ^ gsko[source + 1] ^ gsko[source + 2];
    }
    out
}

fn expand_80_to_120(input: &[u8; 10]) -> [u8; 15] {
    let mut out = [0; 15];
    for index in 0..5 {
        let a = input[index];
        let b = input[9 - index];
        out[index * 3] = a.wrapping_add(b);
        out[index * 3 + 1] = a;
        out[index * 3 + 2] = b;
    }
    out
}
fn expand_80_to_128(input: &[u8; 10]) -> [u8; 16] {
    let mut out = [0; 16];
    out[1..].copy_from_slice(&expand_80_to_120(input));
    out[0] = out[1] ^ out[4] ^ out[7] ^ out[10] ^ out[13];
    out
}
fn expand_80_to_120_alt(input: &[u8; 10]) -> [u8; 15] {
    let mut out = [0; 15];
    for group in 0..5 {
        out[group * 3] = input[group * 2];
        out[group * 3 + 1] = input[group * 2 + 1];
        out[group * 3 + 2] = out[group * 3] ^ out[group * 3 + 1];
    }
    out
}
fn expand_80_to_128_alt(input: &[u8; 10]) -> [u8; 16] {
    let mut out = [0; 16];
    out[..15].copy_from_slice(&expand_80_to_120_alt(input));
    out[15] = out[2]
        .wrapping_add(out[5])
        .wrapping_add(out[8])
        .wrapping_add(out[11])
        .wrapping_add(out[14]);
    out
}
fn expand_88_to_120(input: &[u8; 11]) -> [u8; 15] {
    [
        input[0],
        input[1],
        input[0] ^ input[1],
        input[2],
        input[3],
        input[4],
        input[2] ^ input[3] ^ input[4],
        input[5],
        input[6],
        input[7],
        input[5] ^ input[6] ^ input[7],
        input[8],
        input[9],
        input[10],
        input[8] ^ input[9] ^ input[10],
    ]
}
fn shrink_120_to_88(input: &[u8; 15]) -> [u8; 11] {
    [
        input[0], input[1], input[3], input[4], input[5], input[7], input[8], input[9], input[11], input[12], input[13],
    ]
}
fn shrink_120_to_80_alt(input: &[u8; 15]) -> [u8; 10] {
    [
        input[0], input[1], input[3], input[4], input[6], input[7], input[9], input[10], input[12], input[13],
    ]
}
fn adjusted_key_80(key: &[u8; 10], version: &[u8; 2]) -> [u8; 16] {
    expand_80_to_128(&core::array::from_fn(|index| key[index] ^ version[index & 1]))
}
fn adjusted_key_128(key: &[u8; 16], version: &[u8; 2]) -> [u8; 16] {
    core::array::from_fn(|index| key[index] ^ version[index & 1])
}
fn steal(ciphertext: &[u8; 16]) -> [u8; 15] {
    let mut out = [0; 15];
    out[..7].copy_from_slice(&ciphertext[..7]);
    out[7..].copy_from_slice(&ciphertext[8..]);
    out
}
fn check_80_alt(value: &[u8; 15]) -> bool {
    (0..5).all(|group| value[group * 3] ^ value[group * 3 + 1] == value[group * 3 + 2])
}
fn check_88(value: &[u8; 15]) -> bool {
    value[0] ^ value[1] == value[2]
        && value[3] ^ value[4] ^ value[5] == value[6]
        && value[7] ^ value[8] ^ value[9] == value[10]
        && value[11] ^ value[12] ^ value[13] == value[14]
}
fn expand_gck(gck: &[u8; 10], number: &[u8; 2]) -> [u8; 16] {
    [
        gck[0],
        gck[1],
        gck[2],
        gck[3],
        gck[0] ^ gck[1] ^ gck[2] ^ gck[3],
        gck[4],
        gck[5],
        gck[6],
        gck[7],
        gck[4] ^ gck[5] ^ gck[6] ^ gck[7],
        gck[8],
        gck[9],
        number[0],
        number[1],
        gck[8] ^ gck[9] ^ number[0] ^ number[1],
        0,
    ]
}
fn u80_words(value: &[u8; 10]) -> [u32; 3] {
    [
        u32::from(u16::from_be_bytes(value[..2].try_into().unwrap())),
        u32::from_be_bytes(value[2..6].try_into().unwrap()),
        u32::from_be_bytes(value[6..10].try_into().unwrap()),
    ]
}
fn words_u80(value: [u32; 3]) -> [u8; 10] {
    let mut out = [0; 10];
    out[..2].copy_from_slice(&(value[0] as u16).to_be_bytes());
    out[2..6].copy_from_slice(&value[1].to_be_bytes());
    out[6..].copy_from_slice(&value[2].to_be_bytes());
    out
}
fn ta61_compute_c(key: &[u8; 10]) -> [u8; 8] {
    let cipher = Hurdle::new(&expand_80_to_128(key));
    cipher.encrypt(&[
        key[0] ^ key[2],
        key[1] ^ key[3],
        key[2] ^ key[4],
        key[3] ^ key[5],
        key[4] ^ key[6],
        key[5] ^ key[7],
        key[6] ^ key[8],
        key[7] ^ key[9],
    ])
}
fn identity_transform(input: [u8; 3]) -> [u8; 3] {
    [
        sbox(input[1].wrapping_add(input[0]).wrapping_mul(2).wrapping_sub(input[2])),
        sbox(input[2].wrapping_add(input[0]).wrapping_mul(2).wrapping_sub(input[1])),
        sbox(input[2].wrapping_add(input[1]).wrapping_mul(2).wrapping_sub(input[0])),
    ]
}
fn identity_transform_inverse(input: [u8; 3]) -> [u8; 3] {
    let (x, y, z) = (inverse_sbox(input[0]), inverse_sbox(input[1]), inverse_sbox(input[2]));
    [
        114_u8
            .wrapping_mul(x)
            .wrapping_add(114_u8.wrapping_mul(y))
            .wrapping_sub(57_u8.wrapping_mul(z)),
        114_u8
            .wrapping_mul(x)
            .wrapping_sub(57_u8.wrapping_mul(y))
            .wrapping_add(114_u8.wrapping_mul(z)),
        0_u8.wrapping_sub(57_u8.wrapping_mul(x))
            .wrapping_add(114_u8.wrapping_mul(y))
            .wrapping_add(114_u8.wrapping_mul(z)),
    ]
}
fn ta61_inner(intermediate: &[u8; 8], identity: &[u8; 3]) -> [u8; 3] {
    let mut value = [
        identity[0] ^ intermediate[0],
        identity[1] ^ intermediate[3],
        identity[2] ^ intermediate[6],
    ];
    value = identity_transform(value);
    value = [value[0] ^ intermediate[1], value[1] ^ intermediate[4], value[2] ^ intermediate[7]];
    value = identity_transform(value);
    [value[0] ^ intermediate[2], value[1] ^ intermediate[5], value[2] ^ intermediate[0]]
}
fn ta61_inner_inverse(intermediate: &[u8; 8], identity: &[u8; 3]) -> [u8; 3] {
    let mut value = [
        identity[0] ^ intermediate[2],
        identity[1] ^ intermediate[5],
        identity[2] ^ intermediate[0],
    ];
    value = identity_transform_inverse(value);
    value = [value[0] ^ intermediate[1], value[1] ^ intermediate[4], value[2] ^ intermediate[7]];
    value = identity_transform_inverse(value);
    [value[0] ^ intermediate[0], value[1] ^ intermediate[3], value[2] ^ intermediate[6]]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tb6_reference_vector() {
        assert_eq!(
            tb6(
                &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xaa, 0xbb],
                0x02bc,
                &[0x1d, 0xcc, 0x05]
            )
            .unwrap(),
            [0x2a, 0xe2, 0x99, 0xa7, 0xdb, 0x17, 0xd0, 0x23, 0xaf, 0xbe]
        );
    }
    #[test]
    fn ta61_reference_vector() {
        let key = [0xc6, 0x2e, 0x22, 0x85, 0x03, 0x40, 0xbc, 0xeb, 0x55, 0x52];
        let identity = [0x56, 0x5a, 0x72];
        let encrypted = [0xc4, 0x48, 0x53];
        assert_eq!(ta61(&key, &identity), encrypted);
        assert_eq!(ta61_inverse(&key, &encrypted), identity);
    }
    #[test]
    fn ta11_reference_vector() {
        assert_eq!(
            ta11_ta41(
                &[
                    0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15
                ],
                &[0; 10]
            ),
            [
                0x9c, 0x84, 0x51, 0xa3, 0x56, 0x95, 0xd3, 0x3c, 0x30, 0x94, 0x37, 0x12, 0x02, 0x48, 0x54, 0x53
            ]
        );
    }
    #[test]
    fn ta51_round_trip() {
        let key = [
            0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15,
        ];
        let sealed = ta51(&[0; 10], &[0x0f, 0x6d], &key, 0x0f).unwrap();
        assert_eq!(
            sealed,
            [
                0x08, 0x3d, 0x05, 0xa7, 0x8e, 0x86, 0xfd, 0x5f, 0x46, 0xd6, 0x2b, 0x28, 0x42, 0x2b, 0x0b
            ]
        );
        let result = ta52(&sealed, &key, &[0x0f, 0x6d]);
        assert_eq!(result.key, [0; 10]);
        assert_eq!(result.key_number, 0x0f);
        assert!(!result.malformed);
    }

    #[test]
    fn key_sealing_reference_vectors() {
        let sealed_cck = ta31(
            &[0; 10],
            &[0x6b, 0x18],
            &[0x5f, 0xb0, 0x44, 0x2f, 0x4b, 0x5e, 0xe2, 0xf0, 0xea, 0x91],
        );
        assert_eq!(
            sealed_cck,
            [
                0xa3, 0x48, 0x85, 0xfc, 0x27, 0x7d, 0x8d, 0x96, 0x11, 0xd4, 0x0e, 0x22, 0x40, 0x0a, 0x14
            ]
        );
        assert_eq!(
            ta32(
                &sealed_cck,
                &[0x6b, 0x18],
                &[0x5f, 0xb0, 0x44, 0x2f, 0x4b, 0x5e, 0xe2, 0xf0, 0xea, 0x91],
            ),
            SealResult10 {
                key: [0; 10],
                malformed: false
            }
        );

        let gck_key = [
            0x63, 0x59, 0x38, 0xac, 0xe8, 0x1f, 0x6b, 0x67, 0x82, 0xa6, 0xfa, 0x46, 0xae, 0x4f, 0x7f, 0x69,
        ];
        let sealed_gck = ta81(&[0; 10], &[0xa3, 0x97], &[0x1f, 0x5d], &gck_key);
        assert_eq!(
            sealed_gck,
            [
                0x1c, 0xcf, 0x9c, 0x6b, 0xa8, 0x5c, 0x5b, 0x45, 0x60, 0xf9, 0xcf, 0x5c, 0x63, 0xb0, 0xdc
            ]
        );
        assert_eq!(ta82(&sealed_gck, &[0xa3, 0x97], &gck_key), ([0; 10], [0x1f, 0x5d], false));
    }

    #[test]
    fn remaining_reference_vectors() {
        assert_eq!(
            ta21(
                &[
                    0xc6, 0x2e, 0x22, 0x85, 0x03, 0x40, 0xbc, 0xeb, 0x55, 0x52, 0x22, 0x28, 0x60, 0x17, 0x3d, 0x7e
                ],
                &[0x56, 0x5a, 0x72, 0xd6, 0x3c, 0xce, 0xed, 0x0b, 0x6f, 0x30],
            ),
            [
                0xfc, 0xfa, 0xf4, 0x55, 0x92, 0xdf, 0xc6, 0x5d, 0x8a, 0x1f, 0x5c, 0x45, 0xdc, 0xa2, 0x93, 0xda
            ]
        );
        assert_eq!(
            ta71(&[0; 10], &[0; 10]),
            [0x32, 0x14, 0xcd, 0x6b, 0xc0, 0x48, 0x8c, 0xdc, 0x46, 0x76]
        );
        assert_eq!(
            tb5(0x02bc, 0x1dcc, 0x05, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xaa, 0xbb]).unwrap(),
            [0x76, 0x13, 0xea, 0x62, 0xa2, 0x6a, 0x87, 0x1f, 0xf8, 0x07]
        );
        assert_eq!(
            tb7(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xaa, 0xbb, 0x02, 0xbc]),
            [
                0x01, 0x23, 0x45, 0x67, 0x67, 0x89, 0xab, 0x45, 0xcd, 0xef, 0xaa, 0x88, 0xbb, 0x02, 0xbc, 0x05
            ]
        );
    }
}
