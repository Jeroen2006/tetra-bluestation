/// Generator matrix from Section 8.2.3.2
pub const RM_30_14_GEN: [[u8; 16]; 14] = [
    [1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0],
    [0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0],
    [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
    [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0],
    [1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0],
    [0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0],
    [0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0],
    [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1],
    [1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1],
    [0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1],
    [0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1],
    [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1],
    [0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1],
    [0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1],
];

/// Static array with precomputed row masks
pub static RM_30_14_ROWS_PRECOMPUTED: [u32; 14] = [
    0x20009b60, 0x10002de0, 0x0800fc20, 0x0400e03c, 0x0200983a, 0x01005436, 0x00802c2e, 0x0040ffdf, 0x00208339, 0x001042b5, 0x000821ad,
    0x00041273, 0x0002096b, 0x000104e7,
];

/// Compute RM(30,14) codeword for a 14-bit input (upper 14 bits of codeword)
pub fn tetra_rm3014_compute(input: u16) -> u32 {
    let mut val = 0u32;

    for i in 0..14 {
        let bit = (input >> (13 - i)) & 1;
        if bit == 1 {
            val ^= RM_30_14_ROWS_PRECOMPUTED[i];
        }
    }
    val
}

/// "Decode" systematic RM(30,14): extract original 14-bit data
/// Does not perform error correction, just extracts the upper 14 bits
pub fn tetra_rm3014_decode_naive(codeword: u32) -> u16 {
    (codeword >> 16) as u16
}

/// Compute column‐syndromes for single‐error decoding
pub const fn compute_col_syndromes() -> [u16; 30] {
    let mut out = [0u16; 30];
    let mut k = 0;
    while k < 30 {
        let mut syn = 0u16;
        let mut j = 0;
        while j < 16 {
            let bit = if k < 14 {
                RM_30_14_GEN[k][j] as u16
            } else {
                ((k - 14) == j) as u16
            };
            syn |= bit << j;
            j += 1;
        }
        out[k] = syn;
        k += 1;
    }
    out
}

pub const COL_SYNDROMES: [u16; 30] = compute_col_syndromes();

/// Quick and dirty single-bit error correction
/// Compute syndrome of a 30‐bit codeword
pub fn compute_syndrome(codeword: u32) -> u16 {
    let mut syn = 0u16;
    let mut j = 0;
    while j < 16 {
        let mut sum = 0u8;
        let mut i = 0;
        while i < 14 {
            sum ^= ((codeword >> (29 - i)) & 1) as u8 & RM_30_14_GEN[i][j];
            i += 1;
        }
        sum ^= ((codeword >> (29 - (14 + j))) & 1) as u8;
        if sum & 1 != 0 {
            syn |= 1 << j;
        }
        j += 1;
    }
    syn
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rm3014Decoded {
    pub data: u16,
    pub corrected_bits: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rm3014Uncorrectable {
    pub syndrome: u16,
}

#[inline]
fn bit_mask(bit: usize) -> u32 {
    1u32 << (29 - bit)
}

/// Decode within the guaranteed radius of the shortened RM(30,14) code.
/// Its minimum distance is eight, so error patterns of weight up to three are
/// uniquely correctable; all other syndromes are deliberately rejected.
pub fn tetra_rm3014_decode(codeword: u32) -> Result<Rm3014Decoded, Rm3014Uncorrectable> {
    let syndrome = compute_syndrome(codeword);
    if syndrome == 0 {
        return Ok(Rm3014Decoded { data: (codeword >> 16) as u16, corrected_bits: 0 });
    }
    for i in 0..30 {
        if COL_SYNDROMES[i] == syndrome {
            return Ok(Rm3014Decoded { data: ((codeword ^ bit_mask(i)) >> 16) as u16, corrected_bits: 1 });
        }
    }
    for i in 0..29 {
        for j in i + 1..30 {
            if COL_SYNDROMES[i] ^ COL_SYNDROMES[j] == syndrome {
                return Ok(Rm3014Decoded { data: ((codeword ^ bit_mask(i) ^ bit_mask(j)) >> 16) as u16, corrected_bits: 2 });
            }
        }
    }
    for i in 0..28 {
        for j in i + 1..29 {
            for k in j + 1..30 {
                if COL_SYNDROMES[i] ^ COL_SYNDROMES[j] ^ COL_SYNDROMES[k] == syndrome {
                    return Ok(Rm3014Decoded { data: ((codeword ^ bit_mask(i) ^ bit_mask(j) ^ bit_mask(k)) >> 16) as u16, corrected_bits: 3 });
                }
            }
        }
    }
    Err(Rm3014Uncorrectable { syndrome })
}

/// Compatibility helper for legacy callers. New receive paths must use
/// [`tetra_rm3014_decode`] so uncorrectable words are never accepted.
pub fn tetra_rm3014_decode_limited_ecc(codeword: u32) -> u16 {
    tetra_rm3014_decode(codeword)
        .map(|decoded| decoded.data)
        .unwrap_or_else(|_| tetra_rm3014_decode_naive(codeword))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_no_error() {
        let messages = [0u16, 1u16, 0x1FFFu16, 0x1234u16, 0x2A3Bu16];
        for &msg in &messages {
            let code = tetra_rm3014_compute(msg);
            assert_eq!(tetra_rm3014_decode_naive(code), msg);
            assert_eq!(tetra_rm3014_decode_limited_ecc(code), msg);
        }
    }

    #[test]
    fn test_single_bit_error_correction() {
        let messages = [0u16, 1u16, 0x1FFFu16, 0x1234u16, 0x2A3Bu16];

        for &msg in &messages {
            let code = tetra_rm3014_compute(msg);
            for bit in 0..30 {
                let erroneous = code ^ (1 << bit);
                let decoded = tetra_rm3014_decode_limited_ecc(erroneous);
                assert_eq!(decoded, msg, "Failed to correct bit {}", bit);
            }
        }
    }

    #[test]
    fn test_uncorrectable_errors() {
        let msg = 0x1234u16;
        let code = tetra_rm3014_compute(msg);
        let erroneous = code ^ 0xbadd00;
        let decoded = tetra_rm3014_decode_limited_ecc(erroneous);
        assert_ne!(decoded, msg);
    }
}
