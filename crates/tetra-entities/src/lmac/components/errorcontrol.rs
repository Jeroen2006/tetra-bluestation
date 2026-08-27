use tetra_core::{BitBuffer, PhyBlockType, SoftBit};
use tetra_saps::tmv::TmvUnitdataReq;
use tetra_saps::tmv::enums::logical_chans::LogicalChannel;
use tetra_saps::tp::TpUnitdataInd;

use crate::lmac::components::convenc::{self, ConvEncState, RcpcPunctMode, SpeechConvEncState};
use crate::lmac::components::scrambler;
use crate::lmac::components::tch_reorder;
use crate::lmac::components::{crc16, errorcontrol_params, interleaver, rm3014, viterbi};

const MAX_TYPE1_BITS: usize = 274; // TCH/S has the largest type-1 block
const MAX_TYPE2_BITS: usize = 288;

const MAX_TYPE345_BITS: usize = 432;
const MAX_TYPE345_HALFSLOT_BITS: usize = 216;

/// Encodes control plane message from type1 to type5 bits
/// Handles CP channels except AACH
pub fn encode_cp(mut prim: TmvUnitdataReq) -> BitBuffer {
    let lchan = prim.logical_channel;
    assert!(lchan.is_control_channel() && lchan != LogicalChannel::Aach);

    let params = errorcontrol_params::get_params(lchan);

    assert!(
        prim.mac_block.get_len() == params.type1_bits,
        "encode_cp: prim.mac_block length {} does not match type1_bits {} for lchan {:?}",
        prim.mac_block.get_len(),
        params.type1_bits,
        lchan
    );
    tracing::trace!("encode_cp {:?} type1 {}", lchan, prim.mac_block.dump_bin());

    // Convert bitbuffer to bitarray -> type1
    prim.mac_block.seek(0);
    let mut type2_arr = [0u8; MAX_TYPE2_BITS]; // largest possible type1 block
    prim.mac_block.to_bitarr(&mut type2_arr[0..params.type1_bits]);

    // CRC addition, type1 -> type2
    assert!(params.have_crc16);
    let crc = !crc16::crc16_ccitt_bits(&type2_arr[0..params.type1_bits], params.type1_bits);
    for i in 0..16 {
        type2_arr[params.type1_bits + i] = ((crc >> (15 - i)) & 1) as u8;
    }
    tracing::trace!(
        "encode_cp {:?} type2: {:?}",
        lchan,
        BitBuffer::from_bitarr(&type2_arr[0..params.type2_bits]).dump_bin()
    );

    // Viterbi, type2 -> type3dp
    let mut type3dp_arr = [0u8; MAX_TYPE345_BITS * 4];
    let mut ces = ConvEncState::new();
    ces.encode(&type2_arr[0..params.type2_bits], &mut type3dp_arr);
    // tracing::trace!("encode_cp: t3dp:  {:?}", &type3dp_arr[0..4*params.type2_bits]);

    // Puncturing, type3dp -> type3
    let mut type3_arr = [0u8; MAX_TYPE345_BITS]; // Need params.type345_bits
    convenc::get_punctured_rate(RcpcPunctMode::Rate2_3, &type3dp_arr, &mut type3_arr);
    tracing::trace!(
        "encode_cp {:?} type3: {:?}",
        lchan,
        BitBuffer::from_bitarr(&type3_arr[0..params.type345_bits]).dump_bin()
    );

    // Interleaving, type3 -> type4
    let mut type4_arr = [0u8; MAX_TYPE345_BITS]; // Need params.type345_bits
    interleaver::block_interleave(params.type345_bits, params.interleave_a, &type3_arr, &mut type4_arr);
    let mut type4 = BitBuffer::from_bitarr(&type4_arr[0..params.type345_bits]);
    tracing::trace!("encode_cp {:?} type4: {:?}", lchan, type4.dump_bin());

    // Scrambling, type4 -> type5
    scrambler::tetra_scramb_bits(prim.scrambling_code, &mut type4);
    let type5 = type4;
    tracing::trace!("encode_cp {:?} type5: {:?}", lchan, type5.dump_bin());

    // Pass block to Phy
    type5
}

/// Decodes control plane message from type5 to type1 bits
/// Returns (buf, bool) tuple
/// buf is BitBuffer with type1 bits if decoding successful
/// bool is true if CRC check was successful
pub fn decode_cp(lchan: LogicalChannel, prim: TpUnitdataInd, default_scramb_code: Option<u32>) -> (Option<BitBuffer>, bool) {
    assert!(lchan.is_control_channel() && lchan != LogicalChannel::Aach);

    // Various intermediate buffers, needed for decoding stages
    // We allocate the largest block we may possibly need
    let mut type4_arr = [0u8; MAX_TYPE345_BITS];
    let mut type3_arr = [0u8; MAX_TYPE345_BITS];
    let mut type3dp_arr = [0xFFu8; MAX_TYPE345_BITS * 4];
    let mut type2_arr = [0u8; MAX_TYPE2_BITS];

    // Fetch decoding parameters for this logical channel type
    let params = errorcontrol_params::get_params(lchan);

    let mut soft_type4 = prim.soft_bits.filter(|bits| bits.len() == params.type345_bits);
    let mut type5 = prim.block;
    tracing::trace!("decode_cp {:?} type5: {:?}", lchan, type5.dump_bin());

    // Get scrambling code. For sync block, we use the default scranbling code.
    // For others, we use the scrambling code previously retrieved from SYNC.
    let scrambling_code = if prim.block_type == PhyBlockType::SB1 {
        scrambler::SCRAMB_INIT
    } else if let Some(scrambling_code) = default_scramb_code {
        scrambling_code
    } else {
        tracing::warn!("decode_cp: no scrambling code set, need to receive SYNC first");
        return (None, false);
    };

    scrambler::tetra_scramb_bits(scrambling_code, &mut type5);
    if let Some(soft_bits) = &mut soft_type4 {
        descramble_soft_bits(scrambling_code, soft_bits);
    }
    let mut type4 = type5;
    tracing::trace!("decode_cp {:?} type4: {:?}", lchan, type4.dump_bin());

    // De-interleaving, type4 -> type3
    type4.to_bitarr(&mut type4_arr[0..params.type345_bits]);
    interleaver::block_deinterleave(params.type345_bits, params.interleave_a, &type4_arr, &mut type3_arr);
    tracing::trace!(
        "decode_cp {:?} type3: {:?}",
        lchan,
        BitBuffer::from_bitarr(&type3_arr[0..params.type345_bits]).dump_bin()
    );

    if let Some(soft_type4) = soft_type4 {
        let mut soft_type3 = [0 as SoftBit; MAX_TYPE345_BITS];
        interleaver::block_deinterleave(params.type345_bits, params.interleave_a, &soft_type4, &mut soft_type3);
        let mut soft_type3dp = [0 as SoftBit; MAX_TYPE345_BITS * 4];
        convenc::tetra_rcpc_depunct_soft(RcpcPunctMode::Rate2_3, &soft_type3, params.type345_bits, &mut soft_type3dp);
        viterbi::dec_sb1_soft(&soft_type3dp, &mut type2_arr, params.type2_bits);
    } else {
        convenc::tetra_rcpc_depunct(RcpcPunctMode::Rate2_3, &type3_arr, params.type345_bits, &mut type3dp_arr);
        viterbi::dec_sb1(&type3dp_arr, &mut type2_arr, params.type2_bits);
    }
    tracing::trace!(
        "decode_cp {:?} type2: {:?}",
        lchan,
        BitBuffer::from_bitarr(&type2_arr[0..params.type2_bits]).dump_bin()
    );

    // CRC check, type2 -> type1
    assert!(params.have_crc16);
    let type1_arr = &type2_arr[0..params.type1_bits];
    let crc = crc16::crc16_ccitt_bits(&type2_arr, params.type1_bits + 16);
    let crc_ok = crc == crc16::TETRA_CRC_OK;
    let type1bits = BitBuffer::from_bitarr(&type1_arr[0..params.type1_bits]);
    // if crc_ok {
    //     // tracing::debug!("decode_cp {:>5?} crc: OK type1: {:?}", lchan, BitBuffer::from_bitarr(&type1_arr[0..params.type1_bits]).dump_bin());
    // } else {
    //     // tracing::info!("decode_cp {:>5?} CRC: WRONG {:x}", lchan, crc);
    // }

    (Some(type1bits), crc_ok)
}

/// Compute 8 CRC parity bits for 60 Class 2 bits using G(X) = 1 + X³ + X⁷ (EN 300 395-2, §5.5.1).
/// Returns [b1..b7, b8] where b8 is overall parity (XOR of all 60 data bits + 7 CRC bits).
fn speech_crc(class2_bits: &[u8]) -> [u8; 8] {
    debug_assert_eq!(class2_bits.len(), 60);

    // Polynomial division: compute X⁷ · I(X) mod (X⁷ + X³ + 1)
    // Build dividend in w[7..67], reduce from degree 66 down to 7, remainder in w[0..7].
    let mut w = [0u8; 67]; // degrees 0 .. 66
    for k in 0..60 {
        w[k + 7] = class2_bits[k] & 1;
    }

    for d in (7..67).rev() {
        if w[d] == 1 {
            // XOR with G(X) · X^(d-7) = X^d + X^(d-4) + X^(d-7)
            w[d] ^= 1;
            w[d - 4] ^= 1;
            w[d - 7] ^= 1;
        }
    }

    // w[0..7] = f(0), f(1), …, f(6)
    let mut result = [0u8; 8];
    for i in 0..7 {
        result[i] = w[i]; // b(i+1) = f(i)
    }

    // b8 = overall parity = XOR of all 60 data bits + 7 CRC bits
    let mut parity = 0u8;
    for &bit in class2_bits.iter() {
        parity ^= bit & 1;
    }
    for i in 0..7 {
        parity ^= result[i];
    }
    result[7] = parity;

    result
}

/// Compute the four CRC parity bits used by the single speech frame that
/// remains after frame stealing (EN 300 395-2, clause 5.6.1).
fn stolen_speech_crc(class2_bits: &[u8]) -> [u8; 4] {
    debug_assert_eq!(class2_bits.len(), 30);

    // X^4 * I(X) modulo G(X) = X^4 + X + 1. Array indices are
    // polynomial degrees, matching `speech_crc` above.
    let mut remainder = [0u8; 34];
    for (degree, &bit) in class2_bits.iter().enumerate() {
        remainder[degree + 4] = bit & 1;
    }
    for degree in (4..34).rev() {
        if remainder[degree] != 0 {
            remainder[degree] ^= 1;
            remainder[degree - 3] ^= 1;
            remainder[degree - 4] ^= 1;
        }
    }

    [remainder[0], remainder[1], remainder[2], remainder[3]]
}

/// Select speech frame B from the two codec-order frames supplied for a
/// normal TCH/S slot. Frame A is discarded when STCH steals the first half
/// slot (EN 300 392-2, clause 8.3.1.3.6).
pub fn take_tch_s_frame_b(full_speech: &mut BitBuffer) -> BitBuffer {
    assert_eq!(full_speech.get_len(), 274, "TCH/S source must contain two 137-bit speech frames");

    let mut frame_b = [0u8; 137];
    full_speech.seek(137);
    full_speech.to_bitarr(&mut frame_b);
    full_speech.seek(0);
    BitBuffer::from_bitarr(&frame_b)
}

/// Encode the one 137-bit codec-order speech frame carried in the second
/// half of an STCH+TCH/S slot.
///
/// EN 300 395-2, clause 5.6 defines a separate 216-bit codeword for frame
/// stealing: class 0 is uncoded, class 1 uses rate 2/3, class 2 plus CRC and
/// tail uses rate 8/17, followed by the STCH (216, 101) interleaver.
pub fn encode_tch_s_half(mut speech_frame_b: BitBuffer, scrambling_code: u32) -> BitBuffer {
    const CLASS0_BITS: usize = 51;
    const CLASS1_BITS: usize = 56;
    const CLASS2_BITS: usize = 30;
    const CLASS2_TYPE2_BITS: usize = 38; // 30 data + 4 CRC + 4 tail

    assert_eq!(speech_frame_b.get_len(), 137, "stolen TCH/S must contain one 137-bit speech frame");
    speech_frame_b.seek(0);
    let mut codec_bits = [0u8; 137];
    speech_frame_b.to_bitarr(&mut codec_bits);
    let channel_bits = tch_reorder::codec_frame_to_channel(&codec_bits);

    let mut type3 = [0u8; MAX_TYPE345_HALFSLOT_BITS];
    type3[..CLASS0_BITS].copy_from_slice(&channel_bits[..CLASS0_BITS]);
    let mut type3_index = CLASS0_BITS;

    // The convolutional state is continuous across classes 1 and 2 even
    // though the puncturing rate changes at the class boundary.
    let mut encoder = SpeechConvEncState::new();

    let class1 = &channel_bits[CLASS0_BITS..CLASS0_BITS + CLASS1_BITS];
    let mut class1_mother = [0u8; CLASS1_BITS * 3];
    encoder.encode(class1, &mut class1_mother);
    let mut class1_punctured = [0u8; 84];
    convenc::get_punctured_rate(RcpcPunctMode::Rate112_168, &class1_mother, &mut class1_punctured);
    type3[type3_index..type3_index + class1_punctured.len()].copy_from_slice(&class1_punctured);
    type3_index += class1_punctured.len();

    let class2_start = CLASS0_BITS + CLASS1_BITS;
    let class2 = &channel_bits[class2_start..class2_start + CLASS2_BITS];
    let mut class2_type2 = [0u8; CLASS2_TYPE2_BITS];
    class2_type2[..CLASS2_BITS].copy_from_slice(class2);
    class2_type2[CLASS2_BITS..CLASS2_BITS + 4].copy_from_slice(&stolen_speech_crc(class2));
    // The final four tail bits remain zero.

    let mut class2_mother = [0u8; CLASS2_TYPE2_BITS * 3];
    encoder.encode(&class2_type2, &mut class2_mother);
    let mut class2_punctured = [0u8; 81];
    convenc::get_punctured_rate(RcpcPunctMode::Rate38_81, &class2_mother, &mut class2_punctured);
    type3[type3_index..type3_index + class2_punctured.len()].copy_from_slice(&class2_punctured);
    type3_index += class2_punctured.len();
    debug_assert_eq!(type3_index, MAX_TYPE345_HALFSLOT_BITS);

    let mut type4 = [0u8; MAX_TYPE345_HALFSLOT_BITS];
    interleaver::block_interleave(MAX_TYPE345_HALFSLOT_BITS, 101, &type3, &mut type4);
    let mut type5 = BitBuffer::from_bitarr(&type4);
    scrambler::tetra_scramb_bits(scrambling_code, &mut type5);
    type5
}

/// Encode traffic plane from type1 to type5 bits (EN 300 395-2): 274 ACELP bits → UEP encoding
/// (class0 uncoded, class1/2 convenc+punct) → 432 bits → interleave → scramble.
/// `blk_num` must be 1. Frame-stealing TCH/S uses [`encode_tch_s_half`]
/// because it is a separately encoded 137-bit speech frame, not half of this
/// full-slot codeword.
pub fn encode_tp(mut prim: TmvUnitdataReq, blk_num: u8) -> BitBuffer {
    assert_eq!(blk_num, 1, "frame-stealing TCH/S requires encode_tch_s_half");
    let lchan = prim.logical_channel;
    let params = errorcontrol_params::get_params(lchan);

    // ── Extract type-1 bits from BitBuffer ──────────────────────────
    prim.mac_block.seek(0);
    let mut type1_arr = [0u8; MAX_TYPE1_BITS];
    let type1_len = prim.mac_block.get_len().min(params.type1_bits);
    prim.mac_block.to_bitarr(&mut type1_arr[0..type1_len]);

    let mut type3_arr = [0u8; MAX_TYPE345_BITS];

    // ── ACELP bit reordering (EN 300 395-2, Table 4/5) ───────────
    if lchan == LogicalChannel::TchS && type1_len == 274 {
        let mut codec_bits = [0u8; 274];
        codec_bits.copy_from_slice(&type1_arr[0..274]);
        let channel_bits = tch_reorder::codec_to_channel(&codec_bits);
        type1_arr[0..274].copy_from_slice(&channel_bits);
    }

    const CLASS0_BITS: usize = 102; // 2 × 51
    const CLASS1_BITS: usize = 112; // 2 × 56
    const CLASS2_BITS: usize = 60; // 2 × 30
    const CLASS2_TYPE2: usize = 72; // 60 data + 8 CRC + 4 tail

    let mut type3_idx: usize = 0;

    // ── Class 0: UNCODED (102 bits) ─────────────────────────
    type3_arr[0..CLASS0_BITS].copy_from_slice(&type1_arr[0..CLASS0_BITS]);
    type3_idx += CLASS0_BITS;

    // The convolutional encoder state is CONTINUOUS across Class 1
    // and Class 2 (EN 300 395-2, Section 5.5.2.0)
    let mut ces = SpeechConvEncState::new();

    // ── Class 1: Speech convenc → Rate 8/12 (= 2/3) puncturing ──
    {
        let class1_start = CLASS0_BITS;
        let class1_input = &type1_arr[class1_start..class1_start + CLASS1_BITS];
        let mut mother_buf = [0u8; CLASS1_BITS * 3]; // 336 bits
        ces.encode(class1_input, &mut mother_buf);
        let mut punct_buf = [0u8; 168];
        convenc::get_punctured_rate(RcpcPunctMode::Rate112_168, &mother_buf, &mut punct_buf);
        type3_arr[type3_idx..type3_idx + 168].copy_from_slice(&punct_buf);
        type3_idx += 168;
    }

    // ── Class 2: CRC + Speech convenc → Rate 8/18 puncturing ─────
    {
        let class2_start = CLASS0_BITS + CLASS1_BITS;
        let class2_data = &type1_arr[class2_start..class2_start + CLASS2_BITS];

        // Build type-2 block: data(60) + CRC(8) + tail(4) = 72 bits
        let mut class2_type2 = [0u8; CLASS2_TYPE2];
        class2_type2[0..CLASS2_BITS].copy_from_slice(class2_data);

        // CRC: G(X) = 1 + X³ + X⁷ → 7 parity bits + 1 overall parity
        let crc_bits = speech_crc(class2_data);
        class2_type2[CLASS2_BITS..CLASS2_BITS + 8].copy_from_slice(&crc_bits);
        // Tail bits [68..72] stay zero (already initialized)

        let mut mother_buf = [0u8; CLASS2_TYPE2 * 3]; // 216 bits
        // Encoder state carries over from Class 1 (continuous encoding)
        ces.encode(&class2_type2, &mut mother_buf);
        let mut punct_buf = [0u8; 162];
        convenc::get_punctured_rate(RcpcPunctMode::Rate72_162, &mother_buf, &mut punct_buf);
        type3_arr[type3_idx..type3_idx + 162].copy_from_slice(&punct_buf);
        type3_idx += 162;
    }

    debug_assert_eq!(type3_idx, 432);

    // ── type-3 → type-4 (matrix interleaving, 24×18 transpose) ──
    let mut type4_arr = [0u8; MAX_TYPE345_BITS];
    interleaver::matrix_interleave(24, 18, &type3_arr, &mut type4_arr);
    let mut type4 = BitBuffer::from_bitarr(&type4_arr[0..params.type345_bits]);

    // ── type-4 → type-5 (scrambling) ─────────────────────────────
    scrambler::tetra_scramb_bits(prim.scrambling_code, &mut type4);

    type4
}

/// Decode traffic plane from type5 to type1 bits (ACELP codec order). Reverse of `encode_tp()`:
/// descramble → deinterleave → split UEP → Class0 copy, Class1+2 depuncture+Viterbi → CRC → reassemble → reorder.
/// Returns (Option<BitBuffer>, bool): 274 ACELP bits if successful, CRC check result for Class 2.
pub fn decode_tp_with_soft(
    lchan: LogicalChannel,
    type5_block: BitBuffer,
    soft_type5: Option<&[SoftBit]>,
    scrambling_code: u32,
) -> (Option<BitBuffer>, bool) {
    assert_eq!(lchan, LogicalChannel::TchS);

    let params = errorcontrol_params::get_params(lchan);

    // ── De-scramble type5 → type4 ──────────────────────────────────
    let mut type5 = type5_block;
    scrambler::tetra_scramb_bits(scrambling_code, &mut type5);
    let mut soft_type4 = soft_type5.filter(|bits| bits.len() == params.type345_bits).map(<[SoftBit]>::to_vec);
    if let Some(soft_bits) = &mut soft_type4 {
        descramble_soft_bits(scrambling_code, soft_bits);
    }
    let mut type4 = type5;

    // ── Matrix de-interleave type4 → type3 (reverse 24×18 transpose)
    let mut type4_arr = [0u8; MAX_TYPE345_BITS];
    type4.seek(0);
    type4.to_bitarr(&mut type4_arr[0..params.type345_bits]);
    let mut type3_arr = [0u8; MAX_TYPE345_BITS];
    interleaver::matrix_deinterleave(24, 18, &type4_arr, &mut type3_arr);
    let soft_type3 = soft_type4.map(|soft_type4| {
        let mut output = [0 as SoftBit; MAX_TYPE345_BITS];
        interleaver::matrix_deinterleave(24, 18, &soft_type4, &mut output);
        output
    });

    // ── Split type3 into UEP classes and decode ────────────────────
    const CLASS0_BITS: usize = 102;
    const CLASS1_BITS: usize = 112;
    const CLASS2_BITS: usize = 60;
    const CLASS2_TYPE2: usize = 72; // 60 data + 8 CRC + 4 tail
    const CLASS1_TYPE3: usize = 168; // punctured output size
    const CLASS2_TYPE3: usize = 162; // punctured output size

    let mut type1_arr = [0u8; MAX_TYPE1_BITS];

    // ── Class 0: UNCODED (102 bits) → copy directly ────────────────
    type1_arr[0..CLASS0_BITS].copy_from_slice(&type3_arr[0..CLASS0_BITS]);

    // ── Class 1 + Class 2: decoded together as one continuous Viterbi stream ──
    // Encoder state is continuous across classes (EN 300 395-2, §5.5.2.0):
    // depuncture each, concatenate, single Viterbi pass.
    let crc_ok;
    {
        // De-puncture Class 1: 168 type3 → 336 mother code bits
        let class1_type3 = &type3_arr[CLASS0_BITS..CLASS0_BITS + CLASS1_TYPE3];
        let mut mother_class1 = [0xFFu8; CLASS1_BITS * 3]; // 336
        convenc::tetra_rcpc_depunct(RcpcPunctMode::Rate112_168, class1_type3, CLASS1_TYPE3, &mut mother_class1);

        // De-puncture Class 2: 162 type3 → 216 mother code bits
        let class2_type3 = &type3_arr[CLASS0_BITS + CLASS1_TYPE3..CLASS0_BITS + CLASS1_TYPE3 + CLASS2_TYPE3];
        let mut mother_class2 = [0xFFu8; CLASS2_TYPE2 * 3]; // 216
        convenc::tetra_rcpc_depunct(RcpcPunctMode::Rate72_162, class2_type3, CLASS2_TYPE3, &mut mother_class2);

        // Concatenate mother code bits: Class1(336) + Class2(216) = 552
        let mut combined_mother = [0xFFu8; (CLASS1_BITS + CLASS2_TYPE2) * 3]; // 552
        combined_mother[..CLASS1_BITS * 3].copy_from_slice(&mother_class1);
        combined_mother[CLASS1_BITS * 3..].copy_from_slice(&mother_class2);

        let soft: Vec<SoftBit> = if let Some(soft_type3) = &soft_type3 {
            let mut output = vec![0 as SoftBit; (CLASS1_BITS + CLASS2_TYPE2) * 3];
            convenc::tetra_rcpc_depunct_soft(
                RcpcPunctMode::Rate112_168,
                &soft_type3[CLASS0_BITS..CLASS0_BITS + CLASS1_TYPE3],
                CLASS1_TYPE3,
                &mut output[..CLASS1_BITS * 3],
            );
            convenc::tetra_rcpc_depunct_soft(
                RcpcPunctMode::Rate72_162,
                &soft_type3[CLASS0_BITS + CLASS1_TYPE3..CLASS0_BITS + CLASS1_TYPE3 + CLASS2_TYPE3],
                CLASS2_TYPE3,
                &mut output[CLASS1_BITS * 3..],
            );
            output
        } else {
            combined_mother
                .iter()
                .map(|&bit| match bit {
                    0x00 => -1,
                    0x01 => 1,
                    _ => 0,
                })
                .collect()
        };

        let decoder = viterbi::TetraCodecViterbiDecoder::new();
        let decoded = decoder.decode(&soft);
        // decoded: 184 bits = Class1(112) + Class2_type2(72)

        // Extract Class 1 bits
        type1_arr[CLASS0_BITS..CLASS0_BITS + CLASS1_BITS].copy_from_slice(&decoded[..CLASS1_BITS]);

        // Extract Class 2 and CRC check
        let class2_decoded = &decoded[CLASS1_BITS..];
        // class2_decoded[0..60] = data, [60..68] = CRC, [68..72] = tail
        let data = &class2_decoded[0..CLASS2_BITS];
        let received_crc = &class2_decoded[CLASS2_BITS..CLASS2_BITS + 8];

        let expected_crc = speech_crc(data);
        crc_ok = expected_crc[..] == received_crc[..];

        type1_arr[CLASS0_BITS + CLASS1_BITS..CLASS0_BITS + CLASS1_BITS + CLASS2_BITS].copy_from_slice(data);
    }

    // ── channel_to_codec reorder (274 channel → 274 codec bits) ────
    let channel_bits: [u8; 274] = type1_arr[0..274].try_into().unwrap();
    let codec_bits = tch_reorder::channel_to_codec(&channel_bits);
    let result = BitBuffer::from_bitarr(&codec_bits);

    (Some(result), crc_ok)
}

/// Backwards-compatible hard-decision traffic decoder.
pub fn decode_tp(lchan: LogicalChannel, type5_block: BitBuffer, scrambling_code: u32) -> (Option<BitBuffer>, bool) {
    decode_tp_with_soft(lchan, type5_block, None, scrambling_code)
}

/// Encodes AACH message from type1 to type5 bits
pub fn encode_aach(buf: BitBuffer, scrambling_code: u32) -> BitBuffer {
    let mut type1 = buf;
    tracing::trace!("encode_aach type1: {:?}", type1.dump_bin());
    assert!(type1.get_len_remaining() == 14);

    // RM code type1 -> type2
    let type1_int = type1.read_bits(14).unwrap() as u16; // Guaranteed
    let type2_int = rm3014::tetra_rm3014_compute(type1_int);

    let mut type2 = BitBuffer::new(30);
    type2.write_bits(type2_int as u64, 30);
    type2.seek(0);
    tracing::trace!("encode_aach type2: {:?}", type2.dump_bin());

    // No de-interleaving or rcpc needed for AACH

    // Scrambling, type2 -> type5
    scrambler::tetra_scramb_bits(scrambling_code, &mut type2);
    let type5 = type2;

    tracing::trace!("encode_aach type5: {:?}", type5.dump_bin());

    type5
}

/// Decodes
pub fn decode_aach(buf: BitBuffer, scrambling_code: u32) -> Result<BitBuffer, rm3014::Rm3014Uncorrectable> {
    let mut type5 = buf;
    tracing::trace!("decode_aach type5: {:?}", type5.dump_bin());
    assert!(type5.get_len_remaining() == 30);

    // Unscrambling, type5 -> type2
    scrambler::tetra_scramb_bits(scrambling_code, &mut type5);
    let mut type2 = type5;
    tracing::trace!("decode_aach type2: {:?}", type2.dump_bin());

    // No de-interleaving or rcpc needed for AACH

    // RM code type2 -> type1

    // The ETSI RM(30,14) code has d_min = 8, hence its unique bounded
    // correction radius is three bits. Reject words beyond that radius.
    let x = type2.read_bits(30).unwrap() as u32; // Guaranteed
    let decoded = rm3014::tetra_rm3014_decode(x)?;

    // Write error-corrected data to type1 and return
    let mut type1 = type2;
    type1.set_raw_start(0);
    type1.set_raw_pos(0);
    type1.set_raw_end(14);
    type1.write_bits(decoded.data as u64, 14);
    type1.seek(0);

    tracing::debug!("decode_aach type1: {:?}", type1.dump_bin());
    Ok(type1)
}

fn descramble_soft_bits(scrambling_code: u32, soft_bits: &mut [SoftBit]) {
    let mut scrambling_bits = [0u8; MAX_TYPE345_BITS];
    assert!(soft_bits.len() <= scrambling_bits.len());
    scrambler::tetra_scramb_get_bits(scrambling_code, &mut scrambling_bits[..soft_bits.len()]);
    for (soft_bit, scrambling_bit) in soft_bits.iter_mut().zip(scrambling_bits) {
        if scrambling_bit != 0 {
            *soft_bit = soft_bit.saturating_neg();
        }
    }
}

#[cfg(test)]
mod tests {
    use tetra_core::{BurstType, PhyBlockNum, TdmaTime, TrainingSequence, debug::setup_logging_verbose};

    use super::*;

    /// Tests SCH/HD, STCH, BNCH encoding and decoding
    #[test]
    fn test_encdec_bnch() {
        // setup_logging_verbose();
        let type1vec =
            "1000001111101001010000000000101001101110011000000000000000001010000101010100000000000000000000101111111111111111110100100000";
        let type5vec = "001101111110011111000110100001101110011100110000111100011000011100101011111100010101101001101001001110011100001010001101101010100000000011010001001101001010101100100110011001111100001011000001010010000011010110110110";
        let bb = BitBuffer::from_bitstr(type1vec);
        let lchan = LogicalChannel::Bnch;
        let scramb_code = scrambler::tetra_scramb_get_init(204, 1337, 1);
        // println!("start: {}", bb.dump_bin());
        let prim_req = TmvUnitdataReq {
            mac_block: bb,
            logical_channel: lchan,
            scrambling_code: scramb_code,
            air_interface_encryption: None,
            cipher_region: None,
        };
        let type5 = encode_cp(prim_req);
        // println!("type5:   {}", type5.dump_bin());
        assert_eq!(type5vec, type5.to_bitstr());

        let prim_ind = TpUnitdataInd {
            ul_time: TdmaTime::default(),
            train_type: TrainingSequence::SyncTrainSeq,
            burst_type: BurstType::SDB,
            block_type: PhyBlockType::SB2,
            block_num: PhyBlockNum::Block2,
            soft_bits: None,
            block: type5,
        };

        let (type1, crc_ok) = decode_cp(lchan, prim_ind, Some(scramb_code));
        let type1 = type1.unwrap();

        assert!(crc_ok);
        assert_eq!(type1vec, type1.to_bitstr());
    }

    /// Tests BSCH encoding and decoding
    #[test]
    fn test_encdec_bsch() {
        // setup_logging_verbose();
        let type1_vec = "000100000111000010000010000000000110011000001010011100110001";
        let bb = BitBuffer::from_bitstr(type1_vec);
        let lchan = LogicalChannel::Bsch;
        let scramb_code = scrambler::SCRAMB_INIT;
        let prim_req = TmvUnitdataReq {
            mac_block: bb,
            logical_channel: lchan,
            scrambling_code: scramb_code,
            air_interface_encryption: None,
            cipher_region: None,
        };
        let type5 = encode_cp(prim_req);
        let prim_ind = TpUnitdataInd {
            ul_time: TdmaTime::default(),
            train_type: TrainingSequence::SyncTrainSeq,
            burst_type: BurstType::SDB,
            block_type: PhyBlockType::SB2,
            block_num: PhyBlockNum::Block2,
            soft_bits: None,
            block: type5,
        };

        let (type1, crc_ok) = decode_cp(lchan, prim_ind, Some(scramb_code));
        let type1 = type1.unwrap();
        assert!(crc_ok);
        assert_eq!(type1_vec, type1.to_bitstr());
    }

    /// Tests AACH encoding and decoding
    #[test]
    fn test_encdec_aach() {
        // setup_logging_verbose();
        let scramb_code = scrambler::tetra_scramb_get_init(204, 1337, 1);
        let type5vec = "100100100001011110111010111011";
        let type1vec = "00001010001010";

        let type5vec_bb = BitBuffer::from_bitstr(type5vec);
        let type1vec_bb = BitBuffer::from_bitstr(type1vec);

        let type1 = decode_aach(type5vec_bb, scramb_code).unwrap();
        let type5 = encode_aach(type1vec_bb, scramb_code);

        assert_eq!(type5vec, type5.to_bitstr());
        assert_eq!(type1vec, type1.to_bitstr());
    }

    /// Tests speech CRC-7 computation (EN 300 395-2 Section 5.5.1)
    #[test]
    fn test_speech_crc() {
        // All-zero input → CRC should be all zeros
        let zeros = [0u8; 60];
        let crc = speech_crc(&zeros);
        assert_eq!(crc, [0, 0, 0, 0, 0, 0, 0, 0], "CRC of all-zeros should be all-zeros");

        // Single bit at position 0: I(X) = 1
        // X^7 * 1 mod (X^7 + X^3 + 1) = X^3 + 1
        // → f(0)=1, f(3)=1, rest=0
        let mut data = [0u8; 60];
        data[0] = 1;
        let crc = speech_crc(&data);
        assert_eq!(&crc[0..7], &[1, 0, 0, 1, 0, 0, 0], "X^7 mod G = X^3+1");
        // Overall parity: 1 data bit + 2 CRC bits = 1^1^1 = 1
        assert_eq!(crc[7], 1, "b8 overall parity");

        // Single bit at position 1: I(X) = X
        // X^8 mod (X^7 + X^3 + 1) = X^4 + X
        // → f(1)=1, f(4)=1, rest=0
        let mut data2 = [0u8; 60];
        data2[1] = 1;
        let crc2 = speech_crc(&data2);
        assert_eq!(&crc2[0..7], &[0, 1, 0, 0, 1, 0, 0], "X^8 mod G = X^4+X");
    }

    #[test]
    fn test_stolen_speech_crc() {
        assert_eq!(stolen_speech_crc(&[0u8; 30]), [0, 0, 0, 0]);

        let mut data = [0u8; 30];
        data[0] = 1;
        // X^4 mod (X^4 + X + 1) = X + 1.
        assert_eq!(stolen_speech_crc(&data), [1, 1, 0, 0]);
    }

    #[test]
    fn stolen_tch_s_uses_only_frame_b_and_emits_one_half_slot() {
        let scrambling_code = scrambler::tetra_scramb_get_init(204, 1337, 1);
        let frame_b: Vec<u8> = (0..137).map(|index| ((index * 5 + 1) % 2) as u8).collect();

        let mut first_source = vec![0u8; 274];
        first_source[137..].copy_from_slice(&frame_b);
        let mut second_source = vec![1u8; 274];
        second_source[137..].copy_from_slice(&frame_b);

        let first = encode_tch_s_half(take_tch_s_frame_b(&mut BitBuffer::from_bitarr(&first_source)), scrambling_code);
        let second = encode_tch_s_half(take_tch_s_frame_b(&mut BitBuffer::from_bitarr(&second_source)), scrambling_code);

        assert_eq!(first.get_len(), 216);
        assert_eq!(
            first.to_bitstr(),
            second.to_bitstr(),
            "discarded speech frame A affected the stolen half"
        );

        let mut changed_source = first_source;
        changed_source[137 + 34] ^= 1;
        let changed = encode_tch_s_half(take_tch_s_frame_b(&mut BitBuffer::from_bitarr(&changed_source)), scrambling_code);
        assert_ne!(
            first.to_bitstr(),
            changed.to_bitstr(),
            "speech frame B did not affect the stolen half"
        );
    }

    #[test]
    fn stolen_tch_s_matches_en_300_395_2_impulse_vectors() {
        // These vectors are derived directly from EN 300 395-2 table 6 and
        // clauses 5.6.1 through 5.6.3.  A zero scrambling state deliberately
        // leaves type-4 visible, so this is not a self-consistent
        // encode/decode test that could hide the same error on both sides.
        // Each input has one set codec bit: the first class-0, class-1 or
        // class-2 bit in table 6 (B35, B58 and B18 respectively).
        let vectors = [
            (34, "000000000000000000000000040000000000000000000000000000"),
            (57, "000800200000020008000000000000010004001000400000000000"),
            (17, "00040008000000a0028000000800a0008001000000040050004005"),
        ];

        for (codec_index, expected_type4_hex) in vectors {
            let mut codec_frame = [0u8; 137];
            codec_frame[codec_index] = 1;
            let encoded = encode_tch_s_half(BitBuffer::from_bitarr(&codec_frame), 0);
            let mut encoded_bits = [0u8; 216];
            let mut encoded = encoded;
            encoded.seek(0);
            encoded.to_bitarr(&mut encoded_bits);
            let actual_hex: String = encoded_bits
                .chunks(8)
                .map(|chunk| {
                    let byte = chunk.iter().fold(0u8, |value, bit| (value << 1) | (bit & 1));
                    format!("{byte:02x}")
                })
                .collect();

            assert_eq!(
                actual_hex,
                expected_type4_hex,
                "half-slot vector failed for codec bit B{}",
                codec_index + 1
            );
        }
    }

    /// Tests SCH/F encoding and decoding
    #[test]
    fn test_encdec_sch_f() {
        setup_logging_verbose();
        let type1_vec = "0000000000110001000000000010011100010001000001110010000010000001000000000010011100010001010000000000001000110110011011100000100110000001011100000000110101000110011100000100000000000000000100001000000000000000000000000000000000000000000000000000000000000000000000000000";
        let bb = BitBuffer::from_bitstr(type1_vec);
        let lchan = LogicalChannel::SchF;
        let scramb_code = scrambler::tetra_scramb_get_init(204, 1337, 1);
        let prim_req = TmvUnitdataReq {
            mac_block: bb,
            logical_channel: lchan,
            scrambling_code: scramb_code,
            air_interface_encryption: None,
            cipher_region: None,
        };
        let type5 = encode_cp(prim_req);
        let prim_ind = TpUnitdataInd {
            ul_time: TdmaTime::default(),
            train_type: TrainingSequence::NormalTrainSeq1,
            burst_type: BurstType::NDB,
            block_type: PhyBlockType::NDB,
            block_num: PhyBlockNum::Both,
            soft_bits: None,
            block: type5,
        };

        let (type1, crc_ok) = decode_cp(lchan, prim_ind, Some(scramb_code));
        let type1 = type1.unwrap();
        assert!(crc_ok);
        assert_eq!(type1_vec, type1.to_bitstr());
    }

    /// Tests TCH/S speech encoding and decoding round-trip
    #[test]
    fn test_encdec_tch_s() {
        // Generate a random 274-bit ACELP frame (in codec order)
        let codec_bits: Vec<u8> = (0..274).map(|_| rand::random_range(0..2) as u8).collect();
        let bb = BitBuffer::from_bitarr(&codec_bits);
        let lchan = LogicalChannel::TchS;
        let scramb_code = scrambler::tetra_scramb_get_init(204, 1337, 1);

        let prim_req = TmvUnitdataReq {
            mac_block: bb,
            logical_channel: lchan,
            scrambling_code: scramb_code,
            air_interface_encryption: None,
            cipher_region: None,
        };
        let type5 = encode_tp(prim_req, 1);
        assert_eq!(type5.get_len(), 432);

        let (decoded, crc_ok) = decode_tp(lchan, type5, scramb_code);
        let decoded = decoded.unwrap();
        assert!(crc_ok, "CRC check failed for speech decode");
        assert_eq!(
            decoded.to_bitstr(),
            BitBuffer::from_bitarr(&codec_bits).to_bitstr(),
            "Round-trip encode→decode mismatch for TCH/S"
        );
    }
}
