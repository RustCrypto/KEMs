/// Reed-Muller RM(1,7) encoding and decoding with repetition.
///
/// Each byte is encoded into a 128-bit RM(1,7) codeword, then repeated
/// `mult` times to fill `n2` bits per symbol.
use crate::params::HqcParameters;

/// Number of repetitions for a given parameter set.
fn multiplicity(p: &HqcParameters) -> usize {
    p.n2.div_ceil(128)
}

/// Copy bit 0 of x into all 32 bits.
#[inline]
fn bit0mask(x: u32) -> u32 {
    0u32.wrapping_sub(x & 1)
}

/// Encode a single byte into a 128-bit RM(1,7) codeword (two u64s).
fn encode_single(message: u8) -> [u64; 2] {
    // bit 7 flips all bits
    let mut first_word: u32 = bit0mask((message >> 7) as u32);
    first_word ^= bit0mask(message as u32) & 0xAAAAAAAA;
    first_word ^= bit0mask((message >> 1) as u32) & 0xCCCCCCCC;
    first_word ^= bit0mask((message >> 2) as u32) & 0xF0F0F0F0;
    first_word ^= bit0mask((message >> 3) as u32) & 0xFF00FF00;
    first_word ^= bit0mask((message >> 4) as u32) & 0xFFFF0000;

    let mut cword = [0u64; 2];
    cword[0] = first_word as u64;

    // bit 5 flips entries 1 and 3; bit 6 flips entries 2 and 3
    first_word ^= bit0mask((message >> 5) as u32);
    cword[0] |= (first_word as u64) << 32;

    first_word ^= bit0mask((message >> 6) as u32);
    cword[1] = (first_word as u64) << 32;

    first_word ^= bit0mask((message >> 5) as u32);
    cword[1] |= first_word as u64;

    cword
}

/// Hadamard transform using a flag to track which buffer has the result.
fn hadamard_transform(expanded: &mut [i16; 128], transform: &mut [i16; 128]) {
    // Copy expanded to a working buffer
    let mut buf_a = *expanded;
    let mut buf_b = [0i16; 128];

    let mut src = &mut buf_a;
    let mut dst = &mut buf_b;

    for _pass in 0..7 {
        for i in 0..64 {
            dst[i] = src[2 * i].wrapping_add(src[2 * i + 1]);
            dst[i + 64] = src[2 * i].wrapping_sub(src[2 * i + 1]);
        }
        core::mem::swap(&mut src, &mut dst);
    }
    // After 7 passes, result is in `src`
    transform.copy_from_slice(src);
}

/// Sum repeated codewords into 128 accumulators.
fn expand_and_sum(dest: &mut [i16; 128], src: &[u64], mult: usize) {
    // First copy
    for part in 0..2 {
        for bit in 0..64 {
            dest[part * 64 + bit] = ((src[part] >> bit) & 1) as i16;
        }
    }
    // Sum remaining copies
    for copy in 1..mult {
        for part in 0..2 {
            if 2 * copy + part < src.len() {
                for bit in 0..64 {
                    dest[part * 64 + bit] += ((src[2 * copy + part] >> bit) & 1) as i16;
                }
            }
        }
    }
}

/// Find the peak in the Hadamard transform (constant-time).
fn find_peaks(transform: &[i16; 128], _mult: usize) -> u8 {
    let mut peak_abs: u16 = 0;
    let mut peak: i16 = 0;
    let mut pos: u16 = 0;

    for i in 0..128u16 {
        let t = transform[i as usize];
        // Branchless absolute value: avoids timing leak on Hadamard coefficients
        let mask = t >> 15; // arithmetic right shift: -1 if negative, 0 if non-negative
        let abs_t = ((t ^ mask).wrapping_sub(mask)) as u16;

        // Update if this abs is strictly greater (constant time)
        let mask = 0u16.wrapping_sub((peak_abs.wrapping_sub(abs_t)) >> 15); // mask = 0xFFFF if peak_abs < abs_t
        peak = (peak & !(mask as i16)) | (t & (mask as i16));
        pos = (pos & !mask) | (i & mask);
        peak_abs = (peak_abs & !mask) | (abs_t & mask);
    }

    // Set bit 7 if peak is positive (>=0)
    let positive = 0u16.wrapping_sub(1u16.wrapping_sub((peak as u16) >> 15)); // 0xFFFF if positive
    pos |= 128 & positive;

    pos as u8
}

/// Encode message bytes into concatenated RM codewords.
///
/// Each byte of `msg` (length n1) is RM-encoded into `mult` repetitions of
/// 128-bit codewords, producing n1*n2 bits total in `cdw`.
pub(crate) fn reed_muller_encode(cdw: &mut [u64], msg: &[u8], p: &HqcParameters) {
    let mult = multiplicity(p);
    for (i, &byte) in msg.iter().enumerate().take(p.n1) {
        let cword = encode_single(byte);
        // Write first codeword
        let base = 2 * i * mult;
        if base + 1 < cdw.len() {
            cdw[base] = cword[0];
            cdw[base + 1] = cword[1];
        }
        // Copy to remaining repetitions
        for copy in 1..mult {
            let dst = base + 2 * copy;
            if dst + 1 < cdw.len() {
                cdw[dst] = cword[0];
                cdw[dst + 1] = cword[1];
            }
        }
    }
}

/// Decode concatenated RM codewords into message bytes.
pub(crate) fn reed_muller_decode(msg: &mut [u8], cdw: &[u64], p: &HqcParameters) {
    let mult = multiplicity(p);
    let mut expanded = [0i16; 128];
    let mut transform = [0i16; 128];

    for (i, byte) in msg.iter_mut().enumerate().take(p.n1) {
        let base = 2 * i * mult;
        expand_and_sum(&mut expanded, &cdw[base..], mult);
        hadamard_transform(&mut expanded, &mut transform);
        // Fix first entry: subtract 64 * mult
        transform[0] = transform[0].wrapping_sub((64 * mult) as i16);
        *byte = find_peaks(&transform, mult);
    }
}
