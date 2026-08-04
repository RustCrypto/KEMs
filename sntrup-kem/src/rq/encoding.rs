use super::modq;
use crate::params::SntrupParameters;

/// Maximum number of pairing levels across all parameter sets (P up to 1277).
/// Levels: 1277 -> 639 -> 320 -> 160 -> 80 -> 40 -> 20 -> 10 -> 5 -> 3 -> 2 -> base case (n=1).
const fn compute_levels(p: usize) -> usize {
    let mut n = p;
    let mut levels = 0;
    while n > 1 {
        levels += 1;
        n = n.div_ceil(2);
    }
    levels
}

/// Total moduli storage across all levels (including the base case modulus).
const fn compute_m_storage(p: usize) -> usize {
    let mut n = p;
    let mut total = 0;
    while n > 1 {
        total += n;
        n = n.div_ceil(2);
    }
    total + 1 // +1 for base case modulus
}

const MAX_LEVELS: usize = compute_levels(1277); // 11
const MAX_M_STORAGE: usize = compute_m_storage(1277); // 2557

/// Constant-time divmod: *quotient = x / m, returns x % m.
/// m must be > 0 and < 16384. Matches PQClean's two-step Barrett reduction.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn uint32_divmod_uint14(quotient: &mut u32, x: u32, m: u16) -> u16 {
    let m32 = m as u32;
    let v = (0x80000000u32 as u64) / (m32 as u64);
    // First Barrett step
    let mut qpart = ((x as u64 * v) >> 31) as u32;
    let mut r = x - qpart * m32;
    *quotient = qpart;
    // Second Barrett step on remainder
    qpart = ((r as u64 * v) >> 31) as u32;
    r -= qpart * m32;
    *quotient += qpart;
    // Final speculative correction
    r = r.wrapping_sub(m32);
    *quotient += 1;
    let mask = (r >> 31).wrapping_neg(); // 0xFFFFFFFF if r underflowed (was < m), else 0
    r = r.wrapping_add(mask & m32);
    *quotient = quotient.wrapping_add(mask); // subtract 1 if we over-corrected
    r as u16
}

#[inline(always)]
fn uint32_mod_uint14(x: u32, m: u16) -> u16 {
    let mut q = 0u32;
    uint32_divmod_uint14(&mut q, x, m)
}

/// Iterative variable-radix encoding. Pairs values, emits bottom bytes when the
/// combined modulus reaches 16384, then repeats on the paired values.
/// `r` and `m` are modified in place across levels.
#[allow(clippy::cast_possible_truncation)]
fn encode(out: &mut [u8], r: &mut [u16], m: &mut [u16], n_start: usize) -> usize {
    if n_start == 0 {
        return 0;
    }
    if n_start == 1 {
        return encode_single(out, r[0] as u32, m[0] as u32);
    }

    let mut n = n_start;
    let mut pos = 0;

    while n > 1 {
        let n2 = n.div_ceil(2);
        // In-place pairing: read from [2*i, 2*i+1], write to [i].
        // Safe because i < 2*i for i >= 1, so reads precede writes.
        for i in 0..n2 {
            if 2 * i + 1 < n {
                let mut combined = r[2 * i] as u32 + (r[2 * i + 1] as u32) * (m[2 * i] as u32);
                let mut cm = (m[2 * i] as u32) * (m[2 * i + 1] as u32);
                while cm >= 16384 {
                    out[pos] = combined as u8;
                    pos += 1;
                    combined >>= 8;
                    cm = (cm + 255) >> 8;
                }
                r[i] = combined as u16;
                m[i] = cm as u16;
            } else {
                r[i] = r[2 * i];
                m[i] = m[2 * i];
            }
        }
        n = n2;
    }

    // Base case: single remaining value
    pos + encode_single(&mut out[pos..], r[0] as u32, m[0] as u32)
}

#[allow(clippy::cast_possible_truncation)]
fn encode_single(out: &mut [u8], mut val: u32, mut modulus: u32) -> usize {
    let mut pos = 0;
    while modulus > 1 {
        out[pos] = val as u8;
        pos += 1;
        val >>= 8;
        modulus = (modulus + 255) >> 8;
    }
    pos
}

/// Iterative variable-radix decoding. Forward pass computes moduli and byte
/// offsets at each level; backward pass expands decoded values from base case.
#[allow(clippy::cast_possible_truncation)]
fn decode(out: &mut [u16], s: &[u8], m_in: &[u16], n_start: usize) {
    if n_start == 0 {
        return;
    }
    if n_start == 1 {
        decode_single(out, s, m_in[0]);
        return;
    }

    // --- Forward pass: compute level sizes, moduli, and bottom-byte totals ---

    let mut ns = [0usize; MAX_LEVELS];
    let mut num_levels = 0;
    {
        let mut n = n_start;
        while n > 1 {
            ns[num_levels] = n;
            num_levels += 1;
            n = n.div_ceil(2);
        }
    }

    // Flat storage for moduli at every level (including paired output for base case)
    let mut all_m = [0u16; MAX_M_STORAGE];
    let mut level_m_offset = [0usize; MAX_LEVELS + 1];
    let mut level_bottom_total = [0usize; MAX_LEVELS];

    // Level 0 input moduli
    all_m[..n_start].copy_from_slice(&m_in[..n_start]);
    level_m_offset[0] = 0;
    let mut m_pos = n_start;

    for level in 0..num_levels {
        let n = ns[level];
        let n2 = n.div_ceil(2);
        let m_off = level_m_offset[level];
        level_m_offset[level + 1] = m_pos;
        let mut total_bottom = 0usize;

        for i in 0..n2 {
            if 2 * i + 1 < n {
                let mut cm = (all_m[m_off + 2 * i] as u32) * (all_m[m_off + 2 * i + 1] as u32);
                let mut bb = 0usize;
                while cm >= 16384 {
                    bb += 1;
                    cm = (cm + 255) >> 8;
                }
                total_bottom += bb;
                all_m[m_pos] = cm as u16;
            } else {
                all_m[m_pos] = all_m[m_off + 2 * i];
            }
            m_pos += 1;
        }

        level_bottom_total[level] = total_bottom;
    }

    // Cumulative bottom-byte start positions
    let mut level_bottom_start = [0usize; MAX_LEVELS];
    let mut cum_bottom = 0usize;
    for level in 0..num_levels {
        level_bottom_start[level] = cum_bottom;
        cum_bottom += level_bottom_total[level];
    }

    // --- Decode base case (n = 1) ---
    let base_m_off = level_m_offset[num_levels];
    decode_single(out, &s[cum_bottom..], all_m[base_m_off]);

    // --- Backward pass: expand decoded values level by level ---
    for level in (0..num_levels).rev() {
        let n = ns[level];
        let n2 = n.div_ceil(2);
        let m_off = level_m_offset[level];

        // out[0..n2] holds decoded values; expand in-place to out[0..n].
        // Process backwards: reads from out[i], writes to out[2*i] / out[2*i+1].
        let mut bpos = level_bottom_start[level] + level_bottom_total[level];

        for i in (0..n2).rev() {
            if 2 * i + 1 < n {
                // Recompute bottom-byte count for this pair
                let mut cm = (all_m[m_off + 2 * i] as u32) * (all_m[m_off + 2 * i + 1] as u32);
                let mut bb = 0usize;
                while cm >= 16384 {
                    bb += 1;
                    cm = (cm + 255) >> 8;
                }

                bpos -= bb;
                let mut combined = out[i] as u32;
                for j in (0..bb).rev() {
                    combined = (combined << 8) | (s[bpos + j] as u32);
                }

                let mut q = 0u32;
                let remainder = uint32_divmod_uint14(&mut q, combined, all_m[m_off + 2 * i]);
                out[2 * i] = remainder;
                out[2 * i + 1] = uint32_mod_uint14(q, all_m[m_off + 2 * i + 1]);
            } else {
                out[2 * i] = out[i];
            }
        }
    }
}

fn decode_single(out: &mut [u16], s: &[u8], m: u16) {
    if m == 1 {
        out[0] = 0;
    } else if m <= 256 {
        out[0] = uint32_mod_uint14(s[0] as u32, m);
    } else {
        out[0] = uint32_mod_uint14(s[0] as u32 + ((s[1] as u32) << 8), m);
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rq_encode(f: &[i16], params: &SntrupParameters) -> Vec<u8> {
    let p = params.p;
    let q12 = params.q12;
    let q_u16 = params.q as u16;

    let mut r = vec![0u16; p];
    for (ri, &fi) in r.iter_mut().zip(f.iter()) {
        *ri = (fi as i32 + q12) as u16;
    }
    let mut m = vec![q_u16; p];
    let mut out = vec![0u8; params.pk_size];
    encode(&mut out, &mut r, &mut m, p);
    out
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rq_decode(c: &[u8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q12 = params.q12;
    let q_u16 = params.q as u16;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let m = vec![q_u16; p];
    let mut r = vec![0u16; p];
    // Callers pass exactly `pk_size` bytes, so borrow directly on the hot path.
    // Only allocate-and-pad if the input is short (defensive; never happens via
    // the public API, where `EncapsulationKey::try_from` enforces the size).
    let mut padded;
    let s: &[u8] = if c.len() >= params.pk_size {
        &c[..params.pk_size]
    } else {
        padded = vec![0u8; params.pk_size];
        padded[..c.len()].copy_from_slice(c);
        &padded
    };
    decode(&mut r, s, &m, p);
    let mut f = vec![0i16; p];
    for (fi, &ri) in f.iter_mut().zip(r.iter()) {
        *fi = modq::freeze(ri as i32 - q12, q, b1, b2);
    }
    f
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rounded_encode(f: &[i16], params: &SntrupParameters) -> Vec<u8> {
    let p = params.p;
    let q12 = params.q12;
    let q_rounded = (params.q as u16).div_ceil(3);

    let mut r = vec![0u16; p];
    for (ri, &fi) in r.iter_mut().zip(f.iter()) {
        *ri = (((fi as i32 + q12) * 10923) >> 15) as u16;
    }
    let mut m = vec![q_rounded; p];
    let mut out = vec![0u8; params.rounded_encode_size];
    encode(&mut out, &mut r, &mut m, p);
    out
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rounded_decode(c: &[u8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q12 = params.q12;
    let q_rounded = (params.q as u16).div_ceil(3);
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let m = vec![q_rounded; p];
    let mut r = vec![0u16; p];
    // Callers pass exactly `rounded_encode_size` bytes, so borrow directly on the
    // hot path. Only allocate-and-pad if the input is short (defensive; never
    // happens via the public API, where `Ciphertext::try_from` enforces the size).
    let mut padded;
    let s: &[u8] = if c.len() >= params.rounded_encode_size {
        &c[..params.rounded_encode_size]
    } else {
        padded = vec![0u8; params.rounded_encode_size];
        padded[..c.len()].copy_from_slice(c);
        &padded
    };
    decode(&mut r, s, &m, p);
    let mut f = vec![0i16; p];
    for (fi, &ri) in f.iter_mut().zip(r.iter()) {
        *fi = modq::freeze(ri as i32 * 3 - q12, q, b1, b2);
    }
    f
}
