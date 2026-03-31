/// Fixed-weight vector sampling.
///
/// Two methods per v5.0.0:
/// - `sample_fixed_wt_mod`: modular mapping, used in encrypt (r2, e, r1).
/// - `sample_fixed_wt_rej`: rejection sampling, used in keygen (y, x).
/// - `sample_vect`: uniform random vector via XOF.
use crate::params::HqcParameters;
use crate::shake::SeedExpander;

/// Sample a random binary vector of n bits via XOF.
pub(crate) fn sample_vect(xof: &mut SeedExpander, v: &mut [u64], p: &HqcParameters) {
    let mut rand_bytes = vec![0u8; p.n_bytes];
    xof.get_bytes(&mut rand_bytes);
    crate::poly::load8_arr(v, &rand_bytes);
    if p.vec_n_size_64 > 0 {
        v[p.vec_n_size_64 - 1] &= p.red_mask;
    }
}

/// Sample a fixed-weight vector using modular mapping (v5.0.0 encrypt).
///
/// Reads 4*weight bytes from XOF (with alignment waste), maps each u32
/// to position via multiplication-based reduction, deduplicates.
pub(crate) fn sample_fixed_wt_mod(
    xof: &mut SeedExpander,
    v: &mut [u64],
    weight: usize,
    p: &HqcParameters,
) {
    let mut rand_bytes = vec![0u8; 4 * weight];
    xof.get_bytes(&mut rand_bytes);

    let mut pos = vec![0u32; weight];
    for i in 0..weight {
        let u = u32::from_le_bytes([
            rand_bytes[4 * i],
            rand_bytes[4 * i + 1],
            rand_bytes[4 * i + 2],
            rand_bytes[4 * i + 3],
        ]);
        // v5.0.0 modular mapping: pos = ((u * (n-i)) >> 32) + i
        let n_minus_i = (p.n - i) as u64;
        pos[i] = (((u as u64 * n_minus_i) >> 32) + i as u64) as u32;
    }

    // Dedup backwards (v5.0.0 style): for each i from wt-1 down to 1,
    // check if any j < i has the same position. If so, set pos[i] = i.
    for i in (1..weight).rev() {
        let mut found = 0u32;
        for j in 0..i {
            // Constant-time equality check
            let diff = pos[j] ^ pos[i];
            let is_zero = (diff as u64 | (diff as u64).wrapping_neg()) >> 63; // 1 if non-zero
            found |= 1u32.wrapping_sub(is_zero as u32); // 1 if zero (equal)
        }
        let mask = 0u32.wrapping_sub(found & 1);
        pos[i] = (pos[i] & !mask) | (i as u32 & mask);
    }

    // Set bits in output vector
    for i in 0..p.vec_n_size_64.min(v.len()) {
        v[i] = 0;
    }
    for &position in pos.iter().take(weight) {
        let idx = position as usize >> 6;
        let bit = position as usize & 0x3f;
        if idx < v.len() {
            v[idx] |= 1u64 << bit;
        }
    }
}

/// Barrett reduction: val mod n using precomputed reciprocal.
///
/// Avoids variable-time `div` instruction. Uses `floor(2^32 / n)` as reciprocal.
/// Requires val < n * (2^32 / n), which holds for val < 2^24 and n < 2^17.
#[inline]
fn barrett_reduce(val: u32, n: u32, reciprocal: u32) -> u32 {
    let q = ((val as u64 * reciprocal as u64) >> 32) as u32;
    let mut r = val.wrapping_sub(q.wrapping_mul(n));
    // At most one correction needed: if r >= n, subtract n.
    // Constant-time: mask is all-ones if r >= n, all-zeros otherwise.
    let correction = n & 0u32.wrapping_sub((r >= n) as u32);
    r = r.wrapping_sub(correction);
    r
}

/// Sample a fixed-weight vector using rejection sampling (v5.0.0 keygen).
///
/// Reads 3*weight bytes per XOF chunk (matching reference implementation),
/// parses as big-endian 3-byte values, rejects if >= n_rej or duplicate.
/// Uses Barrett reduction instead of modulo to avoid variable-time division.
pub(crate) fn sample_fixed_wt_rej(
    xof: &mut SeedExpander,
    v: &mut [u64],
    weight: usize,
    p: &HqcParameters,
) {
    let n = p.n as u32;
    let n_rej = ((1u32 << 24) / n) * n;
    let chunk_size = 3 * weight;

    // Clear output vector
    for i in 0..p.vec_n_size_64.min(v.len()) {
        v[i] = 0;
    }

    let mut count = 0usize;
    let mut rand_bytes = vec![0u8; chunk_size];
    let mut j = chunk_size; // Start at chunk_size to trigger first read

    // Maximum iteration bound to prevent potential DoS from degenerate XOF output.
    // Expected iterations ≈ weight * (2^24 / n_rej). Bound at 16x weight.
    let max_iters = 16 * weight;
    let mut iters = 0usize;

    while count < weight && iters < max_iters {
        if j >= chunk_size {
            xof.get_bytes(&mut rand_bytes);
            j = 0;
        }

        // Big-endian 3-byte read
        let val = ((rand_bytes[j] as u32) << 16)
            | ((rand_bytes[j + 1] as u32) << 8)
            | (rand_bytes[j + 2] as u32);
        j += 3;
        iters += 1;

        if val < n_rej {
            // Barrett reduction: constant-time modular reduction (no div instruction)
            let pos = barrett_reduce(val, n, p.barrett_recip) as usize;
            let idx = pos >> 6;
            let bit = pos & 0x3f;
            if idx < v.len() {
                let bit_mask = 1u64 << bit;
                // Branchless duplicate check: only set bit and increment count
                // if this position is not already set.
                let already_set = (v[idx] >> bit) & 1;
                let is_new = 1u64.wrapping_sub(already_set); // 1 if new, 0 if dup
                v[idx] |= bit_mask; // harmless if already set
                count += is_new as usize;
            }
        }
    }
}
