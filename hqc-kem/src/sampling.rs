/// Fixed-weight vector sampling (official reference @ commit 161cd4f).
///
/// - `sample_fixed_wt_mod`: modular mapping, used in encrypt (r2, e, r1).
/// - `sample_fixed_wt_rej`: rejection sampling, used in keygen (y, x).
/// - `sample_vect`: uniform random vector via XOF.
use crate::params::{HqcParameters, MAX_W};
use crate::shake::SeedExpander;
use ctutils::{CtLt, CtSelect};
use zeroize::Zeroize;

/// Sample a random binary vector of n bits via XOF.
///
/// `rand_bytes` is a caller-provided buffer of at least `p.n_bytes` bytes
/// ([`HqcParams::NBytesBuf`](crate::params::HqcParams)).
pub(crate) fn sample_vect(
    xof: &mut SeedExpander,
    v: &mut [u64],
    rand_bytes: &mut [u8],
    p: &HqcParameters,
) {
    let rand_bytes = &mut rand_bytes[..p.n_bytes];
    xof.get_bytes(rand_bytes);
    crate::poly::load8_arr(v, rand_bytes);
    if p.vec_n_size_64 > 0 {
        v[p.vec_n_size_64 - 1] &= p.red_mask;
    }
}

/// Sample a fixed-weight vector using modular mapping (encrypt path).
///
/// Reads 4*weight bytes from the XOF, maps each u32 to a position via
/// multiplication-based reduction, deduplicates.
pub(crate) fn sample_fixed_wt_mod(
    xof: &mut SeedExpander,
    v: &mut [u64],
    weight: usize,
    p: &HqcParameters,
) {
    debug_assert!(weight <= MAX_W);
    let mut rand_bytes = [0u8; 4 * MAX_W];
    let rand_bytes = &mut rand_bytes[..4 * weight];
    xof.get_bytes(rand_bytes);

    let mut pos = [0u32; MAX_W];
    let pos = &mut pos[..weight];
    for i in 0..weight {
        let u = u32::from_le_bytes([
            rand_bytes[4 * i],
            rand_bytes[4 * i + 1],
            rand_bytes[4 * i + 2],
            rand_bytes[4 * i + 3],
        ]);
        // Modular mapping: pos = ((u * (n-i)) >> 32) + i
        let n_minus_i = (p.n - i) as u64;
        pos[i] = (((u as u64 * n_minus_i) >> 32) + i as u64) as u32;
    }

    // Dedup (reference `vect_generate_random_support2`): for each i from
    // weight-2 down to 0, if any LATER j holds the same position, set
    // pos[i] = i (keep-last semantics — the direction matters for KAT
    // equivalence whenever a sampling collision occurs).
    for i in (0..weight.saturating_sub(1)).rev() {
        let mut found = 0u32;
        for j in (i + 1)..weight {
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

    // Zeroize transient secret material (raw XOF bytes and support positions).
    rand_bytes.zeroize();
    pos.zeroize();
}

/// Barrett reduction: val mod n using precomputed reciprocal.
///
/// Avoids variable-time `div` instruction. Uses `floor(2^32 / n)` as reciprocal.
/// Requires val < n * (2^32 / n), which holds for val < 2^24 and n < 2^17.
#[inline]
fn barrett_reduce(val: u32, n: u32, reciprocal: u32) -> u32 {
    let q = ((val as u64 * reciprocal as u64) >> 32) as u32;
    let r = val.wrapping_sub(q.wrapping_mul(n));
    // At most one correction needed: subtract n iff r >= n, selected
    // branchlessly via ctutils (no compare-flag-dependent instruction).
    r.wrapping_sub(u32::ct_select(&n, &0u32, r.ct_lt(&n)))
}

/// Sample a fixed-weight vector using rejection sampling (keygen path).
///
/// Reference commit 161cd4f semantics: reads exactly 3 bytes per candidate
/// from the XOF, assembles them little-endian (`b0 | b1<<8 | b2<<16`),
/// rejects candidates >= n_rej, Barrett-reduces, and skips duplicates.
/// The duplicate check here is branchless (the reference uses an early-exit
/// scan that is variable-time on secret support positions); both strategies
/// consume identical XOF bytes and accept/reject identically, so outputs
/// match the reference KATs exactly.
pub(crate) fn sample_fixed_wt_rej(
    xof: &mut SeedExpander,
    v: &mut [u64],
    weight: usize,
    p: &HqcParameters,
) {
    let n = p.n as u32;
    let n_rej = ((1u32 << 24) / n) * n;

    // Clear output vector
    for i in 0..p.vec_n_size_64.min(v.len()) {
        v[i] = 0;
    }

    let mut count = 0usize;
    let mut rand_bytes = [0u8; 3];

    // Maximum attempt bound to prevent potential DoS from degenerate XOF output.
    // Expected attempts ~ weight * (2^24 / n_rej). Bound at 16x weight.
    let max_iters = 16 * weight;
    let mut iters = 0usize;

    while count < weight && iters < max_iters {
        xof.get_bytes(&mut rand_bytes);
        iters += 1;

        // Little-endian 3-byte candidate (reference commit 161cd4f)
        let val =
            (rand_bytes[0] as u32) | ((rand_bytes[1] as u32) << 8) | ((rand_bytes[2] as u32) << 16);

        if val < n_rej {
            // Barrett reduction: constant-time modular reduction (no div instruction)
            let pos = barrett_reduce(val, n, p.barrett_recip) as usize;
            let idx = pos >> 6;
            let bit = pos & 0x3f;
            if idx < v.len() {
                let bit_mask = 1u64 << bit;
                // Branchless duplicate check: only count the position as new
                // if this bit was not already set.
                let already_set = (v[idx] >> bit) & 1;
                let is_new = 1u64.wrapping_sub(already_set); // 1 if new, 0 if dup
                v[idx] |= bit_mask; // harmless if already set
                count += is_new as usize;
            }
        }
    }

    // Zeroize the transient candidate buffer.
    rand_bytes.zeroize();
}
