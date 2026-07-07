/// Binary polynomial operations in Z_2[X]/(X^n - 1).
///
/// Polynomials are stored as arrays of u64, where each bit is a coefficient.
/// Uses Karatsuba multiplication for efficiency.
use crate::params::HqcParameters;

/// Polynomial addition: o = v1 XOR v2.
#[inline]
pub(crate) fn vect_add(o: &mut [u64], v1: &[u64], v2: &[u64], size: usize) {
    for ((o, a), b) in o.iter_mut().zip(v1).zip(v2).take(size) {
        *o = a ^ b;
    }
}

/// In-place polynomial addition: v ^= rhs.
#[inline]
pub(crate) fn vect_add_assign(v: &mut [u64], rhs: &[u64], size: usize) {
    for (v, r) in v.iter_mut().zip(rhs).take(size) {
        *v ^= r;
    }
}

/// Carry-less multiplication of two 64-bit words (test-oracle path).
///
/// Uses PCLMULQDQ on x86-64 when available (runtime-detected with `std`,
/// compile-time `target_feature` otherwise), else a constant-time software fallback.
#[cfg(test)]
#[inline]
fn base_mul(a: u64, b: u64) -> [u64; 2] {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if std::is_x86_feature_detected!("pclmulqdq") {
            return unsafe { base_mul_pclmul(a, b) };
        }
    }
    #[cfg(all(
        target_arch = "x86_64",
        not(feature = "std"),
        target_feature = "pclmulqdq"
    ))]
    {
        return unsafe { base_mul_pclmul(a, b) };
    }
    #[allow(unreachable_code)]
    base_mul_soft(a, b)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn base_mul_pclmul(a: u64, b: u64) -> [u64; 2] {
    use core::arch::x86_64::*;
    unsafe {
        let va = _mm_set_epi64x(0, a as i64);
        let vb = _mm_set_epi64x(0, b as i64);
        let r = _mm_clmulepi64_si128(va, vb, 0x00);
        let mut result = [0u64; 2];
        _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, r);
        result
    }
}

/// Software carry-less multiplication (constant-time).
#[cfg(test)]
#[inline]
fn base_mul_soft(a: u64, b: u64) -> [u64; 2] {
    let mut h: u64 = 0;
    let mut l: u64;
    let mut g: u64;
    let mut u = [0u64; 16];

    // Precompute small multiples of b (with top 4 bits masked)
    u[0] = 0;
    u[1] = b & ((1u64 << 60) - 1);
    u[2] = u[1] << 1;
    u[3] = u[2] ^ u[1];
    u[4] = u[2] << 1;
    u[5] = u[4] ^ u[1];
    u[6] = u[3] << 1;
    u[7] = u[6] ^ u[1];
    u[8] = u[4] << 1;
    u[9] = u[8] ^ u[1];
    u[10] = u[5] << 1;
    u[11] = u[10] ^ u[1];
    u[12] = u[6] << 1;
    u[13] = u[12] ^ u[1];
    u[14] = u[7] << 1;
    u[15] = u[14] ^ u[1];

    // First nibble
    g = 0;
    let tmp1 = a & 0x0f;
    for i in 0..16u64 {
        let tmp2 = tmp1.wrapping_sub(i);
        let mask = 0u64.wrapping_sub(1u64.wrapping_sub((tmp2 | tmp2.wrapping_neg()) >> 63));
        g ^= u[i as usize] & mask;
    }
    l = g;

    // Remaining nibbles
    for shift in (4..64).step_by(4) {
        g = 0;
        let tmp1 = (a >> shift) & 0x0f;
        for j in 0..16u64 {
            let tmp2 = tmp1.wrapping_sub(j);
            let mask = 0u64.wrapping_sub(1u64.wrapping_sub((tmp2 | tmp2.wrapping_neg()) >> 63));
            g ^= u[j as usize] & mask;
        }
        l ^= g << shift;
        h ^= g >> (64 - shift);
    }

    // Handle top 4 bits of b
    let masks = [
        0u64.wrapping_sub((b >> 60) & 1),
        0u64.wrapping_sub((b >> 61) & 1),
        0u64.wrapping_sub((b >> 62) & 1),
        0u64.wrapping_sub((b >> 63) & 1),
    ];

    l ^= (a << 60) & masks[0];
    h ^= (a >> 4) & masks[0];
    l ^= (a << 61) & masks[1];
    h ^= (a >> 3) & masks[1];
    l ^= (a << 62) & masks[2];
    h ^= (a >> 2) & masks[2];
    l ^= (a << 63) & masks[3];
    h ^= (a >> 1) & masks[3];

    [l, h]
}

#[cfg(test)]
#[inline]
fn karatsuba_add1(
    alh: &mut [u64],
    blh: &mut [u64],
    a: &[u64],
    b: &[u64],
    size_l: usize,
    size_h: usize,
) {
    for i in 0..size_h {
        alh[i] = a[i] ^ a[i + size_l];
        blh[i] = b[i] ^ b[i + size_l];
    }
    if size_h < size_l {
        alh[size_h] = a[size_h];
        blh[size_h] = b[size_h];
    }
}

#[cfg(test)]
#[inline]
fn karatsuba_add2(o: &mut [u64], tmp1: &mut [u64], tmp2: &[u64], size_l: usize, size_h: usize) {
    for i in 0..(2 * size_l) {
        tmp1[i] ^= o[i];
    }
    for i in 0..(2 * size_h) {
        tmp1[i] ^= tmp2[i];
    }
    for i in 0..(2 * size_l) {
        o[i + size_l] ^= tmp1[i];
    }
}

/// Recursive Karatsuba multiplication (retained as the test oracle for the
/// accumulated variant; no longer used in production paths).
///
/// Stack layout per level: [alh(size_l) | blh(size_l) | tmp1(2*size_l) | copies(2*size_l) | deeper...]
/// Total local = 6*size_l per level. The 8*vec_n pre-allocation is sufficient for all levels.
#[cfg(test)]
fn karatsuba(o: &mut [u64], a: &[u64], b: &[u64], size: usize, stack: &mut [u64]) {
    if size == 1 {
        let c = base_mul(a[0], b[0]);
        o[0] = c[0];
        o[1] = c[1];
        return;
    }

    let size_h = size / 2;
    let size_l = size.div_ceil(2);

    // Split stack: 6*size_l for this level, rest for recursion
    let (local, stack_rest) = stack.split_at_mut(6 * size_l);

    // local layout: [alh | blh | tmp1 | copies]
    let (alh_blh, tmp1_copies) = local.split_at_mut(2 * size_l);
    let (tmp1_part, copies_part) = tmp1_copies.split_at_mut(2 * size_l);

    karatsuba(o, a, b, size_l, stack_rest);
    karatsuba(
        &mut o[2 * size_l..],
        &a[size_l..],
        &b[size_l..],
        size_h,
        stack_rest,
    );

    {
        let (alh_part, blh_part) = alh_blh.split_at_mut(size_l);
        karatsuba_add1(alh_part, blh_part, a, b, size_l, size_h);
    }

    // Copy alh/blh into copies region so we can pass tmp1 as mutable output
    let (alh, blh) = alh_blh.split_at(size_l);
    let (alh_copy, blh_copy) = copies_part.split_at_mut(size_l);
    alh_copy[..size_l].copy_from_slice(alh);
    blh_copy[..size_l].copy_from_slice(&blh[..size_l]);

    // Clear tmp1 before writing
    for v in tmp1_part[..2 * size_l].iter_mut() {
        *v = 0;
    }
    karatsuba(
        tmp1_part,
        &alh_copy[..size_l],
        &blh_copy[..size_l],
        size_l,
        stack_rest,
    );

    // Copy tmp2 (in o[2*size_l..]) into copies region to avoid aliasing
    let tmp2_len = 2 * size_h;
    copies_part[..tmp2_len].copy_from_slice(&o[2 * size_l..2 * size_l + tmp2_len]);

    karatsuba_add2(o, tmp1_part, &copies_part[..tmp2_len], size_l, size_h);
}

// ---------------------------------------------------------------------------
// Accumulated (in-place) Karatsuba: `c ^= a·b` over GF(2)[X] with NO
// recursion scratch buffer; operands are temporarily modified and restored.
// Chosen over a clean-room Dumas–Grenet Algorithm 7 implementation by
// benchmark (see Plans/hqc-nicstr-integration.md, Phase 2).
// ---------------------------------------------------------------------------

/// Accumulating carry-less word multiply: `c[0..2] ^= a ⊗ b`.
///
/// PCLMULQDQ on x86-64 when available, otherwise the BGTZ `mul1` window
/// kernel — substantially faster than the masked-scan fallback on non-x86.
/// (CT note for Phase 3: BGTZ tabulates 8 multiples = 128 bytes indexed by
/// operand bits; the masked-scan kernel remains strictly access-uniform.)
#[inline]
fn base_mul_acc(c: &mut [u64], a: u64, b: u64) {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if std::is_x86_feature_detected!("pclmulqdq") {
            let r = unsafe { base_mul_pclmul(a, b) };
            c[0] ^= r[0];
            c[1] ^= r[1];
            return;
        }
    }
    #[cfg(all(
        target_arch = "x86_64",
        not(feature = "std"),
        target_feature = "pclmulqdq"
    ))]
    {
        let r = unsafe { base_mul_pclmul(a, b) };
        c[0] ^= r[0];
        c[1] ^= r[1];
        return;
    }
    #[allow(unreachable_code)]
    acc_bgtz::base_mul_acc(c, a, b)
}

/// Base word multiply: Algorithm `mul1` from Brent–Gaudry–Thomé–Zimmermann,
/// "Faster multiplication in GF(2)[x]" (2007), 3-bit window with top-bit
/// repair. Structure adapted from NicsTr/hqc-kem (MIT License,
/// Copyright (c) 2026 Nics); repair uses mask arithmetic instead of ctutils.
mod acc_bgtz {
    #[inline(always)]
    fn w(val: u64, off: usize) -> usize {
        ((val >> off) & 7) as usize
    }

    #[inline]
    pub(super) fn base_mul_acc(c: &mut [u64], a: u64, b: u64) {
        // Step 1: tabulate small multiples of a
        let mut u = [0u64; 8];
        u[1] = a;
        u[2] = u[1] << 1;
        u[3] = u[2] ^ a;
        u[4] = u[2] << 1;
        u[5] = u[4] ^ a;
        u[6] = u[3] << 1;
        u[7] = u[6] ^ a;

        // Step 2: multiply via 3-bit windows of b
        let mut lo = (u[(b >> 63) as usize] << 3) ^ u[w(b, 60)];
        let mut hi = lo >> 58;
        lo = (lo << 6) ^ (u[w(b, 57)] << 3) ^ u[w(b, 54)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 51)] << 3) ^ u[w(b, 48)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 45)] << 3) ^ u[w(b, 42)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 39)] << 3) ^ u[w(b, 36)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 33)] << 3) ^ u[w(b, 30)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 27)] << 3) ^ u[w(b, 24)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 21)] << 3) ^ u[w(b, 18)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 15)] << 3) ^ u[w(b, 12)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 9)] << 3) ^ u[w(b, 6)];
        hi = (hi << 6) | (lo >> 58);
        lo = (lo << 6) ^ (u[w(b, 3)] << 3) ^ u[(b & 7) as usize];

        // Step 3: repair contributions of the top 5 bits of a shifted out
        // of the 64-bit table entries (constant-time mask selection).
        hi ^= ((b & 0xefbe_fbef_befb_efbe) >> 1) & 0u64.wrapping_sub((a >> 63) & 1);
        hi ^= ((b & 0xcf3c_f3cf_3cf3_cf3c) >> 2) & 0u64.wrapping_sub((a >> 62) & 1);
        hi ^= ((b & 0x8e38_e38e_38e3_8e38) >> 3) & 0u64.wrapping_sub((a >> 61) & 1);
        hi ^= ((b & 0x0c30_c30c_30c3_0c30) >> 4) & 0u64.wrapping_sub((a >> 60) & 1);
        hi ^= ((b & 0x0820_8208_2082_0820) >> 5) & 0u64.wrapping_sub((a >> 59) & 1);

        c[0] ^= lo;
        c[1] ^= hi;
    }
}

/// In-place accumulated Karatsuba adapted from NicsTr/hqc-kem
/// (MIT License, Copyright (c) 2026 Nics), `polynomial.rs`, which implements
/// the accumulation scheme of Dumas & Grenet 2025 (arXiv:2307.12712).
mod acc_nicstr {
    /// XOR a range of `value` onto another (possibly overlapping) range.
    #[inline]
    fn overlapping_xor(value: &mut [u64], dst: usize, src: usize, len: usize) {
        if dst <= src {
            for i in 0..len {
                value[dst + i] ^= value[src + i];
            }
        } else {
            for i in (0..len).rev() {
                value[dst + i] ^= value[src + i];
            }
        }
    }

    /// XOR `a` into `b` (zips by the shorter length).
    #[inline]
    fn xor_into(b: &mut [u64], a: &[u64]) {
        for (bi, ai) in b.iter_mut().zip(a) {
            *bi ^= *ai;
        }
    }

    /// `c ^= a·b`; `a`/`b` equal length, `c` twice that length.
    pub(crate) fn karatsuba_acc(c: &mut [u64], a: &mut [u64], b: &mut [u64]) {
        debug_assert_eq!(a.len(), b.len());
        debug_assert_eq!(c.len(), a.len() + b.len());

        if a.len() == 1 {
            super::base_mul_acc(c, a[0], b[0]);
            return;
        }

        let split = a.len().div_ceil(2);
        let c_len = c.len();

        overlapping_xor(c, split, 0, split);
        overlapping_xor(c, 2 * split, split, split);
        overlapping_xor(c, 3 * split, 2 * split, c_len - 3 * split);

        let (a0, a1) = a.split_at_mut(split);
        let (b0, b1) = b.split_at_mut(split);

        let l0 = a0.len() + b0.len();
        let l1 = a1.len() + b1.len();
        karatsuba_acc(&mut c[..l0], a0, b0);
        karatsuba_acc(&mut c[split..split + l1], a1, b1);

        overlapping_xor(c, 3 * split, 2 * split, c_len - 3 * split);
        overlapping_xor(c, 2 * split, split, split);
        overlapping_xor(c, split, 0, split);

        xor_into(a0, a1);
        xor_into(b0, b1);

        let lm = a0.len() + b0.len();
        karatsuba_acc(&mut c[split..split + lm], a0, b0);

        xor_into(a0, a1);
        xor_into(b0, b1);
    }
}

/// Reduce polynomial modulo X^n - 1.
fn reduce(o: &mut [u64], a: &[u64], n: usize, vec_n_size_64: usize) {
    let shift = n & 0x3f;
    for i in 0..vec_n_size_64 {
        let r = a[i + vec_n_size_64 - 1] >> shift;
        let carry = if i + vec_n_size_64 < a.len() {
            a[i + vec_n_size_64] << (64 - shift)
        } else {
            0
        };
        o[i] = a[i] ^ r ^ carry;
    }
}

/// Multiply two polynomials modulo X^n - 1.
///
/// `prod` must hold at least `2 * vec_n` words; callers pass the per-level
/// stack buffer [`HqcParams::ProdBuf`](crate::params::HqcParams). The
/// accumulated Karatsuba mutates-and-restores its operands, so the inputs
/// are copied into per-level buffers first.
pub(crate) fn vect_mul<P: crate::params::HqcParams>(
    o: &mut [u64],
    v1: &[u64],
    v2: &[u64],
    prod: &mut [u64],
    p: &HqcParameters,
) {
    use crate::params::Buffer;
    use zeroize::Zeroize;
    let vec_n = p.vec_n_size_64;
    prod[..vec_n << 1].fill(0);

    // `karatsuba_acc` mutates-and-restores its operands, so the inputs are
    // copied into local buffers first. When an operand is secret (e.g. the
    // decryption key `y`), this copy duplicates that secret onto the stack;
    // zeroize both copies before returning to preserve the callers' hygiene.
    let mut c1 = P::VecN::zeroed();
    let mut c2 = P::VecN::zeroed();
    c1.as_mut()[..vec_n].copy_from_slice(&v1[..vec_n]);
    c2.as_mut()[..vec_n].copy_from_slice(&v2[..vec_n]);
    acc_nicstr::karatsuba_acc(
        &mut prod[..vec_n << 1],
        &mut c1.as_mut()[..vec_n],
        &mut c2.as_mut()[..vec_n],
    );

    reduce(o, &prod[..vec_n << 1], p.n, vec_n);
    o[vec_n - 1] &= p.red_mask;

    c1.as_mut().zeroize();
    c2.as_mut().zeroize();
}

/// Load byte array into u64 array (little-endian).
#[inline]
pub(crate) fn load8_arr(out: &mut [u64], inp: &[u8]) {
    let full_chunks = inp.len() / 8;
    let count = full_chunks.min(out.len());
    for i in 0..count {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&inp[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(buf);
    }
    let rem = inp.len() - count * 8;
    if rem > 0 && count < out.len() {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&inp[count * 8..]);
        out[count] = u64::from_le_bytes(buf);
    }
}

/// Store u64 array into byte array (little-endian).
#[inline]
pub(crate) fn store8_arr(out: &mut [u8], inp: &[u64]) {
    let full_chunks = out.len() / 8;
    let count = full_chunks.min(inp.len());
    for i in 0..count {
        out[i * 8..(i + 1) * 8].copy_from_slice(&inp[i].to_le_bytes());
    }
    let rem = out.len() - count * 8;
    if rem > 0 && count < inp.len() {
        let bytes = inp[count].to_le_bytes();
        out[count * 8..].copy_from_slice(&bytes[..rem]);
    }
}

/// Resize vector: copy and potentially truncate.
pub(crate) fn vect_resize(o: &mut [u64], size_o: usize, v: &[u64], size_v: usize) {
    if size_o < size_v {
        let n1n2_64 = size_o.div_ceil(64);
        let copy_words = n1n2_64.min(o.len()).min(v.len());
        o[..copy_words].copy_from_slice(&v[..copy_words]);
        let bits_in_last = size_o % 64;
        if bits_in_last != 0 && n1n2_64 > 0 && n1n2_64 - 1 < o.len() {
            o[n1n2_64 - 1] &= (1u64 << bits_in_last) - 1;
        }
    } else {
        let words = size_v.div_ceil(64);
        let copy_words = words.min(o.len()).min(v.len());
        o[..copy_words].copy_from_slice(&v[..copy_words]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_LEN: usize = 901;

    /// Deterministic xorshift64* generator — no dependency on RNG crates.
    fn next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(buf: &mut [u64], state: &mut u64) {
        for w in buf.iter_mut() {
            *w = next(state);
        }
    }

    /// Both accumulated variants must match the original Karatsuba product
    /// (pre-reduction) for random operands at every HQC size and edge sizes.
    #[test]
    fn accumulated_variants_match_original() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut a = [0u64; MAX_LEN];
        let mut b = [0u64; MAX_LEN];
        let mut expected = [0u64; 2 * MAX_LEN];
        let mut stack = [0u64; 8 * MAX_LEN];
        let mut got = [0u64; 2 * MAX_LEN];
        let mut a1 = [0u64; MAX_LEN];
        let mut b1 = [0u64; MAX_LEN];

        for &len in &[1usize, 2, 3, 4, 5, 8, 13, 64, 276, 277, 561, 900, 901] {
            for _ in 0..4 {
                fill(&mut a[..len], &mut state);
                fill(&mut b[..len], &mut state);

                expected[..2 * len].fill(0);
                stack[..8 * len].fill(0);
                karatsuba(
                    &mut expected[..2 * len],
                    &a[..len],
                    &b[..len],
                    len,
                    &mut stack[..8 * len],
                );

                a1[..len].copy_from_slice(&a[..len]);
                b1[..len].copy_from_slice(&b[..len]);
                got[..2 * len].fill(0);
                acc_nicstr::karatsuba_acc(&mut got[..2 * len], &mut a1[..len], &mut b1[..len]);
                assert_eq!(&got[..2 * len], &expected[..2 * len], "len {len}");
                assert_eq!(&a1[..len], &a[..len], "must restore a, len {len}");
                assert_eq!(&b1[..len], &b[..len], "must restore b, len {len}");
            }
        }
    }

    /// Accumulation semantics: with nonzero initial c, result is c ^ a*b.
    #[test]
    fn accumulation_xors_into_existing_content() {
        let mut state = 0xDEAD_BEEF_CAFE_F00Du64;
        const LEN: usize = 277;
        let mut a = [0u64; LEN];
        let mut b = [0u64; LEN];
        let mut init = [0u64; 2 * LEN];
        fill(&mut a, &mut state);
        fill(&mut b, &mut state);
        fill(&mut init, &mut state);

        let mut product = [0u64; 2 * LEN];
        let mut stack = [0u64; 8 * LEN];
        karatsuba(&mut product, &a, &b, LEN, &mut stack);
        let mut expected = [0u64; 2 * LEN];
        for i in 0..2 * LEN {
            expected[i] = init[i] ^ product[i];
        }

        let mut a1 = a;
        let mut b1 = b;
        let mut c = init;
        acc_nicstr::karatsuba_acc(&mut c, &mut a1, &mut b1);
        assert_eq!(c, expected, "accumulation must XOR into existing content");
    }
}
