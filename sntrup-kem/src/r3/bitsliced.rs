//! Bitsliced constant-time R/3 inversion (Bernstein–Yang divstep), ported from
//! the SUPERCOP AVX2 `crypto_core_inv3sntrup761` and generalized over all six
//! parameter sets.
//!
//! Ternary coefficients are stored as two bitplanes — plane 0 is the nonzero
//! bit, plane 1 the negative bit: `0 → (0,0)`, `1 → (1,0)`, `-1 → (1,1)` — with
//! 256 coefficients per `__m256i`, so a whole polynomial is `numvec =
//! ceil((p+1)/256)` registers per plane. Within a register, coefficient `j`
//! lives at bit `(j % 256) / 4` of 64-bit word `j % 4`: that interleaving makes
//! the shift-by-one-coefficient (`divx`/`timesx`) a 64-bit-word rotation plus a
//! single scalar shift, instead of a cross-register bit shift.
//!
//! The divstep loop eliminates the constant term (inputs are reversed) with
//! pure boolean operations — no multiplies anywhere. The reference hand-unrolls
//! five phases with fixed register counts; here the two register-width
//! schedules are computed per iteration from public data only, which is what
//! the phases encode: the V/R side grows one coefficient per iteration
//! (`min(numvec, k/256 + 1)`) and the F/G side shrinks with the remaining
//! iteration count (`ceil((2p - 1 - k)/256)`, the divstep degree-sum
//! invariant). Both formulas reproduce the reference's phase boundaries for
//! p = 761 exactly.
#![allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use crate::wipe::wipe;
use core::arch::x86_64::*;

const NUMVEC_MAX: usize = 5; // ceil((1277 + 1) / 256)

#[inline]
fn numvec(p: usize) -> usize {
    (p + 1).div_ceil(256)
}

/// Bit-transpose 256 bytes (values 0/1) into one register, in the interleaved
/// coefficient order described in the module docs.
#[target_feature(enable = "avx2")]
fn frombits(b: &[i8]) -> __m256i {
    unsafe {
        const TRANSPOSE: [i8; 32] = [
            0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 16, 20, 24, 28, 17, 21, 25, 29,
            18, 22, 26, 30, 19, 23, 27, 31,
        ];

        let ld = |k: usize| _mm256_loadu_si256(b.as_ptr().add(32 * k) as *const __m256i);
        let (b0, b1, b2, b3) = (ld(0), ld(1), ld(2), ld(3));
        let (b4, b5, b6, b7) = (ld(4), ld(5), ld(6), ld(7));

        let c0 = _mm256_unpacklo_epi32(b0, b1);
        let c1 = _mm256_unpackhi_epi32(b0, b1);
        let c2 = _mm256_unpacklo_epi32(b2, b3);
        let c3 = _mm256_unpackhi_epi32(b2, b3);
        let c4 = _mm256_unpacklo_epi32(b4, b5);
        let c5 = _mm256_unpackhi_epi32(b4, b5);
        let c6 = _mm256_unpacklo_epi32(b6, b7);
        let c7 = _mm256_unpackhi_epi32(b6, b7);

        let d0 = _mm256_or_si256(c0, _mm256_slli_epi32(c1, 2));
        let d2 = _mm256_or_si256(c2, _mm256_slli_epi32(c3, 2));
        let d4 = _mm256_or_si256(c4, _mm256_slli_epi32(c5, 2));
        let d6 = _mm256_or_si256(c6, _mm256_slli_epi32(c7, 2));

        let e0 = _mm256_unpacklo_epi64(d0, d2);
        let e2 = _mm256_unpackhi_epi64(d0, d2);
        let e4 = _mm256_unpacklo_epi64(d4, d6);
        let e6 = _mm256_unpackhi_epi64(d4, d6);

        let f0 = _mm256_or_si256(e0, _mm256_slli_epi32(e2, 1));
        let f4 = _mm256_or_si256(e4, _mm256_slli_epi32(e6, 1));

        let g0 = _mm256_permute2x128_si256::<0x20>(f0, f4);
        let g4 = _mm256_permute2x128_si256::<0x31>(f0, f4);

        let h = _mm256_or_si256(g0, _mm256_slli_epi32(g4, 4));
        let h = _mm256_shuffle_epi8(h, _mm256_loadu_si256(TRANSPOSE.as_ptr() as *const __m256i));
        let h = _mm256_permute4x64_epi64::<0xd8>(h);
        _mm256_shuffle_epi32::<0xd8>(h)
    }
}

/// Inverse of [`frombits`]: one register back to 256 bytes of 0/1.
#[target_feature(enable = "avx2")]
fn tobits(h: __m256i, b: &mut [i8]) {
    unsafe {
        const TRANSPOSE: [i8; 32] = [
            0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 16, 20, 24, 28, 17, 21, 25, 29,
            18, 22, 26, 30, 19, 23, 27, 31,
        ];

        let h = _mm256_shuffle_epi32::<0xd8>(h);
        let h = _mm256_permute4x64_epi64::<0xd8>(h);
        let h = _mm256_shuffle_epi8(h, _mm256_loadu_si256(TRANSPOSE.as_ptr() as *const __m256i));

        let g0 = _mm256_and_si256(h, _mm256_set1_epi8(15));
        let g4 = _mm256_and_si256(_mm256_srli_epi32(h, 4), _mm256_set1_epi8(15));

        let f0 = _mm256_permute2x128_si256::<0x20>(g0, g4);
        let f4 = _mm256_permute2x128_si256::<0x31>(g0, g4);

        let e0 = _mm256_and_si256(f0, _mm256_set1_epi8(5));
        let e2 = _mm256_and_si256(_mm256_srli_epi32(f0, 1), _mm256_set1_epi8(5));
        let e4 = _mm256_and_si256(f4, _mm256_set1_epi8(5));
        let e6 = _mm256_and_si256(_mm256_srli_epi32(f4, 1), _mm256_set1_epi8(5));

        let d0 = _mm256_unpacklo_epi32(e0, e2);
        let d2 = _mm256_unpackhi_epi32(e0, e2);
        let d4 = _mm256_unpacklo_epi32(e4, e6);
        let d6 = _mm256_unpackhi_epi32(e4, e6);

        let one = _mm256_set1_epi8(1);
        let c0 = _mm256_and_si256(d0, one);
        let c1 = _mm256_and_si256(_mm256_srli_epi32(d0, 2), one);
        let c2 = _mm256_and_si256(d2, one);
        let c3 = _mm256_and_si256(_mm256_srli_epi32(d2, 2), one);
        let c4 = _mm256_and_si256(d4, one);
        let c5 = _mm256_and_si256(_mm256_srli_epi32(d4, 2), one);
        let c6 = _mm256_and_si256(d6, one);
        let c7 = _mm256_and_si256(_mm256_srli_epi32(d6, 2), one);

        let st = |k: usize, v: __m256i, b: &mut [i8]| {
            _mm256_storeu_si256(b.as_mut_ptr().add(32 * k) as *mut __m256i, v);
        };
        st(0, _mm256_unpacklo_epi64(c0, c1), b);
        st(1, _mm256_unpackhi_epi64(c0, c1), b);
        st(2, _mm256_unpacklo_epi64(c2, c3), b);
        st(3, _mm256_unpackhi_epi64(c2, c3), b);
        st(4, _mm256_unpacklo_epi64(c4, c5), b);
        st(5, _mm256_unpackhi_epi64(c4, c5), b);
        st(6, _mm256_unpacklo_epi64(c6, c7), b);
        st(7, _mm256_unpackhi_epi64(c6, c7), b);
    }
}

/// Bitplane-encode a ternary polynomial (given as bytes of 0/1 per plane).
#[target_feature(enable = "avx2")]
fn planes_from_small(dst0: &mut [__m256i], dst1: &mut [__m256i], s: &[i8], n: usize) {
    let mut b0 = [0i8; NUMVEC_MAX * 256];
    let mut b1 = [0i8; NUMVEC_MAX * 256];
    for (i, &si) in s.iter().enumerate() {
        b0[i] = si & 1;
        b1[i] = (si >> 1) & b0[i];
    }
    for i in 0..n {
        dst0[i] = frombits(&b0[256 * i..]);
        dst1[i] = frombits(&b1[256 * i..]);
    }
}

#[inline]
fn negative_mask(x: i32) -> i32 {
    x >> 31
}

#[target_feature(enable = "avx2")]
fn swap(f: &mut [__m256i], g: &mut [__m256i], len: usize, mask: __m256i) {
    for i in 0..len {
        let flip = _mm256_and_si256(mask, _mm256_xor_si256(f[i], g[i]));
        f[i] = _mm256_xor_si256(f[i], flip);
        g[i] = _mm256_xor_si256(g[i], flip);
    }
}

/// `g -= c·f` in GF(3) on the bitplane encoding (then the caller divides by x).
#[target_feature(enable = "avx2")]
fn eliminate(
    f0: &[__m256i],
    f1: &[__m256i],
    g0: &mut [__m256i],
    g1: &mut [__m256i],
    len: usize,
    c0: __m256i,
    c1: __m256i,
) {
    for i in 0..len {
        let f0i = _mm256_and_si256(f0[i], c0);
        let f1i = _mm256_and_si256(_mm256_xor_si256(f1[i], c1), f0i);
        let g0i = g0[i];
        let g1i = g1[i];

        let t = _mm256_xor_si256(g0i, f0i);
        g0[i] = _mm256_or_si256(t, _mm256_xor_si256(g1i, f1i));
        g1[i] = _mm256_and_si256(_mm256_xor_si256(g1i, f0i), _mm256_xor_si256(f1i, t));
    }
}

/// Multiply V by the unit `c` (bitplane-broadcast masks), for the final scale.
#[target_feature(enable = "avx2")]
fn scale(f0: &mut [__m256i], f1: &mut [__m256i], n: usize, c0: __m256i, c1: __m256i) {
    for i in 0..n {
        let f0i = _mm256_and_si256(f0[i], c0);
        f0[i] = f0i;
        f1[i] = _mm256_and_si256(_mm256_xor_si256(f1[i], c1), f0i);
    }
}

/// Coefficient 0 (bit 0 of word 0 of register 0) as an all-ones/zero i32 mask.
#[target_feature(enable = "avx2")]
fn bit0mask(f: &[__m256i]) -> i32 {
    -(_mm_cvtsi128_si32(_mm256_castsi256_si128(f[0])) & 1)
}

/// Shift down by one coefficient: rotate each register's 64-bit words and fix
/// word 0 with a scalar shift chained from the next register.
#[target_feature(enable = "avx2")]
fn divx(f: &mut [__m256i], len: usize) {
    let mut lows = [0u64; NUMVEC_MAX];
    for i in 0..len {
        lows[i] = u64::from_ne_bytes(_mm_cvtsi128_si64(_mm256_castsi256_si128(f[i])).to_ne_bytes());
    }
    for i in 0..len {
        let next = if i + 1 < len { lows[i + 1] } else { 0 };
        let low = (lows[i] >> 1) | (next << 63);
        let v = _mm256_blend_epi32::<0x3>(
            f[i],
            _mm256_set_epi64x(0, 0, 0, i64::from_ne_bytes(low.to_ne_bytes())),
        );
        f[i] = _mm256_permute4x64_epi64::<0x39>(v);
    }
}

/// Shift up by one coefficient: inverse rotation, carries flow upward.
#[target_feature(enable = "avx2")]
fn timesx(f: &mut [__m256i], len: usize) {
    let mut rot = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut lows = [0u64; NUMVEC_MAX];
    for i in 0..len {
        rot[i] = _mm256_permute4x64_epi64::<0x93>(f[i]);
        lows[i] =
            u64::from_ne_bytes(_mm_cvtsi128_si64(_mm256_castsi256_si128(rot[i])).to_ne_bytes());
    }
    for i in (0..len).rev() {
        let prev = if i > 0 { lows[i - 1] } else { 0 };
        let low = (lows[i] << 1) | (prev >> 63);
        f[i] = _mm256_blend_epi32::<0x3>(
            rot[i],
            _mm256_set_epi64x(0, 0, 0, i64::from_ne_bytes(low.to_ne_bytes())),
        );
    }
}

/// Constant-time reciprocal in R/3 via bitsliced divstep.
///
/// Returns `(mask, r)` with the same contract as the elimination form: `mask ==
/// 0` iff `s` is invertible, and `r` the reciprocal (valid when invertible).
#[target_feature(enable = "avx2")]
pub fn reciprocal_divstep(s: &[i8], p: usize) -> (isize, Vec<i8>) {
    let n = numvec(p);
    let total = 2 * p - 1;

    let mut f0 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut f1 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut g0 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut g1 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut v0 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut v1 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut r0 = [_mm256_setzero_si256(); NUMVEC_MAX];
    let mut r1 = [_mm256_setzero_si256(); NUMVEC_MAX];

    // f = reversal of x^p - x - 1: coefficients 1 at 0, -1 at p-1, -1 at p.
    let mut fs = [0i8; NUMVEC_MAX * 256];
    fs[0] = 1;
    fs[p - 1] = -1;
    fs[p] = -1;
    planes_from_small(&mut f0, &mut f1, &fs[..n * 256], n);

    // g = reversal of s.
    let mut gs = [0i8; NUMVEC_MAX * 256];
    for i in 0..p {
        gs[i] = s[p - 1 - i];
    }
    planes_from_small(&mut g0, &mut g1, &gs[..n * 256], n);

    // r = 1; v = 0.
    r0[0] = _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 1);

    let mut minusdelta: i32 = -1;

    for k in 0..total {
        // Public width schedules (see module docs): V grows one coefficient
        // per iteration; G's bit-length is bounded by the remaining
        // iteration count (divstep degree-sum invariant).
        let vw = n.min(k / 256 + 1);
        let fw = n.min((total - k).div_ceil(256));

        timesx(&mut v0, vw);
        timesx(&mut v1, vw);

        let swapmask = negative_mask(minusdelta) & bit0mask(&g0);
        let c0 = bit0mask(&f0) & bit0mask(&g0);
        let c1 = (bit0mask(&f1) ^ bit0mask(&g1)) & c0;

        minusdelta ^= swapmask & (minusdelta ^ -minusdelta);
        minusdelta -= 1;

        let swapvec = _mm256_set1_epi32(swapmask);
        swap(&mut f0, &mut g0, fw, swapvec);
        swap(&mut f1, &mut g1, fw, swapvec);

        let c0v = _mm256_set1_epi32(c0);
        let c1v = _mm256_set1_epi32(c1);
        eliminate(&f0, &f1, &mut g0, &mut g1, fw, c0v, c1v);
        divx(&mut g0, fw);
        divx(&mut g1, fw);

        swap(&mut v0, &mut r0, vw, swapvec);
        swap(&mut v1, &mut r1, vw, swapvec);
        eliminate(&v0, &v1, &mut r0, &mut r1, vw, c0v, c1v);
    }

    // Scale V by the unit f0 and unpack, reversing back.
    let c0v = _mm256_set1_epi32(bit0mask(&f0));
    let c1v = _mm256_set1_epi32(bit0mask(&f1));
    scale(&mut v0, &mut v1, n, c0v, c1v);

    let mut b0 = [0i8; NUMVEC_MAX * 256];
    let mut b1 = [0i8; NUMVEC_MAX * 256];
    for i in 0..n {
        tobits(v0[i], &mut b0[256 * i..]);
        tobits(v1[i], &mut b1[256 * i..]);
    }
    let mut out = vec![0i8; p];
    for (i, o) in out.iter_mut().enumerate() {
        let (x0, x1) = (b0[p - 1 - i], b1[p - 1 - i]);
        *o = x0 + 2 * x1 - 4 * (x0 & x1);
    }

    // Everything above is derived from the secret input. The unpacked byte planes
    // and the input scratch zeroize directly; the bitplane registers are wiped
    // through their raw bytes, since `__m256i` has no `Zeroize` impl.
    wipe(&mut b0);
    wipe(&mut b1);
    wipe(&mut fs);
    wipe(&mut gs);
    for regs in [
        f0.as_mut_ptr(),
        f1.as_mut_ptr(),
        g0.as_mut_ptr(),
        g1.as_mut_ptr(),
        v0.as_mut_ptr(),
        v1.as_mut_ptr(),
        r0.as_mut_ptr(),
        r1.as_mut_ptr(),
    ] {
        // SAFETY: each array is NUMVEC_MAX `__m256i` values on this frame, so
        // reinterpreting it as u64 words is in-bounds and correctly aligned
        // (`__m256i` is 32-byte aligned, and its size is a multiple of 8).
        unsafe {
            wipe(core::slice::from_raw_parts_mut(
                regs.cast::<u64>(),
                NUMVEC_MAX * size_of::<__m256i>() / 8,
            ));
        }
    }

    (negative_mask(minusdelta) as isize, out)
}
