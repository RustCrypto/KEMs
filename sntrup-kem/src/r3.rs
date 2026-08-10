#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
mod bitsliced;
pub mod mod3;
mod vector;

use crate::ct::{smaller_mask, swap_int};
use crate::wipe::wipe;

/// Reciprocal in R/3, dispatched: bitsliced divstep on x86_64/AVX2, the
/// elimination form elsewhere. Same `(mask, r)` contract on both paths.
#[allow(unsafe_code)]
pub fn reciprocal(s: &[i8], p: usize) -> (isize, Vec<i8>) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return bitsliced::reciprocal_divstep(s, p);
        }
    }
    #[allow(unreachable_code)]
    reciprocal_eliminate(s, p)
}

/// Top-coefficient elimination form: the non-x86/force-scalar path and the
/// differential oracle for the bitsliced divstep port.
#[allow(clippy::cast_possible_wrap)]
fn reciprocal_eliminate(s: &[i8], p: usize) -> (isize, Vec<i8>) {
    let loops = 2 * p + 1;

    // Buffers are padded to a multiple of the widest SIMD block (32 i8 lanes) so the
    // vector kernels never fall into their scalar tail loops inside the hot iteration.
    // Padding lanes start at zero; in u/v they provably stay zero (their source lanes
    // are zero too), and in f/g anything written above index p only ever propagates
    // upward — index p and below, the only entries ever read, are untouched by it.
    let pad = |len: usize| (len + 31) & !31;

    let mut r = vec![0i8; p];
    let mut f = vec![0i8; pad(p + 1)];
    f[0] = -1;
    f[1] = -1;
    f[p] = 1;

    let mut g = vec![0i8; pad(p + 1)];
    g[..p].copy_from_slice(&s[..p]);
    let fg_len = f.len();
    let mut d = p as isize;
    let mut e = p as isize;
    let mut u = vec![0i8; pad(loops + 1)];
    let mut v = vec![0i8; pad(loops + 1)];
    let uv_cap = u.len();
    v[0] = 1;

    for i in 0..loops {
        let c = mod3::quotient(g[p], f[p]);
        // The swap mask needs the *post-shift* leading coefficient, so compute that
        // single element scalar-first: new g[p] = freeze(g[p-1] - f[p-1]·c). This
        // lets the shift and the conditional swap run as one fused memory pass.
        let new_gp = mod3::minus_product(g[p - 1], f[p - 1], c);
        e -= 1;
        let m = smaller_mask(e, d) & mod3::mask_set(new_gp);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        // After iteration i, the support of u and v is confined to indices 0..=i+1
        // (v starts as {0}, each shift grows it by one, and swaps only exchange the
        // two): entries past that window are zero and stay zero, so processing
        // `i + 2` elements computes exactly what the full-length pass would. The
        // bound depends only on the public loop counter, never on secret data, so
        // the constant-time property is unchanged.
        let uv_len = pad(i + 2).min(uv_cap);
        vector::minus_product_shift_cswap(&mut g, &mut f, fg_len, c, m);
        vector::minus_product_shift_cswap(&mut v, &mut u, uv_len, c, m);
    }

    vector::product(&mut r, p, &u[p..], mod3::reciprocal(f[p]));
    // The Euclidean state is derived from the secret input — wipe it before returning.
    wipe(&mut f);
    wipe(&mut g);
    wipe(&mut u);
    wipe(&mut v);
    (smaller_mask(0, d), r)
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    {
        // Same NTT machine as rq::mult, single-prime (product coefficients are
        // bounded by p, far inside 7681/2). p = 761 only — see rq::ntt.
        if p == 761 && crate::cpu::has_avx2() {
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe {
                return crate::rq::ntt::mult3_761(h, f, g);
            }
        }
        if crate::cpu::has_avxvnni() {
            // SAFETY: AVX2 + AVX-VNNI support confirmed by has_avxvnni()
            unsafe {
                return mult_avxvnni(h, f, g, p);
            }
        }
        if crate::cpu::has_avx2() {
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe {
                return mult_avx2(h, f, g, p);
            }
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return mult_neon(h, f, g, p);
    }
    #[allow(unreachable_code)]
    mult_scalar(h, f, g, p);
}

fn mult_scalar(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    let mut fg = vec![0i8; p * 2 - 1];
    for i in 0..p {
        let mut r = 0i32;
        for j in 0..=i {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = mod3::freeze(r);
    }
    for i in p..(p * 2 - 1) {
        let mut r = 0i32;
        for j in (i - p + 1)..p {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = mod3::freeze(r);
    }
    for i in (p..(p * 2) - 1).rev() {
        fg[i - p] = mod3::freeze(fg[i - p] as i32 + fg[i] as i32);
        fg[i - p + 1] = mod3::freeze(fg[i - p + 1] as i32 + fg[i] as i32);
    }
    h[..p].copy_from_slice(&fg[..p]);
    // At least one operand is secret at every call site — wipe the product scratch.
    wipe(&mut fg);
}

/// Row-major schoolbook multiplication for R3 polynomials on x86_64, expanded once per
/// instruction level by the macro below (`mult_avx2` via [`crate::simd::mac_madd`],
/// `mult_avxvnni` via the fused [`crate::simd::mac_vnni`]).
///
/// Same structure as `rq::mult`'s AVX2 kernel (see its doc comment): contiguous dot products
/// over widened copies of `f` and a reversed `g`, four independent `_mm256_madd_epi16`
/// accumulators (16 multiply-accumulates per instruction), one write per output coefficient,
/// and a single mod-3 freeze per output during the `x^p ≡ x + 1` fold (|folded sum| ≤ 3p,
/// well inside `mod3::freeze`'s i32 domain).
macro_rules! r3_mult_x86_kernel {
    ($name:ident, $features:literal, $mac:path) => {
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        #[target_feature(enable = $features)]
        #[allow(
            unsafe_code,
            clippy::cast_possible_truncation,
            clippy::needless_range_loop
        )]
        unsafe fn $name(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
            unsafe {
                use core::arch::x86_64::*;

                let fg_len = p * 2 - 1;

                let mut f16 = vec![0i16; p];
                let mut g_rev = vec![0i16; p];
                for i in 0..p {
                    f16[i] = f[i] as i16;
                    g_rev[i] = g[p - 1 - i] as i16;
                }

                // Raw i16 row sums (|sum| ≤ p ≤ 1277), padded with one zero so the fold below may
                // read `fg[k + p]` unconditionally at `k = p - 1`.
                let mut fg = vec![0i16; fg_len + 1];
                for (i, out) in fg[..fg_len].iter_mut().enumerate() {
                    let jlo = i.saturating_sub(p - 1);
                    let len = i.min(p - 1) - jlo + 1;
                    let fp = f16.as_ptr().add(jlo);
                    // `p - 1 + jlo` never drops below `i` (jlo = max(0, i-p+1)); the naive
                    // `p - 1 - i + jlo` ordering underflows in debug builds when i ≥ p.
                    let gp = g_rev.as_ptr().add(p - 1 + jlo - i);

                    let mut acc0 = _mm256_setzero_si256();
                    let mut acc1 = _mm256_setzero_si256();
                    let mut acc2 = _mm256_setzero_si256();
                    let mut acc3 = _mm256_setzero_si256();
                    let mut k = 0usize;
                    while k + 64 <= len {
                        acc0 = $mac(
                            acc0,
                            _mm256_loadu_si256(fp.add(k) as *const __m256i),
                            _mm256_loadu_si256(gp.add(k) as *const __m256i),
                        );
                        acc1 = $mac(
                            acc1,
                            _mm256_loadu_si256(fp.add(k + 16) as *const __m256i),
                            _mm256_loadu_si256(gp.add(k + 16) as *const __m256i),
                        );
                        acc2 = $mac(
                            acc2,
                            _mm256_loadu_si256(fp.add(k + 32) as *const __m256i),
                            _mm256_loadu_si256(gp.add(k + 32) as *const __m256i),
                        );
                        acc3 = $mac(
                            acc3,
                            _mm256_loadu_si256(fp.add(k + 48) as *const __m256i),
                            _mm256_loadu_si256(gp.add(k + 48) as *const __m256i),
                        );
                        k += 64;
                    }
                    while k + 16 <= len {
                        acc0 = $mac(
                            acc0,
                            _mm256_loadu_si256(fp.add(k) as *const __m256i),
                            _mm256_loadu_si256(gp.add(k) as *const __m256i),
                        );
                        k += 16;
                    }
                    let s = _mm256_add_epi32(
                        _mm256_add_epi32(acc0, acc1),
                        _mm256_add_epi32(acc2, acc3),
                    );
                    let s4 =
                        _mm_add_epi32(_mm256_castsi256_si128(s), _mm256_extracti128_si256(s, 1));
                    let s2 = _mm_add_epi32(s4, _mm_shuffle_epi32(s4, 0b0000_1110));
                    let s1 = _mm_add_epi32(s2, _mm_shuffle_epi32(s2, 0b0000_0001));
                    let mut sum = _mm_cvtsi128_si32(s1);
                    while k < len {
                        sum += *fp.add(k) as i32 * *gp.add(k) as i32;
                        k += 1;
                    }
                    *out = sum as i16;
                }

                // Fold x^p ≡ x + 1 with a single mod-3 freeze per output coefficient: fg[i] (i ≥ p)
                // contributes to outputs i-p and i-p+1, and no fold target is itself ≥ p, so every
                // output is independent.
                h[0] = mod3::freeze(i32::from(fg[0]) + i32::from(fg[p]));
                for k in 1..p {
                    h[k] = mod3::freeze(
                        i32::from(fg[k]) + i32::from(fg[k + p]) + i32::from(fg[k + p - 1]),
                    );
                }
            }
        }
    };
}

r3_mult_x86_kernel!(mult_avx2, "avx2", crate::simd::mac_madd);
r3_mult_x86_kernel!(mult_avxvnni, "avx2,avxvnni", crate::simd::mac_vnni);

/// Row-major schoolbook multiplication with NEON for R3 polynomials.
///
/// Same structure as `rq::mult`'s NEON kernel (see its doc comment for the reasoning): each
/// output coefficient's convolution sum is a contiguous dot product over `f` and a pre-reversed
/// `g`, held across EIGHT independent widening accumulators so the multiply-accumulate
/// latency is hidden, and written to memory once. Here the operands are ternary i8, so
/// `vmlal_s8`/`vmlal_high_s8` (i8×i8→i16, 8 lanes per instruction) process 64 elements per
/// unrolled iteration, and the i16 accumulator lanes stay far from overflow (each lane absorbs
/// at most `p/8` unit products; the final cross-lane sum is bounded by `p ≤ 1277`).
///
/// The `x^p ≡ x + 1` fold then adds three raw row sums (|sum| ≤ 3p = 3831, well inside
/// `mod3::freeze`'s i32 domain) with a single freeze per output coefficient, instead of the
/// reference's three.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    unsafe {
        use core::arch::aarch64::*;

        let fg_len = p * 2 - 1;

        let mut g_rev = vec![0i8; p];
        for i in 0..p {
            g_rev[i] = g[p - 1 - i];
        }

        // Raw i16 row sums, padded with one zero so the fold below may read `fg[k + p]`
        // unconditionally at `k = p - 1`.
        let mut fg = vec![0i16; fg_len + 1];
        for (i, out) in fg[..fg_len].iter_mut().enumerate() {
            let jlo = i.saturating_sub(p - 1);
            let len = i.min(p - 1) - jlo + 1;
            let fp = f.as_ptr().add(jlo);
            // `p - 1 + jlo` never drops below `i` (jlo = max(0, i-p+1)); the naive
            // `p - 1 - i + jlo` ordering underflows in debug builds when i ≥ p.
            let gp = g_rev.as_ptr().add(p - 1 + jlo - i);

            let mut acc0 = vdupq_n_s16(0);
            let mut acc1 = vdupq_n_s16(0);
            let mut acc2 = vdupq_n_s16(0);
            let mut acc3 = vdupq_n_s16(0);
            let mut acc4 = vdupq_n_s16(0);
            let mut acc5 = vdupq_n_s16(0);
            let mut acc6 = vdupq_n_s16(0);
            let mut acc7 = vdupq_n_s16(0);
            let mut k = 0usize;
            while k + 64 <= len {
                let f0 = vld1q_s8(fp.add(k));
                let f1 = vld1q_s8(fp.add(k + 16));
                let f2 = vld1q_s8(fp.add(k + 32));
                let f3 = vld1q_s8(fp.add(k + 48));
                let g0 = vld1q_s8(gp.add(k));
                let g1 = vld1q_s8(gp.add(k + 16));
                let g2 = vld1q_s8(gp.add(k + 32));
                let g3 = vld1q_s8(gp.add(k + 48));
                acc0 = vmlal_s8(acc0, vget_low_s8(f0), vget_low_s8(g0));
                acc1 = vmlal_high_s8(acc1, f0, g0);
                acc2 = vmlal_s8(acc2, vget_low_s8(f1), vget_low_s8(g1));
                acc3 = vmlal_high_s8(acc3, f1, g1);
                acc4 = vmlal_s8(acc4, vget_low_s8(f2), vget_low_s8(g2));
                acc5 = vmlal_high_s8(acc5, f2, g2);
                acc6 = vmlal_s8(acc6, vget_low_s8(f3), vget_low_s8(g3));
                acc7 = vmlal_high_s8(acc7, f3, g3);
                k += 64;
            }
            while k + 16 <= len {
                let f0 = vld1q_s8(fp.add(k));
                let g0 = vld1q_s8(gp.add(k));
                acc0 = vmlal_s8(acc0, vget_low_s8(f0), vget_low_s8(g0));
                acc1 = vmlal_high_s8(acc1, f0, g0);
                k += 16;
            }
            let total = vaddq_s16(
                vaddq_s16(vaddq_s16(acc0, acc1), vaddq_s16(acc2, acc3)),
                vaddq_s16(vaddq_s16(acc4, acc5), vaddq_s16(acc6, acc7)),
            );
            let mut sum = i32::from(vaddvq_s16(total));
            while k < len {
                sum += i32::from(*fp.add(k)) * i32::from(*gp.add(k));
                k += 1;
            }
            *out = sum as i16;
        }

        // Fold x^p ≡ x + 1 with a single mod-3 freeze per output coefficient: fg[i] (i ≥ p)
        // contributes to outputs i-p and i-p+1, and no fold target is itself ≥ p, so every
        // output is independent.
        h[0] = mod3::freeze(i32::from(fg[0]) + i32::from(fg[p]));
        for k in 1..p {
            h[k] = mod3::freeze(i32::from(fg[k]) + i32::from(fg[k + p]) + i32::from(fg[k + p - 1]));
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {

    /// The NTT mod-3 multiply must agree with the schoolbook kernel exactly.
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    #[test]
    fn ntt_mult3_matches_scalar() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let p = 761usize;
        let mut state = 0xabcd_ef01_2345_6789u64 | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for trial in 0..8 {
            let f: Vec<i8> = (0..p).map(|_| ((next() % 3) as i8) - 1).collect();
            let g: Vec<i8> = (0..p).map(|_| ((next() % 3) as i8) - 1).collect();
            let mut want = vec![0i8; p];
            mult_scalar(&mut want, &f, &g, p);
            let mut got = vec![0i8; p];
            // SAFETY: AVX2 confirmed above.
            unsafe { crate::rq::ntt::mult3_761(&mut got, &f, &g) };
            assert_eq!(got, want, "ntt mult3 vs scalar: trial={trial}");
        }
        // Extremes: all +1 and all -1.
        for &(fv, gv) in &[(1i8, 1i8), (-1, 1), (1, -1), (-1, -1)] {
            let f = vec![fv; p];
            let g = vec![gv; p];
            let mut want = vec![0i8; p];
            mult_scalar(&mut want, &f, &g, p);
            let mut got = vec![0i8; p];
            unsafe { crate::rq::ntt::mult3_761(&mut got, &f, &g) };
            assert_eq!(got, want, "ntt mult3 extremes f={fv} g={gv}");
        }
    }

    /// The bitsliced divstep port must agree with the elimination oracle on
    /// both the invertibility mask and (when invertible) the reciprocal vector,
    /// for every parameter size — including non-invertible inputs.
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    #[test]
    fn bitsliced_reciprocal_matches_eliminate() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let mut state = 0x5eed_5eed_5eed_5eedu64 | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for &p in &[653usize, 761, 857, 953, 1013, 1277] {
            let mut invertible_seen = false;
            let mut singular_seen = false;
            for trial in 0..12 {
                let g: Vec<i8> = (0..p).map(|_| ((next() % 3) as i8) - 1).collect();
                let (want_mask, want) = reciprocal_eliminate(&g, p);
                // SAFETY: AVX2 confirmed above.
                let (got_mask, got) = unsafe { bitsliced::reciprocal_divstep(&g, p) };
                assert_eq!(got_mask, want_mask, "mask p={p} trial={trial}");
                if want_mask == 0 {
                    invertible_seen = true;
                    assert_eq!(got, want, "value p={p} trial={trial}");
                } else {
                    singular_seen = true;
                }
            }
            // g = 0 is always singular.
            let zero = vec![0i8; p];
            let (want_mask, _) = reciprocal_eliminate(&zero, p);
            let (got_mask, _) = unsafe { bitsliced::reciprocal_divstep(&zero, p) };
            assert_ne!(want_mask, 0, "zero must be singular p={p}");
            assert_eq!(got_mask, want_mask, "zero mask p={p}");
            assert!(invertible_seen, "no invertible sample hit for p={p}");
            let _ = singular_seen;
        }
    }
    use super::*;

    /// Deterministic xorshift64* so the test needs no RNG crates or features.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn random_ternary(p: usize, seed: u64) -> Vec<i8> {
        let mut s = seed | 1;
        (0..p).map(|_| ((next(&mut s) % 3) as i8) - 1).collect()
    }

    /// Compare every compiled-in SIMD kernel against the scalar reference. Catches the class
    /// of bug the KAT/roundtrip suite can miss when run with `--all-features`, which enables
    /// `force-scalar` and silently compiles the SIMD kernels out of the test entirely.
    fn check_case(p: usize, f: &[i8], g: &[i8], label: &str) {
        let mut want = vec![0i8; p];
        mult_scalar(&mut want, f, g, p);

        #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
        {
            let mut got = vec![0i8; p];
            // SAFETY: NEON is baseline on aarch64
            unsafe { mult_neon(&mut got, f, g, p) };
            assert_eq!(got, want, "r3 mult_neon vs scalar: {label} p={p}");
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            let mut got = vec![0i8; p];
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe { mult_avx2(&mut got, f, g, p) };
            assert_eq!(got, want, "r3 mult_avx2 vs scalar: {label} p={p}");
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avxvnni() {
            let mut got = vec![0i8; p];
            // SAFETY: AVX2 + AVX-VNNI support confirmed by has_avxvnni()
            unsafe { mult_avxvnni(&mut got, f, g, p) };
            assert_eq!(got, want, "r3 mult_avxvnni vs scalar: {label} p={p}");
        }

        let mut got = vec![0i8; p];
        mult(&mut got, f, g, p);
        assert_eq!(got, want, "dispatched r3 mult vs scalar: {label} p={p}");
    }

    #[test]
    fn simd_mult_matches_scalar_random() {
        for p in [653usize, 761, 857, 953, 1013, 1277] {
            for seed in 1..=8u64 {
                let f = random_ternary(p, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let g = random_ternary(p, seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
                check_case(p, &f, &g, "random");
            }
        }
    }

    /// All-ones operands maximize accumulator magnitude, probing the i16 headroom the NEON
    /// widening-accumulate staging depends on.
    #[test]
    fn simd_mult_extremes_match_scalar() {
        for p in [653usize, 761, 857, 953, 1013, 1277] {
            let ones = vec![1i8; p];
            let neg = vec![-1i8; p];
            check_case(p, &ones, &ones, "all +1");
            check_case(p, &ones, &neg, "+1 × -1");
        }
    }
}
