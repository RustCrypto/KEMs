#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
pub mod codec761;
pub mod encoding;
pub mod modq;
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
pub(crate) mod ntt;
mod vector;

use crate::ct::{smaller_mask, swap_int};
use crate::params::SntrupParameters;
use crate::wipe::wipe;

/// Reciprocal of `3·s` in R/q, dispatched: divstep on x86_64/AVX2, the
/// top-coefficient-elimination form elsewhere. Both produce identical canonical
/// output (differentially tested).
pub fn reciprocal3(s: &[i8], params: &SntrupParameters) -> Vec<i16> {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        return reciprocal3_divstep(s, params);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    return reciprocal3_divstep(s, params);
    #[allow(unreachable_code)]
    reciprocal3_eliminate(s, params)
}

/// Constant-time divstep inversion (Bernstein–Yang, ported from the SUPERCOP
/// AVX2 `crypto_core_invsntrup761`, generalized over all six parameter sets).
///
/// The polynomials are processed *reversed*, so eliminating the leading
/// coefficient of the original becomes eliminating the constant term, and the
/// divstep `/x` is a shift-down. Each iteration eliminates via the cross-multiply
/// `g' = (f0·g − g0·f)/x` — two Montgomery products per element and **no
/// division anywhere in the loop** (the old form pays a ~20-freeze Fermat
/// quotient chain per iteration). The second loop's f/g window shrinks by one
/// per iteration on a public schedule. Montgomery 2⁻¹⁶ factors cancel in the
/// output because each divstep scales a complete row of the transition matrix,
/// and the result is the ratio `v/f0` of same-row entries (times the 1/3 folded
/// into r's initialization).
///
/// The swap decision uses `delta` and the strictly-frozen `g0`: masks only,
/// applied through blends — no secret-dependent branch, index, or bound.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(feature = "force-scalar")
))]
#[allow(clippy::cast_possible_truncation)]
fn reciprocal3_divstep(s: &[i8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;
    // The widest pass is 32 lanes, and `x[1..]` may be touched up to
    // `x[1 ..= ceil32(len)]`. Padding to the widest kernel costs the narrower
    // ones nothing: the extra lanes stay zero, and zero is a fixed point of the
    // elimination step, so they neither affect nor are affected by the result.
    let ppad = 1 + p.next_multiple_of(32);

    /// -1 if x != 0 (x canonical), else 0.
    fn nonzero_mask(x: i16) -> i32 {
        let v = u32::from(u16::from_ne_bytes(x.to_ne_bytes()));
        -i32::from_ne_bytes(((!v).wrapping_add(1) >> 31).to_ne_bytes())
    }
    /// -1 if x < 0, else 0.
    fn negative_mask(x: i32) -> i32 {
        x >> 31
    }

    let mut f = vec![0i16; ppad];
    f[0] = 1;
    f[p - 1] = -1;
    f[p] = -1;
    // g = reversal of s (the reversal makes the divstep shift go downward).
    let mut g = vec![0i16; ppad];
    for i in 0..p {
        g[i] = i16::from(s[p - 1 - i]);
    }
    let mut v = vec![0i16; ppad];
    let mut r = vec![0i16; ppad];
    // Folds the "3" of 1/(3s) into the Bezout side.
    r[0] = modq::reciprocal(3, q, b1, b2);

    let mut delta: i32 = 1;

    let step = |f: &mut Vec<i16>,
                g: &mut Vec<i16>,
                v: &mut Vec<i16>,
                r: &mut Vec<i16>,
                delta: &mut i32,
                fg_len: usize,
                vr_len: usize| {
        let g0 = modq::freeze(i32::from(g[0]), q, b1, b2);
        let f0 = modq::freeze(i32::from(f[0]), q, b1, b2);

        let swap = negative_mask(-*delta) & nonzero_mask(g0);
        *delta ^= swap & (*delta ^ -*delta);
        *delta += 1;

        let flip = (swap as i16) & (f0 ^ g0);
        let f0 = f0 ^ flip;
        let g0 = g0 ^ flip;
        f[0] = f0;

        let mask = swap as isize;
        // Buffers provide the capacity the widest kernel requires; the
        // dispatchers pick the AVX-512, AVX2 or NEON implementation.
        vector::swapeliminate(f, g, fg_len, f0, g0, mask, q);
        vector::xswapeliminate(v, r, vr_len, f0, g0, mask, q);
    };

    for loop_i in 0..p {
        step(&mut f, &mut g, &mut v, &mut r, &mut delta, p, loop_i + 1);
    }
    for loop_i in (1..p).rev() {
        step(&mut f, &mut g, &mut v, &mut r, &mut delta, loop_i, p);
    }

    let scale = modq::reciprocal(modq::freeze(i32::from(f[0]), q, b1, b2), q, b1, b2);
    let mut out = vec![0i16; p];
    for (i, o) in out.iter_mut().enumerate() {
        let vi = modq::freeze(i32::from(v[p - i]), q, b1, b2);
        *o = modq::product(scale, vi, q, b1, b2);
    }
    // The divstep state is derived from the secret input — wipe it before returning.
    wipe(&mut f);
    wipe(&mut g);
    wipe(&mut v);
    wipe(&mut r);
    out
}

/// Top-coefficient elimination form (the pre-divstep algorithm): the non-x86
/// and force-scalar path, and the differential oracle for the divstep port.
#[allow(clippy::cast_possible_wrap)]
fn reciprocal3_eliminate(s: &[i8], params: &SntrupParameters) -> Vec<i16> {
    let p = params.p;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;
    let loops = 2 * p + 1;

    // Buffers are padded to a multiple of this path's SIMD block (16 i16 lanes) so the
    // vector kernels never fall into their scalar tail loops inside the hot iteration.
    // Padding lanes start at zero; in u/v they provably stay zero (their source lanes
    // are zero too), and in f/g anything written above index p only ever propagates
    // upward — index p and below, the only entries ever read, are untouched by it.
    let pad = |len: usize| (len + 15) & !15;

    let mut r = vec![0i16; p];
    let mut f = vec![0i16; pad(p + 1)];
    f[0] = -1;
    f[1] = -1;
    f[p] = 1;
    let mut g = vec![0i16; pad(p + 1)];
    for i in 0..p {
        g[i] = (3 * s[i]) as i16;
    }
    let fg_len = f.len();
    let mut d = p as isize;
    let mut e = p as isize;
    let mut u = vec![0i16; pad(loops + 1)];
    let mut v = vec![0i16; pad(loops + 1)];
    let uv_cap = u.len();
    v[0] = 1;

    for i in 0..loops {
        let c = modq::quotient(g[p], f[p], q, b1, b2);
        // The swap mask needs the *post-shift* leading coefficient, so compute that
        // single element scalar-first: new g[p] = freeze(g[p-1] - f[p-1]·c). This
        // lets the shift and the conditional swap run as one fused memory pass.
        let new_gp = modq::minus_product(g[p - 1], f[p - 1], c, q, b1, b2);
        e -= 1;
        let m = smaller_mask(e, d) & modq::mask_set(new_gp);
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
        vector::minus_product_shift_cswap(&mut g, &mut f, fg_len, c, m, params);
        vector::minus_product_shift_cswap(&mut v, &mut u, uv_len, c, m, params);
    }
    vector::product(
        &mut r,
        p,
        &u[p..],
        modq::reciprocal(f[p], q, b1, b2),
        q,
        b1,
        b2,
    );
    // The Euclidean state is derived from the secret input — wipe it before returning.
    wipe(&mut f);
    wipe(&mut g);
    wipe(&mut u);
    wipe(&mut v);
    // Note: unlike r3::reciprocal, no invertibility check is returned here.
    // For these parameter sets q is prime and x^p - x - 1 is irreducible mod q,
    // so R/q is a field and the weight-w secret f is always invertible — the
    // reciprocal never fails, so there is no failure mask to propagate.
    r
}

#[allow(clippy::cast_possible_truncation)]
pub fn round3(h: &mut [i16], params: &SntrupParameters) {
    let q12 = params.q12;
    for coeff in h.iter_mut() {
        let inner = 21846i32 * (*coeff as i32 + q12);
        *coeff = (((inner + 32768) >> 16) * 3 - q12) as i16;
    }
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    {
        // The NTT machine (Good 3x512, primes 7681/10753) covers products up to
        // 1536 coefficients, so it serves p = 761; larger sets need the factor-5
        // variant and keep the schoolbook kernels for now.
        if params.p == 761 && crate::cpu::has_avx2() {
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe {
                return ntt::mult761(h, f, g);
            }
        }
        if crate::cpu::has_avxvnni() {
            // SAFETY: AVX2 + AVX-VNNI support confirmed by has_avxvnni()
            unsafe {
                return mult_avxvnni(h, f, g, params);
            }
        }
        if crate::cpu::has_avx2() {
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe {
                return mult_avx2(h, f, g, params);
            }
        }
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return mult_neon(h, f, g, params);
    }
    #[allow(unreachable_code)]
    mult_scalar(h, f, g, params);
}

fn mult_scalar(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    let p = params.p;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let mut fg = vec![0i16; p * 2 - 1];
    for i in 0..p {
        let mut r = 0i32;
        for j in 0..=i {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = modq::freeze(r, q, b1, b2);
    }
    for i in p..(p * 2 - 1) {
        let mut r = 0i32;
        for j in (i - p + 1)..p {
            r += f[j] as i32 * g[i - j] as i32;
        }
        fg[i] = modq::freeze(r, q, b1, b2);
    }
    for i in (p..(p * 2) - 1).rev() {
        fg[i - p] = modq::freeze(fg[i - p] as i32 + fg[i] as i32, q, b1, b2);
        fg[i - p + 1] = modq::freeze(fg[i - p + 1] as i32 + fg[i] as i32, q, b1, b2);
    }
    h[..p].copy_from_slice(&fg[..p]);
    // At least one operand is secret at every call site — wipe the product scratch.
    wipe(&mut fg);
}

/// Row-major schoolbook multiplication for x86_64, expanded once per instruction level
/// by the macro below: `mult_avx2` accumulates with `vpmaddwd` + `vpaddd` via
/// `crate::simd::mac_madd`, and `mult_avxvnni` uses the fused `vpdpwssd` via
/// `crate::simd::mac_vnni` (one instruction and one dependency fewer per 16 MACs).
///
/// Same structure as the NEON kernel below (see its doc comment): contiguous dot products over
/// `f` and a pre-reversed `g`, four independent accumulators, one store per output
/// coefficient, and the `x^p ≡ x + 1` fold applied to raw sums with vectorized freezes.
///
/// The widening multiply-accumulate here is `_mm256_madd_epi16` (pmaddwd): i16×i16 products
/// pairwise-summed into i32 lanes — 16 multiply-accumulates per instruction, double the old
/// column-major kernel's 8-lane `_mm256_mullo_epi32` density. A dot product only needs the
/// total, so pmaddwd's pairwise fold loses nothing. (An earlier note in this crate claimed
/// AVX2 has no i16-widening MAC — wrong: pmaddwd is exactly that for dot-product shapes.)
macro_rules! rq_mult_x86_kernel {
    ($name:ident, $features:literal, $mac:path) => {
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        #[target_feature(enable = $features)]
        #[allow(
            unsafe_code,
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            clippy::needless_range_loop
        )]
        unsafe fn $name(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
            unsafe {
                use core::arch::x86_64::*;

                let p = params.p;
                let q = params.q;
                let b1 = params.barrett1;
                let b2 = params.barrett2;
                let fg_len = p * 2 - 1;

                let mut g_rev = vec![0i16; p];
                for i in 0..p {
                    g_rev[i] = g[p - 1 - i] as i16;
                }

                // Raw i32 convolution sums, padded with one zero so the fold below may read
                // `fg32[k + p]` unconditionally at `k = p - 1`.
                let mut fg32 = vec![0i32; fg_len + 1];
                for (i, out) in fg32[..fg_len].iter_mut().enumerate() {
                    let jlo = i.saturating_sub(p - 1);
                    let len = i.min(p - 1) - jlo + 1;
                    let fp = f.as_ptr().add(jlo);
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
                    *out = sum;
                }

                let qv = _mm256_set1_epi32(q);
                let kb1 = _mm256_set1_epi32(b1);
                let kb2 = _mm256_set1_epi32(b2);
                let k134m = _mm256_set1_epi32(134_217_728);
                // Strict-canonical correction bound (see modq::freeze).
                let hqv = _mm256_set1_epi32((q - 1) >> 1);
                let nhqv = _mm256_set1_epi32(-((q - 1) >> 1));

                // Vectorized in-place Barrett freeze of the raw sums (the pad entry stays zero).
                let mut i = 0usize;
                while i + 8 <= fg_len {
                    let a = _mm256_loadu_si256(fg32.as_ptr().add(i) as *const __m256i);
                    let t = _mm256_srai_epi32(_mm256_mullo_epi32(a, kb1), 20);
                    let b = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, qv));
                    let t =
                        _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b, kb2), k134m), 28);
                    let r = _mm256_sub_epi32(b, _mm256_mullo_epi32(t, qv));
                    let r = _mm256_sub_epi32(r, _mm256_and_si256(_mm256_cmpgt_epi32(r, hqv), qv));
                    let r = _mm256_add_epi32(r, _mm256_and_si256(_mm256_cmpgt_epi32(nhqv, r), qv));
                    _mm256_storeu_si256(fg32.as_mut_ptr().add(i) as *mut __m256i, r);
                    i += 8;
                }
                while i < fg_len {
                    fg32[i] = modq::freeze(fg32[i], q, b1, b2) as i32;
                    i += 1;
                }

                // Fold x^p ≡ x + 1 and freeze once more: fg32[i] (i ≥ p) contributes to outputs i-p
                // and i-p+1, so h[k] = freeze(fg32[k] + fg32[k+p] + fg32[k+p-1]) for k ≥ 1, and
                // h[0] = freeze(fg32[0] + fg32[p]).
                h[0] = modq::freeze(fg32[0] + fg32[p], q, b1, b2);
                let mut k = 1usize;
                while k + 8 <= p {
                    let a = _mm256_add_epi32(
                        _mm256_add_epi32(
                            _mm256_loadu_si256(fg32.as_ptr().add(k) as *const __m256i),
                            _mm256_loadu_si256(fg32.as_ptr().add(k + p) as *const __m256i),
                        ),
                        _mm256_loadu_si256(fg32.as_ptr().add(k + p - 1) as *const __m256i),
                    );
                    let t = _mm256_srai_epi32(_mm256_mullo_epi32(a, kb1), 20);
                    let b = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, qv));
                    let t =
                        _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b, kb2), k134m), 28);
                    let r = _mm256_sub_epi32(b, _mm256_mullo_epi32(t, qv));
                    let r = _mm256_sub_epi32(r, _mm256_and_si256(_mm256_cmpgt_epi32(r, hqv), qv));
                    let r = _mm256_add_epi32(r, _mm256_and_si256(_mm256_cmpgt_epi32(nhqv, r), qv));
                    let packed =
                        _mm_packs_epi32(_mm256_castsi256_si128(r), _mm256_extracti128_si256(r, 1));
                    _mm_storeu_si128(h.as_mut_ptr().add(k) as *mut __m128i, packed);
                    k += 8;
                }
                while k < p {
                    h[k] = modq::freeze(fg32[k] + fg32[k + p] + fg32[k + p - 1], q, b1, b2);
                    k += 1;
                }

                // At least one operand is secret at every call site — wipe the
                // reversed copy and the product scratch.
                wipe(&mut g_rev);
                wipe(&mut fg32);
            }
        }
    };
}

rq_mult_x86_kernel!(mult_avx2, "avx2", crate::simd::mac_madd);
rq_mult_x86_kernel!(mult_avxvnni, "avx2,avxvnni", crate::simd::mac_vnni);

/// Row-major schoolbook multiplication with NEON.
///
/// Each output coefficient's convolution sum is a contiguous dot product held in registers and
/// written to memory once. `g` is pre-reversed (`g_rev[k] = g[p-1-k]`) so row `i`'s terms
/// `f[j]·g[i-j]` become `f[jlo+t]·g_rev[g0+t]` — both operands advance together.
///
/// The inner loop uses `vmlal_s16`/`vmlal_high_s16` (i16×i16→i32 widening multiply-accumulate,
/// 8 lanes per instruction pair) across EIGHT independent accumulators, mirroring the structure
/// clang's autovectorizer emits for PQClean's reference C (`smlal`/`smlal2` over `v0`–`v7`):
/// with multi-cycle MAC latency and multiple SIMD pipes, ~8 independent chains are needed to
/// keep the pipes full. An earlier 2-chain attempt (each chain serially feeding its own low and
/// high halves) was latency-bound and only tied the previous column-major kernel; 8 chains is
/// what makes row-major win. Row-major also eliminates the column-major kernel's
/// store-to-load-forwarding hazard, where each `j` iteration reloaded accumulator vectors
/// partially overlapping the previous iteration's stores at a one-element offset.
///
/// Raw i32 row sums are kept unreduced (bounded by `p·(q-1)/2 < 5.1M`, inside the Barrett
/// window), frozen once in a vectorized pass, then the `x^p ≡ x + 1` fold adds three
/// already-frozen values (|sum| ≤ 3·(q-1)/2) with one final vectorized freeze — two freezes
/// per output coefficient where the reference implementation spends three, and no serial
/// dependency anywhere: `fg[i]` for `i ≥ p` is never itself a fold target, so every fold lane
/// is independent.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i16], f: &[i16], g: &[i8], params: &SntrupParameters) {
    unsafe {
        use core::arch::aarch64::*;

        let p = params.p;
        let q = params.q;
        let b1 = params.barrett1;
        let b2 = params.barrett2;
        let fg_len = p * 2 - 1;

        let mut g_rev = vec![0i16; p];
        for i in 0..p {
            g_rev[i] = g[p - 1 - i] as i16;
        }

        // Raw i32 convolution sums, padded with one zero so the fold below may read
        // `fg32[k + p]` unconditionally at `k = p - 1`.
        let mut fg32 = vec![0i32; fg_len + 1];
        for (i, out) in fg32[..fg_len].iter_mut().enumerate() {
            let jlo = i.saturating_sub(p - 1);
            let len = i.min(p - 1) - jlo + 1;
            let fp = f.as_ptr().add(jlo);
            // `p - 1 + jlo` never drops below `i` (jlo = max(0, i-p+1)); the naive
            // `p - 1 - i + jlo` ordering underflows in debug builds when i ≥ p.
            let gp = g_rev.as_ptr().add(p - 1 + jlo - i);

            let mut acc0 = vdupq_n_s32(0);
            let mut acc1 = vdupq_n_s32(0);
            let mut acc2 = vdupq_n_s32(0);
            let mut acc3 = vdupq_n_s32(0);
            let mut acc4 = vdupq_n_s32(0);
            let mut acc5 = vdupq_n_s32(0);
            let mut acc6 = vdupq_n_s32(0);
            let mut acc7 = vdupq_n_s32(0);
            let mut k = 0usize;
            while k + 32 <= len {
                let f0 = vld1q_s16(fp.add(k));
                let f1 = vld1q_s16(fp.add(k + 8));
                let f2 = vld1q_s16(fp.add(k + 16));
                let f3 = vld1q_s16(fp.add(k + 24));
                let g0 = vld1q_s16(gp.add(k));
                let g1 = vld1q_s16(gp.add(k + 8));
                let g2 = vld1q_s16(gp.add(k + 16));
                let g3 = vld1q_s16(gp.add(k + 24));
                acc0 = vmlal_s16(acc0, vget_low_s16(f0), vget_low_s16(g0));
                acc1 = vmlal_high_s16(acc1, f0, g0);
                acc2 = vmlal_s16(acc2, vget_low_s16(f1), vget_low_s16(g1));
                acc3 = vmlal_high_s16(acc3, f1, g1);
                acc4 = vmlal_s16(acc4, vget_low_s16(f2), vget_low_s16(g2));
                acc5 = vmlal_high_s16(acc5, f2, g2);
                acc6 = vmlal_s16(acc6, vget_low_s16(f3), vget_low_s16(g3));
                acc7 = vmlal_high_s16(acc7, f3, g3);
                k += 32;
            }
            while k + 8 <= len {
                let f0 = vld1q_s16(fp.add(k));
                let g0 = vld1q_s16(gp.add(k));
                acc0 = vmlal_s16(acc0, vget_low_s16(f0), vget_low_s16(g0));
                acc1 = vmlal_high_s16(acc1, f0, g0);
                k += 8;
            }
            let total = vaddq_s32(
                vaddq_s32(vaddq_s32(acc0, acc1), vaddq_s32(acc2, acc3)),
                vaddq_s32(vaddq_s32(acc4, acc5), vaddq_s32(acc6, acc7)),
            );
            let mut sum = vaddvq_s32(total);
            while k < len {
                sum += *fp.add(k) as i32 * *gp.add(k) as i32;
                k += 1;
            }
            *out = sum;
        }

        let qv = vdupq_n_s32(q);
        let kb1 = vdupq_n_s32(b1);
        let kb2 = vdupq_n_s32(b2);
        let k134m = vdupq_n_s32(134_217_728);
        // Strict-canonical correction bound (see modq::freeze).
        let hqv = vdupq_n_s32((q - 1) >> 1);
        let nhqv = vdupq_n_s32(-((q - 1) >> 1));

        // Vectorized in-place Barrett freeze of the raw sums (the pad entry stays zero).
        let mut i = 0usize;
        while i + 4 <= fg_len {
            let a = vld1q_s32(fg32.as_ptr().add(i));
            let t = vshrq_n_s32(vmulq_s32(a, kb1), 20);
            let b = vsubq_s32(a, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b, kb2), k134m), 28);
            let r = vsubq_s32(b, vmulq_s32(t, qv));
            let r = vsubq_s32(r, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(r, hqv)), qv));
            let r = vaddq_s32(r, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(nhqv, r)), qv));
            vst1q_s32(fg32.as_mut_ptr().add(i), r);
            i += 4;
        }
        while i < fg_len {
            fg32[i] = modq::freeze(fg32[i], q, b1, b2) as i32;
            i += 1;
        }

        // Fold x^p ≡ x + 1 and freeze once more: fg32[i] (i ≥ p) contributes to outputs i-p
        // and i-p+1, so h[k] = freeze(fg32[k] + fg32[k+p] + fg32[k+p-1]) for k ≥ 1, and
        // h[0] = freeze(fg32[0] + fg32[p]).
        h[0] = modq::freeze(fg32[0] + fg32[p], q, b1, b2);
        let mut k = 1usize;
        while k + 4 <= p {
            let a = vaddq_s32(
                vaddq_s32(
                    vld1q_s32(fg32.as_ptr().add(k)),
                    vld1q_s32(fg32.as_ptr().add(k + p)),
                ),
                vld1q_s32(fg32.as_ptr().add(k + p - 1)),
            );
            let t = vshrq_n_s32(vmulq_s32(a, kb1), 20);
            let b = vsubq_s32(a, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b, kb2), k134m), 28);
            let r = vsubq_s32(b, vmulq_s32(t, qv));
            let r = vsubq_s32(r, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(r, hqv)), qv));
            let r = vaddq_s32(r, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(nhqv, r)), qv));
            vst1_s16(h.as_mut_ptr().add(k), vmovn_s32(r));
            k += 4;
        }
        while k < p {
            h[k] = modq::freeze(fg32[k] + fg32[k + p] + fg32[k + p - 1], q, b1, b2);
            k += 1;
        }

        // At least one operand is secret at every call site — wipe the reversed copy
        // and the product scratch.
        wipe(&mut g_rev);
        wipe(&mut fg32);
    }
}

/// `out[i] = R3(freeze_q(3 · cf[i]))` — the scale-by-3 and lift-to-R3 step of
/// decapsulation (liboqs splits this into `crypto_core_scale3` and
/// `crypto_encode_pxfreeze3`).
///
/// `cf` holds canonical mod-q coefficients, so `3·cf` stays within ±3(q−1)/2
/// and both reductions run comfortably inside i32 lanes.
#[allow(unsafe_code)]
pub fn scale3_freeze3(out: &mut [i8], cf: &[i16], params: &SntrupParameters) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return scale3_freeze3_avx2(out, cf, params);
        }
    }
    #[allow(unreachable_code)]
    scale3_freeze3_scalar(out, cf, params);
}

fn scale3_freeze3_scalar(out: &mut [i8], cf: &[i16], params: &SntrupParameters) {
    for (o, &c) in out.iter_mut().zip(cf.iter()) {
        let scaled = modq::freeze(3 * i32::from(c), params.q, params.barrett1, params.barrett2);
        *o = crate::r3::mod3::freeze(i32::from(scaled));
    }
}

/// AVX2 form: 32 coefficients per iteration, via a threshold rather than the
/// literal composition the scalar path computes.
///
/// Writing `s = 3c - kq` for the `k` that lands `s` in the centered range,
/// every parameter set has `q == 1 (mod 3)`, so `s == -k (mod 3)` and the
/// ternary result depends only on `k` — the value of `c mod 3` cannot reach the
/// output at all. And `|3c| <= 1.5(q - 1)` bounds `k` to `{-1, 0, 1}`, so `k`
/// is just the sign of `c` outside a dead zone. The whole two-Barrett,
/// two-freeze composition is therefore a pair of comparisons, which
/// `scale3_collapses_to_a_threshold_on_c` verifies exhaustively over every
/// representable `c` for all six parameter sets.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(unsafe_code, clippy::cast_possible_truncation)]
unsafe fn scale3_freeze3_avx2(out: &mut [i8], cf: &[i16], params: &SntrupParameters) {
    unsafe {
        use core::arch::x86_64::*;

        let q = params.q;
        // Smallest `c` with `k == 1`: `3c` must reach `q/2`, so `t = ceil((q + 1) / 6)`.
        let t = (q + 6) / 6;
        // `cmpgt` only tests strict `>`, so compare against the neighbours.
        let hi = _mm256_set1_epi16((t - 1) as i16);
        let lo = _mm256_set1_epi16((1 - t) as i16);

        let n = out.len().min(cf.len());
        let mut i = 0usize;
        while i + 32 <= n {
            let c0 = _mm256_loadu_si256(cf.as_ptr().add(i) as *const __m256i);
            let c1 = _mm256_loadu_si256(cf.as_ptr().add(i + 16) as *const __m256i);
            // Each mask is all-ones (-1) when set, so the difference is -1 above
            // the band, +1 below it and 0 inside.
            let v0 = _mm256_sub_epi16(_mm256_cmpgt_epi16(c0, hi), _mm256_cmpgt_epi16(lo, c0));
            let v1 = _mm256_sub_epi16(_mm256_cmpgt_epi16(c1, hi), _mm256_cmpgt_epi16(lo, c1));
            // `packs` interleaves the two 128-bit halves; the permute undoes it.
            let packed = _mm256_permute4x64_epi64::<0b1101_1000>(_mm256_packs_epi16(v0, v1));
            _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, packed);
            i += 32;
        }
        while i < n {
            let c = i32::from(cf[i]);
            out[i] = i8::from(c <= -t) - i8::from(c >= t);
            i += 1;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;
    use crate::params::SntrupParams;

    /// Deterministic xorshift64* so the test needs no RNG crates or features.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn random_case(params: &SntrupParameters, seed: u64) -> (Vec<i16>, Vec<i8>) {
        let mut s = seed | 1;
        let q12 = params.q12;
        let f = (0..params.p)
            .map(|_| ((next(&mut s) % (2 * q12 as u64 + 1)) as i32 - q12) as i16)
            .collect();
        let g = (0..params.p)
            .map(|_| ((next(&mut s) % 3) as i8) - 1)
            .collect();
        (f, g)
    }

    /// The divstep port must produce byte-identical output to the
    /// top-coefficient-elimination oracle for every parameter set: same
    /// canonical reciprocal of 3·s, including the ternary edge patterns.
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(feature = "force-scalar")
    ))]
    #[test]
    fn divstep_reciprocal_matches_eliminate() {
        #[cfg(target_arch = "x86_64")]
        if !crate::cpu::has_avx2() {
            return;
        }
        for params in all_params() {
            let p = params.p;
            for seed in 0..8u64 {
                let (_, g) = random_case(params, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
                let want = reciprocal3_eliminate(&g, params);
                let got = reciprocal3_divstep(&g, params);
                assert_eq!(got, want, "divstep vs eliminate: p={p} seed={seed}");
            }
            // Deterministic patterns: monomial and alternating ternary.
            let mut mono = vec![0i8; p];
            mono[0] = 1;
            assert_eq!(
                reciprocal3_divstep(&mono, params),
                reciprocal3_eliminate(&mono, params),
                "monomial p={p}"
            );
            let alt: Vec<i8> = (0..p).map(|i| [1i8, -1, 0][i % 3]).collect();
            assert_eq!(
                reciprocal3_divstep(&alt, params),
                reciprocal3_eliminate(&alt, params),
                "alternating p={p}"
            );
        }
    }

    /// The NTT multiply must agree with the schoolbook kernel exactly on
    /// p = 761 — random operands plus extreme (±(q−1)/2 × ±1) inputs.
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    #[test]
    fn ntt_mult_matches_scalar() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let params = crate::params::Sntrup761Params::params();
        let p = params.p;
        for seed in 0..8u64 {
            let (f, g) = random_case(params, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut want = vec![0i16; p];
            mult_scalar(&mut want, &f, &g, params);
            let mut got = vec![0i16; p];
            // SAFETY: AVX2 confirmed above.
            unsafe { ntt::mult761(&mut got, &f, &g) };
            assert_eq!(got, want, "ntt vs scalar: random seed={seed}");
        }
        let hq = params.q12 as i16;
        for &(fv, gv) in &[(hq, 1i8), (-hq, 1), (hq, -1), (-hq, -1)] {
            let f = vec![fv; p];
            let g = vec![gv; p];
            let mut want = vec![0i16; p];
            mult_scalar(&mut want, &f, &g, params);
            let mut got = vec![0i16; p];
            unsafe { ntt::mult761(&mut got, &f, &g) };
            assert_eq!(got, want, "ntt vs scalar: extreme f={fv} g={gv}");
        }
    }

    /// The vectorized scale-by-3/lift-to-R3 step must match the scalar form
    /// exactly on every parameter set, including the canonical extremes.
    #[test]
    fn scale3_freeze3_matches_scalar() {
        for params in all_params() {
            let p = params.p;
            let hq = params.q12 as i16;
            for seed in 0..6u64 {
                let (f, _) = random_case(params, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
                let mut want = vec![0i8; p];
                scale3_freeze3_scalar(&mut want, &f, params);
                let mut got = vec![0i8; p];
                scale3_freeze3(&mut got, &f, params);
                assert_eq!(got, want, "scale3 random p={p} seed={seed}");
            }
            for &v in &[0i16, 1, -1, hq, -hq] {
                let f = vec![v; p];
                let mut want = vec![0i8; p];
                scale3_freeze3_scalar(&mut want, &f, params);
                let mut got = vec![0i8; p];
                scale3_freeze3(&mut got, &f, params);
                assert_eq!(got, want, "scale3 const {v} p={p}");
            }
        }
    }

    #[test]
    fn scale3_collapses_to_a_threshold_on_c() {
        for params in all_params() {
            let q = params.q;
            let half = (q - 1) / 2;
            let t = (q + 6) / 6;
            for c in -half..=half {
                let mut got = [0i8; 1];
                scale3_freeze3_scalar(&mut got, &[c as i16], params);
                let want = if c >= t {
                    -1i8
                } else if c <= -t {
                    1
                } else {
                    0
                };
                assert_eq!(got[0], want, "q={q} c={c}");
            }
        }
    }

    fn all_params() -> [&'static SntrupParameters; 6] {
        [
            crate::params::Sntrup653Params::params(),
            crate::params::Sntrup761Params::params(),
            crate::params::Sntrup857Params::params(),
            crate::params::Sntrup953Params::params(),
            crate::params::Sntrup1013Params::params(),
            crate::params::Sntrup1277Params::params(),
        ]
    }

    /// Compare every compiled-in SIMD kernel against the scalar reference. Catches the class
    /// of bug the KAT/roundtrip suite can miss when run with `--all-features`, which enables
    /// `force-scalar` and silently compiles the SIMD kernels out of the test entirely.
    fn check_case(params: &SntrupParameters, f: &[i16], g: &[i8], label: &str) {
        let p = params.p;
        let mut want = vec![0i16; p];
        mult_scalar(&mut want, f, g, params);

        #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
        {
            let mut got = vec![0i16; p];
            // SAFETY: NEON is baseline on aarch64
            unsafe { mult_neon(&mut got, f, g, params) };
            assert_eq!(got, want, "mult_neon vs scalar: {label} p={p}");
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            let mut got = vec![0i16; p];
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe { mult_avx2(&mut got, f, g, params) };
            assert_eq!(got, want, "mult_avx2 vs scalar: {label} p={p}");
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avxvnni() {
            let mut got = vec![0i16; p];
            // SAFETY: AVX2 + AVX-VNNI support confirmed by has_avxvnni()
            unsafe { mult_avxvnni(&mut got, f, g, params) };
            assert_eq!(got, want, "mult_avxvnni vs scalar: {label} p={p}");
        }

        let mut got = vec![0i16; p];
        mult(&mut got, f, g, params);
        assert_eq!(got, want, "dispatched mult vs scalar: {label} p={p}");
    }

    #[test]
    fn simd_mult_matches_scalar_random() {
        for params in all_params() {
            for seed in 1..=8u64 {
                let (f, g) = random_case(params, seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                check_case(params, &f, &g, "random");
            }
        }
    }

    /// Extremes: `f` saturated at ±(q-1)/2 and `g` all ±1 maximize accumulator magnitude,
    /// probing the overflow headroom the SIMD kernels' Barrett-freeze staging depends on.
    #[test]
    fn simd_mult_extremes_match_scalar() {
        for params in all_params() {
            let q12 = params.q12 as i16;
            let f_max: Vec<i16> = (0..params.p).map(|_| q12).collect();
            let f_alt: Vec<i16> = (0..params.p)
                .map(|i| if i % 2 == 0 { q12 } else { -q12 })
                .collect();
            let g_ones = vec![1i8; params.p];
            let g_neg = vec![-1i8; params.p];
            check_case(params, &f_max, &g_ones, "f=+max g=+1");
            check_case(params, &f_max, &g_neg, "f=+max g=-1");
            check_case(params, &f_alt, &g_ones, "f=alt g=+1");
        }
    }
}
