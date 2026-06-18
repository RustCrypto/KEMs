pub mod mod3;
mod vector;

use crate::ct::{smaller_mask, swap_int};

#[allow(clippy::cast_possible_wrap)]
pub fn reciprocal(s: &[i8], p: usize) -> (isize, Vec<i8>) {
    let loops = 2 * p + 1;
    let mut r = vec![0i8; p];
    let mut f = vec![0i8; p + 1];
    f[0] = -1;
    f[1] = -1;
    f[p] = 1;

    let mut g = vec![0i8; p + 1];
    g[..p].copy_from_slice(&s[..p]);
    let mut d = p as isize;
    let mut e = p as isize;
    let mut u = vec![0i8; loops + 1];
    let mut v = vec![0i8; loops + 1];
    v[0] = 1;

    for _ in 0..loops {
        let c = mod3::quotient(g[p], f[p]);
        vector::minus_product_shift(&mut g, p + 1, &f, c);
        vector::minus_product_shift(&mut v, loops + 1, &u, c);
        e -= 1;
        let m = smaller_mask(e, d) & mod3::mask_set(g[p]);
        let (e_tmp, d_tmp) = swap_int(e, d, m);
        e = e_tmp;
        d = d_tmp;
        vector::swap(&mut f, &mut g, p + 1, m);
        vector::swap(&mut u, &mut v, loops + 1, m);
    }

    vector::product(&mut r, p, &u[p..], mod3::reciprocal(f[p]));
    (smaller_mask(0, d), r)
}

#[allow(unsafe_code)]
pub fn mult(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return mult_avx2(h, f, g, p);
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
}

/// Column-major schoolbook multiplication with AVX2 for R3 polynomials.
/// Uses _mm256_sign_epi16 for {-1,0,1} multiplication and i16 accumulators.
/// Processes 16 coefficients per SIMD instruction.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_avx2(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    unsafe {
        use core::arch::x86_64::*;

        let g_pad_len = (p + 15) & !15; // multiple of 16
        let fg_pad_len = p + g_pad_len; // >= 2p-1
        let fg_len = p * 2 - 1;

        // Sign-extend g to i16, padded
        let mut g_pad = vec![0i16; g_pad_len];
        for i in 0..p {
            g_pad[i] = g[i] as i16;
        }

        // i16 accumulators (max value: ±p, fits in i16 for p <= 1277)
        let mut fg = vec![0i16; fg_pad_len];

        // Column-major accumulation: fg[j+k] += f[j] * g[k]
        for j in 0..p {
            let fj = _mm256_set1_epi16(f[j] as i16);
            let mut k = 0usize;
            while k + 16 <= g_pad_len {
                let gk = _mm256_loadu_si256(g_pad.as_ptr().add(k) as *const __m256i);
                // sign_epi16: if fj>0 → gk, if fj==0 → 0, if fj<0 → -gk
                let prod = _mm256_sign_epi16(gk, fj);
                let acc = _mm256_loadu_si256(fg.as_ptr().add(j + k) as *const __m256i);
                _mm256_storeu_si256(
                    fg.as_mut_ptr().add(j + k) as *mut __m256i,
                    _mm256_add_epi16(acc, prod),
                );
                k += 16;
            }
        }

        // Vectorized mod-3 freeze: mulhrs(a, 10923) gives floor((a*10923+16384)/32768)
        // which is the correct quotient for |a| <= 1277.
        // Result: a - 3*q is in {-1, 0, 1}.
        let k10923 = _mm256_set1_epi16(10923);
        let three16 = _mm256_set1_epi16(3);

        let mut fg8 = vec![0i8; fg_len];
        let mut i = 0usize;
        while i + 32 <= fg_len {
            // Process 32 values: two batches of 16 i16 → 32 i8
            let a0 = _mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i);
            let q0 = _mm256_mulhrs_epi16(a0, k10923);
            let r0 = _mm256_sub_epi16(a0, _mm256_mullo_epi16(q0, three16));

            let a1 = _mm256_loadu_si256(fg.as_ptr().add(i + 16) as *const __m256i);
            let q1 = _mm256_mulhrs_epi16(a1, k10923);
            let r1 = _mm256_sub_epi16(a1, _mm256_mullo_epi16(q1, three16));

            // Pack 16+16 i16 → 32 i8, fix AVX2 lane ordering
            let packed = _mm256_permute4x64_epi64(_mm256_packs_epi16(r0, r1), 0xD8);
            _mm256_storeu_si256(fg8.as_mut_ptr().add(i) as *mut __m256i, packed);
            i += 32;
        }
        while i < fg_len {
            fg8[i] = mod3::freeze(fg[i] as i32);
            i += 1;
        }

        // Reduction: x^p ≡ x + 1 (mod x^p - x - 1)
        for i in (p..(p * 2) - 1).rev() {
            fg8[i - p] = mod3::freeze(fg8[i - p] as i32 + fg8[i] as i32);
            fg8[i - p + 1] = mod3::freeze(fg8[i - p + 1] as i32 + fg8[i] as i32);
        }
        h[..p].copy_from_slice(&fg8[..p]);
    }
}

/// Column-major schoolbook multiplication with NEON for R3 polynomials.
/// Uses vmulq_s16 for {-1,0,1} multiplication and i16 accumulators.
/// Processes 8 coefficients per SIMD instruction.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop
)]
unsafe fn mult_neon(h: &mut [i8], f: &[i8], g: &[i8], p: usize) {
    unsafe {
        use core::arch::aarch64::*;

        let g_pad_len = (p + 7) & !7; // multiple of 8
        let fg_pad_len = p + g_pad_len; // >= 2p-1
        let fg_len = p * 2 - 1;

        // Sign-extend g to i16, padded
        let mut g_pad = vec![0i16; g_pad_len];
        for i in 0..p {
            g_pad[i] = g[i] as i16;
        }

        // i16 accumulators (max value: ±p, fits in i16 for p <= 1277)
        let mut fg = vec![0i16; fg_pad_len];

        // Column-major accumulation: fg[j+k] += f[j] * g[k]
        // vmulq_s16(gk, fj): for fj in {-1,0,1} this produces correct signed product
        for j in 0..p {
            let fj = vdupq_n_s16(f[j] as i16);
            let mut k = 0usize;
            while k + 8 <= g_pad_len {
                let gk = vld1q_s16(g_pad.as_ptr().add(k));
                let prod = vmulq_s16(gk, fj);
                let acc = vld1q_s16(fg.as_ptr().add(j + k));
                vst1q_s16(fg.as_mut_ptr().add(j + k), vaddq_s16(acc, prod));
                k += 8;
            }
        }

        // Vectorized mod-3 freeze: vqrdmulhq_s16(a, 10923) gives correct quotient
        // for |a| <= 1277.  Result: a - 3*q is in {-1, 0, 1}.
        let k10923 = vdupq_n_s16(10923);
        let three16 = vdupq_n_s16(3);

        let mut fg8 = vec![0i8; fg_len];
        let mut i = 0usize;
        while i + 16 <= fg_len {
            // Process 16 values: two batches of 8 i16 → 16 i8
            let a0 = vld1q_s16(fg.as_ptr().add(i));
            let q0 = vqrdmulhq_s16(a0, k10923);
            let r0 = vsubq_s16(a0, vmulq_s16(q0, three16));

            let a1 = vld1q_s16(fg.as_ptr().add(i + 8));
            let q1 = vqrdmulhq_s16(a1, k10923);
            let r1 = vsubq_s16(a1, vmulq_s16(q1, three16));

            // Pack 8+8 i16 → 16 i8 (naturally ordered, no permute needed)
            let packed = vcombine_s8(vqmovn_s16(r0), vqmovn_s16(r1));
            vst1q_s8(fg8.as_mut_ptr().add(i), packed);
            i += 16;
        }
        while i < fg_len {
            fg8[i] = mod3::freeze(fg[i] as i32);
            i += 1;
        }

        // Reduction: x^p ≡ x + 1 (mod x^p - x - 1)
        for i in (p..(p * 2) - 1).rev() {
            fg8[i - p] = mod3::freeze(fg8[i - p] as i32 + fg8[i] as i32);
            fg8[i - p + 1] = mod3::freeze(fg8[i - p + 1] as i32 + fg8[i] as i32);
        }
        h[..p].copy_from_slice(&fg8[..p]);
    }
}
