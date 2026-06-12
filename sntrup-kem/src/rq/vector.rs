#![allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::rq::modq;

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn swap(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return swap_avx2(x, y, n, mask);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return swap_neon(x, y, n, mask);
    }
    #[allow(unreachable_code)]
    swap_scalar(x, y, n, mask);
}

#[allow(clippy::cast_possible_truncation)]
fn swap_scalar(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    let c = mask as i16;
    for i in 0..n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn swap_avx2(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    unsafe {
        use core::arch::x86_64::*;
        let cv = _mm256_set1_epi16(mask as i16);
        let mut i = 0usize;
        while i + 16 <= n {
            let xv = _mm256_loadu_si256(x.as_ptr().add(i) as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr().add(i) as *const __m256i);
            let t = _mm256_and_si256(cv, _mm256_xor_si256(xv, yv));
            _mm256_storeu_si256(
                x.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_xor_si256(xv, t),
            );
            _mm256_storeu_si256(
                y.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_xor_si256(yv, t),
            );
            i += 16;
        }
        let c = mask as i16;
        while i < n {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
            i += 1;
        }
    }
}

#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn swap_neon(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    unsafe {
        use core::arch::aarch64::*;
        let cv = vdupq_n_s16(mask as i16);
        let mut i = 0usize;
        while i + 8 <= n {
            let xv = vld1q_s16(x.as_ptr().add(i));
            let yv = vld1q_s16(y.as_ptr().add(i));
            let t = vandq_s16(cv, veorq_s16(xv, yv));
            vst1q_s16(x.as_mut_ptr().add(i), veorq_s16(xv, t));
            vst1q_s16(y.as_mut_ptr().add(i), veorq_s16(yv, t));
            i += 8;
        }
        let c = mask as i16;
        while i < n {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
            i += 1;
        }
    }
}

#[inline(always)]
pub fn product(z: &mut [i16], n: usize, x: &[i16], c: i16, q: i32, b1: i32, b2: i32) {
    for i in 0..n {
        z[i] = modq::product(x[i], c, q, b1, b2);
    }
}

/// Fused minus_product and shift: z[i+1] = freeze(z[i] - y[i]*c), z[0] = 0.
/// Processes backward to avoid overwrite conflicts, eliminating a separate memmove.
#[inline(always)]
pub fn minus_product_shift(z: &mut [i16], n: usize, y: &[i16], c: i16, q: i32, b1: i32, b2: i32) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return minus_product_shift_avx2(z, n, y, c, q, b1, b2);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return minus_product_shift_neon(z, n, y, c, q, b1, b2);
    }
    #[allow(unreachable_code)]
    minus_product_shift_scalar(z, n, y, c, q, b1, b2);
}

fn minus_product_shift_scalar(
    z: &mut [i16],
    n: usize,
    y: &[i16],
    c: i16,
    q: i32,
    b1: i32,
    b2: i32,
) {
    for i in (0..n - 1).rev() {
        z[i + 1] = modq::minus_product(z[i], y[i], c, q, b1, b2);
    }
    z[0] = 0;
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_avx2(
    z: &mut [i16],
    n: usize,
    y: &[i16],
    c: i16,
    q: i32,
    b1: i32,
    b2: i32,
) {
    unsafe {
        use core::arch::x86_64::*;
        let qv = _mm256_set1_epi32(q);
        let kb1 = _mm256_set1_epi32(b1);
        let kb2 = _mm256_set1_epi32(b2);
        let k134m = _mm256_set1_epi32(134_217_728);
        let cv = _mm256_set1_epi32(c as i32);

        let mut j = (n - 2) as isize;

        // Process 16 at a time (two 8-wide batches for ILP), backward
        while j >= 15 {
            let start = (j - 15) as usize;

            // Batch 0: elements start..start+8
            let zv0 =
                _mm256_cvtepi16_epi32(_mm_loadu_si128(z.as_ptr().add(start) as *const __m128i));
            let yv0 =
                _mm256_cvtepi16_epi32(_mm_loadu_si128(y.as_ptr().add(start) as *const __m128i));
            let a0 = _mm256_sub_epi32(zv0, _mm256_mullo_epi32(yv0, cv));

            // Batch 1: elements start+8..start+16
            let zv1 =
                _mm256_cvtepi16_epi32(_mm_loadu_si128(z.as_ptr().add(start + 8) as *const __m128i));
            let yv1 =
                _mm256_cvtepi16_epi32(_mm_loadu_si128(y.as_ptr().add(start + 8) as *const __m128i));
            let a1 = _mm256_sub_epi32(zv1, _mm256_mullo_epi32(yv1, cv));

            // Barrett freeze batch 0
            let t0 = _mm256_srai_epi32(_mm256_mullo_epi32(a0, kb1), 20);
            let b0 = _mm256_sub_epi32(a0, _mm256_mullo_epi32(t0, qv));
            let t0 = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b0, kb2), k134m), 28);
            let r0 = _mm256_sub_epi32(b0, _mm256_mullo_epi32(t0, qv));

            // Barrett freeze batch 1
            let t1 = _mm256_srai_epi32(_mm256_mullo_epi32(a1, kb1), 20);
            let b1 = _mm256_sub_epi32(a1, _mm256_mullo_epi32(t1, qv));
            let t1 = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b1, kb2), k134m), 28);
            let r1 = _mm256_sub_epi32(b1, _mm256_mullo_epi32(t1, qv));

            // Pack 8+8 i32 -> 16 i16 and store at offset +1 (the shift)
            let packed = _mm256_permute4x64_epi64(_mm256_packs_epi32(r0, r1), 0xD8);
            _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, packed);
            j -= 16;
        }

        // Process remaining 8 at a time
        while j >= 7 {
            let start = (j - 7) as usize;
            let zv =
                _mm256_cvtepi16_epi32(_mm_loadu_si128(z.as_ptr().add(start) as *const __m128i));
            let yv =
                _mm256_cvtepi16_epi32(_mm_loadu_si128(y.as_ptr().add(start) as *const __m128i));
            let a = _mm256_sub_epi32(zv, _mm256_mullo_epi32(yv, cv));

            let t = _mm256_srai_epi32(_mm256_mullo_epi32(a, kb1), 20);
            let b = _mm256_sub_epi32(a, _mm256_mullo_epi32(t, qv));
            let t = _mm256_srai_epi32(_mm256_add_epi32(_mm256_mullo_epi32(b, kb2), k134m), 28);
            let r = _mm256_sub_epi32(b, _mm256_mullo_epi32(t, qv));

            let lo = _mm256_castsi256_si128(r);
            let hi = _mm256_extracti128_si256(r, 1);
            _mm_storeu_si128(
                z.as_mut_ptr().add(start + 1) as *mut __m128i,
                _mm_packs_epi32(lo, hi),
            );
            j -= 8;
        }

        // Scalar remainder
        while j >= 0 {
            z[(j + 1) as usize] = modq::minus_product(z[j as usize], y[j as usize], c, q, b1, b2);
            j -= 1;
        }
        z[0] = 0;
    }
}

/// NEON Barrett minus_product_shift: 4 i32 elements at a time (128-bit), backward.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn minus_product_shift_neon(
    z: &mut [i16],
    n: usize,
    y: &[i16],
    c: i16,
    q: i32,
    b1: i32,
    b2: i32,
) {
    unsafe {
        use core::arch::aarch64::*;
        let qv = vdupq_n_s32(q);
        let kb1 = vdupq_n_s32(b1);
        let kb2 = vdupq_n_s32(b2);
        let k134m = vdupq_n_s32(134_217_728);
        let cv = vdupq_n_s32(c as i32);

        let mut j = (n - 2) as isize;

        // Process 8 at a time (two 4-wide batches), backward
        while j >= 7 {
            let start = (j - 7) as usize;

            // Batch 0: elements start..start+4
            let zv0 = vmovl_s16(vld1_s16(z.as_ptr().add(start)));
            let yv0 = vmovl_s16(vld1_s16(y.as_ptr().add(start)));
            let a0 = vsubq_s32(zv0, vmulq_s32(yv0, cv));

            // Batch 1: elements start+4..start+8
            let zv1 = vmovl_s16(vld1_s16(z.as_ptr().add(start + 4)));
            let yv1 = vmovl_s16(vld1_s16(y.as_ptr().add(start + 4)));
            let a1 = vsubq_s32(zv1, vmulq_s32(yv1, cv));

            // Barrett freeze batch 0
            let t0 = vshrq_n_s32(vmulq_s32(a0, kb1), 20);
            let b0 = vsubq_s32(a0, vmulq_s32(t0, qv));
            let t0 = vshrq_n_s32(vaddq_s32(vmulq_s32(b0, kb2), k134m), 28);
            let r0 = vsubq_s32(b0, vmulq_s32(t0, qv));

            // Barrett freeze batch 1
            let t1 = vshrq_n_s32(vmulq_s32(a1, kb1), 20);
            let b1 = vsubq_s32(a1, vmulq_s32(t1, qv));
            let t1 = vshrq_n_s32(vaddq_s32(vmulq_s32(b1, kb2), k134m), 28);
            let r1 = vsubq_s32(b1, vmulq_s32(t1, qv));

            // Pack 4+4 i32 -> 8 i16 (naturally ordered, no permute needed)
            let packed = vcombine_s16(vmovn_s32(r0), vmovn_s32(r1));
            vst1q_s16(z.as_mut_ptr().add(start + 1), packed);
            j -= 8;
        }

        // Process 4 at a time
        while j >= 3 {
            let start = (j - 3) as usize;
            let zv = vmovl_s16(vld1_s16(z.as_ptr().add(start)));
            let yv = vmovl_s16(vld1_s16(y.as_ptr().add(start)));
            let a = vsubq_s32(zv, vmulq_s32(yv, cv));

            let t = vshrq_n_s32(vmulq_s32(a, kb1), 20);
            let b = vsubq_s32(a, vmulq_s32(t, qv));
            let t = vshrq_n_s32(vaddq_s32(vmulq_s32(b, kb2), k134m), 28);
            let r = vsubq_s32(b, vmulq_s32(t, qv));

            vst1_s16(z.as_mut_ptr().add(start + 1), vmovn_s32(r));
            j -= 4;
        }

        // Scalar remainder
        while j >= 0 {
            z[(j + 1) as usize] = modq::minus_product(z[j as usize], y[j as usize], c, q, b1, b2);
            j -= 1;
        }
        z[0] = 0;
    }
}
