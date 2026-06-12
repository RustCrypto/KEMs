#![allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use super::mod3;

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn swap(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
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
fn swap_scalar(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
    let c = mask as i8;
    for i in 0..n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

/// 32 i8 elements per SIMD iteration.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn swap_avx2(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
    unsafe {
        use core::arch::x86_64::*;
        let cv = _mm256_set1_epi8(mask as i8);
        let mut i = 0usize;
        while i + 32 <= n {
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
            i += 32;
        }
        let c = mask as i8;
        while i < n {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
            i += 1;
        }
    }
}

/// 16 i8 elements per NEON iteration.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn swap_neon(x: &mut [i8], y: &mut [i8], n: usize, mask: isize) {
    unsafe {
        use core::arch::aarch64::*;
        let cv = vdupq_n_s8(mask as i8);
        let mut i = 0usize;
        while i + 16 <= n {
            let xv = vld1q_s8(x.as_ptr().add(i));
            let yv = vld1q_s8(y.as_ptr().add(i));
            let t = vandq_s8(cv, veorq_s8(xv, yv));
            vst1q_s8(x.as_mut_ptr().add(i), veorq_s8(xv, t));
            vst1q_s8(y.as_mut_ptr().add(i), veorq_s8(yv, t));
            i += 16;
        }
        let c = mask as i8;
        while i < n {
            let t = c & (x[i] ^ y[i]);
            x[i] ^= t;
            y[i] ^= t;
            i += 1;
        }
    }
}

#[inline(always)]
pub fn product(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return product_avx2(z, n, x, c);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return product_neon(z, n, x, c);
    }
    #[allow(unreachable_code)]
    product_scalar(z, n, x, c);
}

fn product_scalar(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    for i in 0..n {
        z[i] = mod3::product(x[i], c);
    }
}

/// For c in {-1, 0, 1}: _mm256_sign_epi8(x, c) computes x * c.
/// Processes 32 elements per iteration.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn product_avx2(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    unsafe {
        use core::arch::x86_64::*;
        let cv = _mm256_set1_epi8(c);
        let mut i = 0usize;
        while i + 32 <= n {
            let xv = _mm256_loadu_si256(x.as_ptr().add(i) as *const __m256i);
            _mm256_storeu_si256(
                z.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_sign_epi8(xv, cv),
            );
            i += 32;
        }
        while i < n {
            z[i] = mod3::product(x[i], c);
            i += 1;
        }
    }
}

/// NEON sign_epi8 equivalent: branchless x*sign(c).
/// For c in {-1, 0, 1}: returns x if c>0, -x if c<0, 0 if c==0.
/// Constant-time: no branches on c (which may be secret-derived).
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
unsafe fn sign_epi8_neon(
    xv: core::arch::aarch64::int8x16_t,
    cv: core::arch::aarch64::int8x16_t,
) -> core::arch::aarch64::int8x16_t {
    unsafe {
        use core::arch::aarch64::*;
        let sign_mask = vreinterpretq_u8_s8(vshrq_n_s8(cv, 7)); // 0xFF if c<0
        let nonzero = vtstq_s8(cv, cv); // 0xFF if c!=0 (uint8x16_t)
        let neg_x = vnegq_s8(xv);
        let selected = vreinterpretq_s8_u8(vbslq_u8(
            sign_mask,
            vreinterpretq_u8_s8(neg_x),
            vreinterpretq_u8_s8(xv),
        ));
        vandq_s8(selected, vreinterpretq_s8_u8(nonzero))
    }
}

/// NEON product for i8: 16 elements per iteration.
/// For c in {-1, 0, 1}, uses branchless sign_epi8 equivalent.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn product_neon(z: &mut [i8], n: usize, x: &[i8], c: i8) {
    unsafe {
        use core::arch::aarch64::*;
        let cv = vdupq_n_s8(c);
        let mut i = 0usize;
        while i + 16 <= n {
            let xv = vld1q_s8(x.as_ptr().add(i));
            vst1q_s8(z.as_mut_ptr().add(i), sign_epi8_neon(xv, cv));
            i += 16;
        }
        while i < n {
            z[i] = mod3::product(x[i], c);
            i += 1;
        }
    }
}

/// Fused minus_product and shift: z[i+1] = freeze(z[i] - y[i]*c), z[0] = 0.
/// Processes backward to avoid overwrite conflicts, eliminating a separate memmove.
#[inline(always)]
pub fn minus_product_shift(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return minus_product_shift_avx2(z, n, y, c);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return minus_product_shift_neon(z, n, y, c);
    }
    #[allow(unreachable_code)]
    minus_product_shift_scalar(z, n, y, c);
}

fn minus_product_shift_scalar(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    for i in (0..n - 1).rev() {
        z[i + 1] = mod3::minus_product(z[i], y[i], c);
    }
    z[0] = 0;
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_avx2(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    unsafe {
        use core::arch::x86_64::*;
        let cv = _mm256_set1_epi8(c);
        let neg2 = _mm256_set1_epi8(-2);
        let pos2 = _mm256_set1_epi8(2);
        let three = _mm256_set1_epi8(3);

        let mut j = (n - 2) as isize;

        // Process 32 i8 elements at a time, backward
        while j >= 31 {
            let start = (j - 31) as usize;
            let zv = _mm256_loadu_si256(z.as_ptr().add(start) as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr().add(start) as *const __m256i);
            let yc = _mm256_sign_epi8(yv, cv);
            let r = _mm256_sub_epi8(zv, yc);
            // Mod-3 fixup: r is in [-2, 2]
            let add = _mm256_and_si256(three, _mm256_cmpeq_epi8(r, neg2));
            let sub = _mm256_and_si256(three, _mm256_cmpeq_epi8(r, pos2));
            let r = _mm256_add_epi8(_mm256_sub_epi8(r, sub), add);
            // Store at offset +1 (the shift)
            _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, r);
            j -= 32;
        }

        // Scalar remainder
        while j >= 0 {
            z[(j + 1) as usize] = mod3::minus_product(z[j as usize], y[j as usize], c);
            j -= 1;
        }
        z[0] = 0;
    }
}

/// NEON minus_product_shift for i8: 16 elements at a time, backward.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn minus_product_shift_neon(z: &mut [i8], n: usize, y: &[i8], c: i8) {
    unsafe {
        use core::arch::aarch64::*;
        let cv = vdupq_n_s8(c);
        let neg2 = vdupq_n_s8(-2);
        let pos2 = vdupq_n_s8(2);
        let three = vdupq_n_s8(3);

        let mut j = (n - 2) as isize;

        // Process 16 i8 elements at a time, backward
        while j >= 15 {
            let start = (j - 15) as usize;
            let zv = vld1q_s8(z.as_ptr().add(start));
            let yv = vld1q_s8(y.as_ptr().add(start));
            let yc = sign_epi8_neon(yv, cv);
            let r = vsubq_s8(zv, yc);
            // Mod-3 fixup: r is in [-2, 2]
            let eq_neg2 = vceqq_s8(r, neg2);
            let eq_pos2 = vceqq_s8(r, pos2);
            let add = vandq_s8(three, vreinterpretq_s8_u8(eq_neg2));
            let sub = vandq_s8(three, vreinterpretq_s8_u8(eq_pos2));
            let r = vaddq_s8(vsubq_s8(r, sub), add);
            // Store at offset +1 (the shift)
            vst1q_s8(z.as_mut_ptr().add(start + 1), r);
            j -= 16;
        }

        // Scalar remainder
        while j >= 0 {
            z[(j + 1) as usize] = mod3::minus_product(z[j as usize], y[j as usize], c);
            j -= 1;
        }
        z[0] = 0;
    }
}
