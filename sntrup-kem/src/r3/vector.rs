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
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return swap_avx2(x, y, n, mask);
        }
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
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
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
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return product_avx2(z, n, x, c);
        }
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
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
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
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return minus_product_shift_avx2(z, n, y, c);
        }
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

/// Fused `minus_product_shift` + conditional swap — one memory pass instead of two.
///
/// Same contract as the rq version: exactly `minus_product_shift(z, n, y, c)` then
/// `swap(z, y, n, mask)`; non-AVX2 targets (including aarch64/NEON, untouched)
/// take the two-pass fallback.
#[inline(always)]
pub fn minus_product_shift_cswap(z: &mut [i8], y: &mut [i8], n: usize, c: i8, mask: isize) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return minus_product_shift_cswap_avx2(z, y, n, c, mask);
        }
    }
    minus_product_shift(z, n, y, c);
    swap(z, y, n, mask);
}

/// AVX2 fused kernel. The mod-3 fixup is a `vpshufb` register LUT: `r ∈ [-2,2]`
/// biased to `[0,4]` indexes the table `[1, -1, 0, 1, -1]` (freeze of `r`),
/// replacing the 6-op compare/mask chain with add + shuffle. vpshufb is an
/// in-lane register permute with data-independent timing — constant-time safe.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_cswap_avx2(z: &mut [i8], y: &mut [i8], n: usize, c: i8, mask: isize) {
    unsafe {
        use core::arch::x86_64::*;
        let cv = _mm256_set1_epi8(c);
        let two = _mm256_set1_epi8(2);
        #[rustfmt::skip]
        let table = _mm256_setr_epi8(
            1, -1, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, -1, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let mv = _mm256_set1_epi8(mask as i8);

        let mut j = (n - 2) as isize;

        while j >= 31 {
            let start = (j - 31) as usize;
            let zv = _mm256_loadu_si256(z.as_ptr().add(start) as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr().add(start) as *const __m256i);
            let r = _mm256_sub_epi8(zv, _mm256_sign_epi8(yv, cv));
            let w = _mm256_shuffle_epi8(table, _mm256_add_epi8(r, two));

            let y1 = _mm256_loadu_si256(y.as_ptr().add(start + 1) as *const __m256i);
            let new_z = _mm256_blendv_epi8(w, y1, mv);
            let new_y = _mm256_blendv_epi8(y1, w, mv);
            _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, new_z);
            _mm256_storeu_si256(y.as_mut_ptr().add(start + 1) as *mut __m256i, new_y);
            j -= 32;
        }

        // Bottom overlapped block; the +1 loads' topmost byte (index 32) is
        // post-swap and is preserved via the keep mask rather than recomputed.
        if j >= 0 && n >= 33 && n & 31 == 0 {
            let zv = _mm256_loadu_si256(z.as_ptr() as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr() as *const __m256i);
            let r = _mm256_sub_epi8(zv, _mm256_sign_epi8(yv, cv));
            let w = _mm256_shuffle_epi8(table, _mm256_add_epi8(r, two));

            let z1 = _mm256_loadu_si256(z.as_ptr().add(1) as *const __m256i);
            let y1 = _mm256_loadu_si256(y.as_ptr().add(1) as *const __m256i);
            let new_z = _mm256_blendv_epi8(w, y1, mv);
            let new_y = _mm256_blendv_epi8(y1, w, mv);
            #[rustfmt::skip]
            let keep = _mm256_setr_epi8(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1,
            );
            _mm256_storeu_si256(
                z.as_mut_ptr().add(1) as *mut __m256i,
                _mm256_blendv_epi8(new_z, z1, keep),
            );
            _mm256_storeu_si256(
                y.as_mut_ptr().add(1) as *mut __m256i,
                _mm256_blendv_epi8(new_y, y1, keep),
            );
            j = -1;
        }

        // Scalar remainder (only when n < 33).
        let mi = mask as i8;
        while j >= 0 {
            let k = (j + 1) as usize;
            let w = mod3::minus_product(z[k - 1], y[k - 1], c);
            let yk = y[k];
            z[k] = (mi & yk) | (!mi & w);
            y[k] = (mi & w) | (!mi & yk);
            j -= 1;
        }
        let y0 = y[0];
        z[0] = mi & y0;
        y[0] = !mi & y0;
    }
}

#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
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

        // The backward loop strands `(n - 2) % 32` bottom elements. When n is a
        // multiple of 32 and the body ran at least once, a final full-width block at
        // start = 0 covers them:
        // z[0..32] is still original (higher blocks only wrote z[32..] and beyond),
        // and the overlap element it rewrites (z[32]) gets the identical value the
        // previous block computed from the same inputs.
        if j >= 0 && n >= 33 && n & 31 == 0 {
            let zv = _mm256_loadu_si256(z.as_ptr() as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr() as *const __m256i);
            let yc = _mm256_sign_epi8(yv, cv);
            let r = _mm256_sub_epi8(zv, yc);
            let add = _mm256_and_si256(three, _mm256_cmpeq_epi8(r, neg2));
            let sub = _mm256_and_si256(three, _mm256_cmpeq_epi8(r, pos2));
            let r = _mm256_add_epi8(_mm256_sub_epi8(r, sub), add);
            _mm256_storeu_si256(z.as_mut_ptr().add(1) as *mut __m256i, r);
            j = -1;
        }

        // Scalar remainder (only when n < 33)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The fused kernel must match scalar minus_product_shift + scalar swap
    /// exactly, for both mask values, at lengths exercising the vector loop,
    /// the overlapped bottom block, and the scalar path.
    #[test]
    fn fused_cswap_matches_two_pass_reference() {
        let mut s = 0xfeed_face_cafe_beefu64;
        for &n in &[2usize, 9, 32, 33, 65, 762, 768, 1536] {
            for &mask in &[0isize, -1] {
                for &c in &[-1i8, 0, 1] {
                    let z0: Vec<i8> = (0..n).map(|_| ((next(&mut s) % 3) as i8) - 1).collect();
                    let y0: Vec<i8> = (0..n).map(|_| ((next(&mut s) % 3) as i8) - 1).collect();

                    let mut z_ref = z0.clone();
                    let mut y_ref = y0.clone();
                    minus_product_shift_scalar(&mut z_ref, n, &y_ref, c);
                    swap_scalar(&mut z_ref, &mut y_ref, n, mask);

                    let mut z_got = z0.clone();
                    let mut y_got = y0.clone();
                    minus_product_shift_cswap(&mut z_got, &mut y_got, n, c, mask);

                    assert_eq!(z_got, z_ref, "z mismatch n={n} mask={mask} c={c}");
                    assert_eq!(y_got, y_ref, "y mismatch n={n} mask={mask} c={c}");
                }
            }
        }
    }
}
