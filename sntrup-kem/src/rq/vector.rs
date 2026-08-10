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
fn swap_scalar(x: &mut [i16], y: &mut [i16], n: usize, mask: isize) {
    let c = mask as i16;
    for i in 0..n {
        let t = c & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
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
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return minus_product_shift_avx2(z, n, y, c, q, b1, b2);
        }
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

/// Fused `minus_product_shift` + conditional swap: one memory pass instead of two.
///
/// Semantics are exactly `minus_product_shift(z, n, y, c, ..)` followed by
/// `swap(z, y, n, mask)` — the caller derives `mask` from the scalar-computed
/// post-shift leading coefficient before invoking this. On x86_64 with AVX2 the
/// fused kernel performs 3 loads + 2 stores per block where the two-pass form
/// performs 4 loads + 3 stores; other targets (including aarch64/NEON, whose
/// kernels are intentionally untouched) fall back to the two-pass form.
#[inline(always)]
pub fn minus_product_shift_cswap(
    z: &mut [i16],
    y: &mut [i16],
    n: usize,
    c: i16,
    mask: isize,
    params: &crate::params::SntrupParameters,
) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2()
        unsafe {
            return minus_product_shift_cswap_avx2(z, y, n, c, mask, params);
        }
    }
    minus_product_shift(z, n, y, c, params.q, params.barrett1, params.barrett2);
    swap(z, y, n, mask);
}

/// AVX2 fused kernel: the signed-Montgomery shift (see `minus_product_shift_avx2`)
/// with the conditional swap applied in-register via `blendv` before storing.
///
/// The `+1`-shifted store means each block also loads `y[start+1..start+17]` for
/// the swap half. In the bottom overlapped block, the topmost of those lanes
/// (index 16) was already written by the previous block, so that lane is
/// preserved through a keep-mask blend against current memory instead of being
/// recomputed from a stale input.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
unsafe fn minus_product_shift_cswap_avx2(
    z: &mut [i16],
    y: &mut [i16],
    n: usize,
    c: i16,
    mask: isize,
    params: &crate::params::SntrupParameters,
) {
    unsafe {
        use core::arch::x86_64::*;

        let q = params.q;
        let b1 = params.barrett1;
        let b2 = params.barrett2;

        // Montgomery constants — see minus_product_shift_avx2 for the derivation.
        let qw = q as u16;
        let mut qinv = qw;
        for _ in 0..3 {
            qinv = qinv.wrapping_mul(2u16.wrapping_sub(qw.wrapping_mul(qinv)));
        }
        let cp = modq::freeze(
            (modq::freeze((c as i32) << 8, q, b1, b2) as i32) << 8,
            q,
            b1,
            b2,
        );
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cpqinv = (cp as u16).wrapping_mul(qinv) as i16;

        let cpv = _mm256_set1_epi16(cp);
        let cpqv = _mm256_set1_epi16(cpqinv);
        #[allow(clippy::cast_possible_truncation)]
        let qv = _mm256_set1_epi16(q as i16);
        #[allow(clippy::cast_possible_truncation)]
        let hqv = _mm256_set1_epi16(((q - 1) / 2) as i16);
        #[allow(clippy::cast_possible_truncation)]
        let nhqv = _mm256_set1_epi16((-(q - 1) / 2) as i16);
        let mv = _mm256_set1_epi16(mask as i16);

        let mut j = (n - 2) as isize;

        while j >= 15 {
            let start = (j - 15) as usize;
            let zv = _mm256_loadu_si256(z.as_ptr().add(start) as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr().add(start) as *const __m256i);

            let m = _mm256_mullo_epi16(yv, cpqv);
            let t = _mm256_sub_epi16(_mm256_mulhi_epi16(yv, cpv), _mm256_mulhi_epi16(m, qv));
            let w = _mm256_sub_epi16(zv, t);
            let gt = _mm256_cmpgt_epi16(w, hqv);
            let lt = _mm256_cmpgt_epi16(nhqv, w);
            let w = _mm256_sub_epi16(w, _mm256_and_si256(gt, qv));
            let w = _mm256_add_epi16(w, _mm256_and_si256(lt, qv));

            // Conditional swap against y at the shifted (+1) position.
            let y1 = _mm256_loadu_si256(y.as_ptr().add(start + 1) as *const __m256i);
            let new_z = _mm256_blendv_epi8(w, y1, mv);
            let new_y = _mm256_blendv_epi8(y1, w, mv);
            _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, new_z);
            _mm256_storeu_si256(y.as_mut_ptr().add(start + 1) as *mut __m256i, new_y);
            j -= 16;
        }

        // Bottom overlapped block (see minus_product_shift_avx2 for the coverage
        // argument). Inputs at [0..16) are still original; the +1 loads' topmost
        // lane (index 16) is post-swap, so it is preserved, not recomputed.
        if j >= 0 && n >= 17 && n & 15 == 0 {
            let zv = _mm256_loadu_si256(z.as_ptr() as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr() as *const __m256i);
            let m = _mm256_mullo_epi16(yv, cpqv);
            let t = _mm256_sub_epi16(_mm256_mulhi_epi16(yv, cpv), _mm256_mulhi_epi16(m, qv));
            let w = _mm256_sub_epi16(zv, t);
            let gt = _mm256_cmpgt_epi16(w, hqv);
            let lt = _mm256_cmpgt_epi16(nhqv, w);
            let w = _mm256_sub_epi16(w, _mm256_and_si256(gt, qv));
            let w = _mm256_add_epi16(w, _mm256_and_si256(lt, qv));

            let z1 = _mm256_loadu_si256(z.as_ptr().add(1) as *const __m256i);
            let y1 = _mm256_loadu_si256(y.as_ptr().add(1) as *const __m256i);
            let new_z = _mm256_blendv_epi8(w, y1, mv);
            let new_y = _mm256_blendv_epi8(y1, w, mv);
            // Keep the topmost i16 lane (bytes 30-31) from current memory.
            let keep = _mm256_setr_epi8(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, -1, -1,
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

        // Scalar remainder (only when n < 17).
        #[allow(clippy::cast_possible_truncation)]
        let mi = mask as i16;
        while j >= 0 {
            let k = (j + 1) as usize;
            let w = modq::minus_product(z[k - 1], y[k - 1], c, q, b1, b2);
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

/// AVX2 kernel in the 16-bit domain via signed Montgomery multiplication
/// (Seiler, "Faster Kyber" — the same shape Kyber's AVX2 code uses).
///
/// Instead of widening to i32 lanes and running the two-step Barrett chain
/// (five `vpmulld` per 8 elements), each 16-lane block computes
/// `z - y·c mod± q` directly in i16 lanes:
///
/// - `c' = c·2^16 mod± q` (scalar, two Barrett freezes so the i32 window holds),
///   so the Montgomery product `y ⊗ c' = y·c'·2^-16 ≡ y·c (mod q)` is exact.
/// - `m = mullo(y, c'·q^-1 mod 2^16)`, `t = mulhi(y, c') − mulhi(m, q)`:
///   `t ≡ y·c (mod± q)` with `|t| < q` — three 16-bit multiplies per 16 lanes.
/// - `w = z − t` lies in `(−3q/2, 3q/2)`, so a single branchless
///   compare-and-correct lands it in the canonical `[−(q−1)/2, (q−1)/2]`.
///
/// All lane operations are branchless; the scalar precomputation uses the same
/// constant-time `freeze` and wrapping arithmetic, so the constant-time
/// property is unchanged.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
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

        // q^-1 mod 2^16 by Newton iteration (q is odd and public): each step
        // doubles the number of correct low bits, 3 -> 6 -> 12 -> 24 >= 16.
        let qw = q as u16;
        let mut qinv = qw;
        for _ in 0..3 {
            qinv = qinv.wrapping_mul(2u16.wrapping_sub(qw.wrapping_mul(qinv)));
        }

        // c' = c·2^16 mod± q, in two freezes of c·2^8 so each input stays well
        // inside the Barrett window (|c·2^8| <= ~1M << 2^31 / barrett1).
        let cp = modq::freeze(
            (modq::freeze((c as i32) << 8, q, b1, b2) as i32) << 8,
            q,
            b1,
            b2,
        );
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let cpqinv = (cp as u16).wrapping_mul(qinv) as i16;

        let cpv = _mm256_set1_epi16(cp);
        let cpqv = _mm256_set1_epi16(cpqinv);
        #[allow(clippy::cast_possible_truncation)]
        let qv = _mm256_set1_epi16(q as i16);
        #[allow(clippy::cast_possible_truncation)]
        let hqv = _mm256_set1_epi16(((q - 1) / 2) as i16);
        #[allow(clippy::cast_possible_truncation)]
        let nhqv = _mm256_set1_epi16((-(q - 1) / 2) as i16);

        let mut j = (n - 2) as isize;

        // Process 16 i16 elements per iteration, backward.
        while j >= 15 {
            let start = (j - 15) as usize;
            let zv = _mm256_loadu_si256(z.as_ptr().add(start) as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr().add(start) as *const __m256i);

            // t = y·c'·2^-16 mod± q = y·c mod± q, |t| < q.
            let m = _mm256_mullo_epi16(yv, cpqv);
            let t = _mm256_sub_epi16(_mm256_mulhi_epi16(yv, cpv), _mm256_mulhi_epi16(m, qv));

            // w = z - t, then one branchless correction into canonical range.
            let w = _mm256_sub_epi16(zv, t);
            let gt = _mm256_cmpgt_epi16(w, hqv);
            let lt = _mm256_cmpgt_epi16(nhqv, w);
            let w = _mm256_sub_epi16(w, _mm256_and_si256(gt, qv));
            let w = _mm256_add_epi16(w, _mm256_and_si256(lt, qv));

            // Store at offset +1 (the shift).
            _mm256_storeu_si256(z.as_mut_ptr().add(start + 1) as *mut __m256i, w);
            j -= 16;
        }

        // The backward loop strands `(n - 2) % 16` bottom elements. When n is a
        // multiple of 16 and the body ran at least once, a final full-width block at
        // start = 0 covers them:
        // z[0..16] is still original (higher blocks only wrote z[16..] and beyond),
        // and the overlap element it rewrites (z[16]) gets the identical value the
        // previous block computed from the same inputs.
        if j >= 0 && n >= 17 && n & 15 == 0 {
            let zv = _mm256_loadu_si256(z.as_ptr() as *const __m256i);
            let yv = _mm256_loadu_si256(y.as_ptr() as *const __m256i);
            let m = _mm256_mullo_epi16(yv, cpqv);
            let t = _mm256_sub_epi16(_mm256_mulhi_epi16(yv, cpv), _mm256_mulhi_epi16(m, qv));
            let w = _mm256_sub_epi16(zv, t);
            let gt = _mm256_cmpgt_epi16(w, hqv);
            let lt = _mm256_cmpgt_epi16(nhqv, w);
            let w = _mm256_sub_epi16(w, _mm256_and_si256(gt, qv));
            let w = _mm256_add_epi16(w, _mm256_and_si256(lt, qv));
            _mm256_storeu_si256(z.as_mut_ptr().add(1) as *mut __m256i, w);
            j = -1;
        }

        // Scalar remainder (only when n < 17)
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
        // Strict-canonical correction bounds — see `modq::freeze`: the two Barrett steps
        // alone can land a few counts outside ±(q-1)/2, and every freeze path must match
        // the scalar reference byte-for-byte.
        let hqv = vdupq_n_s32((q - 1) >> 1);
        let nhqv = vdupq_n_s32(-((q - 1) >> 1));

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

            // Barrett freeze batch 0, with strict-canonical correction
            let t0 = vshrq_n_s32(vmulq_s32(a0, kb1), 20);
            let b0 = vsubq_s32(a0, vmulq_s32(t0, qv));
            let t0 = vshrq_n_s32(vaddq_s32(vmulq_s32(b0, kb2), k134m), 28);
            let r0 = vsubq_s32(b0, vmulq_s32(t0, qv));
            let r0 = vsubq_s32(r0, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(r0, hqv)), qv));
            let r0 = vaddq_s32(
                r0,
                vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(nhqv, r0)), qv),
            );

            // Barrett freeze batch 1, with strict-canonical correction
            let t1 = vshrq_n_s32(vmulq_s32(a1, kb1), 20);
            let b1 = vsubq_s32(a1, vmulq_s32(t1, qv));
            let t1 = vshrq_n_s32(vaddq_s32(vmulq_s32(b1, kb2), k134m), 28);
            let r1 = vsubq_s32(b1, vmulq_s32(t1, qv));
            let r1 = vsubq_s32(r1, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(r1, hqv)), qv));
            let r1 = vaddq_s32(
                r1,
                vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(nhqv, r1)), qv),
            );

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
            let r = vsubq_s32(r, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(r, hqv)), qv));
            let r = vaddq_s32(r, vandq_s32(vreinterpretq_s32_u32(vcgtq_s32(nhqv, r)), qv));

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

/// Divstep elimination pass over `f[1..]`/`g[1..]` (SUPERCOP `vectormodq_swapeliminate`).
///
/// Per 16-lane block: conditional swap of f/g by `mask`, then
/// `g_new = (f0·g − g0·f)·2⁻¹⁶ mod± q` via two signed-Montgomery products,
/// stored one position *down* (the divstep `/x` — inputs are reversed, so the
/// eliminated "leading" coefficient is the constant term). Processes
/// `len.next_multiple_of(16)` elements: every operation is lanewise (plus the
/// fixed −1 store shift), so overrun lanes never contaminate lanes inside the
/// true window; callers provide `1 + len.next_multiple_of(16)` capacity.
///
/// `mask` is applied as a broadcast blend; no branch, index, or bound depends
/// on secret data.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
unsafe fn swapeliminate_avx2(
    f: &mut [i16],
    g: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    unsafe {
        use core::arch::x86_64::*;

        let qw = q as u16;
        let mut qinv = qw;
        for _ in 0..3 {
            qinv = qinv.wrapping_mul(2u16.wrapping_sub(qw.wrapping_mul(qinv)));
        }
        #[allow(clippy::cast_possible_truncation)]
        let qv = _mm256_set1_epi16(q as i16);
        let f0v = _mm256_set1_epi16(f0);
        let g0v = _mm256_set1_epi16(g0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let f0qinv = _mm256_set1_epi16((f0 as u16).wrapping_mul(qinv) as i16);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let g0qinv = _mm256_set1_epi16((g0 as u16).wrapping_mul(qinv) as i16);
        let mv = _mm256_set1_epi16(mask as i16);

        let mut k = 0usize;
        let blocks = len.div_ceil(16);
        while k < blocks * 16 {
            let fi = _mm256_loadu_si256(f.as_ptr().add(1 + k) as *const __m256i);
            let gi = _mm256_loadu_si256(g.as_ptr().add(1 + k) as *const __m256i);
            let fnew = _mm256_blendv_epi8(fi, gi, mv);
            let gnew = _mm256_blendv_epi8(gi, fi, mv);
            // (f0·g_new − g0·f_new)·2⁻¹⁶, each product |.| < q so the difference
            // stays well inside i16.
            let a = _mm256_sub_epi16(
                _mm256_mulhi_epi16(gnew, f0v),
                _mm256_mulhi_epi16(_mm256_mullo_epi16(gnew, f0qinv), qv),
            );
            let b = _mm256_sub_epi16(
                _mm256_mulhi_epi16(fnew, g0v),
                _mm256_mulhi_epi16(_mm256_mullo_epi16(fnew, g0qinv), qv),
            );
            let gout = _mm256_sub_epi16(a, b);
            _mm256_storeu_si256(f.as_mut_ptr().add(1 + k) as *mut __m256i, fnew);
            _mm256_storeu_si256(g.as_mut_ptr().add(k) as *mut __m256i, gout);
            k += 16;
        }
    }
}

/// Divstep Bezout-side pass over `v`/`r` (SUPERCOP `vectormodq_xswapeliminate`).
///
/// Same elimination as [`swapeliminate`], but `v` is stored one position *up*
/// (multiply by x) and `r` in place, iterating backward so the +1-shifted
/// stores never clobber unread inputs. Capacity contract as above.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
unsafe fn xswapeliminate_avx2(
    v: &mut [i16],
    r: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    unsafe {
        use core::arch::x86_64::*;

        let qw = q as u16;
        let mut qinv = qw;
        for _ in 0..3 {
            qinv = qinv.wrapping_mul(2u16.wrapping_sub(qw.wrapping_mul(qinv)));
        }
        #[allow(clippy::cast_possible_truncation)]
        let qv = _mm256_set1_epi16(q as i16);
        let f0v = _mm256_set1_epi16(f0);
        let g0v = _mm256_set1_epi16(g0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let f0qinv = _mm256_set1_epi16((f0 as u16).wrapping_mul(qinv) as i16);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let g0qinv = _mm256_set1_epi16((g0 as u16).wrapping_mul(qinv) as i16);
        let mv = _mm256_set1_epi16(mask as i16);

        // Descending traversal is required: the `v` store is shifted up by one,
        // so an ascending pass would clobber the next block's first input. A
        // forward variant that carries that input in a register measured 19%
        // slower on key generation when this was the dispatched kernel — the
        // extra per-iteration branch and loop-carried register dependency cost
        // more than any prefetch gain.
        let mut k = (len.div_ceil(16) * 16) as isize;
        while k > 0 {
            k -= 16;
            let ku = k as usize;
            let vi = _mm256_loadu_si256(v.as_ptr().add(ku) as *const __m256i);
            let ri = _mm256_loadu_si256(r.as_ptr().add(ku) as *const __m256i);
            let vnew = _mm256_blendv_epi8(vi, ri, mv);
            let rnew = _mm256_blendv_epi8(ri, vi, mv);
            let a = _mm256_sub_epi16(
                _mm256_mulhi_epi16(rnew, f0v),
                _mm256_mulhi_epi16(_mm256_mullo_epi16(rnew, f0qinv), qv),
            );
            let b = _mm256_sub_epi16(
                _mm256_mulhi_epi16(vnew, g0v),
                _mm256_mulhi_epi16(_mm256_mullo_epi16(vnew, g0qinv), qv),
            );
            let rout = _mm256_sub_epi16(a, b);
            _mm256_storeu_si256(v.as_mut_ptr().add(ku + 1) as *mut __m256i, vnew);
            _mm256_storeu_si256(r.as_mut_ptr().add(ku) as *mut __m256i, rout);
        }
    }
}

/// AVX-512 form of [`swapeliminate_avx2`]: 32 coefficients per iteration.
///
/// Neither PQClean nor liboqs has a 512-bit path for this KEM, and the divstep
/// elimination passes dominate key generation, so doubling the lane count was
/// worth roughly 12% of the whole operation. `mask` is all-ones or all-zero, so it maps
/// directly onto a `__mmask32` and the blend needs no vector constant at all.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx512f,avx512bw,avx512vl")]
#[allow(unsafe_code)]
unsafe fn swapeliminate_avx512(
    f: &mut [i16],
    g: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    unsafe {
        use core::arch::x86_64::*;

        let (qv, f0v, g0v, f0qinv, g0qinv) = avx512_operands(f0, g0, q);
        // -1 selects the swapped operand in every lane, 0 selects neither.
        // `__mmask32` is `u32`; the all-ones/all-zero mask maps straight onto it.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let km: __mmask32 = mask as u32;

        let mut k = 0usize;
        let blocks = len.div_ceil(32);
        while k < blocks * 32 {
            let fi = _mm512_loadu_si512(f.as_ptr().add(1 + k).cast());
            let gi = _mm512_loadu_si512(g.as_ptr().add(1 + k).cast());
            let fnew = _mm512_mask_blend_epi16(km, fi, gi);
            let gnew = _mm512_mask_blend_epi16(km, gi, fi);
            let a = _mm512_sub_epi16(
                _mm512_mulhi_epi16(gnew, f0v),
                _mm512_mulhi_epi16(_mm512_mullo_epi16(gnew, f0qinv), qv),
            );
            let b = _mm512_sub_epi16(
                _mm512_mulhi_epi16(fnew, g0v),
                _mm512_mulhi_epi16(_mm512_mullo_epi16(fnew, g0qinv), qv),
            );
            let gout = _mm512_sub_epi16(a, b);
            _mm512_storeu_si512(f.as_mut_ptr().add(1 + k).cast(), fnew);
            _mm512_storeu_si512(g.as_mut_ptr().add(k).cast(), gout);
            k += 32;
        }
    }
}

/// AVX-512 form of [`xswapeliminate_avx2`]: 32 coefficients per iteration,
/// descending for the same reason the 256-bit pass is.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx512f,avx512bw,avx512vl")]
#[allow(unsafe_code)]
unsafe fn xswapeliminate_avx512(
    v: &mut [i16],
    r: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    unsafe {
        use core::arch::x86_64::*;

        let (qv, f0v, g0v, f0qinv, g0qinv) = avx512_operands(f0, g0, q);
        // `__mmask32` is `u32`; the all-ones/all-zero mask maps straight onto it.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let km: __mmask32 = mask as u32;

        let mut k = (len.div_ceil(32) * 32) as isize;
        while k > 0 {
            k -= 32;
            let ku = k as usize;
            let vi = _mm512_loadu_si512(v.as_ptr().add(ku).cast());
            let ri = _mm512_loadu_si512(r.as_ptr().add(ku).cast());
            let vnew = _mm512_mask_blend_epi16(km, vi, ri);
            let rnew = _mm512_mask_blend_epi16(km, ri, vi);
            let a = _mm512_sub_epi16(
                _mm512_mulhi_epi16(rnew, f0v),
                _mm512_mulhi_epi16(_mm512_mullo_epi16(rnew, f0qinv), qv),
            );
            let b = _mm512_sub_epi16(
                _mm512_mulhi_epi16(vnew, g0v),
                _mm512_mulhi_epi16(_mm512_mullo_epi16(vnew, g0qinv), qv),
            );
            let rout = _mm512_sub_epi16(a, b);
            _mm512_storeu_si512(v.as_mut_ptr().add(ku + 1).cast(), vnew);
            _mm512_storeu_si512(r.as_mut_ptr().add(ku).cast(), rout);
        }
    }
}

/// Broadcast Montgomery operands shared by the two 512-bit divstep kernels:
/// `q^-1 mod 2^16` by Newton iteration, then `q`, `f0`, `g0` and the two
/// pre-multiplied inverses.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx512f,avx512bw,avx512vl")]
#[allow(unsafe_code, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn avx512_operands(
    f0: i16,
    g0: i16,
    q: i32,
) -> (
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
    core::arch::x86_64::__m512i,
) {
    use core::arch::x86_64::*;
    let qw = q as u16;
    let mut qinv = qw;
    for _ in 0..3 {
        qinv = qinv.wrapping_mul(2u16.wrapping_sub(qw.wrapping_mul(qinv)));
    }
    (
        _mm512_set1_epi16(q as i16),
        _mm512_set1_epi16(f0),
        _mm512_set1_epi16(g0),
        _mm512_set1_epi16((f0 as u16).wrapping_mul(qinv) as i16),
        _mm512_set1_epi16((g0 as u16).wrapping_mul(qinv) as i16),
    )
}

/// Dispatching entry point for the divstep elimination pass over `f`/`g`.
///
/// See [`swapeliminate_avx2`] for the semantics. The three kernels differ only
/// in width: AVX-512 takes 32 coefficients per step, AVX2 sixteen and NEON
/// eight. All produce identical output; `reciprocal3` keeps the pre-divstep
/// elimination algorithm as both the fallback and the differential oracle.
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(feature = "force-scalar")
))]
#[inline(always)]
pub fn swapeliminate(
    f: &mut [i16],
    g: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::cpu::has_avx512() {
            // SAFETY: AVX-512 F/BW/VL confirmed present at runtime.
            unsafe { swapeliminate_avx512(f, g, len, f0, g0, mask, q) }
        } else {
            // SAFETY: callers reach this only when has_avx2() is true.
            unsafe { swapeliminate_avx2(f, g, len, f0, g0, mask, q) }
        }
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: NEON is baseline on aarch64.
    unsafe {
        swapeliminate_neon(f, g, len, f0, g0, mask, q);
    }
}

/// Dispatching entry point for the Bezout-side divstep pass over `v`/`r`, with
/// the same width dispatch as [`swapeliminate`].
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(feature = "force-scalar")
))]
#[inline(always)]
pub fn xswapeliminate(
    v: &mut [i16],
    r: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::cpu::has_avx512() {
            // SAFETY: AVX-512 F/BW/VL confirmed present at runtime.
            unsafe { xswapeliminate_avx512(v, r, len, f0, g0, mask, q) }
        } else {
            // SAFETY: callers reach this only when has_avx2() is true.
            unsafe { xswapeliminate_avx2(v, r, len, f0, g0, mask, q) }
        }
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: NEON is baseline on aarch64.
    unsafe {
        xswapeliminate_neon(v, r, len, f0, g0, mask, q);
    }
}

/// Montgomery constants shared by the NEON divstep kernels: `q^-1 mod 2^16` by
/// Newton iteration, plus the broadcast operands.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
fn neon_qinv(q: i32) -> u16 {
    let qw = q as u16;
    let mut qinv = qw;
    for _ in 0..3 {
        qinv = qinv.wrapping_mul(2u16.wrapping_sub(qw.wrapping_mul(qinv)));
    }
    qinv
}

/// Signed high-half product of two i16 vectors — NEON has no single `mulhi`,
/// so widen with `vmull`/`vmull_high` and take the odd (high) halves with
/// `vuzp2q`. Three instructions, exact.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
unsafe fn mulhi_neon(
    a: core::arch::aarch64::int16x8_t,
    b: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        let lo = vmull_s16(vget_low_s16(a), vget_low_s16(b));
        let hi = vmull_high_s16(a, b);
        vuzp2q_s16(vreinterpretq_s16_s32(lo), vreinterpretq_s16_s32(hi))
    }
}

/// `x·y·2^-16 mod± q` (signed Montgomery), with `yqinv = y·q^-1 mod 2^16`.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[inline(always)]
unsafe fn montproduct_neon(
    x: core::arch::aarch64::int16x8_t,
    y: core::arch::aarch64::int16x8_t,
    yqinv: core::arch::aarch64::int16x8_t,
    qv: core::arch::aarch64::int16x8_t,
) -> core::arch::aarch64::int16x8_t {
    unsafe {
        use core::arch::aarch64::*;
        let b = mulhi_neon(x, y);
        let d = vmulq_s16(x, yqinv);
        let e = mulhi_neon(d, qv);
        vsubq_s16(b, e)
    }
}

/// NEON divstep elimination over `f[1..]`/`g[1..]`, eight lanes per block.
/// Mirrors [`swapeliminate_avx2`]: conditional swap by `mask`, then
/// `g_new = (f0·g − g0·f)·2^-16 mod± q` stored one position down.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn swapeliminate_neon(
    f: &mut [i16],
    g: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    unsafe {
        use core::arch::aarch64::*;

        let qinv = neon_qinv(q);
        #[allow(clippy::cast_possible_truncation)]
        let qv = vdupq_n_s16(q as i16);
        let f0v = vdupq_n_s16(f0);
        let g0v = vdupq_n_s16(g0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let f0qinv = vdupq_n_s16((f0 as u16).wrapping_mul(qinv) as i16);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let g0qinv = vdupq_n_s16((g0 as u16).wrapping_mul(qinv) as i16);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mv = vreinterpretq_u16_s16(vdupq_n_s16(mask as i16));

        let mut k = 0usize;
        let blocks = len.div_ceil(8);
        while k < blocks * 8 {
            let fi = vld1q_s16(f.as_ptr().add(1 + k));
            let gi = vld1q_s16(g.as_ptr().add(1 + k));
            let fnew = vbslq_s16(mv, gi, fi);
            let gnew = vbslq_s16(mv, fi, gi);
            let a = montproduct_neon(gnew, f0v, f0qinv, qv);
            let b = montproduct_neon(fnew, g0v, g0qinv, qv);
            let gout = vsubq_s16(a, b);
            vst1q_s16(f.as_mut_ptr().add(1 + k), fnew);
            vst1q_s16(g.as_mut_ptr().add(k), gout);
            k += 8;
        }
    }
}

/// NEON Bezout-side divstep pass. Mirrors [`xswapeliminate_avx2`]: `v` stores
/// one position up, `r` in place, iterating backward so the shifted stores
/// never clobber unread inputs.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
unsafe fn xswapeliminate_neon(
    v: &mut [i16],
    r: &mut [i16],
    len: usize,
    f0: i16,
    g0: i16,
    mask: isize,
    q: i32,
) {
    unsafe {
        use core::arch::aarch64::*;

        let qinv = neon_qinv(q);
        #[allow(clippy::cast_possible_truncation)]
        let qv = vdupq_n_s16(q as i16);
        let f0v = vdupq_n_s16(f0);
        let g0v = vdupq_n_s16(g0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let f0qinv = vdupq_n_s16((f0 as u16).wrapping_mul(qinv) as i16);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let g0qinv = vdupq_n_s16((g0 as u16).wrapping_mul(qinv) as i16);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let mv = vreinterpretq_u16_s16(vdupq_n_s16(mask as i16));

        #[allow(clippy::cast_possible_wrap)]
        let mut k = (len.div_ceil(8) * 8) as isize;
        while k > 0 {
            k -= 8;
            #[allow(clippy::cast_sign_loss)]
            let ku = k as usize;
            let vi = vld1q_s16(v.as_ptr().add(ku));
            let ri = vld1q_s16(r.as_ptr().add(ku));
            let vnew = vbslq_s16(mv, ri, vi);
            let rnew = vbslq_s16(mv, vi, ri);
            let a = montproduct_neon(rnew, f0v, f0qinv, qv);
            let b = montproduct_neon(vnew, g0v, g0qinv, qv);
            let rout = vsubq_s16(a, b);
            vst1q_s16(v.as_mut_ptr().add(ku + 1), vnew);
            vst1q_s16(r.as_mut_ptr().add(ku), rout);
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The fused kernel must match scalar minus_product_shift + scalar swap
    /// exactly, for both mask values, at every parameter set's q and at
    /// lengths that exercise the vector loop, the overlapped bottom block,
    /// and the scalar path.
    #[test]
    fn fused_cswap_matches_two_pass_reference() {
        let mut s = 0x1234_5678_9abc_def1u64;
        for &(q, b1, b2) in &[
            (4621i32, 226i32, 58084i32),
            (4591, 228, 58464),
            (5167, 202, 51948),
            (6343, 165, 42324),
            (7177, 146, 37410),
            (7879, 133, 34073),
        ] {
            let params = crate::params::SntrupParameters {
                p: 0,
                q,
                w: 0,
                q12: (q - 1) / 2,
                small_encode_size: 0,
                rounded_encode_size: 0,
                pk_size: 0,
                sk_size: 0,
                ct_size: 0,
                barrett1: b1,
                barrett2: b2,
            };
            let hq = ((q - 1) / 2) as i16;
            for &n in &[2usize, 5, 16, 17, 33, 762, 768, 1524] {
                for &mask in &[0isize, -1] {
                    let sample =
                        |s: &mut u64| ((next(s) % (2 * hq as u64 + 1)) as i32 - hq as i32) as i16;
                    let z0: Vec<i16> = (0..n).map(|_| sample(&mut s)).collect();
                    let y0: Vec<i16> = (0..n).map(|_| sample(&mut s)).collect();
                    let c: i16 = sample(&mut s);

                    let mut z_ref = z0.clone();
                    let mut y_ref = y0.clone();
                    minus_product_shift_scalar(&mut z_ref, n, &y_ref, c, q, b1, b2);
                    swap_scalar(&mut z_ref, &mut y_ref, n, mask);

                    let mut z_got = z0.clone();
                    let mut y_got = y0.clone();
                    minus_product_shift_cswap(&mut z_got, &mut y_got, n, c, mask, &params);

                    assert_eq!(z_got, z_ref, "z mismatch q={q} n={n} mask={mask}");
                    assert_eq!(y_got, y_ref, "y mismatch q={q} n={n} mask={mask}");
                }
            }
        }
    }
}
