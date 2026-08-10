//! AVX2 kernels for the packed-ternary small-polynomial codec (`x3`).
//!
//! A small polynomial has coefficients in {-1, 0, 1}; the wire format shifts
//! each to {0, 1, 2} and packs four per byte, low trit first. Every parameter
//! set has `p - 1` divisible by 4, so the bulk is a clean 4:1 repack and only
//! the final coefficient needs separate handling — which the callers in
//! [`crate::zx::encoding`] do.
//!
//! The scalar forms these replace cost roughly 27x what liboqs spends on the
//! same work, which made them the largest non-algorithmic item in a
//! decapsulation profile despite touching only ~190 bytes.

use core::arch::x86_64::*;

/// Packs the `4 * out.len()` trits of `f` into `out`, four per byte.
///
/// # Panics
/// Debug-only: `f.len()` must be exactly `4 * out.len()`.
#[target_feature(enable = "avx2")]
pub(crate) fn encode_avx2(f: &[i8], out: &mut [u8]) {
    debug_assert_eq!(f.len(), 4 * out.len());
    unsafe {
        // maddubs pairs adjacent trits as t0 + 4*t1 (max 10, no overflow of the
        // signed 16-bit accumulator); madd then folds pairs of those as
        // x0 + 16*x1, which is exactly the four-trit byte value.
        let w_lo = _mm256_set1_epi16(0x0401);
        let w_hi = _mm256_set1_epi32(0x0010_0001);
        // Byte 0 of each 32-bit lane holds one packed output byte.
        let gather = _mm256_setr_epi8(
            0, 4, 8, 12, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 4, 8, 12, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1,
        );
        let one = _mm256_set1_epi8(1);

        let blocks = out.len() / 8;
        for b in 0..blocks {
            let t = _mm256_loadu_si256(f.as_ptr().add(32 * b) as *const __m256i);
            let t = _mm256_add_epi8(t, one);
            let p16 = _mm256_maddubs_epi16(t, w_lo);
            let p32 = _mm256_madd_epi16(p16, w_hi);
            let packed = _mm256_shuffle_epi8(p32, gather);
            let lo = _mm256_castsi256_si128(packed);
            let hi = _mm256_extracti128_si256(packed, 1);
            _mm_storel_epi64(
                out.as_mut_ptr().add(8 * b) as *mut __m128i,
                _mm_unpacklo_epi32(lo, hi),
            );
        }

        for i in (8 * blocks)..out.len() {
            let q = &f[4 * i..4 * i + 4];
            let t = |x: i8| u8::from_ne_bytes((x + 1).to_ne_bytes());
            out[i] = t(q[0]) | (t(q[1]) << 2) | (t(q[2]) << 4) | (t(q[3]) << 6);
        }
    }
}

/// Unpacks the `4 * src.len()` trits packed in `src` into `f`.
///
/// # Panics
/// Debug-only: `f.len()` must be exactly `4 * src.len()`.
#[target_feature(enable = "avx2")]
pub(crate) fn decode_avx2(src: &[u8], f: &mut [i8]) {
    debug_assert_eq!(f.len(), 4 * src.len());
    unsafe {
        // Each input byte becomes four output bytes, so a 32-bit output lane is
        // one input byte replicated; the four trits then live at shifts 0/2/4/6
        // of that lane. Shifting the whole lane by each amount and selecting the
        // one byte that lands correctly is cheaper than any per-byte shift.
        let spread = _mm256_setr_epi8(
            0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7,
            7, 7, 7,
        );
        let m1 = _mm256_set1_epi32(0x0000_FF00);
        let m2 = _mm256_set1_epi32(0x00FF_0000);
        // 0xFF00_0000 does not fit a positive `i32`; build it by shifting.
        let m3 = _mm256_slli_epi32::<24>(_mm256_set1_epi32(0xFF));
        let three = _mm256_set1_epi8(3);
        let one = _mm256_set1_epi8(1);

        let blocks = src.len() / 8;
        for b in 0..blocks {
            let raw = _mm_loadl_epi64(src.as_ptr().add(8 * b) as *const __m128i);
            let r = _mm256_shuffle_epi8(_mm256_broadcastsi128_si256(raw), spread);
            let v = _mm256_blendv_epi8(r, _mm256_srli_epi32(r, 2), m1);
            let v = _mm256_blendv_epi8(v, _mm256_srli_epi32(r, 4), m2);
            let v = _mm256_blendv_epi8(v, _mm256_srli_epi32(r, 6), m3);
            let v = _mm256_sub_epi8(_mm256_and_si256(v, three), one);
            _mm256_storeu_si256(f.as_mut_ptr().add(32 * b) as *mut __m256i, v);
        }

        for i in (8 * blocks)..src.len() {
            let byte = src[i];
            for j in 0..4 {
                f[4 * i + j] = i8::from_ne_bytes([((byte >> (2 * j)) & 3)]) - 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_encode(f: &[i8], out: &mut [u8]) {
        for (byte, q) in out.iter_mut().zip(f.chunks(4)) {
            let t = |x: i8| u8::from_ne_bytes((x + 1).to_ne_bytes());
            *byte = t(q[0]) | (t(q[1]) << 2) | (t(q[2]) << 4) | (t(q[3]) << 6);
        }
    }

    fn scalar_decode(src: &[u8], f: &mut [i8]) {
        for (byte, q) in src.iter().zip(f.chunks_mut(4)) {
            for (j, slot) in q.iter_mut().enumerate() {
                *slot = i8::from_ne_bytes([((byte >> (2 * j)) & 3)]) - 1;
            }
        }
    }

    /// Deterministic ternary stream: covers every trit in every lane position.
    fn trits(n: usize, seed: u64) -> Vec<i8> {
        let mut s = seed | 1;
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                i8::try_from((s >> 33) % 3).unwrap_or(0) - 1
            })
            .collect()
    }

    #[test]
    fn kernels_match_scalar_over_every_parameter_length() {
        if !crate::cpu::has_avx2() {
            return;
        }
        // Every real `small_encode_size - 1`, plus lengths around the 8-byte
        // block boundary so the scalar tail is exercised in all residues.
        let lens: Vec<usize> = (0usize..24).chain([163, 190, 214, 238, 253, 319]).collect();
        for n in lens {
            for seed in 0..4u64 {
                let f = trits(4 * n, seed * 7 + 1);
                let (mut a, mut b) = (vec![0u8; n], vec![0u8; n]);
                scalar_encode(&f, &mut a);
                unsafe { encode_avx2(&f, &mut b) };
                assert_eq!(a, b, "encode mismatch at n={n} seed={seed}");

                let (mut x, mut y) = (vec![0i8; 4 * n], vec![0i8; 4 * n]);
                scalar_decode(&a, &mut x);
                unsafe { decode_avx2(&a, &mut y) };
                assert_eq!(x, y, "decode mismatch at n={n} seed={seed}");
                assert_eq!(x, f, "decode is not the inverse of encode at n={n}");
            }
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let src: Vec<u8> = (0..=255u8).collect();
        let mut f = vec![0i8; 4 * src.len()];
        unsafe { decode_avx2(&src, &mut f) };
        let mut back = vec![0u8; src.len()];
        unsafe { encode_avx2(&f, &mut back) };
        assert_eq!(src, back);
    }
}
