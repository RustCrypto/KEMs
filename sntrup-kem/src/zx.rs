#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
mod codec3;
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
mod djbsort;

/// Small-element (ternary) encoding and decoding.
pub mod encoding {
    /// Encode a small polynomial `f` of length `p` into `small_encode_size` bytes.
    ///
    /// Packs 4 trits per byte (each trit shifted to {0,1,2} by adding 1).
    /// The last byte holds `f[p-1] + 1`.
    #[allow(clippy::cast_sign_loss)]
    pub fn encode(f: &[i8], p: usize, small_encode_size: usize) -> Vec<u8> {
        let mut c = vec![0u8; small_encode_size];
        encode_into(f, &mut c, p, small_encode_size);
        c
    }

    /// Allocation-free form of [`encode`]: writes into `c[..small_encode_size]`.
    #[allow(clippy::cast_sign_loss)]
    pub fn encode_into(f: &[i8], c: &mut [u8], p: usize, small_encode_size: usize) {
        let n = small_encode_size - 1;
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            // SAFETY: AVX2 confirmed present at runtime. `p - 1 == 4 * n` holds
            // for every parameter set, which is the kernel's length contract.
            unsafe { super::codec3::encode_avx2(&f[..4 * n], &mut c[..n]) };
            c[n] = (f[p - 1] + 1) as u8;
            return;
        }
        for (byte, chunk) in c[..n].iter_mut().zip(f.chunks(4)) {
            let mut c0 = chunk[0] + 1;
            c0 += (chunk[1] + 1) << 2;
            c0 += (chunk[2] + 1) << 4;
            c0 += (chunk[3] + 1) << 6;
            *byte = c0 as u8;
        }
        c[small_encode_size - 1] = (f[p - 1] + 1) as u8;
    }

    /// Allocation-free form of [`decode`]: writes into `f[..p]`.
    #[allow(clippy::cast_possible_wrap)]
    pub fn decode_into(c: &[u8], f: &mut [i8], p: usize) {
        let small_encode_size = c.len();
        let n = small_encode_size - 1;
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            // SAFETY: AVX2 confirmed present at runtime; `p - 1 == 4 * n`.
            unsafe { super::codec3::decode_avx2(&c[..n], &mut f[..4 * n]) };
            f[p - 1] = ((c[n] & 3) as i8) - 1;
            return;
        }
        for (byte, chunk) in c[..n].iter().zip(f.chunks_mut(4)) {
            let mut c0 = *byte;
            chunk[0] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            chunk[1] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            chunk[2] = ((c0 & 3) as i8) - 1;
            c0 >>= 2;
            chunk[3] = ((c0 & 3) as i8) - 1;
        }
        f[p - 1] = ((c[small_encode_size - 1] & 3) as i8) - 1;
    }
}

/// Random polynomial generation and constant-time sorting.
pub mod random {
    use rand::Rng;
    use rand::RngExt;

    /// Branchless constant-time min/max swap (djbsort int32_minmax).
    /// Operates on a slice with two indices to avoid borrow issues.
    ///
    /// Uses wrapping i32 subtraction (matching the original djbsort algorithm)
    /// with an XOR fixup for overflow. The `>> 31` extracts the sign bit.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    fn int32_minmax(x: &mut [i32], i: usize, j: usize) {
        let ab = x[j] ^ x[i];
        let mut c = x[j].wrapping_sub(x[i]);
        c ^= ab & (c ^ x[j]);
        c >>= 31;
        c &= ab;
        x[i] ^= c;
        x[j] ^= c;
    }

    /// Constant-time sort of `n` elements of `x`, dispatching to the best
    /// available implementation.
    ///
    /// On x86_64 with AVX2 this is the port of djb's `crypto_sort_int32`, whose
    /// register-blocked merges keep every lane live; the Batcher network below
    /// runs at roughly half lane utilisation and is ~7.6x slower at p = 761.
    /// Both are differentially tested against each other.
    #[allow(unsafe_code)]
    pub fn sort(x: &mut [i32], n: usize) {
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if crate::cpu::has_avx2() {
            // SAFETY: AVX2 support confirmed by has_avx2()
            unsafe {
                return super::djbsort::sort(x, n);
            }
        }
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        if false {
            // SAFETY: unreachable; retained as the differential oracle.
            unsafe {
                return sort_avx2(x, n);
            }
        }
        #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
        // SAFETY: NEON is baseline on aarch64
        unsafe {
            return sort_neon(x, n);
        }
        #[allow(unreachable_code)]
        sort_scalar(x, n);
    }

    fn sort_scalar(x: &mut [i32], n: usize) {
        if n < 2 {
            return;
        }
        let mut top = 1;
        while top < (n - top) {
            top += top;
        }
        let mut p = top;
        while p > 0 {
            for i in 0..(n - p) {
                if i & p == 0 {
                    int32_minmax(x, i, i + p);
                }
            }
            let mut q = top;
            while q > p {
                for i in 0..(n - q) {
                    if i & p == 0 {
                        int32_minmax(x, i + p, i + q);
                    }
                }
                q >>= 1;
            }
            p >>= 1;
        }
    }

    /// AVX2-accelerated Batcher bitonic sort.
    /// Uses _mm256_min/max_epi32 for 8 parallel comparators when stride >= 8.
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    #[target_feature(enable = "avx2")]
    #[allow(unsafe_code)]
    unsafe fn sort_avx2(x: &mut [i32], n: usize) {
        unsafe {
            if n < 2 {
                return;
            }
            let mut top = 1;
            while top < (n - top) {
                top += top;
            }
            let mut p = top;
            while p > 0 {
                // First pass: comparators at stride p
                minmax_pass_avx2(x, n, p, 0, p);

                // Sub-passes
                let mut q = top;
                while q > p {
                    minmax_pass_avx2(x, n, p, p, q);
                    q >>= 1;
                }
                p >>= 1;
            }
        }
    }

    /// Process one pass of comparators: minmax(x[i+off0], x[i+off1])
    /// for all i in 0..(n-off1) where i & p_mask == 0.
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    #[target_feature(enable = "avx2")]
    #[allow(unsafe_code)]
    unsafe fn minmax_pass_avx2(x: &mut [i32], n: usize, p_mask: usize, off0: usize, off1: usize) {
        unsafe {
            use core::arch::x86_64::*;

            let end = n.saturating_sub(off1);
            if p_mask >= 8 {
                // When p_mask >= 8, the condition i & p_mask == 0 selects contiguous
                // blocks of p_mask elements. Process 8 at a time with SIMD.
                let mut i = 0;
                while i < end {
                    if i & p_mask == 0 {
                        let block_end = (i + p_mask).min(end);
                        let mut j = i;
                        while j + 8 <= block_end {
                            let a = _mm256_loadu_si256(x.as_ptr().add(j + off0) as *const __m256i);
                            let b = _mm256_loadu_si256(x.as_ptr().add(j + off1) as *const __m256i);
                            _mm256_storeu_si256(
                                x.as_mut_ptr().add(j + off0) as *mut __m256i,
                                _mm256_min_epi32(a, b),
                            );
                            _mm256_storeu_si256(
                                x.as_mut_ptr().add(j + off1) as *mut __m256i,
                                _mm256_max_epi32(a, b),
                            );
                            j += 8;
                        }
                        // Scalar remainder for this block
                        while j < block_end {
                            int32_minmax(x, j + off0, j + off1);
                            j += 1;
                        }
                        i = block_end + p_mask; // skip the next block (i & p_mask != 0)
                    } else {
                        i += 1;
                    }
                }
            } else if off0 == 0 && off1 == p_mask {
                // Register-local pass at stride p ∈ {1,2,4}: within one 8-lane
                // block, lane l pairs with lane l ^ p. One load, one permute,
                // min/max, one const-immediate blend, one store.
                let mut i0 = 0usize;
                macro_rules! local_pass {
                    ($swap:expr, $imm:literal) => {
                        while i0 + 8 <= end {
                            let v = _mm256_loadu_si256(x.as_ptr().add(i0) as *const __m256i);
                            let w = $swap(v);
                            let mn = _mm256_min_epi32(v, w);
                            let mx = _mm256_max_epi32(v, w);
                            _mm256_storeu_si256(
                                x.as_mut_ptr().add(i0) as *mut __m256i,
                                _mm256_blend_epi32::<$imm>(mn, mx),
                            );
                            i0 += 8;
                        }
                    };
                }
                match p_mask {
                    4 => local_pass!(|v| _mm256_permute4x64_epi64::<0x4E>(v), 0b1111_0000),
                    2 => local_pass!(|v| _mm256_shuffle_epi32::<0x4E>(v), 0b1100_1100),
                    _ => local_pass!(|v| _mm256_shuffle_epi32::<0xB1>(v), 0b1010_1010),
                }
                for i in i0..end {
                    if i & p_mask == 0 {
                        int32_minmax(x, i + off0, i + off1);
                    }
                }
            } else if off1 >= 8 {
                // Sub-pass with small selection stride p ∈ {1,2,4} but distant
                // partner (off1 ≥ 8): two loads at the two offsets, min/max, and a
                // const-immediate blend keeps inactive lanes (l & p ≠ 0) unchanged.
                let mut i0 = 0usize;
                macro_rules! masked_pass {
                    ($imm:literal) => {
                        while i0 + 8 <= end {
                            let a = _mm256_loadu_si256(x.as_ptr().add(i0 + off0) as *const __m256i);
                            let b = _mm256_loadu_si256(x.as_ptr().add(i0 + off1) as *const __m256i);
                            let mn = _mm256_min_epi32(a, b);
                            let mx = _mm256_max_epi32(a, b);
                            _mm256_storeu_si256(
                                x.as_mut_ptr().add(i0 + off0) as *mut __m256i,
                                _mm256_blend_epi32::<$imm>(a, mn),
                            );
                            _mm256_storeu_si256(
                                x.as_mut_ptr().add(i0 + off1) as *mut __m256i,
                                _mm256_blend_epi32::<$imm>(b, mx),
                            );
                            i0 += 8;
                        }
                    };
                }
                match p_mask {
                    4 => masked_pass!(0b0000_1111),
                    2 => masked_pass!(0b0011_0011),
                    _ => masked_pass!(0b0101_0101),
                }
                for i in i0..end {
                    if i & p_mask == 0 {
                        int32_minmax(x, i + off0, i + off1);
                    }
                }
            } else {
                // Small p with nearby partner (off1 < 8): overlapping-store hazard,
                // scalar. Only the (2,2,4), (1,1,2), (1,1,4) shapes land here.
                for i in 0..end {
                    if i & p_mask == 0 {
                        int32_minmax(x, i + off0, i + off1);
                    }
                }
            }
        }
    }

    /// NEON-accelerated Batcher bitonic sort.
    /// Uses vminq_s32/vmaxq_s32 for 4 parallel comparators when stride >= 4.
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    #[allow(unsafe_code)]
    unsafe fn sort_neon(x: &mut [i32], n: usize) {
        unsafe {
            if n < 2 {
                return;
            }
            let mut top = 1;
            while top < (n - top) {
                top += top;
            }
            let mut p = top;
            while p > 0 {
                // First pass: comparators at stride p
                minmax_pass_neon(x, n, p, 0, p);

                // Sub-passes
                let mut q = top;
                while q > p {
                    minmax_pass_neon(x, n, p, p, q);
                    q >>= 1;
                }
                p >>= 1;
            }
        }
    }

    /// Process one pass of comparators with NEON.
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    #[allow(unsafe_code)]
    unsafe fn minmax_pass_neon(x: &mut [i32], n: usize, p_mask: usize, off0: usize, off1: usize) {
        unsafe {
            use core::arch::aarch64::*;

            let end = n.saturating_sub(off1);
            if p_mask >= 4 {
                // Contiguous blocks of p_mask elements; four vectors per iteration for ILP.
                let mut i = 0;
                while i < end {
                    if i & p_mask == 0 {
                        let block_end = (i + p_mask).min(end);
                        let mut j = i;
                        while j + 16 <= block_end {
                            let a0 = vld1q_s32(x.as_ptr().add(j + off0));
                            let a1 = vld1q_s32(x.as_ptr().add(j + off0 + 4));
                            let a2 = vld1q_s32(x.as_ptr().add(j + off0 + 8));
                            let a3 = vld1q_s32(x.as_ptr().add(j + off0 + 12));
                            let b0 = vld1q_s32(x.as_ptr().add(j + off1));
                            let b1 = vld1q_s32(x.as_ptr().add(j + off1 + 4));
                            let b2 = vld1q_s32(x.as_ptr().add(j + off1 + 8));
                            let b3 = vld1q_s32(x.as_ptr().add(j + off1 + 12));
                            vst1q_s32(x.as_mut_ptr().add(j + off0), vminq_s32(a0, b0));
                            vst1q_s32(x.as_mut_ptr().add(j + off0 + 4), vminq_s32(a1, b1));
                            vst1q_s32(x.as_mut_ptr().add(j + off0 + 8), vminq_s32(a2, b2));
                            vst1q_s32(x.as_mut_ptr().add(j + off0 + 12), vminq_s32(a3, b3));
                            vst1q_s32(x.as_mut_ptr().add(j + off1), vmaxq_s32(a0, b0));
                            vst1q_s32(x.as_mut_ptr().add(j + off1 + 4), vmaxq_s32(a1, b1));
                            vst1q_s32(x.as_mut_ptr().add(j + off1 + 8), vmaxq_s32(a2, b2));
                            vst1q_s32(x.as_mut_ptr().add(j + off1 + 12), vmaxq_s32(a3, b3));
                            j += 16;
                        }
                        while j + 4 <= block_end {
                            let a = vld1q_s32(x.as_ptr().add(j + off0));
                            let b = vld1q_s32(x.as_ptr().add(j + off1));
                            vst1q_s32(x.as_mut_ptr().add(j + off0), vminq_s32(a, b));
                            vst1q_s32(x.as_mut_ptr().add(j + off1), vmaxq_s32(a, b));
                            j += 4;
                        }
                        // Scalar remainder for this block
                        while j < block_end {
                            int32_minmax(x, j + off0, j + off1);
                            j += 1;
                        }
                        i = block_end + p_mask;
                    } else {
                        i += 1;
                    }
                }
            } else if off0 == 0 {
                // Register-local first pass at stride p ∈ {1, 2}: within one 4-lane
                // vector, lane l pairs with lane l ^ p. One load, one in-register
                // partner shuffle, min/max, one constant-mask blend, one store.
                // The blend keeps min in the low lane of each pair and max in the
                // high lane, exactly the scalar comparator's writeback.
                let mut i0 = 0usize;
                if p_mask == 2 {
                    // Partner = lanes rotated by 2 (swap 64-bit halves).
                    let take_max = vcombine_u32(vdup_n_u32(0), vdup_n_u32(u32::MAX));
                    while i0 + 4 <= end {
                        let v = vld1q_s32(x.as_ptr().add(i0));
                        let w = vextq_s32::<2>(v, v);
                        let mn = vminq_s32(v, w);
                        let mx = vmaxq_s32(v, w);
                        vst1q_s32(x.as_mut_ptr().add(i0), vbslq_s32(take_max, mx, mn));
                        i0 += 4;
                    }
                } else {
                    // p = 1: partner = lanes swapped within each 64-bit pair.
                    let take_max = vreinterpretq_u32_u64(vdupq_n_u64(0xFFFF_FFFF_0000_0000));
                    while i0 + 4 <= end {
                        let v = vld1q_s32(x.as_ptr().add(i0));
                        let w = vrev64q_s32(v);
                        let mn = vminq_s32(v, w);
                        let mx = vmaxq_s32(v, w);
                        vst1q_s32(x.as_mut_ptr().add(i0), vbslq_s32(take_max, mx, mn));
                        i0 += 4;
                    }
                }
                for i in i0..end {
                    if i & p_mask == 0 {
                        int32_minmax(x, i + off0, i + off1);
                    }
                }
            } else if off1 >= 4 && !(off0 == 1 && off1 == 2) {
                // Sub-pass with small selection stride p ∈ {1, 2} (off0 == p) and a
                // partner at off1 ≥ 4: two loads, min/max, constant-mask blends keep
                // inactive lanes (l & p ≠ 0) at their loaded values.
                //
                // For off1 = 4 the two 4-lane windows overlap by off1 − off0 ∈ {2, 3}
                // trailing lanes of the low window. Those overlapping low-window lanes
                // are always inactive (their element index has bit `p` set), so the
                // low store writes them back unchanged and the high store — issued
                // after it — supplies their comparator results. The one shape where an
                // overlapping low-window lane is *active*, (p, off0, off1) = (1, 1, 2),
                // is excluded above and stays scalar: either store order would clobber
                // a comparator result there.
                let take_lo = if p_mask == 2 {
                    vcombine_u32(vdup_n_u32(u32::MAX), vdup_n_u32(0))
                } else {
                    vreinterpretq_u32_u64(vdupq_n_u64(0x0000_0000_FFFF_FFFF))
                };
                let mut i0 = 0usize;
                while i0 + 4 <= end {
                    let a = vld1q_s32(x.as_ptr().add(i0 + off0));
                    let b = vld1q_s32(x.as_ptr().add(i0 + off1));
                    let mn = vminq_s32(a, b);
                    let mx = vmaxq_s32(a, b);
                    vst1q_s32(x.as_mut_ptr().add(i0 + off0), vbslq_s32(take_lo, mn, a));
                    vst1q_s32(x.as_mut_ptr().add(i0 + off1), vbslq_s32(take_lo, mx, b));
                    i0 += 4;
                }
                for i in i0..end {
                    if i & p_mask == 0 {
                        int32_minmax(x, i + off0, i + off1);
                    }
                }
            } else {
                // (1, 1, 2): overlapping windows with an active lane in the overlap —
                // scalar is the only correct order.
                for i in 0..end {
                    if i & p_mask == 0 {
                        int32_minmax(x, i + off0, i + off1);
                    }
                }
            }
        }
    }

    /// Fill `g` with random small elements in {-1, 0, 1}.
    #[allow(clippy::cast_sign_loss)]
    pub fn random_small(g: &mut [i8], rng: &mut impl Rng) {
        for val in g.iter_mut() {
            let r: i32 = rng.random();
            *val = ((((1_073_741_823 & (r as u32)) * 3) >> 30) as i8) - 1;
        }
    }

    /// Unsigned sort: XOR with 0x80000000, signed sort, XOR back.
    /// Matches PQClean's crypto_sort_uint32.
    #[allow(clippy::cast_possible_wrap)]
    fn sort_uint32(x: &mut [i32], n: usize) {
        for val in x.iter_mut().take(n) {
            *val ^= 0x80000000u32 as i32;
        }
        sort(x, n);
        for val in x.iter_mut().take(n) {
            *val ^= 0x80000000u32 as i32;
        }
    }

    /// Generate a random ternary polynomial with exactly `w` non-zero entries out of `p`.
    ///
    /// The first `w` positions get weight (odd), the remaining `p - w` get zero (even tag),
    /// then a constant-time sort shuffles them.
    #[allow(clippy::cast_possible_wrap)]
    pub fn random_tsmall(f: &mut [i8], p: usize, w: usize, rng: &mut impl Rng) {
        use crate::params::MAX_P;
        use crate::scratch::uninit_scratch;

        // One bulk RNG call instead of `p` per-element calls. For any `rand_core`
        // generator, `next_u32` is defined as the next four stream bytes little-endian,
        // so a byte fill reinterpreted LE is value-identical to the per-element
        // `rng.random::<i32>()` loop this replaces — the deterministic-keygen KATs
        // pin that equivalence.
        // SAFETY: `fill_bytes` writes all `4 * p` bytes before they are read.
        uninit_scratch!(bytes_buf: [u8; 4 * MAX_P]);
        let bytes = &mut bytes_buf[..4 * p];
        rng.fill_bytes(bytes);

        // SAFETY: every element of `r` is written from `bytes` before being read.
        uninit_scratch!(r_buf: [i32; MAX_P]);
        let r = &mut r_buf[..p];
        for (val, chunk) in r.iter_mut().zip(bytes.chunks_exact(4)) {
            // SAFETY (index): chunks_exact(4) yields exactly 4-byte chunks.
            *val = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for val in r[..w].iter_mut() {
            *val &= -2;
        }
        for val in r[w..p].iter_mut() {
            *val = (*val & -3) | 1
        }
        sort_uint32(r, p);
        for (fv, &rv) in f.iter_mut().zip(r.iter()) {
            *fv = ((rv & 3) as i8) - 1;
        }
        // The tagged randomness fully determines the secret polynomial — wipe both
        // frames (padding included), at wide-store granularity.
        crate::wipe::wipe(bytes_buf);
        crate::wipe::wipe(r_buf);
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod sort_tests {
    use super::random::sort;

    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The dispatched sort must produce fully sorted output at every length that
    /// exercises the vectorized large-stride, register-local, masked sub-pass,
    /// and scalar paths — including the six parameter sizes.
    #[test]
    fn sort_orders_correctly_at_all_path_lengths() {
        let mut s = 0x0dd_ba11u64 | 1;
        for &n in &[
            0usize, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 64, 100, 653, 761, 857, 953, 1013, 1277,
        ] {
            for pattern in 0..7 {
                let mut x: Vec<i32> = (0..n)
                    .map(|i| match pattern {
                        0..=2 => next(&mut s) as i32,   // random
                        3 => 42,                        // all equal
                        4 => i as i32,                  // sorted
                        5 => (n - i) as i32,            // reverse sorted
                        _ => (next(&mut s) % 4) as i32, // heavy duplicates
                    })
                    .collect();
                let mut want = x.clone();
                want.sort_unstable();
                sort(&mut x, n);
                assert_eq!(x, want, "sort mismatch at n={n} pattern={pattern}");
            }
        }
    }
}
