/// Small-element (ternary) encoding and decoding.
pub mod encoding {
    /// Encode a small polynomial `f` of length `p` into `small_encode_size` bytes.
    ///
    /// Packs 4 trits per byte (each trit shifted to {0,1,2} by adding 1).
    /// The last byte holds `f[p-1] + 1`.
    #[allow(clippy::cast_sign_loss)]
    pub fn encode(f: &[i8], p: usize, small_encode_size: usize) -> Vec<u8> {
        let mut c = vec![0u8; small_encode_size];
        for (byte, chunk) in c[..small_encode_size - 1].iter_mut().zip(f.chunks(4)) {
            let mut c0 = chunk[0] + 1;
            c0 += (chunk[1] + 1) << 2;
            c0 += (chunk[2] + 1) << 4;
            c0 += (chunk[3] + 1) << 6;
            *byte = c0 as u8;
        }
        c[small_encode_size - 1] = (f[p - 1] + 1) as u8;
        c
    }

    /// Decode `small_encode_size` bytes into a small polynomial of length `p`.
    ///
    /// Inverse of [`encode`]: unpacks 4 trits per byte, last element from last byte.
    #[allow(clippy::cast_possible_wrap)]
    pub fn decode(c: &[u8], p: usize) -> Vec<i8> {
        let small_encode_size = c.len();
        let mut f = vec![0i8; p];
        for (byte, chunk) in c[..small_encode_size - 1].iter().zip(f.chunks_mut(4)) {
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
        f
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

    /// Batcher bitonic sort on `n` elements of `x`, dispatching to SIMD when available.
    #[allow(unsafe_code)]
    pub fn sort(x: &mut [i32], n: usize) {
        #[cfg(all(
            target_arch = "x86_64",
            target_feature = "avx2",
            not(feature = "force-scalar")
        ))]
        // SAFETY: AVX2 verified by cfg
        unsafe {
            return sort_avx2(x, n);
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
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
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
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
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
            } else {
                // Small strides: scalar
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
                let mut i = 0;
                while i < end {
                    if i & p_mask == 0 {
                        let block_end = (i + p_mask).min(end);
                        let mut j = i;
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
            } else {
                // Small strides: scalar
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
        let mut r = vec![0i32; p];
        for val in r.iter_mut() {
            *val = rng.random();
        }
        for val in r[..w].iter_mut() {
            *val &= -2;
        }
        for val in r[w..p].iter_mut() {
            *val = (*val & -3) | 1
        }
        sort_uint32(&mut r, p);
        for (fv, &rv) in f.iter_mut().zip(r.iter()) {
            *fv = ((rv & 3) as i8) - 1;
        }
    }
}
