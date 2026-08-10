//! Port of djb's AVX2 constant-time `crypto_sort_int32` (in progress).
//!
//! Motivation, from the round-8 comparator census: our Batcher network spends
//! 52% of its comparators in passes whose selection stride is below the vector
//! width, and those run at **half lane utilisation** — only the lanes with
//! `l & p == 0` do useful work. No per-pass fix reaches that; the structure has
//! to change. This implementation does, by keeping several merge stages resident
//! in registers (`merge16_finish` runs four stages with a single load and store;
//! `threestages` runs three across eight vectors) so every lane is live.
//!
//! Complete: base cases, the general power-of-two driver, and the
//! non-power-of-two dispatch. [`crate::zx::random::sort`] routes here on
//! x86_64/AVX2; the Batcher network it replaces is retained as the fallback for
//! other targets and as the differential oracle.
#![allow(unsafe_code)]

use core::arch::x86_64::*;

/// Branchless scalar min/max, from the reference's `int32_MINMAX`.
///
/// The widened subtraction is deliberately truncated back to i32: only the sign
/// bit is used, and the wrap is what makes the comparison total across the full
/// i32 range without branching.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn minmax1(a: &mut i32, b: &mut i32) {
    let ab = *b ^ *a;
    let mut c = (i64::from(*b) - i64::from(*a)) as i32;
    c ^= ab & (c ^ *b);
    c >>= 31;
    c &= ab;
    *a ^= c;
    *b ^= c;
}

/// Lanewise min/max of two vectors: `a` takes the minima, `b` the maxima.
#[inline]
#[target_feature(enable = "avx2")]
fn minmax8(a: &mut __m256i, b: &mut __m256i) {
    let c = _mm256_min_epi32(*a, *b);
    *b = _mm256_max_epi32(*a, *b);
    *a = c;
}

#[inline]
#[target_feature(enable = "avx2")]
fn ld(x: &[i32], i: usize) -> __m256i {
    unsafe { _mm256_loadu_si256(x.as_ptr().add(i) as *const __m256i) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn st(x: &mut [i32], i: usize, v: __m256i) {
    unsafe { _mm256_storeu_si256(x.as_mut_ptr().add(i) as *mut __m256i, v) }
}

/// Stages 64 and 32 of a bitonic merge over 128-element blocks: four vectors
/// resident, four MINMAX ops, one store round trip.
#[target_feature(enable = "avx2")]
fn twostages_32(x: &mut [i32], n: usize) {
    let mut base = 0usize;
    let mut left = n;
    while left > 0 {
        let mut i = 0usize;
        while i < 32 {
            let mut x0 = ld(x, base + i);
            let mut x1 = ld(x, base + i + 32);
            let mut x2 = ld(x, base + i + 64);
            let mut x3 = ld(x, base + i + 96);

            minmax8(&mut x0, &mut x2);
            minmax8(&mut x1, &mut x3);
            minmax8(&mut x0, &mut x1);
            minmax8(&mut x2, &mut x3);

            st(x, base + i, x0);
            st(x, base + i + 32, x1);
            st(x, base + i + 64, x2);
            st(x, base + i + 96, x3);
            i += 8;
        }
        base += 128;
        left -= 128;
    }
}

/// Stages 4q, 2q and q of a bitonic merge: eight vectors resident, twelve
/// MINMAX ops covering three stages, one load and store round trip. This is the
/// register blocking our per-pass network cannot express.
#[target_feature(enable = "avx2")]
fn threestages(x: &mut [i32], n: usize, q: usize) -> usize {
    let mut k = 0usize;
    while k + 8 * q <= n {
        let mut i = k;
        while i < k + q {
            let mut x0 = ld(x, i);
            let mut x1 = ld(x, i + q);
            let mut x2 = ld(x, i + 2 * q);
            let mut x3 = ld(x, i + 3 * q);
            let mut x4 = ld(x, i + 4 * q);
            let mut x5 = ld(x, i + 5 * q);
            let mut x6 = ld(x, i + 6 * q);
            let mut x7 = ld(x, i + 7 * q);

            minmax8(&mut x0, &mut x4);
            minmax8(&mut x1, &mut x5);
            minmax8(&mut x2, &mut x6);
            minmax8(&mut x3, &mut x7);
            minmax8(&mut x0, &mut x2);
            minmax8(&mut x1, &mut x3);
            minmax8(&mut x4, &mut x6);
            minmax8(&mut x5, &mut x7);
            minmax8(&mut x0, &mut x1);
            minmax8(&mut x2, &mut x3);
            minmax8(&mut x4, &mut x5);
            minmax8(&mut x6, &mut x7);

            st(x, i, x0);
            st(x, i + q, x1);
            st(x, i + 2 * q, x2);
            st(x, i + 3 * q, x3);
            st(x, i + 4 * q, x4);
            st(x, i + 5 * q, x5);
            st(x, i + 6 * q, x6);
            st(x, i + 7 * q, x7);
            i += 8;
        }
        k += 8 * q;
    }
    k
}

/// Stages 8, 4, 2 and 1 of a size-16 bitonic merge, held entirely in registers.
///
/// This is the shape our per-pass sort cannot express: four comparator stages
/// with one load and one store, at full lane utilisation. The shuffles between
/// `minmax8` calls are what bring each stage's partners into aligned lanes.
#[target_feature(enable = "avx2")]
fn merge16_finish(x: &mut [i32], at: usize, mut x0: __m256i, mut x1: __m256i, flagdown: bool) {
    minmax8(&mut x0, &mut x1);

    let mut b0 = _mm256_permute2x128_si256::<0x20>(x0, x1); // A0123 B0123
    let mut b1 = _mm256_permute2x128_si256::<0x31>(x0, x1); // A4567 B4567
    minmax8(&mut b0, &mut b1);

    let mut c0 = _mm256_unpacklo_epi64(b0, b1); // A0145 B0145
    let mut c1 = _mm256_unpackhi_epi64(b0, b1); // A2367 B2367
    minmax8(&mut c0, &mut c1);

    b0 = _mm256_unpacklo_epi32(c0, c1); // A0213 B0213
    b1 = _mm256_unpackhi_epi32(c0, c1); // A4657 B4657

    c0 = _mm256_unpacklo_epi64(b0, b1); // A0246 B0246
    c1 = _mm256_unpackhi_epi64(b0, b1); // A1357 B1357
    minmax8(&mut c0, &mut c1);

    b0 = _mm256_unpacklo_epi32(c0, c1); // A0123 B0123
    b1 = _mm256_unpackhi_epi32(c0, c1); // A4567 B4567

    x0 = _mm256_permute2x128_si256::<0x20>(b0, b1);
    x1 = _mm256_permute2x128_si256::<0x31>(b0, b1);

    if flagdown {
        let mask = _mm256_set1_epi32(-1);
        x0 = _mm256_xor_si256(x0, mask);
        x1 = _mm256_xor_si256(x1, mask);
    }

    st(x, at, x0);
    st(x, at + 8, x1);
}

/// Sort `x[at..at + n]` for a power-of-two `n`, ascending when `flagdown` is
/// false. Base cases only so far; larger `n` is not yet implemented.
#[target_feature(enable = "avx2")]
fn sort_2power(x: &mut [i32], at: usize, n: usize, flagdown: bool) {
    if n == 8 {
        // Odd-even sorting network on eight scalars.
        let mut v = [0i32; 8];
        v.copy_from_slice(&x[at..at + 8]);
        let [
            mut x0,
            mut x1,
            mut x2,
            mut x3,
            mut x4,
            mut x5,
            mut x6,
            mut x7,
        ] = v;

        minmax1(&mut x1, &mut x0);
        minmax1(&mut x3, &mut x2);
        minmax1(&mut x2, &mut x0);
        minmax1(&mut x3, &mut x1);
        minmax1(&mut x2, &mut x1);

        minmax1(&mut x5, &mut x4);
        minmax1(&mut x7, &mut x6);
        minmax1(&mut x6, &mut x4);
        minmax1(&mut x7, &mut x5);
        minmax1(&mut x6, &mut x5);

        minmax1(&mut x4, &mut x0);
        minmax1(&mut x6, &mut x2);
        minmax1(&mut x4, &mut x2);

        minmax1(&mut x5, &mut x1);
        minmax1(&mut x7, &mut x3);
        minmax1(&mut x5, &mut x3);

        minmax1(&mut x2, &mut x1);
        minmax1(&mut x4, &mut x3);
        minmax1(&mut x6, &mut x5);

        x[at..at + 8].copy_from_slice(&[x0, x1, x2, x3, x4, x5, x6, x7]);
        return;
    }

    if n == 16 {
        let mut x0 = ld(x, at);
        let mut x1 = ld(x, at + 8);

        let mut mask = _mm256_set_epi32(0, 0, -1, -1, 0, 0, -1, -1);
        x0 = _mm256_xor_si256(x0, mask);
        x1 = _mm256_xor_si256(x1, mask);

        let mut b0 = _mm256_unpacklo_epi32(x0, x1);
        let mut b1 = _mm256_unpackhi_epi32(x0, x1);

        let mut c0 = _mm256_unpacklo_epi64(b0, b1);
        let mut c1 = _mm256_unpackhi_epi64(b0, b1);
        minmax8(&mut c0, &mut c1);

        mask = _mm256_set_epi32(0, 0, -1, -1, -1, -1, 0, 0);
        c0 = _mm256_xor_si256(c0, mask);
        c1 = _mm256_xor_si256(c1, mask);

        b0 = _mm256_unpacklo_epi32(c0, c1);
        b1 = _mm256_unpackhi_epi32(c0, c1);
        minmax8(&mut b0, &mut b1);

        x0 = _mm256_unpacklo_epi64(b0, b1);
        x1 = _mm256_unpackhi_epi64(b0, b1);

        b0 = _mm256_unpacklo_epi32(x0, x1);
        b1 = _mm256_unpackhi_epi32(x0, x1);

        c0 = _mm256_unpacklo_epi64(b0, b1);
        c1 = _mm256_unpackhi_epi64(b0, b1);
        minmax8(&mut c0, &mut c1);

        b0 = _mm256_unpacklo_epi32(c0, c1);
        b1 = _mm256_unpackhi_epi32(c0, c1);

        b0 = _mm256_xor_si256(b0, mask);
        b1 = _mm256_xor_si256(b1, mask);

        c0 = _mm256_permute2x128_si256::<0x20>(b0, b1);
        c1 = _mm256_permute2x128_si256::<0x31>(b0, b1);
        minmax8(&mut c0, &mut c1);

        b0 = _mm256_permute2x128_si256::<0x20>(c0, c1);
        b1 = _mm256_permute2x128_si256::<0x31>(c0, c1);
        minmax8(&mut b0, &mut b1);

        x0 = _mm256_unpacklo_epi64(b0, b1);
        x1 = _mm256_unpackhi_epi64(b0, b1);

        b0 = _mm256_unpacklo_epi32(x0, x1);
        b1 = _mm256_unpackhi_epi32(x0, x1);

        c0 = _mm256_unpacklo_epi64(b0, b1);
        c1 = _mm256_unpackhi_epi64(b0, b1);
        minmax8(&mut c0, &mut c1);

        b0 = _mm256_unpacklo_epi32(c0, c1);
        b1 = _mm256_unpackhi_epi32(c0, c1);

        x0 = _mm256_unpacklo_epi64(b0, b1);
        x1 = _mm256_unpackhi_epi64(b0, b1);

        mask = _mm256_set1_epi32(-1);
        if flagdown {
            x1 = _mm256_xor_si256(x1, mask);
        } else {
            x0 = _mm256_xor_si256(x0, mask);
        }

        merge16_finish(x, at, x0, x1, flagdown);
        return;
    }

    if n == 32 {
        sort_2power(x, at, 16, true);
        sort_2power(x, at + 16, 16, false);

        let mut x0 = ld(x, at);
        let mut x1 = ld(x, at + 8);
        let mut x2 = ld(x, at + 16);
        let mut x3 = ld(x, at + 24);

        if flagdown {
            let mask = _mm256_set1_epi32(-1);
            x0 = _mm256_xor_si256(x0, mask);
            x1 = _mm256_xor_si256(x1, mask);
            x2 = _mm256_xor_si256(x2, mask);
            x3 = _mm256_xor_si256(x3, mask);
        }

        minmax8(&mut x0, &mut x2);
        minmax8(&mut x1, &mut x3);

        merge16_finish(x, at, x0, x1, flagdown);
        merge16_finish(x, at + 16, x2, x3, flagdown);
        return;
    }

    // ---- general power-of-two path (ported from the reference) ----
    let mut mask;
    let mut p: usize;
    let mut q: usize;
    p = n >> 3;
    let mut i = 0;
    while i < p {
        let mut x0 = ld(x, i);
        let mut x2 = ld(x, i + 2 * p);
        let mut x4 = ld(x, i + 4 * p);
        let mut x6 = ld(x, i + 6 * p);

        // odd-even stage instead of bitonic stage

        minmax8(&mut x4, &mut x0);
        minmax8(&mut x6, &mut x2);
        minmax8(&mut x2, &mut x0);
        minmax8(&mut x6, &mut x4);
        minmax8(&mut x2, &mut x4);

        st(x, i, x0);
        st(x, i + 2 * p, x2);
        st(x, i + 4 * p, x4);
        st(x, i + 6 * p, x6);

        let mut x1 = ld(x, i + p);
        let mut x3 = ld(x, i + 3 * p);
        let mut x5 = ld(x, i + 5 * p);
        let mut x7 = ld(x, i + 7 * p);

        minmax8(&mut x1, &mut x5);
        minmax8(&mut x3, &mut x7);
        minmax8(&mut x1, &mut x3);
        minmax8(&mut x5, &mut x7);
        minmax8(&mut x5, &mut x3);

        st(x, i + p, x1);
        st(x, i + 3 * p, x3);
        st(x, i + 5 * p, x5);
        st(x, i + 7 * p, x7);
        i += 8;
    }

    if n >= 128 {
        let mut flip;
        let mut flipflip;

        mask = _mm256_set1_epi32(-1);

        let mut j = 0;
        while j < n {
            let mut x0 = ld(x, j);
            let mut x1 = ld(x, j + 16);
            x0 = _mm256_xor_si256(x0, mask);
            x1 = _mm256_xor_si256(x1, mask);
            st(x, j, x0);
            st(x, j + 16, x1);
            j += 32;
        }

        p = 8;
        loop {
            q = p >> 1;
            while q >= 128 {
                threestages(x, n, q >> 2);
                q >>= 3;
            }
            if q == 64 {
                twostages_32(x, n);
                q = 16;
            }
            if q == 32 {
                q = 8;
                let mut k = 0;
                while k < n {
                    let mut i = k;
                    while i < k + q {
                        let mut x0 = ld(x, i);
                        let mut x1 = ld(x, i + q);
                        let mut x2 = ld(x, i + 2 * q);
                        let mut x3 = ld(x, i + 3 * q);
                        let mut x4 = ld(x, i + 4 * q);
                        let mut x5 = ld(x, i + 5 * q);
                        let mut x6 = ld(x, i + 6 * q);
                        let mut x7 = ld(x, i + 7 * q);

                        minmax8(&mut x0, &mut x4);
                        minmax8(&mut x1, &mut x5);
                        minmax8(&mut x2, &mut x6);
                        minmax8(&mut x3, &mut x7);
                        minmax8(&mut x0, &mut x2);
                        minmax8(&mut x1, &mut x3);
                        minmax8(&mut x4, &mut x6);
                        minmax8(&mut x5, &mut x7);
                        minmax8(&mut x0, &mut x1);
                        minmax8(&mut x2, &mut x3);
                        minmax8(&mut x4, &mut x5);
                        minmax8(&mut x6, &mut x7);

                        st(x, i, x0);
                        st(x, i + q, x1);
                        st(x, i + 2 * q, x2);
                        st(x, i + 3 * q, x3);
                        st(x, i + 4 * q, x4);
                        st(x, i + 5 * q, x5);
                        st(x, i + 6 * q, x6);
                        st(x, i + 7 * q, x7);
                        i += 8;
                    }
                    k += 8 * q;
                }
                q = 4;
            }
            if q == 16 {
                q = 8;
                let mut k = 0;
                while k < n {
                    let mut i = k;
                    while i < k + q {
                        let mut x0 = ld(x, i);
                        let mut x1 = ld(x, i + q);
                        let mut x2 = ld(x, i + 2 * q);
                        let mut x3 = ld(x, i + 3 * q);

                        minmax8(&mut x0, &mut x2);
                        minmax8(&mut x1, &mut x3);
                        minmax8(&mut x0, &mut x1);
                        minmax8(&mut x2, &mut x3);

                        st(x, i, x0);
                        st(x, i + q, x1);
                        st(x, i + 2 * q, x2);
                        st(x, i + 3 * q, x3);
                        i += 8;
                    }
                    k += 4 * q;
                }
                q = 4;
            }
            if q == 8 {
                let mut k = 0;
                while k < n {
                    let mut x0 = ld(x, k);
                    let mut x1 = ld(x, k + q);

                    minmax8(&mut x0, &mut x1);

                    st(x, k, x0);
                    st(x, k + q, x1);
                    k += q + q;
                }
            }

            q = n >> 3;
            flip = 0;
            if p << 1 == q {
                flip = 1;
            }
            flipflip = 1 - flip;
            let mut j = 0;
            while j < q {
                let mut k = j;
                while k < j + p + p {
                    let mut i = k;
                    while i < k + p {
                        let mut x0 = ld(x, i);
                        let mut x1 = ld(x, i + q);
                        let mut x2 = ld(x, i + 2 * q);
                        let mut x3 = ld(x, i + 3 * q);
                        let mut x4 = ld(x, i + 4 * q);
                        let mut x5 = ld(x, i + 5 * q);
                        let mut x6 = ld(x, i + 6 * q);
                        let mut x7 = ld(x, i + 7 * q);

                        minmax8(&mut x0, &mut x1);
                        minmax8(&mut x2, &mut x3);
                        minmax8(&mut x4, &mut x5);
                        minmax8(&mut x6, &mut x7);
                        minmax8(&mut x0, &mut x2);
                        minmax8(&mut x1, &mut x3);
                        minmax8(&mut x4, &mut x6);
                        minmax8(&mut x5, &mut x7);
                        minmax8(&mut x0, &mut x4);
                        minmax8(&mut x1, &mut x5);
                        minmax8(&mut x2, &mut x6);
                        minmax8(&mut x3, &mut x7);

                        if flip != 0 {
                            x0 = _mm256_xor_si256(x0, mask);
                            x1 = _mm256_xor_si256(x1, mask);
                            x2 = _mm256_xor_si256(x2, mask);
                            x3 = _mm256_xor_si256(x3, mask);
                            x4 = _mm256_xor_si256(x4, mask);
                            x5 = _mm256_xor_si256(x5, mask);
                            x6 = _mm256_xor_si256(x6, mask);
                            x7 = _mm256_xor_si256(x7, mask);
                        }

                        st(x, i, x0);
                        st(x, i + q, x1);
                        st(x, i + 2 * q, x2);
                        st(x, i + 3 * q, x3);
                        st(x, i + 4 * q, x4);
                        st(x, i + 5 * q, x5);
                        st(x, i + 6 * q, x6);
                        st(x, i + 7 * q, x7);
                        i += 8;
                    }
                    flip ^= 1;
                    k += p;
                }
                flip ^= flipflip;
                j += p + p;
            }

            if p << 4 == n {
                break;
            }
            p <<= 1;
        }
    }

    let mut p = 4;
    while p >= 1 {
        let mut zi = 0usize;
        if p == 4 {
            mask = _mm256_set_epi32(0, 0, 0, 0, -1, -1, -1, -1);
            while zi != n {
                let mut x0 = ld(x, zi);
                let mut x1 = ld(x, zi + 8);
                x0 = _mm256_xor_si256(x0, mask);
                x1 = _mm256_xor_si256(x1, mask);
                st(x, zi, x0);
                st(x, zi + 8, x1);
                zi += 16;
            }
        } else if p == 2 {
            mask = _mm256_set_epi32(0, 0, -1, -1, -1, -1, 0, 0);
            while zi != n {
                let mut x0 = ld(x, zi);
                let mut x1 = ld(x, zi + 8);
                x0 = _mm256_xor_si256(x0, mask);
                x1 = _mm256_xor_si256(x1, mask);
                let mut b0 = _mm256_permute2x128_si256(x0, x1, 0x20);
                let mut b1 = _mm256_permute2x128_si256(x0, x1, 0x31);
                minmax8(&mut b0, &mut b1);
                let c0 = _mm256_permute2x128_si256(b0, b1, 0x20);
                let c1 = _mm256_permute2x128_si256(b0, b1, 0x31);
                st(x, zi, c0);
                st(x, zi + 8, c1);
                zi += 16;
            }
        } else {
            mask = _mm256_set_epi32(0, -1, -1, 0, 0, -1, -1, 0);
            while zi != n {
                let mut x0 = ld(x, zi);
                let mut x1 = ld(x, zi + 8);
                x0 = _mm256_xor_si256(x0, mask);
                x1 = _mm256_xor_si256(x1, mask);
                let b0 = _mm256_permute2x128_si256(x0, x1, 0x20);
                let b1 = _mm256_permute2x128_si256(x0, x1, 0x31);
                let mut c0 = _mm256_unpacklo_epi64(b0, b1);
                let mut c1 = _mm256_unpackhi_epi64(b0, b1);
                minmax8(&mut c0, &mut c1);
                let mut d0 = _mm256_unpacklo_epi64(c0, c1);
                let mut d1 = _mm256_unpackhi_epi64(c0, c1);
                minmax8(&mut d0, &mut d1);
                let e0 = _mm256_permute2x128_si256(d0, d1, 0x20);
                let e1 = _mm256_permute2x128_si256(d0, d1, 0x31);
                st(x, zi, e0);
                st(x, zi + 8, e1);
                zi += 16;
            }
        }

        q = n >> 4;
        while q >= 128 || q == 32 {
            threestages(x, n, q >> 2);
            q >>= 3;
        }
        while q >= 16 {
            q >>= 1;
            let mut j = 0;
            while j < n {
                let mut k = j;
                while k < j + q {
                    let mut x0 = ld(x, k);
                    let mut x1 = ld(x, k + q);
                    let mut x2 = ld(x, k + 2 * q);
                    let mut x3 = ld(x, k + 3 * q);

                    minmax8(&mut x0, &mut x2);
                    minmax8(&mut x1, &mut x3);
                    minmax8(&mut x0, &mut x1);
                    minmax8(&mut x2, &mut x3);

                    st(x, k, x0);
                    st(x, k + q, x1);
                    st(x, k + 2 * q, x2);
                    st(x, k + 3 * q, x3);
                    k += 8;
                }
                j += 4 * q;
            }
            q >>= 1;
        }
        if q == 8 {
            let mut j = 0;
            while j < n {
                let mut x0 = ld(x, j);
                let mut x1 = ld(x, j + q);

                minmax8(&mut x0, &mut x1);

                st(x, j, x0);
                st(x, j + q, x1);
                j += 2 * q;
            }
        }

        q = n >> 3;
        let mut k = 0;
        while k < q {
            let mut x0 = ld(x, k);
            let mut x1 = ld(x, k + q);
            let mut x2 = ld(x, k + 2 * q);
            let mut x3 = ld(x, k + 3 * q);
            let mut x4 = ld(x, k + 4 * q);
            let mut x5 = ld(x, k + 5 * q);
            let mut x6 = ld(x, k + 6 * q);
            let mut x7 = ld(x, k + 7 * q);

            minmax8(&mut x0, &mut x1);
            minmax8(&mut x2, &mut x3);
            minmax8(&mut x4, &mut x5);
            minmax8(&mut x6, &mut x7);
            minmax8(&mut x0, &mut x2);
            minmax8(&mut x1, &mut x3);
            minmax8(&mut x4, &mut x6);
            minmax8(&mut x5, &mut x7);
            minmax8(&mut x0, &mut x4);
            minmax8(&mut x1, &mut x5);
            minmax8(&mut x2, &mut x6);
            minmax8(&mut x3, &mut x7);

            st(x, k, x0);
            st(x, k + q, x1);
            st(x, k + 2 * q, x2);
            st(x, k + 3 * q, x3);
            st(x, k + 4 * q, x4);
            st(x, k + 5 * q, x5);
            st(x, k + 6 * q, x6);
            st(x, k + 7 * q, x7);
            k += 8;
        }
        p >>= 1;
    }

    // everything is still masked with _mm256_set_epi32(0,-1,0,-1,0,-1,0,-1);
    mask = _mm256_set1_epi32(-1);

    let mut i = 0;
    while i < n {
        let a0 = ld(x, i);
        let a1 = ld(x, i + 8);
        let a2 = ld(x, i + 16);
        let a3 = ld(x, i + 24);
        let a4 = ld(x, i + 32);
        let a5 = ld(x, i + 40);
        let a6 = ld(x, i + 48);
        let a7 = ld(x, i + 56);

        let b0 = _mm256_unpacklo_epi32(a0, a1);
        let b1 = _mm256_unpackhi_epi32(a0, a1);
        let b2 = _mm256_unpacklo_epi32(a2, a3);
        let b3 = _mm256_unpackhi_epi32(a2, a3);
        let b4 = _mm256_unpacklo_epi32(a4, a5);
        let b5 = _mm256_unpackhi_epi32(a4, a5);
        let b6 = _mm256_unpacklo_epi32(a6, a7);
        let b7 = _mm256_unpackhi_epi32(a6, a7);

        let mut c0 = _mm256_unpacklo_epi64(b0, b2);
        let mut c1 = _mm256_unpacklo_epi64(b1, b3);
        let mut c2 = _mm256_unpackhi_epi64(b0, b2);
        let mut c3 = _mm256_unpackhi_epi64(b1, b3);
        let mut c4 = _mm256_unpacklo_epi64(b4, b6);
        let mut c5 = _mm256_unpacklo_epi64(b5, b7);
        let mut c6 = _mm256_unpackhi_epi64(b4, b6);
        let mut c7 = _mm256_unpackhi_epi64(b5, b7);

        if flagdown {
            c2 = _mm256_xor_si256(c2, mask);
            c3 = _mm256_xor_si256(c3, mask);
            c6 = _mm256_xor_si256(c6, mask);
            c7 = _mm256_xor_si256(c7, mask);
        } else {
            c0 = _mm256_xor_si256(c0, mask);
            c1 = _mm256_xor_si256(c1, mask);
            c4 = _mm256_xor_si256(c4, mask);
            c5 = _mm256_xor_si256(c5, mask);
        }

        let mut d0 = _mm256_permute2x128_si256(c0, c4, 0x20);
        let mut d1 = _mm256_permute2x128_si256(c2, c6, 0x20);
        let mut d2 = _mm256_permute2x128_si256(c1, c5, 0x20);
        let mut d3 = _mm256_permute2x128_si256(c3, c7, 0x20);
        let mut d4 = _mm256_permute2x128_si256(c0, c4, 0x31);
        let mut d5 = _mm256_permute2x128_si256(c2, c6, 0x31);
        let mut d6 = _mm256_permute2x128_si256(c1, c5, 0x31);
        let mut d7 = _mm256_permute2x128_si256(c3, c7, 0x31);

        minmax8(&mut d0, &mut d1);
        minmax8(&mut d2, &mut d3);
        minmax8(&mut d4, &mut d5);
        minmax8(&mut d6, &mut d7);
        minmax8(&mut d0, &mut d2);
        minmax8(&mut d1, &mut d3);
        minmax8(&mut d4, &mut d6);
        minmax8(&mut d5, &mut d7);
        minmax8(&mut d0, &mut d4);
        minmax8(&mut d1, &mut d5);
        minmax8(&mut d2, &mut d6);
        minmax8(&mut d3, &mut d7);

        let e0 = _mm256_unpacklo_epi32(d0, d1);
        let e1 = _mm256_unpackhi_epi32(d0, d1);
        let e2 = _mm256_unpacklo_epi32(d2, d3);
        let e3 = _mm256_unpackhi_epi32(d2, d3);
        let e4 = _mm256_unpacklo_epi32(d4, d5);
        let e5 = _mm256_unpackhi_epi32(d4, d5);
        let e6 = _mm256_unpacklo_epi32(d6, d7);
        let e7 = _mm256_unpackhi_epi32(d6, d7);

        let f0 = _mm256_unpacklo_epi64(e0, e2);
        let f1 = _mm256_unpacklo_epi64(e1, e3);
        let f2 = _mm256_unpackhi_epi64(e0, e2);
        let f3 = _mm256_unpackhi_epi64(e1, e3);
        let f4 = _mm256_unpacklo_epi64(e4, e6);
        let f5 = _mm256_unpacklo_epi64(e5, e7);
        let f6 = _mm256_unpackhi_epi64(e4, e6);
        let f7 = _mm256_unpackhi_epi64(e5, e7);

        let g0 = _mm256_permute2x128_si256(f0, f4, 0x20);
        let g1 = _mm256_permute2x128_si256(f2, f6, 0x20);
        let g2 = _mm256_permute2x128_si256(f1, f5, 0x20);
        let g3 = _mm256_permute2x128_si256(f3, f7, 0x20);
        let g4 = _mm256_permute2x128_si256(f0, f4, 0x31);
        let g5 = _mm256_permute2x128_si256(f2, f6, 0x31);
        let g6 = _mm256_permute2x128_si256(f1, f5, 0x31);
        let g7 = _mm256_permute2x128_si256(f3, f7, 0x31);

        st(x, i, g0);
        st(x, i + 8, g1);
        st(x, i + 16, g2);
        st(x, i + 24, g3);
        st(x, i + 32, g4);
        st(x, i + 40, g5);
        st(x, i + 48, g6);
        st(x, i + 56, g7);
        i += 64;
    }

    q = n >> 4;
    while q >= 128 || q == 32 {
        q >>= 2;
        let mut j = 0;
        while j < n {
            let mut i = j;
            while i < j + q {
                let mut x0 = ld(x, i);
                let mut x1 = ld(x, i + q);
                let mut x2 = ld(x, i + 2 * q);
                let mut x3 = ld(x, i + 3 * q);
                let mut x4 = ld(x, i + 4 * q);
                let mut x5 = ld(x, i + 5 * q);
                let mut x6 = ld(x, i + 6 * q);
                let mut x7 = ld(x, i + 7 * q);
                minmax8(&mut x0, &mut x4);
                minmax8(&mut x1, &mut x5);
                minmax8(&mut x2, &mut x6);
                minmax8(&mut x3, &mut x7);
                minmax8(&mut x0, &mut x2);
                minmax8(&mut x1, &mut x3);
                minmax8(&mut x4, &mut x6);
                minmax8(&mut x5, &mut x7);
                minmax8(&mut x0, &mut x1);
                minmax8(&mut x2, &mut x3);
                minmax8(&mut x4, &mut x5);
                minmax8(&mut x6, &mut x7);
                st(x, i, x0);
                st(x, i + q, x1);
                st(x, i + 2 * q, x2);
                st(x, i + 3 * q, x3);
                st(x, i + 4 * q, x4);
                st(x, i + 5 * q, x5);
                st(x, i + 6 * q, x6);
                st(x, i + 7 * q, x7);
                i += 8;
            }
            j += 8 * q;
        }
        q >>= 1;
    }
    while q >= 16 {
        q >>= 1;
        let mut j = 0;
        while j < n {
            let mut i = j;
            while i < j + q {
                let mut x0 = ld(x, i);
                let mut x1 = ld(x, i + q);
                let mut x2 = ld(x, i + 2 * q);
                let mut x3 = ld(x, i + 3 * q);
                minmax8(&mut x0, &mut x2);
                minmax8(&mut x1, &mut x3);
                minmax8(&mut x0, &mut x1);
                minmax8(&mut x2, &mut x3);
                st(x, i, x0);
                st(x, i + q, x1);
                st(x, i + 2 * q, x2);
                st(x, i + 3 * q, x3);
                i += 8;
            }
            j += 4 * q;
        }
        q >>= 1;
    }
    if q == 8 {
        let mut j = 0;
        while j < n {
            let mut x0 = ld(x, j);
            let mut x1 = ld(x, j + q);
            minmax8(&mut x0, &mut x1);
            st(x, j, x0);
            st(x, j + q, x1);
            j += q + q;
        }
    }

    q = n >> 3;
    let mut i = 0;
    while i < q {
        let mut x0 = ld(x, i);
        let mut x1 = ld(x, i + q);
        let mut x2 = ld(x, i + 2 * q);
        let mut x3 = ld(x, i + 3 * q);
        let mut x4 = ld(x, i + 4 * q);
        let mut x5 = ld(x, i + 5 * q);
        let mut x6 = ld(x, i + 6 * q);
        let mut x7 = ld(x, i + 7 * q);

        minmax8(&mut x0, &mut x1);
        minmax8(&mut x2, &mut x3);
        minmax8(&mut x4, &mut x5);
        minmax8(&mut x6, &mut x7);
        minmax8(&mut x0, &mut x2);
        minmax8(&mut x1, &mut x3);
        minmax8(&mut x4, &mut x6);
        minmax8(&mut x5, &mut x7);
        minmax8(&mut x0, &mut x4);
        minmax8(&mut x1, &mut x5);
        minmax8(&mut x2, &mut x6);
        minmax8(&mut x3, &mut x7);

        let b0 = _mm256_unpacklo_epi32(x0, x4);
        let b1 = _mm256_unpackhi_epi32(x0, x4);
        let b2 = _mm256_unpacklo_epi32(x1, x5);
        let b3 = _mm256_unpackhi_epi32(x1, x5);
        let b4 = _mm256_unpacklo_epi32(x2, x6);
        let b5 = _mm256_unpackhi_epi32(x2, x6);
        let b6 = _mm256_unpacklo_epi32(x3, x7);
        let b7 = _mm256_unpackhi_epi32(x3, x7);

        let c0 = _mm256_unpacklo_epi64(b0, b4);
        let c1 = _mm256_unpacklo_epi64(b1, b5);
        let c2 = _mm256_unpackhi_epi64(b0, b4);
        let c3 = _mm256_unpackhi_epi64(b1, b5);
        let c4 = _mm256_unpacklo_epi64(b2, b6);
        let c5 = _mm256_unpacklo_epi64(b3, b7);
        let c6 = _mm256_unpackhi_epi64(b2, b6);
        let c7 = _mm256_unpackhi_epi64(b3, b7);

        let mut d0 = _mm256_permute2x128_si256(c0, c4, 0x20);
        let mut d1 = _mm256_permute2x128_si256(c1, c5, 0x20);
        let mut d2 = _mm256_permute2x128_si256(c2, c6, 0x20);
        let mut d3 = _mm256_permute2x128_si256(c3, c7, 0x20);
        let mut d4 = _mm256_permute2x128_si256(c0, c4, 0x31);
        let mut d5 = _mm256_permute2x128_si256(c1, c5, 0x31);
        let mut d6 = _mm256_permute2x128_si256(c2, c6, 0x31);
        let mut d7 = _mm256_permute2x128_si256(c3, c7, 0x31);

        if flagdown {
            d0 = _mm256_xor_si256(d0, mask);
            d1 = _mm256_xor_si256(d1, mask);
            d2 = _mm256_xor_si256(d2, mask);
            d3 = _mm256_xor_si256(d3, mask);
            d4 = _mm256_xor_si256(d4, mask);
            d5 = _mm256_xor_si256(d5, mask);
            d6 = _mm256_xor_si256(d6, mask);
            d7 = _mm256_xor_si256(d7, mask);
        }

        st(x, i, d0);
        st(x, i + q, d4);
        st(x, i + 2 * q, d1);
        st(x, i + 3 * q, d5);
        st(x, i + 4 * q, d2);
        st(x, i + 5 * q, d6);
        st(x, i + 6 * q, d3);
        st(x, i + 7 * q, d7);
        i += 8;
    }
}

/// Scalar min/max on two slice positions.
#[inline]
fn minmax_at(x: &mut [i32], i: usize, j: usize) {
    let (mut a, mut b) = (x[i], x[j]);
    minmax1(&mut a, &mut b);
    x[i] = a;
    x[j] = b;
}

/// Lanewise min/max between two windows `x[a..]` and `x[b..]` of length `len`,
/// handling a ragged tail by overlapping the final vector.
#[target_feature(enable = "avx2")]
fn minmax_vector(x: &mut [i32], a: usize, b: usize, len: usize) {
    let mut n = len;
    if n < 8 {
        for t in 0..n {
            minmax_at(x, a + t, b + t);
        }
        return;
    }
    if n & 7 != 0 {
        let mut x0 = ld(x, a + n - 8);
        let mut y0 = ld(x, b + n - 8);
        minmax8(&mut x0, &mut y0);
        st(x, a + n - 8, x0);
        st(x, b + n - 8, y0);
        n &= !7;
    }
    let mut o = 0usize;
    while o < n {
        let mut x0 = ld(x, a + o);
        let mut y0 = ld(x, b + o);
        minmax8(&mut x0, &mut y0);
        st(x, a + o, x0);
        st(x, b + o, y0);
        o += 8;
    }
}

/// Sort `x[..n]` ascending, for any `n` (the reference's `int32_sort`).
#[target_feature(enable = "avx2")]
pub fn sort(x: &mut [i32], n: usize) {
    if n <= 8 {
        if n == 8 {
            minmax_at(x, 0, 1);
            minmax_at(x, 1, 2);
            minmax_at(x, 2, 3);
            minmax_at(x, 3, 4);
            minmax_at(x, 4, 5);
            minmax_at(x, 5, 6);
            minmax_at(x, 6, 7);
        }
        if n >= 7 {
            minmax_at(x, 0, 1);
            minmax_at(x, 1, 2);
            minmax_at(x, 2, 3);
            minmax_at(x, 3, 4);
            minmax_at(x, 4, 5);
            minmax_at(x, 5, 6);
        }
        if n >= 6 {
            minmax_at(x, 0, 1);
            minmax_at(x, 1, 2);
            minmax_at(x, 2, 3);
            minmax_at(x, 3, 4);
            minmax_at(x, 4, 5);
        }
        if n >= 5 {
            minmax_at(x, 0, 1);
            minmax_at(x, 1, 2);
            minmax_at(x, 2, 3);
            minmax_at(x, 3, 4);
        }
        if n >= 4 {
            minmax_at(x, 0, 1);
            minmax_at(x, 1, 2);
            minmax_at(x, 2, 3);
        }
        if n >= 3 {
            minmax_at(x, 0, 1);
            minmax_at(x, 1, 2);
        }
        if n >= 2 {
            minmax_at(x, 0, 1);
        }
        return;
    }

    if n & (n - 1) == 0 {
        sort_2power(x, 0, n, false);
        return;
    }

    let mut q: usize = 8;
    let mut j: usize = 0;
    while q < n - q {
        q += q;
    }
    // n > q >= 8

    if q <= 128 {
        // n <= 256: pad to the next power of two with sentinels that sort to the
        // end, sort that, and copy back. The reference type-puns an
        // `int32x8[32]` for alignment; a plain array suffices here.
        let mut y = [0x7fff_ffffi32; 256];
        y[..n].copy_from_slice(&x[..n]);
        sort_2power(&mut y, 0, 2 * q, false);
        x[..n].copy_from_slice(&y[..n]);
        return;
    }

    sort_2power(x, 0, q, true);
    sort(&mut x[q..], n - q);

    while q >= 64 {
        q >>= 2;
        j = threestages(x, n, q);
        minmax_vector(x, j, j + 4 * q, n.saturating_sub(4 * q).saturating_sub(j));
        if j + 4 * q <= n {
            let mut i = j;
            while i < j + q {
                let mut x0 = ld(x, i);
                let mut x1 = ld(x, i + q);
                let mut x2 = ld(x, i + 2 * q);
                let mut x3 = ld(x, i + 3 * q);
                minmax8(&mut x0, &mut x2);
                minmax8(&mut x1, &mut x3);
                minmax8(&mut x0, &mut x1);
                minmax8(&mut x2, &mut x3);
                st(x, i, x0);
                st(x, i + q, x1);
                st(x, i + 2 * q, x2);
                st(x, i + 3 * q, x3);
                i += 8;
            }
            j += 4 * q;
        }
        minmax_vector(x, j, j + 2 * q, n.saturating_sub(2 * q).saturating_sub(j));
        if j + 2 * q <= n {
            let mut i = j;
            while i < j + q {
                let mut x0 = ld(x, i);
                let mut x1 = ld(x, i + q);
                minmax8(&mut x0, &mut x1);
                st(x, i, x0);
                st(x, i + q, x1);
                i += 8;
            }
            j += 2 * q;
        }
        minmax_vector(x, j, j + q, n.saturating_sub(q).saturating_sub(j));
        q >>= 1;
    }
    if q == 32 {
        j = 0;
        while j + 64 <= n {
            let mut x0 = ld(x, j);
            let mut x1 = ld(x, j + 8);
            let mut x2 = ld(x, j + 16);
            let mut x3 = ld(x, j + 24);
            let mut x4 = ld(x, j + 32);
            let mut x5 = ld(x, j + 40);
            let mut x6 = ld(x, j + 48);
            let mut x7 = ld(x, j + 56);
            minmax8(&mut x0, &mut x4);
            minmax8(&mut x1, &mut x5);
            minmax8(&mut x2, &mut x6);
            minmax8(&mut x3, &mut x7);
            minmax8(&mut x0, &mut x2);
            minmax8(&mut x1, &mut x3);
            minmax8(&mut x4, &mut x6);
            minmax8(&mut x5, &mut x7);
            minmax8(&mut x0, &mut x1);
            minmax8(&mut x2, &mut x3);
            minmax8(&mut x4, &mut x5);
            minmax8(&mut x6, &mut x7);
            let mut a0 = _mm256_permute2x128_si256(x0, x1, 0x20);
            let mut a1 = _mm256_permute2x128_si256(x0, x1, 0x31);
            let mut a2 = _mm256_permute2x128_si256(x2, x3, 0x20);
            let mut a3 = _mm256_permute2x128_si256(x2, x3, 0x31);
            let mut a4 = _mm256_permute2x128_si256(x4, x5, 0x20);
            let mut a5 = _mm256_permute2x128_si256(x4, x5, 0x31);
            let mut a6 = _mm256_permute2x128_si256(x6, x7, 0x20);
            let mut a7 = _mm256_permute2x128_si256(x6, x7, 0x31);
            minmax8(&mut a0, &mut a1);
            minmax8(&mut a2, &mut a3);
            minmax8(&mut a4, &mut a5);
            minmax8(&mut a6, &mut a7);
            let b0 = _mm256_permute2x128_si256(a0, a1, 0x20);
            let b1 = _mm256_permute2x128_si256(a0, a1, 0x31);
            let b2 = _mm256_permute2x128_si256(a2, a3, 0x20);
            let b3 = _mm256_permute2x128_si256(a2, a3, 0x31);
            let b4 = _mm256_permute2x128_si256(a4, a5, 0x20);
            let b5 = _mm256_permute2x128_si256(a4, a5, 0x31);
            let b6 = _mm256_permute2x128_si256(a6, a7, 0x20);
            let b7 = _mm256_permute2x128_si256(a6, a7, 0x31);
            let mut c0 = _mm256_unpacklo_epi64(b0, b1);
            let mut c1 = _mm256_unpackhi_epi64(b0, b1);
            let mut c2 = _mm256_unpacklo_epi64(b2, b3);
            let mut c3 = _mm256_unpackhi_epi64(b2, b3);
            let mut c4 = _mm256_unpacklo_epi64(b4, b5);
            let mut c5 = _mm256_unpackhi_epi64(b4, b5);
            let mut c6 = _mm256_unpacklo_epi64(b6, b7);
            let mut c7 = _mm256_unpackhi_epi64(b6, b7);
            minmax8(&mut c0, &mut c1);
            minmax8(&mut c2, &mut c3);
            minmax8(&mut c4, &mut c5);
            minmax8(&mut c6, &mut c7);
            let d0 = _mm256_unpacklo_epi32(c0, c1);
            let d1 = _mm256_unpackhi_epi32(c0, c1);
            let d2 = _mm256_unpacklo_epi32(c2, c3);
            let d3 = _mm256_unpackhi_epi32(c2, c3);
            let d4 = _mm256_unpacklo_epi32(c4, c5);
            let d5 = _mm256_unpackhi_epi32(c4, c5);
            let d6 = _mm256_unpacklo_epi32(c6, c7);
            let d7 = _mm256_unpackhi_epi32(c6, c7);
            let mut e0 = _mm256_unpacklo_epi64(d0, d1);
            let mut e1 = _mm256_unpackhi_epi64(d0, d1);
            let mut e2 = _mm256_unpacklo_epi64(d2, d3);
            let mut e3 = _mm256_unpackhi_epi64(d2, d3);
            let mut e4 = _mm256_unpacklo_epi64(d4, d5);
            let mut e5 = _mm256_unpackhi_epi64(d4, d5);
            let mut e6 = _mm256_unpacklo_epi64(d6, d7);
            let mut e7 = _mm256_unpackhi_epi64(d6, d7);
            minmax8(&mut e0, &mut e1);
            minmax8(&mut e2, &mut e3);
            minmax8(&mut e4, &mut e5);
            minmax8(&mut e6, &mut e7);
            let f0 = _mm256_unpacklo_epi32(e0, e1);
            let f1 = _mm256_unpackhi_epi32(e0, e1);
            let f2 = _mm256_unpacklo_epi32(e2, e3);
            let f3 = _mm256_unpackhi_epi32(e2, e3);
            let f4 = _mm256_unpacklo_epi32(e4, e5);
            let f5 = _mm256_unpackhi_epi32(e4, e5);
            let f6 = _mm256_unpacklo_epi32(e6, e7);
            let f7 = _mm256_unpackhi_epi32(e6, e7);
            st(x, j, f0);
            st(x, j + 8, f1);
            st(x, j + 16, f2);
            st(x, j + 24, f3);
            st(x, j + 32, f4);
            st(x, j + 40, f5);
            st(x, j + 48, f6);
            st(x, j + 56, f7);
            j += 64;
        }
        minmax_vector(x, j, j + 32, n.saturating_sub(32).saturating_sub(j));
        // goto continue16; (restructured as fallthrough)
    }
    // `goto continue16` from the q == 32 branch lands inside this body, past the
    // `j = 0`, carrying j forward — hence the guarded reset.
    if q >= 16 {
        if q == 16 {
            j = 0;
        }
        while j + 32 <= n {
            let mut x0 = ld(x, j);
            let mut x1 = ld(x, j + 8);
            let mut x2 = ld(x, j + 16);
            let mut x3 = ld(x, j + 24);
            minmax8(&mut x0, &mut x2);
            minmax8(&mut x1, &mut x3);
            minmax8(&mut x0, &mut x1);
            minmax8(&mut x2, &mut x3);
            let mut a0 = _mm256_permute2x128_si256(x0, x1, 0x20);
            let mut a1 = _mm256_permute2x128_si256(x0, x1, 0x31);
            let mut a2 = _mm256_permute2x128_si256(x2, x3, 0x20);
            let mut a3 = _mm256_permute2x128_si256(x2, x3, 0x31);
            minmax8(&mut a0, &mut a1);
            minmax8(&mut a2, &mut a3);
            let b0 = _mm256_permute2x128_si256(a0, a1, 0x20);
            let b1 = _mm256_permute2x128_si256(a0, a1, 0x31);
            let b2 = _mm256_permute2x128_si256(a2, a3, 0x20);
            let b3 = _mm256_permute2x128_si256(a2, a3, 0x31);
            let mut c0 = _mm256_unpacklo_epi64(b0, b1);
            let mut c1 = _mm256_unpackhi_epi64(b0, b1);
            let mut c2 = _mm256_unpacklo_epi64(b2, b3);
            let mut c3 = _mm256_unpackhi_epi64(b2, b3);
            minmax8(&mut c0, &mut c1);
            minmax8(&mut c2, &mut c3);
            let d0 = _mm256_unpacklo_epi32(c0, c1);
            let d1 = _mm256_unpackhi_epi32(c0, c1);
            let d2 = _mm256_unpacklo_epi32(c2, c3);
            let d3 = _mm256_unpackhi_epi32(c2, c3);
            let mut e0 = _mm256_unpacklo_epi64(d0, d1);
            let mut e1 = _mm256_unpackhi_epi64(d0, d1);
            let mut e2 = _mm256_unpacklo_epi64(d2, d3);
            let mut e3 = _mm256_unpackhi_epi64(d2, d3);
            minmax8(&mut e0, &mut e1);
            minmax8(&mut e2, &mut e3);
            let f0 = _mm256_unpacklo_epi32(e0, e1);
            let f1 = _mm256_unpackhi_epi32(e0, e1);
            let f2 = _mm256_unpacklo_epi32(e2, e3);
            let f3 = _mm256_unpackhi_epi32(e2, e3);
            st(x, j, f0);
            st(x, j + 8, f1);
            st(x, j + 16, f2);
            st(x, j + 24, f3);
            j += 32;
        }
        minmax_vector(x, j, j + 16, n.saturating_sub(16).saturating_sub(j));
        // goto continue8; (restructured as fallthrough)
    }
    // q == 8; `goto continue8` from the block above lands here past the reset.
    if q == 8 {
        j = 0;
    }
    while j + 16 <= n {
        let mut x0 = ld(x, j);
        let mut x1 = ld(x, j + 8);
        minmax8(&mut x0, &mut x1);
        st(x, j, x0);
        st(x, j + 8, x1);
        let mut a0 = _mm256_permute2x128_si256(x0, x1, 0x20);
        let mut a1 = _mm256_permute2x128_si256(x0, x1, 0x31);
        minmax8(&mut a0, &mut a1);
        let b0 = _mm256_permute2x128_si256(a0, a1, 0x20);
        let b1 = _mm256_permute2x128_si256(a0, a1, 0x31);
        let mut c0 = _mm256_unpacklo_epi64(b0, b1);
        let mut c1 = _mm256_unpackhi_epi64(b0, b1);
        minmax8(&mut c0, &mut c1);
        let d0 = _mm256_unpacklo_epi32(c0, c1);
        let d1 = _mm256_unpackhi_epi32(c0, c1);
        let mut e0 = _mm256_unpacklo_epi64(d0, d1);
        let mut e1 = _mm256_unpackhi_epi64(d0, d1);
        minmax8(&mut e0, &mut e1);
        let f0 = _mm256_unpacklo_epi32(e0, e1);
        let f1 = _mm256_unpackhi_epi32(e0, e1);
        st(x, j, f0);
        st(x, j + 8, f1);
        j += 16;
    }
    minmax_vector(x, j, j + 8, n.saturating_sub(8).saturating_sub(j));
    if j + 8 <= n {
        minmax_at(x, j, j + 4);
        minmax_at(x, j + 1, j + 5);
        minmax_at(x, j + 2, j + 6);
        minmax_at(x, j + 3, j + 7);
        minmax_at(x, j, j + 2);
        minmax_at(x, j + 1, j + 3);
        minmax_at(x, j, j + 1);
        minmax_at(x, j + 2, j + 3);
        minmax_at(x, j + 4, j + 6);
        minmax_at(x, j + 5, j + 7);
        minmax_at(x, j + 4, j + 5);
        minmax_at(x, j + 6, j + 7);
        j += 8;
    }
    minmax_vector(x, j, j + 4, n.saturating_sub(4).saturating_sub(j));
    if j + 4 <= n {
        minmax_at(x, j, j + 2);
        minmax_at(x, j + 1, j + 3);
        minmax_at(x, j, j + 1);
        minmax_at(x, j + 2, j + 3);
        j += 4;
    }
    if j + 3 <= n {
        minmax_at(x, j, j + 2);
    }
    if j + 2 <= n {
        minmax_at(x, j, j + 1);
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

    /// The full `sort` entry point must sort every length correctly, including
    /// the six parameter sizes and the awkward boundaries around each internal
    /// dispatch (power-of-two, the <=256 padding path, and the recursive path).
    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn full_sort_matches_reference_ordering() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let mut s = 0xfeed_face_dead_beefu64;
        let lens = [
            0usize, 1, 2, 3, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 100, 128, 200, 255, 256,
            257, 300, 511, 512, 513, 653, 761, 857, 953, 1013, 1024, 1277, 2048,
        ];
        for &n in &lens {
            for pattern in 0..7 {
                let mut x: Vec<i32> = (0..n)
                    .map(|i| match pattern {
                        0..=2 => next(&mut s) as i32,
                        3 => 42,
                        4 => i as i32,
                        5 => (n - i) as i32,
                        _ => (next(&mut s) % 4) as i32,
                    })
                    .collect();
                let mut want = x.clone();
                want.sort_unstable();
                // SAFETY: AVX2 confirmed above.
                unsafe { sort(&mut x, n) };
                assert_eq!(x, want, "full sort n={n} pattern={pattern}");
            }
        }
    }

    /// The ported base cases must reproduce the reference's ordering exactly,
    /// on random data and on the degenerate patterns that break naive networks.
    ///
    /// `flagdown` selects direction: `false` ascending, `true` descending. The
    /// `n == 8` network ignores it and always descends — that is the reference's
    /// documented precondition ("if n == 8 then flagdown"), not an omission.
    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn base_cases_sort_correctly() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let mut s = 0x1234_5678_9abc_def1u64;
        for &n in &[8usize, 16, 32, 64, 128, 256, 512, 1024] {
            // n == 8 is descending-only by contract.
            let dirs: &[bool] = if n == 8 { &[true] } else { &[false, true] };
            for &flagdown in dirs {
                for pattern in 0..7 {
                    let mut x: Vec<i32> = (0..n)
                        .map(|i| match pattern {
                            0..=2 => next(&mut s) as i32,
                            3 => 42,
                            4 => i as i32,
                            5 => (n - i) as i32,
                            _ => (next(&mut s) % 4) as i32,
                        })
                        .collect();
                    let mut want = x.clone();
                    want.sort_unstable();
                    if flagdown {
                        want.reverse();
                    }
                    // SAFETY: AVX2 confirmed above.
                    unsafe { sort_2power(&mut x, 0, n, flagdown) };
                    assert_eq!(x, want, "djbsort n={n} down={flagdown} pattern={pattern}");
                }
            }
        }
    }
}
