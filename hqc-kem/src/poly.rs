/// Binary polynomial operations in Z_2[X]/(X^n - 1).
///
/// Polynomials are stored as arrays of u64, where each bit is a coefficient.
/// Uses Karatsuba multiplication for efficiency.
use crate::params::HqcParameters;

/// Polynomial addition: o = v1 XOR v2.
#[inline]
pub(crate) fn vect_add(o: &mut [u64], v1: &[u64], v2: &[u64], size: usize) {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        // Safety: AVX2 detected; pointers valid for `size` elements.
        unsafe {
            return vect_add_avx2(o, v1, v2, size);
        }
    }
    for i in 0..size {
        o[i] = v1[i] ^ v2[i];
    }
}

/// In-place polynomial addition: v ^= rhs.
#[inline]
pub(crate) fn vect_add_assign(v: &mut [u64], rhs: &[u64], size: usize) {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        unsafe {
            return vect_add_assign_avx2(v, rhs, size);
        }
    }
    for i in 0..size {
        v[i] ^= rhs[i];
    }
}

/// Constant-time byte comparison. Returns 0 if equal, non-zero otherwise.
pub(crate) fn vect_compare(v1: &[u8], v2: &[u8]) -> u8 {
    let mut r: u16 = 0x0100;
    for i in 0..v1.len().min(v2.len()) {
        r |= (v1[i] ^ v2[i]) as u16;
    }
    ((r.wrapping_sub(1)) >> 8) as u8
}

/// Carry-less multiplication of two 64-bit words.
///
/// Uses PCLMULQDQ on x86-64 when available, otherwise constant-time software fallback.
#[inline]
fn base_mul(a: u64, b: u64) -> [u64; 2] {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("pclmulqdq") {
            return unsafe { base_mul_pclmul(a, b) };
        }
    }
    base_mul_soft(a, b)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
#[inline]
unsafe fn base_mul_pclmul(a: u64, b: u64) -> [u64; 2] {
    use std::arch::x86_64::*;
    unsafe {
        let va = _mm_set_epi64x(0, a as i64);
        let vb = _mm_set_epi64x(0, b as i64);
        let r = _mm_clmulepi64_si128(va, vb, 0x00);
        let mut result = [0u64; 2];
        _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, r);
        result
    }
}

/// Software carry-less multiplication (constant-time).
#[inline]
fn base_mul_soft(a: u64, b: u64) -> [u64; 2] {
    let mut h: u64 = 0;
    let mut l: u64;
    let mut g: u64;
    let mut u = [0u64; 16];

    // Precompute small multiples of b (with top 4 bits masked)
    u[0] = 0;
    u[1] = b & ((1u64 << 60) - 1);
    u[2] = u[1] << 1;
    u[3] = u[2] ^ u[1];
    u[4] = u[2] << 1;
    u[5] = u[4] ^ u[1];
    u[6] = u[3] << 1;
    u[7] = u[6] ^ u[1];
    u[8] = u[4] << 1;
    u[9] = u[8] ^ u[1];
    u[10] = u[5] << 1;
    u[11] = u[10] ^ u[1];
    u[12] = u[6] << 1;
    u[13] = u[12] ^ u[1];
    u[14] = u[7] << 1;
    u[15] = u[14] ^ u[1];

    // First nibble
    g = 0;
    let tmp1 = a & 0x0f;
    for i in 0..16u64 {
        let tmp2 = tmp1.wrapping_sub(i);
        let mask = 0u64.wrapping_sub(1u64.wrapping_sub((tmp2 | tmp2.wrapping_neg()) >> 63));
        g ^= u[i as usize] & mask;
    }
    l = g;

    // Remaining nibbles
    for shift in (4..64).step_by(4) {
        g = 0;
        let tmp1 = (a >> shift) & 0x0f;
        for j in 0..16u64 {
            let tmp2 = tmp1.wrapping_sub(j);
            let mask = 0u64.wrapping_sub(1u64.wrapping_sub((tmp2 | tmp2.wrapping_neg()) >> 63));
            g ^= u[j as usize] & mask;
        }
        l ^= g << shift;
        h ^= g >> (64 - shift);
    }

    // Handle top 4 bits of b
    let masks = [
        0u64.wrapping_sub((b >> 60) & 1),
        0u64.wrapping_sub((b >> 61) & 1),
        0u64.wrapping_sub((b >> 62) & 1),
        0u64.wrapping_sub((b >> 63) & 1),
    ];

    l ^= (a << 60) & masks[0];
    h ^= (a >> 4) & masks[0];
    l ^= (a << 61) & masks[1];
    h ^= (a >> 3) & masks[1];
    l ^= (a << 62) & masks[2];
    h ^= (a >> 2) & masks[2];
    l ^= (a << 63) & masks[3];
    h ^= (a >> 1) & masks[3];

    [l, h]
}

#[inline]
fn karatsuba_add1(
    alh: &mut [u64],
    blh: &mut [u64],
    a: &[u64],
    b: &[u64],
    size_l: usize,
    size_h: usize,
) {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        unsafe {
            return karatsuba_add1_avx2(alh, blh, a, b, size_l, size_h);
        }
    }
    for i in 0..size_h {
        alh[i] = a[i] ^ a[i + size_l];
        blh[i] = b[i] ^ b[i + size_l];
    }
    if size_h < size_l {
        alh[size_h] = a[size_h];
        blh[size_h] = b[size_h];
    }
}

#[inline]
fn karatsuba_add2(o: &mut [u64], tmp1: &mut [u64], tmp2: &[u64], size_l: usize, size_h: usize) {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        unsafe {
            return karatsuba_add2_avx2(o, tmp1, tmp2, size_l, size_h);
        }
    }
    for i in 0..(2 * size_l) {
        tmp1[i] ^= o[i];
    }
    for i in 0..(2 * size_h) {
        tmp1[i] ^= tmp2[i];
    }
    for i in 0..(2 * size_l) {
        o[i + size_l] ^= tmp1[i];
    }
}

/// Recursive Karatsuba multiplication.
///
/// Stack layout per level: [alh(size_l) | blh(size_l) | tmp1(2*size_l) | copies(2*size_l) | deeper...]
/// Total local = 6*size_l per level. The 8*vec_n pre-allocation is sufficient for all levels.
fn karatsuba(o: &mut [u64], a: &[u64], b: &[u64], size: usize, stack: &mut [u64]) {
    if size == 1 {
        let c = base_mul(a[0], b[0]);
        o[0] = c[0];
        o[1] = c[1];
        return;
    }

    let size_h = size / 2;
    let size_l = size.div_ceil(2);

    // Split stack: 6*size_l for this level, rest for recursion
    let (local, stack_rest) = stack.split_at_mut(6 * size_l);

    // local layout: [alh | blh | tmp1 | copies]
    let (alh_blh, tmp1_copies) = local.split_at_mut(2 * size_l);
    let (tmp1_part, copies_part) = tmp1_copies.split_at_mut(2 * size_l);

    karatsuba(o, a, b, size_l, stack_rest);
    karatsuba(
        &mut o[2 * size_l..],
        &a[size_l..],
        &b[size_l..],
        size_h,
        stack_rest,
    );

    {
        let (alh_part, blh_part) = alh_blh.split_at_mut(size_l);
        karatsuba_add1(alh_part, blh_part, a, b, size_l, size_h);
    }

    // Copy alh/blh into copies region so we can pass tmp1 as mutable output
    let (alh, blh) = alh_blh.split_at(size_l);
    let (alh_copy, blh_copy) = copies_part.split_at_mut(size_l);
    alh_copy[..size_l].copy_from_slice(alh);
    blh_copy[..size_l].copy_from_slice(&blh[..size_l]);

    // Clear tmp1 before writing
    for v in tmp1_part[..2 * size_l].iter_mut() {
        *v = 0;
    }
    karatsuba(
        tmp1_part,
        &alh_copy[..size_l],
        &blh_copy[..size_l],
        size_l,
        stack_rest,
    );

    // Copy tmp2 (in o[2*size_l..]) into copies region to avoid aliasing
    let tmp2_len = 2 * size_h;
    copies_part[..tmp2_len].copy_from_slice(&o[2 * size_l..2 * size_l + tmp2_len]);

    karatsuba_add2(o, tmp1_part, &copies_part[..tmp2_len], size_l, size_h);
}

/// Reduce polynomial modulo X^n - 1.
fn reduce(o: &mut [u64], a: &[u64], n: usize, vec_n_size_64: usize) {
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        unsafe {
            return reduce_avx2(o, a, n, vec_n_size_64);
        }
    }
    let shift = n & 0x3f;
    for i in 0..vec_n_size_64 {
        let r = a[i + vec_n_size_64 - 1] >> shift;
        let carry = if i + vec_n_size_64 < a.len() {
            a[i + vec_n_size_64] << (64 - shift)
        } else {
            0
        };
        o[i] = a[i] ^ r ^ carry;
    }
}

/// Multiply two polynomials modulo X^n - 1.
pub(crate) fn vect_mul(o: &mut [u64], v1: &[u64], v2: &[u64], p: &HqcParameters) {
    let vec_n = p.vec_n_size_64;
    let mut stack = vec![0u64; vec_n << 3];
    let mut o_karat = vec![0u64; vec_n << 1];

    karatsuba(&mut o_karat, &v1[..vec_n], &v2[..vec_n], vec_n, &mut stack);
    reduce(o, &o_karat, p.n, vec_n);
    o[vec_n - 1] &= p.red_mask;
}

/// Load byte array into u64 array (little-endian).
#[inline]
pub(crate) fn load8_arr(out: &mut [u64], inp: &[u8]) {
    let full_chunks = inp.len() / 8;
    let count = full_chunks.min(out.len());
    for i in 0..count {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&inp[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(buf);
    }
    let rem = inp.len() - count * 8;
    if rem > 0 && count < out.len() {
        let mut buf = [0u8; 8];
        buf[..rem].copy_from_slice(&inp[count * 8..]);
        out[count] = u64::from_le_bytes(buf);
    }
}

/// Store u64 array into byte array (little-endian).
#[inline]
pub(crate) fn store8_arr(out: &mut [u8], inp: &[u64]) {
    let full_chunks = out.len() / 8;
    let count = full_chunks.min(inp.len());
    for i in 0..count {
        out[i * 8..(i + 1) * 8].copy_from_slice(&inp[i].to_le_bytes());
    }
    let rem = out.len() - count * 8;
    if rem > 0 && count < inp.len() {
        let bytes = inp[count].to_le_bytes();
        out[count * 8..].copy_from_slice(&bytes[..rem]);
    }
}

// ---- AVX2 SIMD acceleration (x86-64 only) ----

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn vect_add_avx2(o: &mut [u64], v1: &[u64], v2: &[u64], size: usize) {
    use std::arch::x86_64::*;
    let chunks = size / 4;
    unsafe {
        let p1 = v1.as_ptr() as *const __m256i;
        let p2 = v2.as_ptr() as *const __m256i;
        let po = o.as_mut_ptr() as *mut __m256i;
        for i in 0..chunks {
            _mm256_storeu_si256(
                po.add(i),
                _mm256_xor_si256(_mm256_loadu_si256(p1.add(i)), _mm256_loadu_si256(p2.add(i))),
            );
        }
    }
    for i in (chunks * 4)..size {
        o[i] = v1[i] ^ v2[i];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn vect_add_assign_avx2(v: &mut [u64], rhs: &[u64], size: usize) {
    use std::arch::x86_64::*;
    let chunks = size / 4;
    unsafe {
        let pv = v.as_mut_ptr() as *mut __m256i;
        let pr = rhs.as_ptr() as *const __m256i;
        for i in 0..chunks {
            _mm256_storeu_si256(
                pv.add(i),
                _mm256_xor_si256(
                    _mm256_loadu_si256(pv.add(i) as *const __m256i),
                    _mm256_loadu_si256(pr.add(i)),
                ),
            );
        }
    }
    for i in (chunks * 4)..size {
        v[i] ^= rhs[i];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn karatsuba_add1_avx2(
    alh: &mut [u64],
    blh: &mut [u64],
    a: &[u64],
    b: &[u64],
    size_l: usize,
    size_h: usize,
) {
    use std::arch::x86_64::*;
    let chunks = size_h / 4;
    for i in 0..chunks {
        let idx = i * 4;
        unsafe {
            let a_lo = _mm256_loadu_si256(a.as_ptr().add(idx) as *const __m256i);
            let a_hi = _mm256_loadu_si256(a.as_ptr().add(idx + size_l) as *const __m256i);
            _mm256_storeu_si256(
                alh.as_mut_ptr().add(idx) as *mut __m256i,
                _mm256_xor_si256(a_lo, a_hi),
            );
            let b_lo = _mm256_loadu_si256(b.as_ptr().add(idx) as *const __m256i);
            let b_hi = _mm256_loadu_si256(b.as_ptr().add(idx + size_l) as *const __m256i);
            _mm256_storeu_si256(
                blh.as_mut_ptr().add(idx) as *mut __m256i,
                _mm256_xor_si256(b_lo, b_hi),
            );
        }
    }
    for i in (chunks * 4)..size_h {
        alh[i] = a[i] ^ a[i + size_l];
        blh[i] = b[i] ^ b[i + size_l];
    }
    if size_h < size_l {
        alh[size_h] = a[size_h];
        blh[size_h] = b[size_h];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn karatsuba_add2_avx2(
    o: &mut [u64],
    tmp1: &mut [u64],
    tmp2: &[u64],
    size_l: usize,
    size_h: usize,
) {
    use std::arch::x86_64::*;
    let len1 = 2 * size_l;
    let len2 = 2 * size_h;

    // tmp1[i] ^= o[i] for i in 0..2*size_l
    let chunks1 = len1 / 4;
    for i in 0..chunks1 {
        let idx = i * 4;
        unsafe {
            let pt = tmp1.as_mut_ptr().add(idx) as *mut __m256i;
            _mm256_storeu_si256(
                pt,
                _mm256_xor_si256(
                    _mm256_loadu_si256(pt as *const __m256i),
                    _mm256_loadu_si256(o.as_ptr().add(idx) as *const __m256i),
                ),
            );
        }
    }
    for i in (chunks1 * 4)..len1 {
        tmp1[i] ^= o[i];
    }

    // tmp1[i] ^= tmp2[i] for i in 0..2*size_h
    let chunks2 = len2 / 4;
    for i in 0..chunks2 {
        let idx = i * 4;
        unsafe {
            let pt = tmp1.as_mut_ptr().add(idx) as *mut __m256i;
            _mm256_storeu_si256(
                pt,
                _mm256_xor_si256(
                    _mm256_loadu_si256(pt as *const __m256i),
                    _mm256_loadu_si256(tmp2.as_ptr().add(idx) as *const __m256i),
                ),
            );
        }
    }
    for i in (chunks2 * 4)..len2 {
        tmp1[i] ^= tmp2[i];
    }

    // o[i + size_l] ^= tmp1[i] for i in 0..2*size_l
    for i in 0..chunks1 {
        let idx = i * 4;
        unsafe {
            let po = o.as_mut_ptr().add(idx + size_l) as *mut __m256i;
            _mm256_storeu_si256(
                po,
                _mm256_xor_si256(
                    _mm256_loadu_si256(po as *const __m256i),
                    _mm256_loadu_si256(tmp1.as_ptr().add(idx) as *const __m256i),
                ),
            );
        }
    }
    for i in (chunks1 * 4)..len1 {
        o[i + size_l] ^= tmp1[i];
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn reduce_avx2(o: &mut [u64], a: &[u64], n: usize, vec_n: usize) {
    use std::arch::x86_64::*;
    let shift = (n & 0x3f) as i64;
    let inv_shift = 64 - shift;
    let chunks = vec_n / 4;

    unsafe {
        let shift_v = _mm_set_epi64x(0, shift);
        let inv_shift_v = _mm_set_epi64x(0, inv_shift);

        for i in 0..chunks {
            let idx = i * 4;
            let base = _mm256_loadu_si256(a.as_ptr().add(idx) as *const __m256i);
            let hi_prev = _mm256_loadu_si256(a.as_ptr().add(idx + vec_n - 1) as *const __m256i);
            let hi_next = _mm256_loadu_si256(a.as_ptr().add(idx + vec_n) as *const __m256i);
            let r = _mm256_srl_epi64(hi_prev, shift_v);
            let carry = _mm256_sll_epi64(hi_next, inv_shift_v);
            _mm256_storeu_si256(
                o.as_mut_ptr().add(idx) as *mut __m256i,
                _mm256_xor_si256(base, _mm256_xor_si256(r, carry)),
            );
        }
    }
    // Scalar remainder
    let shift_s = n & 0x3f;
    for i in (chunks * 4)..vec_n {
        let r = a[i + vec_n - 1] >> shift_s;
        let carry = if i + vec_n < a.len() {
            a[i + vec_n] << (64 - shift_s)
        } else {
            0
        };
        o[i] = a[i] ^ r ^ carry;
    }
}

/// Resize vector: copy and potentially truncate.
pub(crate) fn vect_resize(o: &mut [u64], size_o: usize, v: &[u64], size_v: usize) {
    if size_o < size_v {
        let n1n2_64 = size_o.div_ceil(64);
        let copy_words = n1n2_64.min(o.len()).min(v.len());
        o[..copy_words].copy_from_slice(&v[..copy_words]);
        let bits_in_last = size_o % 64;
        if bits_in_last != 0 && n1n2_64 > 0 && n1n2_64 - 1 < o.len() {
            o[n1n2_64 - 1] &= (1u64 << bits_in_last) - 1;
        }
    } else {
        let words = size_v.div_ceil(64);
        let copy_words = words.min(o.len()).min(v.len());
        o[..copy_words].copy_from_slice(&v[..copy_words]);
    }
}
