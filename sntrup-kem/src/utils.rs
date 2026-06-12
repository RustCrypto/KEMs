use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::params::SntrupParameters;
use crate::{r3, rq, zx};

/// Hash prefix helper: SHA-512(prefix || input), truncated to 32 bytes.
pub(crate) fn hash_prefix(out: &mut [u8; 32], prefix: u8, input: &[u8]) {
    let mut hasher = Sha512::new();
    hasher.update([prefix]);
    hasher.update(input);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
}

/// hash_confirm: Hash(2 || Hash(3 || r_enc) || cache)
/// where cache = Hash4(pk) stored in the secret key.
pub(crate) fn hash_confirm(out: &mut [u8; 32], r_enc: &[u8], cache: &[u8; 32]) {
    let mut inner = [0u8; 32];
    hash_prefix(&mut inner, 3, r_enc);

    let mut hasher = Sha512::new();
    hasher.update([2u8]);
    hasher.update(inner);
    hasher.update(&cache[..]);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
}

/// hash_session: Hash(b || Hash(3 || y) || z)
pub(crate) fn hash_session(out: &mut [u8; 32], b: u8, y: &[u8], z: &[u8]) {
    let mut inner = [0u8; 32];
    hash_prefix(&mut inner, 3, y);

    let mut hasher = Sha512::new();
    hasher.update([b]);
    hasher.update(inner);
    hasher.update(z);
    let digest = hasher.finalize();
    out.copy_from_slice(&digest[..32]);
}

/// Constant-time: returns 0 if x == 0, -1 (0xFFFFFFFF) otherwise.
#[allow(clippy::cast_sign_loss)]
fn int16_nonzero_mask(x: i16) -> i32 {
    let u = x as u16;
    let mut r = u.wrapping_neg() | u;
    r >>= 15;
    -(r as i32)
}

/// Constant-time check if weight of `r` equals `w`.
/// Returns 0 if weight == w, -1 otherwise.
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
pub(crate) fn weightw_mask(r: &[i8], p: usize, w: usize) -> i32 {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return weightw_mask_avx2(r, p, w);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return weightw_mask_neon(r, p, w);
    }
    #[allow(unreachable_code)]
    weightw_mask_scalar(r, p, w)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn weightw_mask_scalar(r: &[i8], _p: usize, w: usize) -> i32 {
    let mut weight: i32 = 0;
    for &val in r.iter() {
        weight += (val & 1) as i32;
    }
    int16_nonzero_mask((weight - w as i32) as i16)
}

/// Count non-zero elements 32 at a time using AVX2.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
unsafe fn weightw_mask_avx2(r: &[i8], p: usize, w: usize) -> i32 {
    unsafe {
        use core::arch::x86_64::*;
        let ones = _mm256_set1_epi8(1);
        let mut acc = _mm256_setzero_si256();
        let mut i = 0usize;
        while i + 32 <= p {
            let v = _mm256_loadu_si256(r.as_ptr().add(i) as *const __m256i);
            let masked = _mm256_and_si256(v, ones);
            acc = _mm256_add_epi8(acc, masked);
            i += 32;
        }
        // Horizontal sum: sad against zero gives sum of abs values in each 8-byte lane
        let sad = _mm256_sad_epu8(acc, _mm256_setzero_si256());
        // sad has 4 u64 lanes with partial sums
        let lo = _mm256_castsi256_si128(sad);
        let hi = _mm256_extracti128_si256(sad, 1);
        let sum128 = _mm_add_epi64(lo, hi);
        let sum_hi = _mm_srli_si128(sum128, 8);
        let total = _mm_add_epi64(sum128, sum_hi);
        let mut weight = _mm_cvtsi128_si64(total) as i32;
        // Handle remainder
        while i < p {
            weight += (r[i] & 1) as i32;
            i += 1;
        }
        int16_nonzero_mask((weight - w as i32) as i16)
    }
}

/// Count non-zero elements 16 at a time using NEON.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
unsafe fn weightw_mask_neon(r: &[i8], p: usize, w: usize) -> i32 {
    unsafe {
        use core::arch::aarch64::*;
        let ones = vdupq_n_s8(1);
        let mut acc = vdupq_n_u8(0);
        let mut i = 0usize;
        while i + 16 <= p {
            let v = vld1q_s8(r.as_ptr().add(i));
            let masked = vreinterpretq_u8_s8(vandq_s8(v, ones));
            acc = vaddq_u8(acc, masked);
            i += 16;
        }
        // Progressive horizontal sum: u8 -> u16 -> u32 -> u64
        let sum16 = vpaddlq_u8(acc);
        let sum32 = vpaddlq_u16(sum16);
        let sum64 = vpaddlq_u32(sum32);
        let mut weight = (vgetq_lane_u64(sum64, 0) + vgetq_lane_u64(sum64, 1)) as i32;
        // Handle remainder
        while i < p {
            weight += (r[i] & 1) as i32;
            i += 1;
        }
        int16_nonzero_mask((weight - w as i32) as i16)
    }
}

/// Constant-time comparison of two byte slices.
/// Returns 0 if equal, -1 otherwise.
#[allow(unsafe_code, clippy::cast_possible_wrap)]
fn ciphertexts_diff_mask(a: &[u8], b: &[u8]) -> i32 {
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(feature = "force-scalar")
    ))]
    // SAFETY: AVX2 verified by cfg
    unsafe {
        return ciphertexts_diff_mask_avx2(a, b);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
    // SAFETY: NEON is baseline on aarch64
    unsafe {
        return ciphertexts_diff_mask_neon(a, b);
    }
    #[allow(unreachable_code)]
    ciphertexts_diff_mask_scalar(a, b)
}

#[allow(clippy::cast_possible_wrap)]
fn ciphertexts_diff_mask_scalar(a: &[u8], b: &[u8]) -> i32 {
    let mut diff: u16 = 0;
    let len = a.len().min(b.len());
    for i in 0..len {
        diff |= (a[i] ^ b[i]) as u16;
    }
    int16_nonzero_mask(diff as i16)
}

/// XOR-accumulate 32 bytes at a time, then horizontal OR.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(feature = "force-scalar")
))]
#[target_feature(enable = "avx2")]
#[allow(unsafe_code, clippy::cast_possible_wrap, clippy::cast_sign_loss)]
unsafe fn ciphertexts_diff_mask_avx2(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        use core::arch::x86_64::*;
        let len = a.len().min(b.len());
        let mut acc = _mm256_setzero_si256();
        let mut i = 0usize;
        while i + 32 <= len {
            let av = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
            let bv = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
            acc = _mm256_or_si256(acc, _mm256_xor_si256(av, bv));
            i += 32;
        }
        // Horizontal OR reduction.
        // movemask bit i is 1 iff byte i of acc == 0; mask == 0xFFFFFFFF iff equal.
        // Collapse to 0/1 branchlessly — a source-level branch here would leak,
        // via the branch predictor, whether the ciphertexts matched (the secret
        // the implicit-rejection comparison must hide).
        let inv = !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(acc, _mm256_setzero_si256())) as u32);
        let mut diff: u16 = ((inv | inv.wrapping_neg()) >> 31) as u16;
        // Handle remainder
        while i < len {
            diff |= (a[i] ^ b[i]) as u16;
            i += 1;
        }
        int16_nonzero_mask(diff as i16)
    }
}

/// XOR-accumulate 16 bytes at a time, then horizontal OR.
#[cfg(all(target_arch = "aarch64", not(feature = "force-scalar")))]
#[allow(unsafe_code, clippy::cast_possible_wrap, clippy::cast_sign_loss)]
unsafe fn ciphertexts_diff_mask_neon(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        use core::arch::aarch64::*;
        let len = a.len().min(b.len());
        let mut acc = vdupq_n_u8(0);
        let mut i = 0usize;
        while i + 16 <= len {
            let av = vld1q_u8(a.as_ptr().add(i));
            let bv = vld1q_u8(b.as_ptr().add(i));
            acc = vorrq_u8(acc, veorq_u8(av, bv));
            i += 16;
        }
        // Horizontal max: any-nonzero check
        let mut diff: u16 = vmaxvq_u8(acc) as u16;
        // Handle remainder
        while i < len {
            diff |= (a[i] ^ b[i]) as u16;
            i += 1;
        }
        int16_nonzero_mask(diff as i16)
    }
}

/// Derive a keypair from secret polynomials.
///
/// Returns `(pk_bytes, sk_bytes)` as `Vec<u8>`.
///
/// SK layout: `f_enc || ginv_enc || pk || rho || Hash4(pk)`
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn derive_key(
    f: &[i8],
    g: &[i8],
    gr: &[i8],
    rho: &[u8],
    params: &SntrupParameters,
) -> (Vec<u8>, Vec<u8>) {
    let p = params.p;

    let mut f3r = rq::reciprocal3(f, params);
    let mut h = vec![0i16; p];
    rq::mult(&mut h, &f3r, g, params);
    let pk = rq::encoding::rq_encode(&h, params);

    // SK layout: f_enc || ginv_enc || pk || rho || Hash4(pk)
    let mut sk = vec![0u8; params.sk_size];
    let mut f_enc = zx::encoding::encode(f, p, params.small_encode_size);
    let mut ginv_enc = zx::encoding::encode(gr, p, params.small_encode_size);

    let ses = params.small_encode_size;
    sk[..ses].copy_from_slice(&f_enc);
    sk[ses..(2 * ses)].copy_from_slice(&ginv_enc);
    sk[(2 * ses)..(2 * ses + params.pk_size)].copy_from_slice(&pk);
    sk[(2 * ses + params.pk_size)..(2 * ses + params.pk_size + ses)].copy_from_slice(rho);

    // Hash4(pk) = Hash(4 || pk) truncated to 32 bytes
    let mut cache = [0u8; 32];
    hash_prefix(&mut cache, 4, &pk);
    sk[(2 * ses + params.pk_size + ses)..].copy_from_slice(&cache);

    // Zeroize secret intermediates
    f3r.zeroize();
    h.zeroize();
    f_enc.zeroize();
    ginv_enc.zeroize();
    cache.zeroize();

    (pk, sk)
}

/// Encrypt a small polynomial `r` under a public key.
///
/// Returns `(ciphertext_bytes, shared_secret)`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn create_cipher(r: &[i8], pk: &[u8], params: &SntrupParameters) -> (Vec<u8>, [u8; 32]) {
    let p = params.p;

    let h = rq::encoding::rq_decode(pk, params);
    let mut c = vec![0i16; p];
    rq::mult(&mut c, &h, r, params);
    rq::round3(&mut c, params);

    let r_enc = zx::encoding::encode(r, p, params.small_encode_size);

    // Compute confirm hash: Hash(2 || Hash(3 || r_enc) || Hash4(pk))
    let mut cache = [0u8; 32];
    hash_prefix(&mut cache, 4, pk);
    let mut confirm = [0u8; 32];
    hash_confirm(&mut confirm, &r_enc, &cache);

    // Ciphertext layout: rounded(rounded_encode_size) || confirm_hash(32)
    let mut cstr = vec![0u8; params.ct_size];
    cstr[..params.rounded_encode_size].copy_from_slice(&rq::encoding::rounded_encode(&c, params));
    cstr[params.rounded_encode_size..].copy_from_slice(&confirm);

    // Shared key: hash_session(1, r_enc, cstr)
    let mut k = [0u8; 32];
    hash_session(&mut k, 1, &r_enc, &cstr);

    // Zeroize secret intermediates
    // r_enc, cache, confirm are on the stack / local Vecs and will be dropped,
    // but we zeroize explicitly for defense in depth.
    let mut r_enc = r_enc;
    r_enc.zeroize();
    cache.zeroize();
    confirm.zeroize();

    (cstr, k)
}

/// Decapsulate a ciphertext with a secret key.
///
/// Implements implicit rejection (IND-CCA2): on failure, returns a pseudorandom
/// key derived from `rho`, indistinguishable from a valid key.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
pub(crate) fn decapsulate_inner(cstr: &[u8], sk: &[u8], params: &SntrupParameters) -> [u8; 32] {
    let p = params.p;
    let w = params.w;
    let ses = params.small_encode_size;

    // Parse SK: f(ses) || ginv(ses) || pk(pk_size) || rho(ses) || cache(32)
    let mut f = zx::encoding::decode(&sk[..ses], p);
    let mut ginv = zx::encoding::decode(&sk[ses..(2 * ses)], p);
    let pk_start = 2 * ses;
    let pk_end = pk_start + params.pk_size;
    let rho_start = pk_end;
    let rho_end = rho_start + ses;
    let cache_start = rho_end;

    let mut cache = [0u8; 32];
    cache.copy_from_slice(&sk[cache_start..cache_start + 32]);

    // Decrypt: Rounded_decode, multiply by f, Rq_mult3, R3_fromRq, R3_mult by ginv
    let c = rq::encoding::rounded_decode(&cstr[..params.rounded_encode_size], params);
    let mut cf = vec![0i16; p];
    rq::mult(&mut cf, &c, &f, params);
    let mut t3 = vec![0i8; p];
    for i in 0..p {
        t3[i] = r3::mod3::freeze(rq::modq::freeze(
            3 * cf[i] as i32,
            params.q,
            params.barrett1,
            params.barrett2,
        ) as i32);
    }
    let mut r = vec![0i8; p];
    r3::mult(&mut r, &t3, &ginv, p);

    // Weight mask: on failure, set r to default weight-W vector
    // (W ones followed by P-W zeros), matching PQClean's Decrypt
    let w_mask = weightw_mask(&r, p, w);
    let not_mask = (!w_mask) as i8;
    for val in r[..w].iter_mut() {
        *val = ((*val ^ 1) & not_mask) ^ 1;
    }
    for val in r[w..p].iter_mut() {
        *val &= not_mask;
    }

    // Hide: encode r, re-encrypt with pk, compute confirm hash
    let mut r_enc = zx::encoding::encode(&r, p, ses);
    let h = rq::encoding::rq_decode(&sk[pk_start..pk_end], params);
    let mut hr = vec![0i16; p];
    rq::mult(&mut hr, &h, &r, params);
    rq::round3(&mut hr, params);
    let mut cnew = vec![0u8; params.ct_size];
    cnew[..params.rounded_encode_size].copy_from_slice(&rq::encoding::rounded_encode(&hr, params));
    let mut confirm = [0u8; 32];
    hash_confirm(&mut confirm, &r_enc, &cache);
    cnew[params.rounded_encode_size..].copy_from_slice(&confirm);

    // Compare full ciphertexts (rounded + confirm hash)
    let mask = ciphertexts_diff_mask(cstr, &cnew);

    // Constant-time select: r_enc on success (mask=0), rho on failure (mask=-1)
    let rho = &sk[rho_start..rho_end];
    let mut selected = vec![0u8; ses];
    selected.copy_from_slice(&r_enc);
    let mask_byte = mask as u8;
    for i in 0..ses {
        selected[i] ^= mask_byte & (selected[i] ^ rho[i]);
    }

    // Hash session: prefix=1 on success (mask=0), prefix=0 on failure (mask=-1)
    let prefix = (1 + mask) as u8;
    let mut k = [0u8; 32];
    hash_session(&mut k, prefix, &selected, cstr);

    // Zeroize secret intermediates
    f.zeroize();
    ginv.zeroize();
    cache.zeroize();
    cf.zeroize();
    t3.zeroize();
    r.zeroize();
    r_enc.zeroize();
    hr.zeroize();
    cnew.zeroize();
    confirm.zeroize();
    selected.zeroize();

    k
}
