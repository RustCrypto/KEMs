use super::modq;
use crate::params::SntrupParameters;

/// Maximum number of pairing levels across all parameter sets (P up to 1277).
/// Levels: 1277 -> 639 -> 320 -> 160 -> 80 -> 40 -> 20 -> 10 -> 5 -> 3 -> 2 -> base case (n=1).
const fn compute_levels(p: usize) -> usize {
    let mut n = p;
    let mut levels = 0;
    while n > 1 {
        levels += 1;
        n = n.div_ceil(2);
    }
    levels
}

/// Total moduli storage across all levels (including the base case modulus).
const fn compute_m_storage(p: usize) -> usize {
    let mut n = p;
    let mut total = 0;
    while n > 1 {
        total += n;
        n = n.div_ceil(2);
    }
    total + 1 // +1 for base case modulus
}

const MAX_LEVELS: usize = compute_levels(1277); // 11
const MAX_M_STORAGE: usize = compute_m_storage(1277); // 2557

/// Constant-time divmod: *quotient = x / m, returns x % m.
/// m must be > 0 and < 16384. Matches PQClean's two-step Barrett reduction.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn uint32_divmod_uint14(quotient: &mut u32, x: u32, m: u16) -> u16 {
    let m32 = m as u32;
    let v = (0x80000000u32 as u64) / (m32 as u64);
    // First Barrett step
    let mut qpart = ((x as u64 * v) >> 31) as u32;
    let mut r = x - qpart * m32;
    *quotient = qpart;
    // Second Barrett step on remainder
    qpart = ((r as u64 * v) >> 31) as u32;
    r -= qpart * m32;
    *quotient += qpart;
    // Final speculative correction
    r = r.wrapping_sub(m32);
    *quotient += 1;
    let mask = (r >> 31).wrapping_neg(); // 0xFFFFFFFF if r underflowed (was < m), else 0
    r = r.wrapping_add(mask & m32);
    *quotient = quotient.wrapping_add(mask); // subtract 1 if we over-corrected
    r as u16
}

#[inline(always)]
fn uint32_mod_uint14(x: u32, m: u16) -> u16 {
    let mut q = 0u32;
    uint32_divmod_uint14(&mut q, x, m)
}

/// Iterative variable-radix encoding. Pairs values, emits bottom bytes when the
/// combined modulus reaches 16384, then repeats on the paired values.
/// `r` and `m` are modified in place across levels.
#[allow(clippy::cast_possible_truncation)]
fn encode(out: &mut [u8], r: &mut [u16], m: &mut [u16], n_start: usize) -> usize {
    if n_start == 0 {
        return 0;
    }
    if n_start == 1 {
        return encode_single(out, r[0] as u32, m[0] as u32);
    }

    let mut n = n_start;
    let mut pos = 0;

    while n > 1 {
        let n2 = n.div_ceil(2);
        // In-place pairing: read from [2*i, 2*i+1], write to [i].
        // Safe because i < 2*i for i >= 1, so reads precede writes.
        for i in 0..n2 {
            if 2 * i + 1 < n {
                let mut combined = r[2 * i] as u32 + (r[2 * i + 1] as u32) * (m[2 * i] as u32);
                let mut cm = (m[2 * i] as u32) * (m[2 * i + 1] as u32);
                while cm >= 16384 {
                    out[pos] = combined as u8;
                    pos += 1;
                    combined >>= 8;
                    cm = (cm + 255) >> 8;
                }
                r[i] = combined as u16;
                m[i] = cm as u16;
            } else {
                r[i] = r[2 * i];
                m[i] = m[2 * i];
            }
        }
        n = n2;
    }

    // Base case: single remaining value
    pos + encode_single(&mut out[pos..], r[0] as u32, m[0] as u32)
}

#[allow(clippy::cast_possible_truncation)]
fn encode_single(out: &mut [u8], mut val: u32, mut modulus: u32) -> usize {
    let mut pos = 0;
    while modulus > 1 {
        out[pos] = val as u8;
        pos += 1;
        val >>= 8;
        modulus = (modulus + 255) >> 8;
    }
    pos
}

/// AVX2 expansion of one decode level whose pairs all share a modulus `m` and
/// bottom-byte count `bb` — the shape levels 0-2 always have (see RESULTS.md).
///
/// Handles pairs `[lo, hi)` backward in blocks of eight 32-bit lanes:
/// `combined = out[i]·256^bb + LE(s[start + i·bb ..][..bb])`, then
/// `out[2i] = combined mod m`, `out[2i+1] = (combined / m) mod m`, replicating
/// `uint32_divmod_uint14`'s two Barrett steps plus speculative correction
/// lanewise. Callers guarantee `lo >= 8`, so a block's writes (`out[2i..2i+16]`)
/// never overlap its reads (`out[i..i+8]`).
///
/// `bb` is 1 or 2 for every level this is invoked on; other values fall back to
/// the scalar path.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx2")]
#[allow(unsafe_code)]
unsafe fn decode_level_avx2(
    out: &mut [u16],
    s: &[u8],
    m: u16,
    bb: usize,
    start: usize,
    lo: usize,
    hi: usize,
) {
    unsafe {
        use core::arch::x86_64::*;

        let m32 = u32::from(m);
        #[allow(clippy::cast_possible_truncation)]
        let v = (0x8000_0000u64 / u64::from(m32)) as u32;
        let mv = _mm256_set1_epi32(i32::from_ne_bytes(m32.to_ne_bytes()));
        let vv = _mm256_set1_epi64x(i64::from(v));

        // 8-lane u32 multiply-high-by-v, keeping bit 31 upward (the scalar
        // code's `(x as u64 * v) >> 31`). AVX2 only multiplies even 32-bit
        // lanes, so run the even and odd halves separately and reblend.
        let qhat = |x: __m256i| -> __m256i {
            let pe = _mm256_srli_epi64::<31>(_mm256_mul_epu32(x, vv));
            let po = _mm256_srli_epi64::<31>(_mm256_mul_epu32(_mm256_srli_epi64::<32>(x), vv));
            _mm256_blend_epi32::<0b1010_1010>(pe, _mm256_slli_epi64::<32>(po))
        };

        // One Barrett step: returns (quotient_part, remainder).
        let step = |x: __m256i| -> (__m256i, __m256i) {
            let q = qhat(x);
            (q, _mm256_sub_epi32(x, _mm256_mullo_epi32(q, mv)))
        };

        let mut i = hi;
        while i >= lo + 8 {
            i -= 8;

            let ov = _mm256_cvtepu16_epi32(_mm_loadu_si128(out.as_ptr().add(i) as *const __m128i));
            let bytes = if bb == 1 {
                _mm256_cvtepu8_epi32(_mm_loadl_epi64(s.as_ptr().add(start + i) as *const __m128i))
            } else {
                _mm256_cvtepu16_epi32(_mm_loadu_si128(
                    s.as_ptr().add(start + 2 * i) as *const __m128i
                ))
            };
            let shift = if bb == 1 { 8 } else { 16 };
            let combined = _mm256_add_epi32(_mm256_sllv_epi32(ov, _mm256_set1_epi32(shift)), bytes);

            // divmod: two Barrett steps then the speculative correction.
            let (q0, r0) = step(combined);
            let (q1, r1) = step(r0);
            let q = _mm256_add_epi32(q0, q1);
            let rsub = _mm256_sub_epi32(r1, mv);
            let mask = _mm256_srai_epi32::<31>(rsub);
            let rem = _mm256_add_epi32(rsub, _mm256_and_si256(mask, mv));
            let quo = _mm256_add_epi32(_mm256_add_epi32(q, _mm256_set1_epi32(1)), mask);

            // out[2i+1] = quo mod m (one more reduction; quo < m^2 / ... but a
            // single Barrett step plus correction suffices, matching
            // uint32_mod_uint14).
            let (_, hr0) = step(quo);
            let (_, hr1) = step(hr0);
            let hsub = _mm256_sub_epi32(hr1, mv);
            let hmask = _mm256_srai_epi32::<31>(hsub);
            let hi_val = _mm256_add_epi32(hsub, _mm256_and_si256(hmask, mv));

            // Interleave (rem, hi_val) into out[2i .. 2i+16] as u16.
            let lo16 = _mm256_packus_epi32(rem, hi_val); // lanes: r0..3 h0..3 r4..7 h4..7
            let fixed = _mm256_permute4x64_epi64::<0b11_01_10_00>(lo16); // r0..3 r4..7 h0..3 h4..7
            let r16 = _mm256_castsi256_si128(fixed);
            let h16 = _mm256_extracti128_si256::<1>(fixed);
            _mm_storeu_si128(
                out.as_mut_ptr().add(2 * i) as *mut __m128i,
                _mm_unpacklo_epi16(r16, h16),
            );
            _mm_storeu_si128(
                out.as_mut_ptr().add(2 * i + 8) as *mut __m128i,
                _mm_unpackhi_epi16(r16, h16),
            );
        }
    }
}

/// Per-(modulus, length) decode plan: the moduli tree, per-level bottom-byte
/// counts, and level offsets.
///
/// These depend only on the starting modulus and `p`, both public and fixed per
/// parameter set, yet recomputing them cost ~0.75 µs on every decode — 1.5 µs of
/// each decapsulation, which runs two. There are exactly twelve live
/// combinations (six parameter sets x {Rq, rounded}), so they are computed once
/// on first use and reused thereafter.
struct DecodePlan {
    ns: [usize; MAX_LEVELS],
    num_levels: usize,
    all_m: [u16; MAX_M_STORAGE],
    level_m_offset: [usize; MAX_LEVELS + 1],
    level_bottom_total: [usize; MAX_LEVELS],
    level_bottom_start: [usize; MAX_LEVELS],
    all_bb: [u8; MAX_M_STORAGE],
    /// Total bottom bytes across all levels — where the base case is read from.
    cum_bottom: usize,
}

/// Twelve slots: `(parameter set, codec kind)`. Keyed by the pair actually
/// requested, so a miss simply builds and stores its own plan.
static PLANS: [std::sync::OnceLock<(u16, usize, Box<DecodePlan>)>; 12] =
    [const { std::sync::OnceLock::new() }; 12];

fn plan_for(m0: u16, n_start: usize) -> &'static DecodePlan {
    for slot in &PLANS {
        // An occupied slot for a different key is skipped; an empty one is
        // claimed for this key. Twelve slots cover every live combination.
        if let Some((km, kn, plan)) = slot.get() {
            if *km == m0 && *kn == n_start {
                return plan;
            }
            continue;
        }
        let built = slot.get_or_init(|| (m0, n_start, Box::new(build_plan(m0, n_start))));
        if built.0 == m0 && built.1 == n_start {
            return &built.2;
        }
    }
    // Slots exhausted (cannot happen for the supported parameter sets): fall
    // back to leaking one plan rather than failing.
    Box::leak(Box::new(build_plan(m0, n_start)))
}

#[allow(clippy::cast_possible_truncation)]
fn build_plan(m0: u16, n_start: usize) -> DecodePlan {
    let mut ns = [0usize; MAX_LEVELS];
    let mut num_levels = 0;
    {
        let mut n = n_start;
        while n > 1 {
            ns[num_levels] = n;
            num_levels += 1;
            n = n.div_ceil(2);
        }
    }

    let mut all_m = [0u16; MAX_M_STORAGE];
    let mut all_bb = [0u8; MAX_M_STORAGE];
    let mut level_m_offset = [0usize; MAX_LEVELS + 1];
    let mut level_bottom_total = [0usize; MAX_LEVELS];
    let mut level_bottom_start = [0usize; MAX_LEVELS];

    all_m[..n_start].fill(m0);
    level_m_offset[0] = 0;
    let mut m_pos = n_start;

    for level in 0..num_levels {
        let n = ns[level];
        let n2 = n.div_ceil(2);
        let m_off = level_m_offset[level];
        level_m_offset[level + 1] = m_pos;
        let mut total_bottom = 0usize;
        for i in 0..n2 {
            if 2 * i + 1 < n {
                let mut cm = u32::from(all_m[m_off + 2 * i]) * u32::from(all_m[m_off + 2 * i + 1]);
                let mut bb = 0usize;
                while cm >= 16384 {
                    bb += 1;
                    cm = (cm + 255) >> 8;
                }
                total_bottom += bb;
                all_bb[m_pos] = bb as u8;
                all_m[m_pos] = cm as u16;
            } else {
                all_m[m_pos] = all_m[m_off + 2 * i];
            }
            m_pos += 1;
        }
        level_bottom_total[level] = total_bottom;
    }

    // Cumulative bottom-byte start positions, level 0 upward.
    let mut cum = 0usize;
    for level in 0..num_levels {
        level_bottom_start[level] = cum;
        cum += level_bottom_total[level];
    }

    DecodePlan {
        ns,
        num_levels,
        all_m,
        level_m_offset,
        level_bottom_total,
        level_bottom_start,
        all_bb,
        cum_bottom: cum,
    }
}

/// Iterative variable-radix decoding: the moduli tree and byte offsets come
/// from a cached [`DecodePlan`]; the backward pass expands decoded values from
/// the base case.
#[allow(clippy::cast_possible_truncation)]
fn decode(out: &mut [u16], s: &[u8], m_in: &[u16], n_start: usize) {
    if n_start == 0 {
        return;
    }
    if n_start == 1 {
        decode_single(out, s, m_in[0]);
        return;
    }

    // The moduli tree, per-level byte counts and offsets depend only on the
    // (public, fixed) starting modulus and length, so they are built once and
    // cached rather than recomputed on every call.
    let plan = plan_for(m_in[0], n_start);
    let ns = &plan.ns;
    let num_levels = plan.num_levels;
    let all_m = &plan.all_m;
    let all_bb = &plan.all_bb;
    let level_m_offset = &plan.level_m_offset;
    let level_bottom_total = &plan.level_bottom_total;
    let level_bottom_start = &plan.level_bottom_start;
    let cum_bottom = plan.cum_bottom;

    // --- Decode base case (n = 1) ---
    let base_m_off = level_m_offset[num_levels];
    decode_single(out, &s[cum_bottom..], all_m[base_m_off]);

    // --- Backward pass: expand decoded values level by level ---
    for level in (0..num_levels).rev() {
        let n = ns[level];
        let n2 = n.div_ceil(2);
        let m_off = level_m_offset[level];

        // out[0..n2] holds decoded values; expand in-place to out[0..n].
        // Process backwards: reads from out[i], writes to out[2*i] / out[2*i+1].
        let mut bpos = level_bottom_start[level] + level_bottom_total[level];

        // Uniform-modulus fast path. The kernel covers the half-open pair range
        // `[simd_lo, simd_hi)`; the scalar loop below walks every pair anyway to
        // thread `bpos` (whose step varies with each pair's byte count) and
        // simply skips the work the kernel already did.
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        let mut simd_lo = n2;
        #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
        {
            let n_full = n / 2;
            if n_full >= 16 && crate::cpu::has_avx2() {
                let m0 = all_m[m_off];
                let bb = all_bb[level_m_offset[level + 1]] as usize;
                // Every full pair on this level must share the modulus. A
                // prefix-only relaxation is NOT sound here: the kernel's stores
                // reach out[2*n_uniform + 14], so any higher pair still needing
                // its input would have to run first, and the byte-cursor
                // threading then has to be split to match. See RESULTS.md.
                let n_uniform = if (0..n_full)
                    .all(|k| all_m[m_off + 2 * k] == m0 && all_m[m_off + 2 * k + 1] == m0)
                {
                    n_full
                } else {
                    0
                };
                if n_uniform >= 16 && (bb == 1 || bb == 2) {
                    let start = level_bottom_start[level];
                    // The unpaired tail element is the highest index the scalar
                    // loop would visit, so it must be copied BEFORE the kernel
                    // runs — the kernel's stores reach out[2*n_full - 1] and
                    // would otherwise clobber out[n2 - 1] before it is read.
                    if n % 2 == 1 {
                        out[2 * (n2 - 1)] = out[n2 - 1];
                    }
                    // SAFETY: AVX2 confirmed by has_avx2(). `lo = 0` is sound:
                    // within a block every load precedes every store, and
                    // blocks descend, so a block's writes (out[2i..2i+16])
                    // always sit above any lower block's reads (out[i..i+8]).
                    unsafe {
                        decode_level_avx2(out, s, m0, bb, start, 8, n_uniform);
                    }
                    simd_lo = 8 + (n_uniform - 8) % 8;
                    bpos = start + simd_lo * bb;
                }
            }
        }
        #[cfg(not(all(target_arch = "x86_64", not(feature = "force-scalar"))))]
        let simd_lo = n2;

        for i in (0..simd_lo).rev() {
            if 2 * i + 1 < n {
                let bb = all_bb[level_m_offset[level + 1] + i] as usize;
                bpos -= bb;
                let mut combined = out[i] as u32;
                for j in (0..bb).rev() {
                    combined = (combined << 8) | (s[bpos + j] as u32);
                }

                let mut q = 0u32;
                let remainder = uint32_divmod_uint14(&mut q, combined, all_m[m_off + 2 * i]);
                out[2 * i] = remainder;
                out[2 * i + 1] = uint32_mod_uint14(q, all_m[m_off + 2 * i + 1]);
            } else {
                out[2 * i] = out[i];
            }
        }
    }
}

fn decode_single(out: &mut [u16], s: &[u8], m: u16) {
    if m == 1 {
        out[0] = 0;
    } else if m <= 256 {
        out[0] = uint32_mod_uint14(s[0] as u32, m);
    } else {
        out[0] = uint32_mod_uint14(s[0] as u32 + ((s[1] as u32) << 8), m);
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rq_encode(f: &[i16], params: &SntrupParameters) -> Vec<u8> {
    let p = params.p;
    let q12 = params.q12;
    let q_u16 = params.q as u16;

    let mut r = vec![0u16; p];
    for (ri, &fi) in r.iter_mut().zip(f.iter()) {
        *ri = (fi as i32 + q12) as u16;
    }
    let mut m = vec![q_u16; p];
    let mut out = vec![0u8; params.pk_size];
    encode(&mut out, &mut r, &mut m, p);
    out
}

/// Allocation-free form of [`rq_decode`]: writes into `out[..p]`, using stack
/// scratch bounded by [`crate::params::MAX_P`].
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rq_decode_into(c: &[u8], out: &mut [i16], params: &SntrupParameters) {
    let p = params.p;
    let q12 = params.q12;
    let q_u16 = params.q as u16;
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let mut m = [0u16; crate::params::MAX_P];
    m[..p].fill(q_u16);
    let m = &m[..p];
    let mut r_buf = [0u16; crate::params::MAX_P];
    let r = &mut r_buf[..p];
    // Callers pass exactly `pk_size` bytes, so borrow directly on the hot path.
    // Only allocate-and-pad if the input is short (defensive; never happens via
    // the public API, where `EncapsulationKey::try_from` enforces the size).
    let mut padded;
    let s: &[u8] = if c.len() >= params.pk_size {
        &c[..params.pk_size]
    } else {
        padded = vec![0u8; params.pk_size];
        padded[..c.len()].copy_from_slice(c);
        &padded
    };
    decode(r, s, m, p);
    for (fi, &ri) in out[..p].iter_mut().zip(r.iter()) {
        *fi = modq::freeze(ri as i32 - q12, q, b1, b2);
    }
}

/// Round to multiples of 3 and encode in one step.
///
/// The reference fuses these (`crypto_encode_761x1531round`), and the ported
/// p = 761 kernel does the rounding internally — so it takes the *un-rounded*
/// coefficients. Other parameter sets round in place first, as before.
pub fn round_and_encode_into(f: &mut [i16], out: &mut [u8], params: &SntrupParameters) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if params.p == 761 && crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2().
        unsafe {
            return super::codec761::encode_761x1531round(out, f);
        }
    }
    super::round3(f, params);
    rounded_encode_into(f, out, params);
}

/// Allocation-free form of [`rounded_encode`]: writes into
/// `out[..rounded_encode_size]`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rounded_encode_into(f: &[i16], out: &mut [u8], params: &SntrupParameters) {
    let p = params.p;
    let q12 = params.q12;
    let q_rounded = (params.q as u16).div_ceil(3);

    let mut r_buf = [0u16; crate::params::MAX_P];
    let r = &mut r_buf[..p];
    for (ri, &fi) in r.iter_mut().zip(f.iter()) {
        *ri = (((fi as i32 + q12) * 10923) >> 15) as u16;
    }
    let mut m = [0u16; crate::params::MAX_P];
    m[..p].fill(q_rounded);
    encode(&mut out[..params.rounded_encode_size], r, &mut m[..p], p);
    // On the decapsulation path `f` is the re-encrypted candidate, secret until (and unless)
    // the constant-time ciphertext comparison succeeds — wipe the working representation,
    // which `encode` mutates in place across pairing levels. `m` holds only public moduli.
    crate::wipe::wipe(&mut r_buf);
}

/// Allocation-free form of [`rounded_decode`]: writes into `out[..p]`.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn rounded_decode_into(c: &[u8], out: &mut [i16], params: &SntrupParameters) {
    // p = 761 has a ported copy of the reference's generated codec, which is
    // vectorized at every radix level rather than only the uniform ones.
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if params.p == 761 && c.len() >= params.rounded_encode_size && crate::cpu::has_avx2() {
        // SAFETY: AVX2 support confirmed by has_avx2().
        unsafe {
            return super::codec761::decode_761x1531(out, c);
        }
    }
    let p = params.p;
    let q12 = params.q12;
    let q_rounded = (params.q as u16).div_ceil(3);
    let q = params.q;
    let b1 = params.barrett1;
    let b2 = params.barrett2;

    let mut m = [0u16; crate::params::MAX_P];
    m[..p].fill(q_rounded);
    let m = &m[..p];
    let mut r_buf = [0u16; crate::params::MAX_P];
    let r = &mut r_buf[..p];
    // Callers pass exactly `rounded_encode_size` bytes, so borrow directly on the
    // hot path. Only allocate-and-pad if the input is short (defensive; never
    // happens via the public API, where `Ciphertext::try_from` enforces the size).
    let mut padded;
    let s: &[u8] = if c.len() >= params.rounded_encode_size {
        &c[..params.rounded_encode_size]
    } else {
        padded = vec![0u8; params.rounded_encode_size];
        padded[..c.len()].copy_from_slice(c);
        &padded
    };
    decode(r, s, m, p);
    for (fi, &ri) in out[..p].iter_mut().zip(r.iter()) {
        *fi = modq::freeze(ri as i32 * 3 - q12, q, b1, b2);
    }
}
