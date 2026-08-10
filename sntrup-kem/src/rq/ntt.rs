//! NTT-based multiplication in R/q (ported from the SUPERCOP AVX2
//! `crypto_core_multsntrup761` and its generated `_ntt` kernels) — the algorithm
//! liboqs dispatches to on x86_64.
//!
//! Good's trick maps the 768-coefficient operands into 3 interleaved tracks of
//! 512 (3 and 512 are coprime, and 3·512 = 1536 ≥ 2p−1 = 1521), then two
//! 512-point NTTs run over the NTT-friendly primes 7681 and 10753 — 4591 itself
//! is not NTT-friendly, and both primes are ≡ 1 mod 2^10 so 512-point
//! transforms exist. A Karatsuba-shaped 3×3 pointwise stage, inverse NTTs, and
//! CRT recombination bring the result back mod 4591. All arithmetic is 16-bit
//! lanes: signed Montgomery products and `mulhrs` squeezes.
//!
//! **Scope: p = 761 only** (see `super::mult`'s dispatcher). The 3×512 machine
//! holds products up to 1536 coefficients, so p ≤ 768 fits; p ≥ 857 needs the
//! Good factor 5 variant (5·512 = 2560) with a 5×5 pointwise stage, which the
//! reference generates as a separate parameter set. The twiddle tables are
//! prime-specific, not p-specific, so that extension reuses them.
//!
//! `ntt512`/`invntt512` are mechanical translations of the reference's
//! auto-generated kernels, and the twiddle tables are extracted verbatim; both
//! are validated against the schoolbook implementation by differential tests.
#![allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::needless_range_loop
)]

use crate::wipe::wipe;
use core::arch::x86_64::*;

const Q: i16 = 4591;

#[inline]
#[target_feature(enable = "avx2")]
fn ld(qdata: &[i16; 1696], off: usize) -> __m256i {
    unsafe { _mm256_loadu_si256(qdata.as_ptr().add(off) as *const __m256i) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn add16(a: __m256i, b: __m256i) -> __m256i {
    _mm256_add_epi16(a, b)
}

#[inline]
#[target_feature(enable = "avx2")]
fn sub16(a: __m256i, b: __m256i) -> __m256i {
    _mm256_sub_epi16(a, b)
}

/// `x·y·2^-16 mod± q` with a pre-scaled table pair (y, y·q^-1 mod 2^16).
#[inline]
#[target_feature(enable = "avx2")]
fn mulmod_scaled(x: __m256i, y: __m256i, yqinv: __m256i, qv: __m256i) -> __m256i {
    let b = _mm256_mulhi_epi16(x, y);
    let d = _mm256_mullo_epi16(x, yqinv);
    let e = _mm256_mulhi_epi16(d, qv);
    sub16(b, e)
}

/// The reference's `reduce_x16`: mulhrs-based partial reduction.
#[inline]
#[target_feature(enable = "avx2")]
fn reduce(x: __m256i, qv: __m256i, qrv: __m256i) -> __m256i {
    let y = _mm256_mulhrs_epi16(x, qrv);
    let y = _mm256_mullo_epi16(y, qv);
    sub16(x, y)
}

#[inline]
#[target_feature(enable = "avx2")]
fn perm_lo(a: __m256i, b: __m256i) -> __m256i {
    _mm256_permute2x128_si256::<0x20>(a, b)
}

#[inline]
#[target_feature(enable = "avx2")]
fn perm_hi(a: __m256i, b: __m256i) -> __m256i {
    _mm256_permute2x128_si256::<0x31>(a, b)
}

/// Squeeze toward `mod± q` via `mulhrs` with `c = round(2^15/q)`-ish constant.
#[inline]
#[target_feature(enable = "avx2")]
fn squeeze(x: __m256i, c: i16, q: i16) -> __m256i {
    sub16(
        x,
        _mm256_mullo_epi16(
            _mm256_mulhrs_epi16(x, _mm256_set1_epi16(c)),
            _mm256_set1_epi16(q),
        ),
    )
}

/// `x·y·2^-16 mod± q`, deriving `y·q^-1` on the fly (broadcast operands).
#[inline]
#[target_feature(enable = "avx2")]
fn mulmod(x: __m256i, y: __m256i, qinv: i16, q: i16) -> __m256i {
    let yqinv = _mm256_mullo_epi16(y, _mm256_set1_epi16(qinv));
    let b = _mm256_mulhi_epi16(x, y);
    let d = _mm256_mullo_epi16(x, yqinv);
    let e = _mm256_mulhi_epi16(d, _mm256_set1_epi16(q));
    sub16(b, e)
}

#[inline]
#[target_feature(enable = "avx2")]
fn squeeze_4591(x: __m256i) -> __m256i {
    squeeze(x, 7, 4591)
}
#[inline]
#[target_feature(enable = "avx2")]
fn squeeze_7681(x: __m256i) -> __m256i {
    squeeze(x, 4, 7681)
}
#[inline]
#[target_feature(enable = "avx2")]
fn squeeze_10753(x: __m256i) -> __m256i {
    squeeze(x, 3, 10753)
}
#[inline]
#[target_feature(enable = "avx2")]
fn mulmod_4591(x: __m256i, y: __m256i) -> __m256i {
    mulmod(x, y, 15631, 4591)
}
#[inline]
#[target_feature(enable = "avx2")]
fn mulmod_7681(x: __m256i, y: __m256i) -> __m256i {
    mulmod(x, y, -7679, 7681)
}
#[inline]
#[target_feature(enable = "avx2")]
fn mulmod_10753(x: __m256i, y: __m256i) -> __m256i {
    mulmod(x, y, -10751, 10753)
}

/// Fully reduce to `[-(q-1)/2, (q-1)/2]` (the reference's `freeze_4591_x16`).
#[inline]
#[target_feature(enable = "avx2")]
fn freeze_4591(x: __m256i) -> __m256i {
    let q = _mm256_set1_epi16(Q);
    let x = add16(x, _mm256_and_si256(q, _mm256_srai_epi16::<15>(x)));
    let m = _mm256_srai_epi16::<15>(sub16(x, _mm256_set1_epi16((Q + 1) / 2)));
    _mm256_blendv_epi8(sub16(x, q), x, m)
}

const MASKS: [[i16; 16]; 3] = [
    [-1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1],
    [0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0],
    [0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0],
];

#[inline]
#[target_feature(enable = "avx2")]
fn mask(t: usize) -> __m256i {
    unsafe { _mm256_loadu_si256(MASKS[t].as_ptr() as *const __m256i) }
}

/// Good's permutation: 768 coefficients into 3 tracks of 512.
///
/// Coefficient `i` belongs to track `i mod 3`; because a 16-lane block spans
/// indices `16b .. 16b+15` and `16 ≡ 1 (mod 3)`, the three lane masks rotate by
/// one per block: track `t` takes `mask[(t + 3 − b mod 3) mod 3]` of the block
/// at block-index `b`. That single formula reproduces all six unrolled cases in
/// the reference.
#[target_feature(enable = "avx2")]
fn good(fpad: &mut [i16], f: &[i16; 768]) {
    unsafe {
        // Reindexing the track loop by `u = (t - b) mod 3` makes the mask index
        // a constant and moves the block-dependent rotation into the store
        // address, which is scalar arithmetic. The three masks then stay in
        // registers instead of being reloaded six times per block. The second
        // operand's block index is always `b0 + 2 (mod 3)`, so its mask is
        // `m[(u + 1) % 3]`.
        let m = [mask(0), mask(1), mask(2)];
        let mut j = 0usize;
        while j < 512 {
            let b0 = (j / 16) % 3;
            let f0 = _mm256_loadu_si256(f.as_ptr().add(j) as *const __m256i);
            if j < 256 {
                let f1 = _mm256_loadu_si256(f.as_ptr().add(512 + j) as *const __m256i);
                for u in 0..3 {
                    let v = _mm256_or_si256(
                        _mm256_and_si256(f0, m[u]),
                        _mm256_and_si256(f1, m[(u + 1) % 3]),
                    );
                    let track = (u + b0) % 3;
                    _mm256_storeu_si256(fpad.as_mut_ptr().add(512 * track + j) as *mut __m256i, v);
                }
            } else {
                for u in 0..3 {
                    let v = _mm256_and_si256(f0, m[u]);
                    let track = (u + b0) % 3;
                    _mm256_storeu_si256(fpad.as_mut_ptr().add(512 * track + j) as *mut __m256i, v);
                }
            }
            j += 16;
        }
    }
}

/// Inverse of [`good`]: the 3 tracks back to 1536 coefficients. Output block at
/// block-index `B` gathers `mask[(t + 3 − B mod 3) mod 3]` from track `t` — the
/// transpose of the forward formula.
#[target_feature(enable = "avx2")]
fn ungood(h: &mut [i16; 1536], fpad: &[i16]) {
    unsafe {
        // Same reindexing as `good`, in the opposite direction: with `u` as the
        // loop variable the masks are constants held in registers and the
        // block-dependent rotation lands on the load address instead.
        let m = [mask(0), mask(1), mask(2)];
        let mut j = 0usize;
        while j < 512 {
            let jb = j / 16;
            for k in 0..3 {
                // Block index of output block `k`: `(k * 32 + jb) % 3`, and
                // `32 == 2 (mod 3)`.
                let b = (2 * k + jb) % 3;
                let mut g = _mm256_setzero_si256();
                for u in 0..3 {
                    let track = _mm256_loadu_si256(
                        fpad.as_ptr().add(512 * ((u + b) % 3) + j) as *const __m256i
                    );
                    g = _mm256_or_si256(g, _mm256_and_si256(track, m[u]));
                }
                _mm256_storeu_si256(h.as_mut_ptr().add(k * 512 + j) as *mut __m256i, g);
            }
            j += 16;
        }
    }
}

/// One prime's forward-NTT / pointwise / inverse-NTT pass, shared by the
/// mod-q (dual-prime) and mod-3 (single-prime) multiplies. The pointwise stage
/// is the Karatsuba-shaped 3x3 product over Good's three tracks.
macro_rules! prime_pass {
    ($f:expr, $g:expr, $out:expr, $sq:ident, $mm:ident, $qdata:expr) => {{
        // One contiguous 6x512 buffer: Good's three f-tracks then three g-tracks,
        // exactly the layout `ntt512` batches over. Writing the tracks straight
        // into it avoids copying 6 KB in and out per prime.
        // SAFETY: `good` stores to every 16-coefficient block of all three of
        // its output tracks unconditionally, so the two calls below fill all
        // 6 x 512 elements before `ntt512` reads any.
        let mut fg_slot = core::mem::MaybeUninit::<[i16; 6 * 512]>::uninit();
        let fg = crate::scratch::uninit(&mut fg_slot);
        good(&mut fg[..3 * 512], $f);
        good(&mut fg[3 * 512..], $g);
        ntt512(fg, 6, $qdata);

        // SAFETY: the pointwise loop below stores to `i`, `512 + i` and
        // `1024 + i` for every `i` in `(0..512).step_by(16)`, covering all
        // 3 x 512 elements before `invntt512` reads them.
        let mut hpad_slot = core::mem::MaybeUninit::<[i16; 3 * 512]>::uninit();
        let hpad = crate::scratch::uninit(&mut hpad_slot);
        let mut i = 0usize;
        while i < 512 {
            let f0 = $sq(_mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i));
            let f1 = $sq(_mm256_loadu_si256(
                fg.as_ptr().add(512 + i) as *const __m256i
            ));
            let f2 = $sq(_mm256_loadu_si256(
                fg.as_ptr().add(1024 + i) as *const __m256i
            ));
            let g0 = $sq(_mm256_loadu_si256(
                fg.as_ptr().add(1536 + i) as *const __m256i
            ));
            let g1 = $sq(_mm256_loadu_si256(
                fg.as_ptr().add(2048 + i) as *const __m256i
            ));
            let g2 = $sq(_mm256_loadu_si256(
                fg.as_ptr().add(2560 + i) as *const __m256i
            ));
            let dsum = add16(add16($mm(f0, g0), $mm(f1, g1)), $mm(f2, g2));
            let r0 = add16(dsum, $mm(sub16(f2, f1), sub16(g1, g2)));
            let r1 = add16(dsum, $mm(sub16(f1, f0), sub16(g0, g1)));
            let r2 = add16(dsum, $mm(sub16(f0, f2), sub16(g2, g0)));
            _mm256_storeu_si256(hpad.as_mut_ptr().add(i) as *mut __m256i, $sq(r0));
            _mm256_storeu_si256(hpad.as_mut_ptr().add(512 + i) as *mut __m256i, $sq(r1));
            _mm256_storeu_si256(hpad.as_mut_ptr().add(1024 + i) as *mut __m256i, $sq(r2));
            i += 16;
        }

        invntt512(hpad, 3, $qdata);
        ungood($out, &hpad[..]);
    }};
}

/// 1536-coefficient product mod q, via both primes plus CRT (the reference's
/// `mult768`).
#[target_feature(enable = "avx2")]
fn mult768(h: &mut [i16; 1536], f: &[i16; 768], g: &[i16; 768]) {
    unsafe {
        // SAFETY: each is filled by `ungood`, whose store covers `k * 512 + j`
        // for all `k < 3` and every `j` in `(0..512).step_by(16)` — all 1536
        // elements — before the CRT loop reads them.
        let mut h7681_slot = core::mem::MaybeUninit::<[i16; 1536]>::uninit();
        let h7681 = crate::scratch::uninit(&mut h7681_slot);
        let mut h10753_slot = core::mem::MaybeUninit::<[i16; 1536]>::uninit();
        let h10753 = crate::scratch::uninit(&mut h10753_slot);
        prime_pass!(f, g, h7681, squeeze_7681, mulmod_7681, &QDATA_7681);
        prime_pass!(f, g, h10753, squeeze_10753, mulmod_10753, &QDATA_10753);

        // CRT the two residues back to mod 4591.
        let mut i = 0usize;
        while i < 1536 {
            let u1 = mulmod_10753(
                _mm256_loadu_si256(h10753.as_ptr().add(i) as *const __m256i),
                _mm256_set1_epi16(1268),
            );
            let u2 = mulmod_7681(
                _mm256_loadu_si256(h7681.as_ptr().add(i) as *const __m256i),
                _mm256_set1_epi16(956),
            );
            let t = mulmod_7681(sub16(u2, u1), _mm256_set1_epi16(-2539));
            let t = add16(u1, mulmod_4591(t, _mm256_set1_epi16(-710)));
            _mm256_storeu_si256(h.as_mut_ptr().add(i) as *mut __m256i, t);
            i += 16;
        }
    }
}

/// 1536-coefficient product mod 3. Product coefficients are bounded by p = 761,
/// far inside 7681/2, so a single prime suffices — no CRT.
#[target_feature(enable = "avx2")]
fn mult768_3(h: &mut [i16; 1536], f: &[i16; 768], g: &[i16; 768]) {
    unsafe {
        // SAFETY: filled in full by `ungood`, as in `mult768`.
        let mut h7681_slot = core::mem::MaybeUninit::<[i16; 1536]>::uninit();
        let h7681 = crate::scratch::uninit(&mut h7681_slot);
        prime_pass!(f, g, h7681, squeeze_7681, mulmod_7681, &QDATA_7681);
        let mut i = 0usize;
        while i < 1536 {
            let u = mulmod_7681(
                _mm256_loadu_si256(h7681.as_ptr().add(i) as *const __m256i),
                _mm256_set1_epi16(956),
            );
            _mm256_storeu_si256(h.as_mut_ptr().add(i) as *mut __m256i, u);
            i += 16;
        }
    }
}

#[inline]
#[target_feature(enable = "avx2")]
fn squeeze_3(x: __m256i) -> __m256i {
    squeeze(x, 10923, 3)
}

/// Fully reduce to {-1, 0, 1}.
#[inline]
#[target_feature(enable = "avx2")]
fn freeze_3(x: __m256i) -> __m256i {
    let three = _mm256_set1_epi16(3);
    let x = add16(x, _mm256_and_si256(three, _mm256_srai_epi16::<15>(x)));
    let m = _mm256_srai_epi16::<15>(sub16(x, _mm256_set1_epi16(2)));
    _mm256_blendv_epi8(sub16(x, three), x, m)
}

/// `h = f · g` in R/3 for p = 761, via the single-prime NTT.
#[target_feature(enable = "avx2")]
pub fn mult3_761(h: &mut [i8], f: &[i8], g: &[i8]) {
    unsafe {
        const P: usize = 761;
        // SAFETY: the loop writes `0..P` and the tail clear covers `P..768`,
        // so both are complete before `mult768_3` reads them. The 768-length
        // padding is what makes the transform's zero-extension work, so it has
        // to be written explicitly now that the buffer is not pre-zeroed.
        let mut fp_slot = core::mem::MaybeUninit::<[i16; 768]>::uninit();
        let fp = crate::scratch::uninit(&mut fp_slot);
        let mut gp_slot = core::mem::MaybeUninit::<[i16; 768]>::uninit();
        let gp = crate::scratch::uninit(&mut gp_slot);
        for k in 0..P {
            fp[k] = i16::from(f[k]);
            gp[k] = i16::from(g[k]);
        }
        for k in P..768 {
            fp[k] = 0;
            gp[k] = 0;
        }

        // SAFETY: `mult768_3` writes all 1536 coefficients of its output.
        let mut fg_slot = core::mem::MaybeUninit::<[i16; 1536]>::uninit();
        let fg = crate::scratch::uninit(&mut fg_slot);
        mult768_3(fg, fp, gp);

        fg[0] -= fg[P - 1];
        // SAFETY: the loop below stores every 16-element block of `0..768`.
        let mut out_slot = core::mem::MaybeUninit::<[i16; 768]>::uninit();
        let out = crate::scratch::uninit(&mut out_slot);
        let mut i = 0usize;
        while i < 768 {
            let a = _mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i);
            let b = _mm256_loadu_si256(fg.as_ptr().add(i + P) as *const __m256i);
            let c = _mm256_loadu_si256(fg.as_ptr().add(i + P - 1) as *const __m256i);
            let x = freeze_3(squeeze_3(add16(a, add16(b, c))));
            _mm256_storeu_si256(out.as_mut_ptr().add(i) as *mut __m256i, x);
            i += 16;
        }
        for k in 0..P {
            h[k] = out[k] as i8;
        }
        // Both operands are secret at every call site — wipe the working buffers.
        wipe(fp);
        wipe(gp);
        wipe(fg);
        wipe(out);
    }
}

#[target_feature(enable = "avx2")]
pub fn mult761(h: &mut [i16], f: &[i16], g: &[i8]) {
    unsafe {
        const P: usize = 761;
        // SAFETY: the loop below stores every 16-element block of `0..768`.
        let mut fp_slot = core::mem::MaybeUninit::<[i16; 768]>::uninit();
        let fp = crate::scratch::uninit(&mut fp_slot);
        // SAFETY: written over `0..P` by the copy loop and `P..768` by the tail
        // clear, both before `mult768` reads it.
        let mut gp_slot = core::mem::MaybeUninit::<[i16; 768]>::uninit();
        let gp = crate::scratch::uninit(&mut gp_slot);
        let mut i = 0usize;
        while i < 768 {
            let x = if i < P {
                _mm256_loadu_si256(f.as_ptr().add(i) as *const __m256i)
            } else {
                _mm256_setzero_si256()
            };
            _mm256_storeu_si256(
                fp.as_mut_ptr().add(i) as *mut __m256i,
                freeze_4591(squeeze_4591(x)),
            );
            i += 16;
        }
        // The last block overruns p; clear the tail explicitly.
        for k in P..768 {
            fp[k] = 0;
        }
        for k in 0..P {
            gp[k] = i16::from(g[k]);
        }
        for k in P..768 {
            gp[k] = 0;
        }

        // SAFETY: `mult768` writes all 1536 coefficients of its output.
        let mut fg_slot = core::mem::MaybeUninit::<[i16; 1536]>::uninit();
        let fg = crate::scratch::uninit(&mut fg_slot);
        mult768(fg, fp, gp);

        fg[0] -= fg[P - 1];
        let mut i = 0usize;
        while i < 768 {
            let a = _mm256_loadu_si256(fg.as_ptr().add(i) as *const __m256i);
            let b = _mm256_loadu_si256(fg.as_ptr().add(i + P) as *const __m256i);
            let c = _mm256_loadu_si256(fg.as_ptr().add(i + P - 1) as *const __m256i);
            let x = freeze_4591(squeeze_4591(add16(a, add16(b, c))));
            _mm256_storeu_si256(fp.as_mut_ptr().add(i) as *mut __m256i, x);
            i += 16;
        }
        h[..P].copy_from_slice(&fp[..P]);
        // `g` is secret at every call site — wipe the operand copies and the
        // product scratch.
        wipe(fp);
        wipe(gp);
        wipe(fg);
    }
}

#[target_feature(enable = "avx2")]
fn ntt512(f: &mut [i16], reps: usize, qdata: &[i16; 1696]) {
    unsafe {
        let qv = ld(qdata, 768);
        let qround32v = ld(qdata, 1616);
        let mut reps = reps;
        let base = 0usize;
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a0 = _mm256_loadu_si256(fp.add(0) as *const __m256i);
            let a16 = _mm256_loadu_si256(fp.add(256) as *const __m256i);
            let b0 = add16(a0, a16);
            let b16 = sub16(a0, a16);
            let a8 = _mm256_loadu_si256(fp.add(128) as *const __m256i);
            let a24 = _mm256_loadu_si256(fp.add(384) as *const __m256i);
            let b8 = add16(a8, a24);
            let mut b24 = sub16(a8, a24);
            let a4 = _mm256_loadu_si256(fp.add(64) as *const __m256i);
            let a20 = _mm256_loadu_si256(fp.add(320) as *const __m256i);
            let b4 = add16(a4, a20);
            let b20 = sub16(a4, a20);
            let a12 = _mm256_loadu_si256(fp.add(192) as *const __m256i);
            let a28 = _mm256_loadu_si256(fp.add(448) as *const __m256i);
            let b12 = add16(a12, a28);
            let mut b28 = sub16(a12, a28);
            let c0 = add16(b0, b8);
            let c8 = sub16(b0, b8);
            let mut c4 = add16(b4, b12);
            let mut c12 = sub16(b4, b12);
            b24 = mulmod_scaled(b24, ld(qdata, 1632), ld(qdata, 1552), qv);
            let c16 = add16(b16, b24);
            let c24 = sub16(b16, b24);
            b28 = mulmod_scaled(b28, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut c20 = add16(b20, b28);
            let mut c28 = sub16(b20, b28);
            c4 = reduce(c4, qv, qround32v);
            let mut d0 = add16(c0, c4);
            let mut d4 = sub16(c0, c4);
            c12 = mulmod_scaled(c12, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut d8 = add16(c8, c12);
            let mut d12 = sub16(c8, c12);
            c20 = mulmod_scaled(c20, ld(qdata, 1664), ld(qdata, 1584), qv);
            let mut d16 = add16(c16, c20);
            let mut d20 = sub16(c16, c20);
            c28 = mulmod_scaled(c28, ld(qdata, 1680), ld(qdata, 1600), qv);
            let mut d24 = add16(c24, c28);
            let mut d28 = sub16(c24, c28);
            d0 = reduce(d0, qv, qround32v);
            d4 = mulmod_scaled(d4, ld(qdata, 256), ld(qdata, 1040), qv);
            d8 = mulmod_scaled(d8, ld(qdata, 384), ld(qdata, 1168), qv);
            d12 = mulmod_scaled(d12, ld(qdata, 448), ld(qdata, 1232), qv);
            d16 = mulmod_scaled(d16, ld(qdata, 512), ld(qdata, 1296), qv);
            d20 = mulmod_scaled(d20, ld(qdata, 576), ld(qdata, 1360), qv);
            d24 = mulmod_scaled(d24, ld(qdata, 704), ld(qdata, 1488), qv);
            d28 = mulmod_scaled(d28, ld(qdata, 640), ld(qdata, 1424), qv);
            let e0 = perm_lo(d0, d4);
            let e4 = perm_hi(d0, d4);
            let e8 = perm_lo(d8, d12);
            let e12 = perm_hi(d8, d12);
            let e16 = perm_lo(d16, d20);
            let e20 = perm_hi(d16, d20);
            let e24 = perm_lo(d24, d28);
            let e28 = perm_hi(d24, d28);
            _mm256_storeu_si256(fp.add(0) as *mut __m256i, e0);
            _mm256_storeu_si256(fp.add(64) as *mut __m256i, e4);
            _mm256_storeu_si256(fp.add(128) as *mut __m256i, e8);
            _mm256_storeu_si256(fp.add(192) as *mut __m256i, e12);
            _mm256_storeu_si256(fp.add(256) as *mut __m256i, e16);
            _mm256_storeu_si256(fp.add(320) as *mut __m256i, e20);
            _mm256_storeu_si256(fp.add(384) as *mut __m256i, e24);
            _mm256_storeu_si256(fp.add(448) as *mut __m256i, e28);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a1 = _mm256_loadu_si256(fp.add(16) as *const __m256i);
            let a17 = _mm256_loadu_si256(fp.add(272) as *const __m256i);
            let b1 = add16(a1, a17);
            let b17 = sub16(a1, a17);
            let a9 = _mm256_loadu_si256(fp.add(144) as *const __m256i);
            let a25 = _mm256_loadu_si256(fp.add(400) as *const __m256i);
            let b9 = add16(a9, a25);
            let mut b25 = sub16(a9, a25);
            let a5 = _mm256_loadu_si256(fp.add(80) as *const __m256i);
            let a21 = _mm256_loadu_si256(fp.add(336) as *const __m256i);
            let b5 = add16(a5, a21);
            let b21 = sub16(a5, a21);
            let a13 = _mm256_loadu_si256(fp.add(208) as *const __m256i);
            let a29 = _mm256_loadu_si256(fp.add(464) as *const __m256i);
            let b13 = add16(a13, a29);
            let mut b29 = sub16(a13, a29);
            let c1 = add16(b1, b9);
            let c9 = sub16(b1, b9);
            let mut c5 = add16(b5, b13);
            let mut c13 = sub16(b5, b13);
            b25 = mulmod_scaled(b25, ld(qdata, 1632), ld(qdata, 1552), qv);
            let c17 = add16(b17, b25);
            let c25 = sub16(b17, b25);
            b29 = mulmod_scaled(b29, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut c21 = add16(b21, b29);
            let mut c29 = sub16(b21, b29);
            c5 = reduce(c5, qv, qround32v);
            let mut d1 = add16(c1, c5);
            let mut d5 = sub16(c1, c5);
            c13 = mulmod_scaled(c13, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut d9 = add16(c9, c13);
            let mut d13 = sub16(c9, c13);
            c21 = mulmod_scaled(c21, ld(qdata, 1664), ld(qdata, 1584), qv);
            let mut d17 = add16(c17, c21);
            let mut d21 = sub16(c17, c21);
            c29 = mulmod_scaled(c29, ld(qdata, 1680), ld(qdata, 1600), qv);
            let mut d25 = add16(c25, c29);
            let mut d29 = sub16(c25, c29);
            d1 = reduce(d1, qv, qround32v);
            d5 = mulmod_scaled(d5, ld(qdata, 272), ld(qdata, 1056), qv);
            d9 = mulmod_scaled(d9, ld(qdata, 400), ld(qdata, 1184), qv);
            d13 = mulmod_scaled(d13, ld(qdata, 464), ld(qdata, 1248), qv);
            d17 = mulmod_scaled(d17, ld(qdata, 528), ld(qdata, 1312), qv);
            d21 = mulmod_scaled(d21, ld(qdata, 592), ld(qdata, 1376), qv);
            d25 = mulmod_scaled(d25, ld(qdata, 720), ld(qdata, 1504), qv);
            d29 = mulmod_scaled(d29, ld(qdata, 656), ld(qdata, 1440), qv);
            let e1 = perm_lo(d1, d5);
            let e5 = perm_hi(d1, d5);
            let e9 = perm_lo(d9, d13);
            let e13 = perm_hi(d9, d13);
            let e17 = perm_lo(d17, d21);
            let e21 = perm_hi(d17, d21);
            let e25 = perm_lo(d25, d29);
            let e29 = perm_hi(d25, d29);
            _mm256_storeu_si256(fp.add(16) as *mut __m256i, e1);
            _mm256_storeu_si256(fp.add(80) as *mut __m256i, e5);
            _mm256_storeu_si256(fp.add(144) as *mut __m256i, e9);
            _mm256_storeu_si256(fp.add(208) as *mut __m256i, e13);
            _mm256_storeu_si256(fp.add(272) as *mut __m256i, e17);
            _mm256_storeu_si256(fp.add(336) as *mut __m256i, e21);
            _mm256_storeu_si256(fp.add(400) as *mut __m256i, e25);
            _mm256_storeu_si256(fp.add(464) as *mut __m256i, e29);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a2 = _mm256_loadu_si256(fp.add(32) as *const __m256i);
            let a18 = _mm256_loadu_si256(fp.add(288) as *const __m256i);
            let b2 = add16(a2, a18);
            let b18 = sub16(a2, a18);
            let a10 = _mm256_loadu_si256(fp.add(160) as *const __m256i);
            let a26 = _mm256_loadu_si256(fp.add(416) as *const __m256i);
            let b10 = add16(a10, a26);
            let mut b26 = sub16(a10, a26);
            let a6 = _mm256_loadu_si256(fp.add(96) as *const __m256i);
            let a22 = _mm256_loadu_si256(fp.add(352) as *const __m256i);
            let b6 = add16(a6, a22);
            let b22 = sub16(a6, a22);
            let a14 = _mm256_loadu_si256(fp.add(224) as *const __m256i);
            let a30 = _mm256_loadu_si256(fp.add(480) as *const __m256i);
            let b14 = add16(a14, a30);
            let mut b30 = sub16(a14, a30);
            let c2 = add16(b2, b10);
            let c10 = sub16(b2, b10);
            let mut c6 = add16(b6, b14);
            let mut c14 = sub16(b6, b14);
            b26 = mulmod_scaled(b26, ld(qdata, 1632), ld(qdata, 1552), qv);
            let c18 = add16(b18, b26);
            let c26 = sub16(b18, b26);
            b30 = mulmod_scaled(b30, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut c22 = add16(b22, b30);
            let mut c30 = sub16(b22, b30);
            c6 = reduce(c6, qv, qround32v);
            let mut d2 = add16(c2, c6);
            let mut d6 = sub16(c2, c6);
            c14 = mulmod_scaled(c14, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut d10 = add16(c10, c14);
            let mut d14 = sub16(c10, c14);
            c22 = mulmod_scaled(c22, ld(qdata, 1664), ld(qdata, 1584), qv);
            let mut d18 = add16(c18, c22);
            let mut d22 = sub16(c18, c22);
            c30 = mulmod_scaled(c30, ld(qdata, 1680), ld(qdata, 1600), qv);
            let mut d26 = add16(c26, c30);
            let mut d30 = sub16(c26, c30);
            d2 = reduce(d2, qv, qround32v);
            d6 = mulmod_scaled(d6, ld(qdata, 288), ld(qdata, 1072), qv);
            d10 = mulmod_scaled(d10, ld(qdata, 416), ld(qdata, 1200), qv);
            d14 = mulmod_scaled(d14, ld(qdata, 480), ld(qdata, 1264), qv);
            d18 = mulmod_scaled(d18, ld(qdata, 544), ld(qdata, 1328), qv);
            d22 = mulmod_scaled(d22, ld(qdata, 608), ld(qdata, 1392), qv);
            d26 = mulmod_scaled(d26, ld(qdata, 736), ld(qdata, 1520), qv);
            d30 = mulmod_scaled(d30, ld(qdata, 672), ld(qdata, 1456), qv);
            let e2 = perm_lo(d2, d6);
            let e6 = perm_hi(d2, d6);
            let e10 = perm_lo(d10, d14);
            let e14 = perm_hi(d10, d14);
            let e18 = perm_lo(d18, d22);
            let e22 = perm_hi(d18, d22);
            let e26 = perm_lo(d26, d30);
            let e30 = perm_hi(d26, d30);
            _mm256_storeu_si256(fp.add(32) as *mut __m256i, e2);
            _mm256_storeu_si256(fp.add(96) as *mut __m256i, e6);
            _mm256_storeu_si256(fp.add(160) as *mut __m256i, e10);
            _mm256_storeu_si256(fp.add(224) as *mut __m256i, e14);
            _mm256_storeu_si256(fp.add(288) as *mut __m256i, e18);
            _mm256_storeu_si256(fp.add(352) as *mut __m256i, e22);
            _mm256_storeu_si256(fp.add(416) as *mut __m256i, e26);
            _mm256_storeu_si256(fp.add(480) as *mut __m256i, e30);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a3 = _mm256_loadu_si256(fp.add(48) as *const __m256i);
            let a19 = _mm256_loadu_si256(fp.add(304) as *const __m256i);
            let b3 = add16(a3, a19);
            let b19 = sub16(a3, a19);
            let a11 = _mm256_loadu_si256(fp.add(176) as *const __m256i);
            let a27 = _mm256_loadu_si256(fp.add(432) as *const __m256i);
            let b11 = add16(a11, a27);
            let mut b27 = sub16(a11, a27);
            let a7 = _mm256_loadu_si256(fp.add(112) as *const __m256i);
            let a23 = _mm256_loadu_si256(fp.add(368) as *const __m256i);
            let b7 = add16(a7, a23);
            let b23 = sub16(a7, a23);
            let a15 = _mm256_loadu_si256(fp.add(240) as *const __m256i);
            let a31 = _mm256_loadu_si256(fp.add(496) as *const __m256i);
            let b15 = add16(a15, a31);
            let mut b31 = sub16(a15, a31);
            let c3 = add16(b3, b11);
            let c11 = sub16(b3, b11);
            let mut c7 = add16(b7, b15);
            let mut c15 = sub16(b7, b15);
            b27 = mulmod_scaled(b27, ld(qdata, 1632), ld(qdata, 1552), qv);
            let c19 = add16(b19, b27);
            let c27 = sub16(b19, b27);
            b31 = mulmod_scaled(b31, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut c23 = add16(b23, b31);
            let mut c31 = sub16(b23, b31);
            c7 = reduce(c7, qv, qround32v);
            let mut d3 = add16(c3, c7);
            let mut d7 = sub16(c3, c7);
            c15 = mulmod_scaled(c15, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut d11 = add16(c11, c15);
            let mut d15 = sub16(c11, c15);
            c23 = mulmod_scaled(c23, ld(qdata, 1664), ld(qdata, 1584), qv);
            let mut d19 = add16(c19, c23);
            let mut d23 = sub16(c19, c23);
            c31 = mulmod_scaled(c31, ld(qdata, 1680), ld(qdata, 1600), qv);
            let mut d27 = add16(c27, c31);
            let mut d31 = sub16(c27, c31);
            d3 = reduce(d3, qv, qround32v);
            d7 = mulmod_scaled(d7, ld(qdata, 304), ld(qdata, 1088), qv);
            d11 = mulmod_scaled(d11, ld(qdata, 432), ld(qdata, 1216), qv);
            d15 = mulmod_scaled(d15, ld(qdata, 496), ld(qdata, 1280), qv);
            d19 = mulmod_scaled(d19, ld(qdata, 560), ld(qdata, 1344), qv);
            d23 = mulmod_scaled(d23, ld(qdata, 624), ld(qdata, 1408), qv);
            d27 = mulmod_scaled(d27, ld(qdata, 752), ld(qdata, 1536), qv);
            d31 = mulmod_scaled(d31, ld(qdata, 688), ld(qdata, 1472), qv);
            let e3 = perm_lo(d3, d7);
            let e7 = perm_hi(d3, d7);
            let e11 = perm_lo(d11, d15);
            let e15 = perm_hi(d11, d15);
            let e19 = perm_lo(d19, d23);
            let e23 = perm_hi(d19, d23);
            let e27 = perm_lo(d27, d31);
            let e31 = perm_hi(d27, d31);
            _mm256_storeu_si256(fp.add(48) as *mut __m256i, e3);
            _mm256_storeu_si256(fp.add(112) as *mut __m256i, e7);
            _mm256_storeu_si256(fp.add(176) as *mut __m256i, e11);
            _mm256_storeu_si256(fp.add(240) as *mut __m256i, e15);
            _mm256_storeu_si256(fp.add(304) as *mut __m256i, e19);
            _mm256_storeu_si256(fp.add(368) as *mut __m256i, e23);
            _mm256_storeu_si256(fp.add(432) as *mut __m256i, e27);
            _mm256_storeu_si256(fp.add(496) as *mut __m256i, e31);
        }
        reps *= 2;
        reps *= 2;
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 128 * r);
            let a0 = _mm256_loadu_si256(fp.add(0) as *const __m256i);
            let a2 = _mm256_loadu_si256(fp.add(32) as *const __m256i);
            let b0 = add16(a0, a2);
            let b2 = sub16(a0, a2);
            let a4 = _mm256_loadu_si256(fp.add(64) as *const __m256i);
            let a6 = _mm256_loadu_si256(fp.add(96) as *const __m256i);
            let b4 = add16(a4, a6);
            let b6 = sub16(a4, a6);
            let a1 = _mm256_loadu_si256(fp.add(16) as *const __m256i);
            let a3 = _mm256_loadu_si256(fp.add(48) as *const __m256i);
            let b1 = add16(a1, a3);
            let mut b3 = sub16(a1, a3);
            let a5 = _mm256_loadu_si256(fp.add(80) as *const __m256i);
            let a7 = _mm256_loadu_si256(fp.add(112) as *const __m256i);
            let b5 = add16(a5, a7);
            let mut b7 = sub16(a5, a7);
            let mut c0 = add16(b0, b1);
            let mut c1 = sub16(b0, b1);
            let mut c4 = add16(b4, b5);
            let mut c5 = sub16(b4, b5);
            b3 = mulmod_scaled(b3, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut c2 = add16(b2, b3);
            let mut c3 = sub16(b2, b3);
            b7 = mulmod_scaled(b7, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut c6 = add16(b6, b7);
            let mut c7 = sub16(b6, b7);
            c0 = reduce(c0, qv, qround32v);
            c4 = reduce(c4, qv, qround32v);
            c1 = mulmod_scaled(c1, ld(qdata, 128), ld(qdata, 912), qv);
            c5 = mulmod_scaled(c5, ld(qdata, 144), ld(qdata, 928), qv);
            c2 = mulmod_scaled(c2, ld(qdata, 192), ld(qdata, 976), qv);
            c6 = mulmod_scaled(c6, ld(qdata, 208), ld(qdata, 992), qv);
            c3 = mulmod_scaled(c3, ld(qdata, 224), ld(qdata, 1008), qv);
            c7 = mulmod_scaled(c7, ld(qdata, 240), ld(qdata, 1024), qv);
            let d0 = _mm256_unpacklo_epi16(c0, c2);
            let d2 = _mm256_unpackhi_epi16(c0, c2);
            let d1 = _mm256_unpacklo_epi16(c1, c3);
            let d3 = _mm256_unpackhi_epi16(c1, c3);
            let d4 = _mm256_unpacklo_epi16(c4, c6);
            let d6 = _mm256_unpackhi_epi16(c4, c6);
            let d5 = _mm256_unpacklo_epi16(c5, c7);
            let d7 = _mm256_unpackhi_epi16(c5, c7);
            let e0 = add16(d0, d4);
            let e4 = sub16(d0, d4);
            let e2 = add16(d2, d6);
            let e6 = sub16(d2, d6);
            let e1 = add16(d1, d5);
            let e5 = sub16(d1, d5);
            let e3 = add16(d3, d7);
            let e7 = sub16(d3, d7);
            let f0 = _mm256_unpacklo_epi32(e0, e1);
            let f1 = _mm256_unpackhi_epi32(e0, e1);
            let f2 = _mm256_unpacklo_epi32(e2, e3);
            let f3 = _mm256_unpackhi_epi32(e2, e3);
            let f4 = _mm256_unpacklo_epi32(e4, e5);
            let f5 = _mm256_unpackhi_epi32(e4, e5);
            let f6 = _mm256_unpacklo_epi32(e6, e7);
            let f7 = _mm256_unpackhi_epi32(e6, e7);
            _mm256_storeu_si256(fp.add(0) as *mut __m256i, f0);
            _mm256_storeu_si256(fp.add(16) as *mut __m256i, f1);
            _mm256_storeu_si256(fp.add(32) as *mut __m256i, f2);
            _mm256_storeu_si256(fp.add(48) as *mut __m256i, f3);
            _mm256_storeu_si256(fp.add(64) as *mut __m256i, f4);
            _mm256_storeu_si256(fp.add(80) as *mut __m256i, f5);
            _mm256_storeu_si256(fp.add(96) as *mut __m256i, f6);
            _mm256_storeu_si256(fp.add(112) as *mut __m256i, f7);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 128 * r);
            let a0 = _mm256_loadu_si256(fp.add(0) as *const __m256i);
            let a2 = _mm256_loadu_si256(fp.add(32) as *const __m256i);
            let mut b0 = add16(a0, a2);
            let mut b2 = sub16(a0, a2);
            let a1 = _mm256_loadu_si256(fp.add(16) as *const __m256i);
            let a3 = _mm256_loadu_si256(fp.add(48) as *const __m256i);
            let mut b1 = add16(a1, a3);
            let mut b3 = sub16(a1, a3);
            let a4 = _mm256_loadu_si256(fp.add(64) as *const __m256i);
            let mut a6 = _mm256_loadu_si256(fp.add(96) as *const __m256i);
            a6 = mulmod_scaled(a6, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut b4 = add16(a4, a6);
            let mut b6 = sub16(a4, a6);
            let a5 = _mm256_loadu_si256(fp.add(80) as *const __m256i);
            let mut a7 = _mm256_loadu_si256(fp.add(112) as *const __m256i);
            a7 = mulmod_scaled(a7, ld(qdata, 1632), ld(qdata, 1552), qv);
            let mut b5 = add16(a5, a7);
            let mut b7 = sub16(a5, a7);
            b0 = reduce(b0, qv, qround32v);
            b1 = reduce(b1, qv, qround32v);
            b2 = mulmod_scaled(b2, ld(qdata, 0), ld(qdata, 784), qv);
            b3 = mulmod_scaled(b3, ld(qdata, 16), ld(qdata, 800), qv);
            b4 = mulmod_scaled(b4, ld(qdata, 64), ld(qdata, 848), qv);
            b5 = mulmod_scaled(b5, ld(qdata, 80), ld(qdata, 864), qv);
            b6 = mulmod_scaled(b6, ld(qdata, 96), ld(qdata, 880), qv);
            b7 = mulmod_scaled(b7, ld(qdata, 112), ld(qdata, 896), qv);
            let c0 = _mm256_unpacklo_epi64(b0, b4);
            let c4 = _mm256_unpackhi_epi64(b0, b4);
            let c1 = _mm256_unpacklo_epi64(b1, b5);
            let c5 = _mm256_unpackhi_epi64(b1, b5);
            let c2 = _mm256_unpacklo_epi64(b2, b6);
            let c6 = _mm256_unpackhi_epi64(b2, b6);
            let c3 = _mm256_unpacklo_epi64(b3, b7);
            let c7 = _mm256_unpackhi_epi64(b3, b7);
            let d0 = add16(c0, c1);
            let d1 = sub16(c0, c1);
            let d4 = add16(c4, c5);
            let mut d5 = sub16(c4, c5);
            let d2 = add16(c2, c3);
            let d3 = sub16(c2, c3);
            let d6 = add16(c6, c7);
            let mut d7 = sub16(c6, c7);
            let e0 = add16(d0, d4);
            let e4 = sub16(d0, d4);
            let e2 = add16(d2, d6);
            let e6 = sub16(d2, d6);
            d5 = mulmod_scaled(d5, ld(qdata, 1632), ld(qdata, 1552), qv);
            let e1 = add16(d1, d5);
            let e5 = sub16(d1, d5);
            d7 = mulmod_scaled(d7, ld(qdata, 1632), ld(qdata, 1552), qv);
            let e3 = add16(d3, d7);
            let e7 = sub16(d3, d7);
            _mm256_storeu_si256(fp.add(0) as *mut __m256i, e0);
            _mm256_storeu_si256(fp.add(16) as *mut __m256i, e1);
            _mm256_storeu_si256(fp.add(32) as *mut __m256i, e2);
            _mm256_storeu_si256(fp.add(48) as *mut __m256i, e3);
            _mm256_storeu_si256(fp.add(64) as *mut __m256i, e4);
            _mm256_storeu_si256(fp.add(80) as *mut __m256i, e5);
            _mm256_storeu_si256(fp.add(96) as *mut __m256i, e6);
            _mm256_storeu_si256(fp.add(112) as *mut __m256i, e7);
        }
    }
}

#[target_feature(enable = "avx2")]
fn invntt512(f: &mut [i16], reps: usize, qdata: &[i16; 1696]) {
    unsafe {
        let qv = ld(qdata, 768);
        let qround32v = ld(qdata, 1616);
        let mut reps = reps;
        let base = 0usize;
        reps *= 4;
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 128 * r);
            let a3 = _mm256_loadu_si256(fp.add(48) as *const __m256i);
            let a7 = _mm256_loadu_si256(fp.add(112) as *const __m256i);
            let b3 = add16(a3, a7);
            let mut b7 = sub16(a3, a7);
            b7 = mulmod_scaled(b7, ld(qdata, 1648), ld(qdata, 1568), qv);
            let a1 = _mm256_loadu_si256(fp.add(16) as *const __m256i);
            let a5 = _mm256_loadu_si256(fp.add(80) as *const __m256i);
            let b1 = add16(a1, a5);
            let mut b5 = sub16(a1, a5);
            b5 = mulmod_scaled(b5, ld(qdata, 1648), ld(qdata, 1568), qv);
            let a2 = _mm256_loadu_si256(fp.add(32) as *const __m256i);
            let a6 = _mm256_loadu_si256(fp.add(96) as *const __m256i);
            let b2 = add16(a2, a6);
            let b6 = sub16(a2, a6);
            let a0 = _mm256_loadu_si256(fp.add(0) as *const __m256i);
            let a4 = _mm256_loadu_si256(fp.add(64) as *const __m256i);
            let b0 = add16(a0, a4);
            let b4 = sub16(a0, a4);
            let c6 = add16(b6, b7);
            let c7 = sub16(b6, b7);
            let c2 = add16(b2, b3);
            let c3 = sub16(b2, b3);
            let c4 = add16(b4, b5);
            let c5 = sub16(b4, b5);
            let c0 = add16(b0, b1);
            let c1 = sub16(b0, b1);
            let mut d3 = _mm256_unpacklo_epi64(c3, c7);
            let mut d7 = _mm256_unpackhi_epi64(c3, c7);
            let mut d2 = _mm256_unpacklo_epi64(c2, c6);
            let mut d6 = _mm256_unpackhi_epi64(c2, c6);
            let mut d1 = _mm256_unpacklo_epi64(c1, c5);
            let mut d5 = _mm256_unpackhi_epi64(c1, c5);
            let mut d0 = _mm256_unpacklo_epi64(c0, c4);
            let mut d4 = _mm256_unpackhi_epi64(c0, c4);
            d7 = mulmod_scaled(d7, ld(qdata, 80), ld(qdata, 864), qv);
            d6 = mulmod_scaled(d6, ld(qdata, 64), ld(qdata, 848), qv);
            d5 = mulmod_scaled(d5, ld(qdata, 112), ld(qdata, 896), qv);
            d4 = mulmod_scaled(d4, ld(qdata, 96), ld(qdata, 880), qv);
            d3 = mulmod_scaled(d3, ld(qdata, 48), ld(qdata, 832), qv);
            d2 = mulmod_scaled(d2, ld(qdata, 32), ld(qdata, 816), qv);
            d1 = reduce(d1, qv, qround32v);
            d0 = reduce(d0, qv, qround32v);
            let e5 = add16(d5, d7);
            let mut e7 = sub16(d5, d7);
            e7 = mulmod_scaled(e7, ld(qdata, 1648), ld(qdata, 1568), qv);
            let e4 = add16(d4, d6);
            let mut e6 = sub16(d4, d6);
            e6 = mulmod_scaled(e6, ld(qdata, 1648), ld(qdata, 1568), qv);
            let e1 = add16(d1, d3);
            let e3 = sub16(d1, d3);
            let e0 = add16(d0, d2);
            let e2 = sub16(d0, d2);
            _mm256_storeu_si256(fp.add(0) as *mut __m256i, e0);
            _mm256_storeu_si256(fp.add(16) as *mut __m256i, e1);
            _mm256_storeu_si256(fp.add(32) as *mut __m256i, e2);
            _mm256_storeu_si256(fp.add(48) as *mut __m256i, e3);
            _mm256_storeu_si256(fp.add(64) as *mut __m256i, e4);
            _mm256_storeu_si256(fp.add(80) as *mut __m256i, e5);
            _mm256_storeu_si256(fp.add(96) as *mut __m256i, e6);
            _mm256_storeu_si256(fp.add(112) as *mut __m256i, e7);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 128 * r);
            let a6 = _mm256_loadu_si256(fp.add(96) as *const __m256i);
            let a7 = _mm256_loadu_si256(fp.add(112) as *const __m256i);
            let b6 = _mm256_unpacklo_epi32(a6, a7);
            let b7 = _mm256_unpackhi_epi32(a6, a7);
            let c6 = _mm256_unpacklo_epi32(b6, b7);
            let c7 = _mm256_unpackhi_epi32(b6, b7);
            let a4 = _mm256_loadu_si256(fp.add(64) as *const __m256i);
            let a5 = _mm256_loadu_si256(fp.add(80) as *const __m256i);
            let b4 = _mm256_unpacklo_epi32(a4, a5);
            let b5 = _mm256_unpackhi_epi32(a4, a5);
            let c4 = _mm256_unpacklo_epi32(b4, b5);
            let c5 = _mm256_unpackhi_epi32(b4, b5);
            let a2 = _mm256_loadu_si256(fp.add(32) as *const __m256i);
            let a3 = _mm256_loadu_si256(fp.add(48) as *const __m256i);
            let b2 = _mm256_unpacklo_epi32(a2, a3);
            let b3 = _mm256_unpackhi_epi32(a2, a3);
            let c2 = _mm256_unpacklo_epi32(b2, b3);
            let c3 = _mm256_unpackhi_epi32(b2, b3);
            let a0 = _mm256_loadu_si256(fp.add(0) as *const __m256i);
            let a1 = _mm256_loadu_si256(fp.add(16) as *const __m256i);
            let b0 = _mm256_unpacklo_epi32(a0, a1);
            let b1 = _mm256_unpackhi_epi32(a0, a1);
            let c0 = _mm256_unpacklo_epi32(b0, b1);
            let c1 = _mm256_unpackhi_epi32(b0, b1);
            let d3 = add16(c3, c7);
            let d7 = sub16(c3, c7);
            let d1 = add16(c1, c5);
            let d5 = sub16(c1, c5);
            let d2 = add16(c2, c6);
            let d6 = sub16(c2, c6);
            let d0 = add16(c0, c4);
            let d4 = sub16(c0, c4);
            let e5 = _mm256_unpacklo_epi16(d5, d7);
            let e7 = _mm256_unpackhi_epi16(d5, d7);
            let f5 = _mm256_unpacklo_epi16(e5, e7);
            let f7 = _mm256_unpackhi_epi16(e5, e7);
            let mut g5 = _mm256_unpacklo_epi16(f5, f7);
            let mut g7 = _mm256_unpackhi_epi16(f5, f7);
            let e4 = _mm256_unpacklo_epi16(d4, d6);
            let e6 = _mm256_unpackhi_epi16(d4, d6);
            let f4 = _mm256_unpacklo_epi16(e4, e6);
            let f6 = _mm256_unpackhi_epi16(e4, e6);
            let mut g4 = _mm256_unpacklo_epi16(f4, f6);
            let mut g6 = _mm256_unpackhi_epi16(f4, f6);
            let e1 = _mm256_unpacklo_epi16(d1, d3);
            let e3 = _mm256_unpackhi_epi16(d1, d3);
            let f1 = _mm256_unpacklo_epi16(e1, e3);
            let f3 = _mm256_unpackhi_epi16(e1, e3);
            let mut g1 = _mm256_unpacklo_epi16(f1, f3);
            let mut g3 = _mm256_unpackhi_epi16(f1, f3);
            let e0 = _mm256_unpacklo_epi16(d0, d2);
            let e2 = _mm256_unpackhi_epi16(d0, d2);
            let f0 = _mm256_unpacklo_epi16(e0, e2);
            let f2 = _mm256_unpackhi_epi16(e0, e2);
            let mut g0 = _mm256_unpacklo_epi16(f0, f2);
            let mut g2 = _mm256_unpackhi_epi16(f0, f2);
            g7 = mulmod_scaled(g7, ld(qdata, 208), ld(qdata, 992), qv);
            g3 = mulmod_scaled(g3, ld(qdata, 192), ld(qdata, 976), qv);
            g6 = mulmod_scaled(g6, ld(qdata, 240), ld(qdata, 1024), qv);
            g2 = mulmod_scaled(g2, ld(qdata, 224), ld(qdata, 1008), qv);
            g5 = mulmod_scaled(g5, ld(qdata, 176), ld(qdata, 960), qv);
            g1 = mulmod_scaled(g1, ld(qdata, 160), ld(qdata, 944), qv);
            g4 = reduce(g4, qv, qround32v);
            g0 = reduce(g0, qv, qround32v);
            let h6 = add16(g6, g7);
            let mut h7 = sub16(g6, g7);
            h7 = mulmod_scaled(h7, ld(qdata, 1648), ld(qdata, 1568), qv);
            let h2 = add16(g2, g3);
            let mut h3 = sub16(g2, g3);
            h3 = mulmod_scaled(h3, ld(qdata, 1648), ld(qdata, 1568), qv);
            let h4 = add16(g4, g5);
            let h5 = sub16(g4, g5);
            let h0 = add16(g0, g1);
            let h1 = sub16(g0, g1);
            let i5 = add16(h5, h7);
            let i7 = sub16(h5, h7);
            let i1 = add16(h1, h3);
            let i3 = sub16(h1, h3);
            let i4 = add16(h4, h6);
            let i6 = sub16(h4, h6);
            let i0 = add16(h0, h2);
            let i2 = sub16(h0, h2);
            _mm256_storeu_si256(fp.add(0) as *mut __m256i, i0);
            _mm256_storeu_si256(fp.add(16) as *mut __m256i, i1);
            _mm256_storeu_si256(fp.add(32) as *mut __m256i, i2);
            _mm256_storeu_si256(fp.add(48) as *mut __m256i, i3);
            _mm256_storeu_si256(fp.add(64) as *mut __m256i, i4);
            _mm256_storeu_si256(fp.add(80) as *mut __m256i, i5);
            _mm256_storeu_si256(fp.add(96) as *mut __m256i, i6);
            _mm256_storeu_si256(fp.add(112) as *mut __m256i, i7);
        }
        reps /= 2;
        reps /= 2;
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a27 = _mm256_loadu_si256(fp.add(432) as *const __m256i);
            let a31 = _mm256_loadu_si256(fp.add(496) as *const __m256i);
            let mut b27 = perm_lo(a27, a31);
            let mut b31 = perm_hi(a27, a31);
            let a19 = _mm256_loadu_si256(fp.add(304) as *const __m256i);
            let a23 = _mm256_loadu_si256(fp.add(368) as *const __m256i);
            let mut b19 = perm_lo(a19, a23);
            let mut b23 = perm_hi(a19, a23);
            let a11 = _mm256_loadu_si256(fp.add(176) as *const __m256i);
            let a15 = _mm256_loadu_si256(fp.add(240) as *const __m256i);
            let mut b11 = perm_lo(a11, a15);
            let mut b15 = perm_hi(a11, a15);
            let a3 = _mm256_loadu_si256(fp.add(48) as *const __m256i);
            let a7 = _mm256_loadu_si256(fp.add(112) as *const __m256i);
            let mut b3 = perm_lo(a3, a7);
            let mut b7 = perm_hi(a3, a7);
            b31 = mulmod_scaled(b31, ld(qdata, 624), ld(qdata, 1408), qv);
            b27 = mulmod_scaled(b27, ld(qdata, 560), ld(qdata, 1344), qv);
            b23 = mulmod_scaled(b23, ld(qdata, 688), ld(qdata, 1472), qv);
            b19 = mulmod_scaled(b19, ld(qdata, 752), ld(qdata, 1536), qv);
            b15 = mulmod_scaled(b15, ld(qdata, 432), ld(qdata, 1216), qv);
            b11 = mulmod_scaled(b11, ld(qdata, 496), ld(qdata, 1280), qv);
            b7 = mulmod_scaled(b7, ld(qdata, 368), ld(qdata, 1152), qv);
            b3 = reduce(b3, qv, qround32v);
            let c27 = add16(b27, b31);
            let mut c31 = sub16(b27, b31);
            c31 = mulmod_scaled(c31, ld(qdata, 1664), ld(qdata, 1584), qv);
            let c19 = add16(b19, b23);
            let mut c23 = sub16(b19, b23);
            c23 = mulmod_scaled(c23, ld(qdata, 1680), ld(qdata, 1600), qv);
            let c11 = add16(b11, b15);
            let mut c15 = sub16(b11, b15);
            c15 = mulmod_scaled(c15, ld(qdata, 1648), ld(qdata, 1568), qv);
            let c3 = add16(b3, b7);
            let c7 = sub16(b3, b7);
            let d23 = add16(c23, c31);
            let mut d31 = sub16(c23, c31);
            d31 = mulmod_scaled(d31, ld(qdata, 1648), ld(qdata, 1568), qv);
            let mut d19 = add16(c19, c27);
            let mut d27 = sub16(c19, c27);
            d27 = mulmod_scaled(d27, ld(qdata, 1648), ld(qdata, 1568), qv);
            let d7 = add16(c7, c15);
            let d15 = sub16(c7, c15);
            let mut d3 = add16(c3, c11);
            let d11 = sub16(c3, c11);
            d19 = reduce(d19, qv, qround32v);
            d3 = reduce(d3, qv, qround32v);
            let e15 = add16(d15, d31);
            let e31 = sub16(d15, d31);
            let e7 = add16(d7, d23);
            let e23 = sub16(d7, d23);
            let e11 = add16(d11, d27);
            let e27 = sub16(d11, d27);
            let e3 = add16(d3, d19);
            let e19 = sub16(d3, d19);
            _mm256_storeu_si256(fp.add(48) as *mut __m256i, e3);
            _mm256_storeu_si256(fp.add(112) as *mut __m256i, e7);
            _mm256_storeu_si256(fp.add(176) as *mut __m256i, e11);
            _mm256_storeu_si256(fp.add(240) as *mut __m256i, e15);
            _mm256_storeu_si256(fp.add(304) as *mut __m256i, e19);
            _mm256_storeu_si256(fp.add(368) as *mut __m256i, e23);
            _mm256_storeu_si256(fp.add(432) as *mut __m256i, e27);
            _mm256_storeu_si256(fp.add(496) as *mut __m256i, e31);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a26 = _mm256_loadu_si256(fp.add(416) as *const __m256i);
            let a30 = _mm256_loadu_si256(fp.add(480) as *const __m256i);
            let mut b26 = perm_lo(a26, a30);
            let mut b30 = perm_hi(a26, a30);
            let a18 = _mm256_loadu_si256(fp.add(288) as *const __m256i);
            let a22 = _mm256_loadu_si256(fp.add(352) as *const __m256i);
            let mut b18 = perm_lo(a18, a22);
            let mut b22 = perm_hi(a18, a22);
            let a10 = _mm256_loadu_si256(fp.add(160) as *const __m256i);
            let a14 = _mm256_loadu_si256(fp.add(224) as *const __m256i);
            let mut b10 = perm_lo(a10, a14);
            let mut b14 = perm_hi(a10, a14);
            let a2 = _mm256_loadu_si256(fp.add(32) as *const __m256i);
            let a6 = _mm256_loadu_si256(fp.add(96) as *const __m256i);
            let mut b2 = perm_lo(a2, a6);
            let mut b6 = perm_hi(a2, a6);
            b30 = mulmod_scaled(b30, ld(qdata, 608), ld(qdata, 1392), qv);
            b26 = mulmod_scaled(b26, ld(qdata, 544), ld(qdata, 1328), qv);
            b22 = mulmod_scaled(b22, ld(qdata, 672), ld(qdata, 1456), qv);
            b18 = mulmod_scaled(b18, ld(qdata, 736), ld(qdata, 1520), qv);
            b14 = mulmod_scaled(b14, ld(qdata, 416), ld(qdata, 1200), qv);
            b10 = mulmod_scaled(b10, ld(qdata, 480), ld(qdata, 1264), qv);
            b6 = mulmod_scaled(b6, ld(qdata, 352), ld(qdata, 1136), qv);
            b2 = reduce(b2, qv, qround32v);
            let c26 = add16(b26, b30);
            let mut c30 = sub16(b26, b30);
            c30 = mulmod_scaled(c30, ld(qdata, 1664), ld(qdata, 1584), qv);
            let c18 = add16(b18, b22);
            let mut c22 = sub16(b18, b22);
            c22 = mulmod_scaled(c22, ld(qdata, 1680), ld(qdata, 1600), qv);
            let c10 = add16(b10, b14);
            let mut c14 = sub16(b10, b14);
            c14 = mulmod_scaled(c14, ld(qdata, 1648), ld(qdata, 1568), qv);
            let c2 = add16(b2, b6);
            let c6 = sub16(b2, b6);
            let d22 = add16(c22, c30);
            let mut d30 = sub16(c22, c30);
            d30 = mulmod_scaled(d30, ld(qdata, 1648), ld(qdata, 1568), qv);
            let mut d18 = add16(c18, c26);
            let mut d26 = sub16(c18, c26);
            d26 = mulmod_scaled(d26, ld(qdata, 1648), ld(qdata, 1568), qv);
            let d6 = add16(c6, c14);
            let d14 = sub16(c6, c14);
            let mut d2 = add16(c2, c10);
            let d10 = sub16(c2, c10);
            d18 = reduce(d18, qv, qround32v);
            d2 = reduce(d2, qv, qround32v);
            let e14 = add16(d14, d30);
            let e30 = sub16(d14, d30);
            let e6 = add16(d6, d22);
            let e22 = sub16(d6, d22);
            let e10 = add16(d10, d26);
            let e26 = sub16(d10, d26);
            let e2 = add16(d2, d18);
            let e18 = sub16(d2, d18);
            _mm256_storeu_si256(fp.add(32) as *mut __m256i, e2);
            _mm256_storeu_si256(fp.add(96) as *mut __m256i, e6);
            _mm256_storeu_si256(fp.add(160) as *mut __m256i, e10);
            _mm256_storeu_si256(fp.add(224) as *mut __m256i, e14);
            _mm256_storeu_si256(fp.add(288) as *mut __m256i, e18);
            _mm256_storeu_si256(fp.add(352) as *mut __m256i, e22);
            _mm256_storeu_si256(fp.add(416) as *mut __m256i, e26);
            _mm256_storeu_si256(fp.add(480) as *mut __m256i, e30);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a25 = _mm256_loadu_si256(fp.add(400) as *const __m256i);
            let a29 = _mm256_loadu_si256(fp.add(464) as *const __m256i);
            let mut b25 = perm_lo(a25, a29);
            let mut b29 = perm_hi(a25, a29);
            let a17 = _mm256_loadu_si256(fp.add(272) as *const __m256i);
            let a21 = _mm256_loadu_si256(fp.add(336) as *const __m256i);
            let mut b17 = perm_lo(a17, a21);
            let mut b21 = perm_hi(a17, a21);
            let a9 = _mm256_loadu_si256(fp.add(144) as *const __m256i);
            let a13 = _mm256_loadu_si256(fp.add(208) as *const __m256i);
            let mut b9 = perm_lo(a9, a13);
            let mut b13 = perm_hi(a9, a13);
            let a1 = _mm256_loadu_si256(fp.add(16) as *const __m256i);
            let a5 = _mm256_loadu_si256(fp.add(80) as *const __m256i);
            let mut b1 = perm_lo(a1, a5);
            let mut b5 = perm_hi(a1, a5);
            b29 = mulmod_scaled(b29, ld(qdata, 592), ld(qdata, 1376), qv);
            b25 = mulmod_scaled(b25, ld(qdata, 528), ld(qdata, 1312), qv);
            b21 = mulmod_scaled(b21, ld(qdata, 656), ld(qdata, 1440), qv);
            b17 = mulmod_scaled(b17, ld(qdata, 720), ld(qdata, 1504), qv);
            b13 = mulmod_scaled(b13, ld(qdata, 400), ld(qdata, 1184), qv);
            b9 = mulmod_scaled(b9, ld(qdata, 464), ld(qdata, 1248), qv);
            b5 = mulmod_scaled(b5, ld(qdata, 336), ld(qdata, 1120), qv);
            b1 = reduce(b1, qv, qround32v);
            let c25 = add16(b25, b29);
            let mut c29 = sub16(b25, b29);
            c29 = mulmod_scaled(c29, ld(qdata, 1664), ld(qdata, 1584), qv);
            let c17 = add16(b17, b21);
            let mut c21 = sub16(b17, b21);
            c21 = mulmod_scaled(c21, ld(qdata, 1680), ld(qdata, 1600), qv);
            let c9 = add16(b9, b13);
            let mut c13 = sub16(b9, b13);
            c13 = mulmod_scaled(c13, ld(qdata, 1648), ld(qdata, 1568), qv);
            let c1 = add16(b1, b5);
            let c5 = sub16(b1, b5);
            let d21 = add16(c21, c29);
            let mut d29 = sub16(c21, c29);
            d29 = mulmod_scaled(d29, ld(qdata, 1648), ld(qdata, 1568), qv);
            let mut d17 = add16(c17, c25);
            let mut d25 = sub16(c17, c25);
            d25 = mulmod_scaled(d25, ld(qdata, 1648), ld(qdata, 1568), qv);
            let d5 = add16(c5, c13);
            let d13 = sub16(c5, c13);
            let mut d1 = add16(c1, c9);
            let d9 = sub16(c1, c9);
            d17 = reduce(d17, qv, qround32v);
            d1 = reduce(d1, qv, qround32v);
            let e13 = add16(d13, d29);
            let e29 = sub16(d13, d29);
            let e5 = add16(d5, d21);
            let e21 = sub16(d5, d21);
            let e9 = add16(d9, d25);
            let e25 = sub16(d9, d25);
            let e1 = add16(d1, d17);
            let e17 = sub16(d1, d17);
            _mm256_storeu_si256(fp.add(16) as *mut __m256i, e1);
            _mm256_storeu_si256(fp.add(80) as *mut __m256i, e5);
            _mm256_storeu_si256(fp.add(144) as *mut __m256i, e9);
            _mm256_storeu_si256(fp.add(208) as *mut __m256i, e13);
            _mm256_storeu_si256(fp.add(272) as *mut __m256i, e17);
            _mm256_storeu_si256(fp.add(336) as *mut __m256i, e21);
            _mm256_storeu_si256(fp.add(400) as *mut __m256i, e25);
            _mm256_storeu_si256(fp.add(464) as *mut __m256i, e29);
        }
        for r in 0..reps {
            let fp = f.as_mut_ptr().add(base + 512 * r);
            let a24 = _mm256_loadu_si256(fp.add(384) as *const __m256i);
            let a28 = _mm256_loadu_si256(fp.add(448) as *const __m256i);
            let mut b24 = perm_lo(a24, a28);
            let mut b28 = perm_hi(a24, a28);
            let a16 = _mm256_loadu_si256(fp.add(256) as *const __m256i);
            let a20 = _mm256_loadu_si256(fp.add(320) as *const __m256i);
            let mut b16 = perm_lo(a16, a20);
            let mut b20 = perm_hi(a16, a20);
            let a8 = _mm256_loadu_si256(fp.add(128) as *const __m256i);
            let a12 = _mm256_loadu_si256(fp.add(192) as *const __m256i);
            let mut b8 = perm_lo(a8, a12);
            let mut b12 = perm_hi(a8, a12);
            let a0 = _mm256_loadu_si256(fp.add(0) as *const __m256i);
            let a4 = _mm256_loadu_si256(fp.add(64) as *const __m256i);
            let mut b0 = perm_lo(a0, a4);
            let mut b4 = perm_hi(a0, a4);
            b28 = mulmod_scaled(b28, ld(qdata, 576), ld(qdata, 1360), qv);
            b24 = mulmod_scaled(b24, ld(qdata, 512), ld(qdata, 1296), qv);
            b20 = mulmod_scaled(b20, ld(qdata, 640), ld(qdata, 1424), qv);
            b16 = mulmod_scaled(b16, ld(qdata, 704), ld(qdata, 1488), qv);
            b12 = mulmod_scaled(b12, ld(qdata, 384), ld(qdata, 1168), qv);
            b8 = mulmod_scaled(b8, ld(qdata, 448), ld(qdata, 1232), qv);
            b4 = mulmod_scaled(b4, ld(qdata, 320), ld(qdata, 1104), qv);
            b0 = reduce(b0, qv, qround32v);
            let c24 = add16(b24, b28);
            let mut c28 = sub16(b24, b28);
            c28 = mulmod_scaled(c28, ld(qdata, 1664), ld(qdata, 1584), qv);
            let c16 = add16(b16, b20);
            let mut c20 = sub16(b16, b20);
            c20 = mulmod_scaled(c20, ld(qdata, 1680), ld(qdata, 1600), qv);
            let c8 = add16(b8, b12);
            let mut c12 = sub16(b8, b12);
            c12 = mulmod_scaled(c12, ld(qdata, 1648), ld(qdata, 1568), qv);
            let c0 = add16(b0, b4);
            let c4 = sub16(b0, b4);
            let d20 = add16(c20, c28);
            let mut d28 = sub16(c20, c28);
            d28 = mulmod_scaled(d28, ld(qdata, 1648), ld(qdata, 1568), qv);
            let mut d16 = add16(c16, c24);
            let mut d24 = sub16(c16, c24);
            d24 = mulmod_scaled(d24, ld(qdata, 1648), ld(qdata, 1568), qv);
            let d4 = add16(c4, c12);
            let d12 = sub16(c4, c12);
            let mut d0 = add16(c0, c8);
            let d8 = sub16(c0, c8);
            d16 = reduce(d16, qv, qround32v);
            d0 = reduce(d0, qv, qround32v);
            let e12 = add16(d12, d28);
            let e28 = sub16(d12, d28);
            let e4 = add16(d4, d20);
            let e20 = sub16(d4, d20);
            let e8 = add16(d8, d24);
            let e24 = sub16(d8, d24);
            let e0 = add16(d0, d16);
            let e16 = sub16(d0, d16);
            _mm256_storeu_si256(fp.add(0) as *mut __m256i, e0);
            _mm256_storeu_si256(fp.add(64) as *mut __m256i, e4);
            _mm256_storeu_si256(fp.add(128) as *mut __m256i, e8);
            _mm256_storeu_si256(fp.add(192) as *mut __m256i, e12);
            _mm256_storeu_si256(fp.add(256) as *mut __m256i, e16);
            _mm256_storeu_si256(fp.add(320) as *mut __m256i, e20);
            _mm256_storeu_si256(fp.add(384) as *mut __m256i, e24);
            _mm256_storeu_si256(fp.add(448) as *mut __m256i, e28);
        }
    }
}

#[rustfmt::skip]
static QDATA_7681: [i16; 1696] = [
    -3593, -3593, -3593, -3593, -3625, -3625, -3625, -3625, -3593, -3593, -3593, -3593, -3625, -3625, -3625, -3625,
    -3777, -3777, -3777, -3777, 3182, 3182, 3182, 3182, -3777, -3777, -3777, -3777, 3182, 3182, 3182, 3182,
    -3593, -3593, -3593, -3593, -3182, -3182, -3182, -3182, -3593, -3593, -3593, -3593, -3182, -3182, -3182, -3182,
    3777, 3777, 3777, 3777, 3625, 3625, 3625, 3625, 3777, 3777, 3777, 3777, 3625, 3625, 3625, 3625,
    -3593, -3593, -3593, -3593, 2194, 2194, 2194, 2194, -3593, -3593, -3593, -3593, 2194, 2194, 2194, 2194,
    -3625, -3625, -3625, -3625, -1100, -1100, -1100, -1100, -3625, -3625, -3625, -3625, -1100, -1100, -1100, -1100,
    -3593, -3593, -3593, -3593, 3696, 3696, 3696, 3696, -3593, -3593, -3593, -3593, 3696, 3696, 3696, 3696,
    -3182, -3182, -3182, -3182, -2456, -2456, -2456, -2456, -3182, -3182, -3182, -3182, -2456, -2456, -2456, -2456,
    -3593, 1701, 2194, 834, -3625, 2319, -1100, 121, -3593, 1701, 2194, 834, -3625, 2319, -1100, 121,
    -3777, 1414, 2456, 2495, 3182, 2876, -3696, 2250, -3777, 1414, 2456, 2495, 3182, 2876, -3696, 2250,
    -3593, -2250, 3696, -2876, -3182, -2495, -2456, -1414, -3593, -2250, 3696, -2876, -3182, -2495, -2456, -1414,
    3777, -121, 1100, -2319, 3625, -834, -2194, -1701, 3777, -121, 1100, -2319, 3625, -834, -2194, -1701,
    -3593, 3364, 1701, -1599, 2194, 2557, 834, -2816, -3593, 3364, 1701, -1599, 2194, 2557, 834, -2816,
    -3625, 617, 2319, 2006, -1100, -1296, 121, 1986, -3625, 617, 2319, 2006, -1100, -1296, 121, 1986,
    -3593, 2237, -2250, -1483, 3696, 3706, -2876, 1921, -3593, 2237, -2250, -1483, 3696, 3706, -2876, 1921,
    -3182, 2088, -2495, -1525, -2456, 1993, -1414, 2830, -3182, 2088, -2495, -1525, -2456, 1993, -1414, 2830,
    -3593, 514, 3364, 438, 1701, 2555, -1599, -1738, 2194, 103, 2557, 1881, 834, -549, -2816, 638,
    -3625, -1399, 617, -1760, 2319, 2535, 2006, 3266, -1100, -1431, -1296, 3174, 121, 3153, 1986, -810,
    -3777, 2956, -2830, -679, 1414, 2440, -1993, -3689, 2456, 2804, 1525, 3555, 2495, 1535, -2088, -7,
    3182, -1321, -1921, -1305, 2876, -3772, -3706, 3600, -3696, -2043, 1483, -396, 2250, -2310, -2237, 1887,
    -3593, -1887, 2237, 2310, -2250, 396, -1483, 2043, 3696, -3600, 3706, 3772, -2876, 1305, 1921, 1321,
    -3182, 7, 2088, -1535, -2495, -3555, -1525, -2804, -2456, 3689, 1993, -2440, -1414, 679, 2830, -2956,
    3777, 810, -1986, -3153, -121, -3174, 1296, 1431, 1100, -3266, -2006, -2535, -2319, 1760, -617, 1399,
    3625, -638, 2816, 549, -834, -1881, -2557, -103, -2194, 1738, 1599, -2555, -1701, -438, -3364, -514,
    -3593, -1532, 514, -373, 3364, -3816, 438, -3456, 1701, 783, 2555, 2883, -1599, 727, -1738, -2385,
    2194, -2160, 103, -2391, 2557, 2762, 1881, -2426, 834, 3310, -549, -1350, -2816, 1386, 638, -194,
    -3625, 404, -1399, -3692, 617, -2764, -1760, -1054, 2319, 1799, 2535, -3588, 2006, 1533, 3266, 2113,
    -1100, -2579, -1431, -1756, -1296, 1598, 3174, -2, 121, -3480, 3153, -2572, 1986, 2743, -810, 2919,
    -3593, 2789, -1887, -921, 2237, -1497, 2310, -2133, -2250, -915, 396, 1390, -1483, 3135, 2043, -859,
    3696, 2732, -3600, -1464, 3706, 2224, 3772, -2665, -2876, 1698, 1305, 2835, 1921, 730, 1321, 486,
    -3182, 3417, 7, -3428, 2088, -3145, -1535, 1168, -2495, -3831, -3555, -3750, -1525, 660, -2804, 2649,
    -2456, 3405, 3689, -1521, 1993, 1681, -2440, 1056, -1414, 1166, 679, -2233, 2830, 2175, -2956, -1919,
    -3593, -1404, -1532, 451, 514, -402, -373, 1278, 3364, -509, -3816, -3770, 438, -2345, -3456, -226,
    1701, -1689, 783, -1509, 2555, 2963, 2883, 1242, -1599, 1669, 727, 2719, -1738, 642, -2385, -436,
    2194, 3335, -2160, 1779, 103, 3745, -2391, 17, 2557, 2812, 2762, -1144, 1881, 83, -2426, -1181,
    834, -1519, 3310, 3568, -549, -796, -1350, 2072, -2816, -2460, 1386, 2891, 638, -2083, -194, -715,
    -3593, -402, -3816, -226, 2555, 1669, -2385, 1779, 2557, 83, 3310, 2072, 638, 1012, -3692, 1295,
    2319, -3208, 1533, -2071, -1431, -2005, -2, 1586, 1986, -293, 1919, -929, -679, 777, -1681, -3461,
    2456, 3366, 3750, -1203, 1535, -3657, -3417, -1712, -1921, 2515, 2665, -1070, 3600, 2532, -3135, -2589,
    2250, -2258, 921, -658, -514, 509, 3456, 1509, 1599, -642, 2160, -17, -1881, 1519, 1350, -2891,
    -3593, -3434, -1497, 893, 396, -2422, -859, 2965, 3706, -2339, 1698, -2937, 1321, -670, -3428, -3163,
    -2495, -1072, 660, 1084, 3689, -179, 1056, -1338, 2830, 2786, -2919, -3677, -3153, -151, -1598, 3334,
    1100, -3314, 3588, 2262, 1760, -2230, -404, 2083, 2816, -3568, 2426, -2812, -103, 436, -727, -2963,
    -1701, 3770, 373, 1404, 1887, -1649, 2133, -826, 1483, 434, -2732, 3287, -3772, -2378, -2835, 3723,
    -3593, 658, 2789, 370, -1887, -3434, -921, -3752, 2237, 1649, -1497, 2258, 2310, 3581, -2133, 893,
    -2250, 3794, -915, 826, 396, 2589, 1390, 592, -1483, -2422, 3135, 3214, 2043, -434, -859, -2532,
    3696, 1121, 2732, 2965, -3600, 2998, -1464, -3287, 3706, 1070, 2224, -589, 3772, -2339, -2665, 2070,
    -2876, 2378, 1698, -2515, 1305, -2815, 2835, -2937, 1921, -1348, 730, -3723, 1321, 1712, 486, 2130,
    7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681, 7681,
    -9, -9, -9, -9, -16425, -16425, -16425, -16425, -9, -9, -9, -9, -16425, -16425, -16425, -16425,
    -28865, -28865, -28865, -28865, 10350, 10350, 10350, 10350, -28865, -28865, -28865, -28865, 10350, 10350, 10350, 10350,
    -9, -9, -9, -9, -10350, -10350, -10350, -10350, -9, -9, -9, -9, -10350, -10350, -10350, -10350,
    28865, 28865, 28865, 28865, 16425, 16425, 16425, 16425, 28865, 28865, 28865, 28865, 16425, 16425, 16425, 16425,
    -9, -9, -9, -9, -4974, -4974, -4974, -4974, -9, -9, -9, -9, -4974, -4974, -4974, -4974,
    -16425, -16425, -16425, -16425, -7244, -7244, -7244, -7244, -16425, -16425, -16425, -16425, -7244, -7244, -7244, -7244,
    -9, -9, -9, -9, -4496, -4496, -4496, -4496, -9, -9, -9, -9, -4496, -4496, -4496, -4496,
    -10350, -10350, -10350, -10350, -14744, -14744, -14744, -14744, -10350, -10350, -10350, -10350, -14744, -14744, -14744, -14744,
    -9, -20315, -4974, 18242, -16425, 18191, -7244, -11655, -9, -20315, -4974, 18242, -16425, 18191, -7244, -11655,
    -28865, 20870, 14744, -22593, 10350, 828, 4496, 23754, -28865, 20870, 14744, -22593, 10350, 828, 4496, 23754,
    -9, -23754, -4496, -828, -10350, 22593, -14744, -20870, -9, -23754, -4496, -828, -10350, 22593, -14744, -20870,
    28865, 11655, 7244, -18191, 16425, -18242, 4974, 20315, 28865, 11655, 7244, -18191, 16425, -18242, 4974, 20315,
    -9, -10972, -20315, 23489, -4974, 25597, 18242, -2816, -9, -10972, -20315, 23489, -4974, 25597, 18242, -2816,
    -16425, -19351, 18191, -3114, -7244, -9488, -11655, 19394, -16425, -19351, 18191, -3114, -7244, -9488, -11655, 19394,
    -9, -7491, -23754, -15307, -4496, -15750, -828, -5759, -9, -7491, -23754, -15307, -4496, -15750, -828, -5759,
    -10350, 22568, 22593, -20469, -14744, 31177, -20870, 26382, -10350, 22568, 22593, -20469, -14744, 31177, -20870, 26382,
    -9, -14846, -10972, -21066, -20315, -24581, 23489, -23242, -4974, -4505, 25597, -26279, 18242, 21467, -2816, 15998,
    -16425, -4983, -19351, 14624, 18191, -2073, -3114, 20674, -7244, -21399, -9488, 6246, -11655, -29103, 19394, -5930,
    -28865, -23668, -26382, -28839, 20870, 6536, -31177, 16279, 14744, 29428, 20469, 29667, -22593, 9215, -22568, -11783,
    10350, -14121, 5759, -5913, 828, -1724, 15750, 11792, 4496, 25093, 15307, 26228, 23754, -21766, 7491, -6817,
    -9, 6817, -7491, 21766, -23754, -26228, -15307, -25093, -4496, -11792, -15750, 1724, -828, 5913, -5759, 14121,
    -10350, 11783, 22568, -9215, 22593, -29667, -20469, -29428, -14744, -16279, 31177, -6536, -20870, 28839, 26382, 23668,
    28865, 5930, -19394, 29103, 11655, -6246, 9488, 21399, 7244, -20674, 3114, 2073, -18191, -14624, 19351, 4983,
    16425, -15998, 2816, -21467, -18242, 26279, -25597, 4505, 4974, 23242, -23489, 24581, 20315, 21066, 10972, 14846,
    -9, -32252, -14846, -19317, -10972, 8472, -21066, -3456, -20315, 16655, -24581, 12611, 23489, -12073, -23242, 29871,
    -4974, 6032, -4505, 10409, 25597, 24266, -26279, 17030, 18242, 10478, 21467, 11962, -2816, -26262, 15998, -17602,
    -16425, -22124, -4983, -26220, -19351, -8908, 14624, 32738, 18191, 13575, -2073, 27132, -3114, 24573, 20674, 27201,
    -7244, 12269, -21399, -16092, -9488, -15810, 6246, 15358, -11655, -15768, -29103, 24052, 19394, -26441, -5930, -1689,
    -9, 13541, 6817, -5529, -7491, 26663, 21766, -4693, -23754, 13933, -26228, 8558, -15307, -21953, -25093, -22875,
    -4496, -7508, -11792, -30136, -15750, 26800, 1724, 17303, -828, 2722, 5913, -12013, -5759, 30426, 14121, 3558,
    -10350, -24743, 11783, -21860, 22568, -32329, -9215, 9360, 22593, -7415, -29667, 25946, -20469, -21868, -29428, -25511,
    -14744, 1869, -16279, 14351, 31177, 2193, -6536, 17440, -20870, 24718, 28839, -23225, 26382, 9855, 23668, -9599,
    -9, -32124, -32252, 10179, -14846, 6766, -19317, 16638, -10972, -23549, 8472, -17082, -21066, -15145, -3456, 31518,
    -20315, -6297, 16655, -12261, -24581, -11885, 12611, 30938, 23489, 28805, -12073, 26783, -23242, -14718, 29871, 5708,
    -4974, 15111, 6032, -29453, -4505, 12449, 10409, 529, 25597, -32004, 24266, 2952, -26279, 18003, 17030, 24931,
    18242, -1007, 10478, -4624, 21467, 17636, 11962, 14360, -2816, 15972, -26262, 16715, 15998, 4573, -17602, -14539,
    -9, 6766, 8472, 31518, -24581, 28805, 29871, -29453, 25597, 18003, 10478, 14360, 15998, 27636, -26220, 17167,
    18191, -7304, 24573, -22039, -21399, -4565, 15358, 10802, 19394, 21723, 9599, -9633, -28839, -2807, -2193, -30597,
    14744, -26330, -25946, -2739, 9215, 32695, 24743, -26288, 5759, 20435, -17303, 24530, 11792, 20964, 21953, 23523,
    23754, -27858, 5529, 6510, 14846, 23549, 3456, 12261, -23489, 14718, -6032, -529, 26279, 1007, -11962, -16715,
    -9, 24214, 26663, 23933, -26228, -13686, -22875, -27243, -15750, 4317, 2722, 8839, 14121, -32414, -21860, -25179,
    22593, -25648, -21868, -964, -16279, -1715, 17440, -14650, 26382, -28958, 1689, -10333, 29103, -20119, 15810, 22790,
    7244, 20238, -27132, -2858, -14624, 19274, 22124, -4573, 2816, 4624, -17030, 32004, 4505, -5708, 12073, 11885,
    20315, 17082, 19317, 32124, -6817, 14223, 4693, -14138, 15307, 9650, 7508, -9513, -1724, -23882, 12013, -15221,
    -9, -6510, 13541, -23182, 6817, 24214, -5529, -24232, -7491, -14223, 26663, 27858, 21766, 26621, -4693, 23933,
    -23754, 29394, 13933, 14138, -26228, -23523, 8558, -23984, -15307, -13686, -21953, 26766, -25093, -9650, -22875, -20964,
    -4496, -22943, -7508, -27243, -11792, -18506, -30136, 9513, -15750, -24530, 26800, 947, 1724, 4317, 17303, 29718,
    -828, 23882, 2722, -20435, 5913, -10495, -12013, 8839, -5759, -3396, 30426, 15221, 14121, 26288, 3558, 27730,
    -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865, -28865,
    28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865, 28865,
    -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425, -16425,
    -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350, -10350,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777, -3777,
    3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777, 3777,
    -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625, -3625,
    -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182, -3182,
];

#[rustfmt::skip]
static QDATA_10753: [i16; 1696] = [
    1018, 1018, 1018, 1018, 3688, 3688, 3688, 3688, 1018, 1018, 1018, 1018, 3688, 3688, 3688, 3688,
    -223, -223, -223, -223, -4188, -4188, -4188, -4188, -223, -223, -223, -223, -4188, -4188, -4188, -4188,
    1018, 1018, 1018, 1018, 4188, 4188, 4188, 4188, 1018, 1018, 1018, 1018, 4188, 4188, 4188, 4188,
    223, 223, 223, 223, -3688, -3688, -3688, -3688, 223, 223, 223, 223, -3688, -3688, -3688, -3688,
    1018, 1018, 1018, 1018, -376, -376, -376, -376, 1018, 1018, 1018, 1018, -376, -376, -376, -376,
    3688, 3688, 3688, 3688, -3686, -3686, -3686, -3686, 3688, 3688, 3688, 3688, -3686, -3686, -3686, -3686,
    1018, 1018, 1018, 1018, -2413, -2413, -2413, -2413, 1018, 1018, 1018, 1018, -2413, -2413, -2413, -2413,
    4188, 4188, 4188, 4188, -357, -357, -357, -357, 4188, 4188, 4188, 4188, -357, -357, -357, -357,
    1018, -3364, -376, 4855, 3688, 425, -3686, 2695, 1018, -3364, -376, 4855, 3688, 425, -3686, 2695,
    -223, -3784, 357, -2236, -4188, 4544, 2413, 730, -223, -3784, 357, -2236, -4188, 4544, 2413, 730,
    1018, -730, -2413, -4544, 4188, 2236, -357, 3784, 1018, -730, -2413, -4544, 4188, 2236, -357, 3784,
    223, -2695, 3686, -425, -3688, -4855, 376, 3364, 223, -2695, 3686, -425, -3688, -4855, 376, 3364,
    1018, -5175, -3364, 2503, -376, 1341, 4855, -4875, 1018, -5175, -3364, 2503, -376, 1341, 4855, -4875,
    3688, -2629, 425, -4347, -3686, 3823, 2695, -4035, 3688, -2629, 425, -4347, -3686, 3823, 2695, -4035,
    1018, 5063, -730, 341, -2413, -3012, -4544, -5213, 1018, 5063, -730, 341, -2413, -3012, -4544, -5213,
    4188, 1520, 2236, 1931, -357, 918, 3784, 4095, 4188, 1520, 2236, 1931, -357, 918, 3784, 4095,
    1018, 3085, -5175, 2982, -3364, -4744, 2503, -4129, -376, -2576, 1341, -193, 4855, 3062, -4875, 4,
    3688, 2388, -2629, -4513, 425, 4742, -4347, 2935, -3686, -544, 3823, -2178, 2695, 847, -4035, 268,
    -223, -1299, -4095, -1287, -3784, -4876, -918, 3091, 357, -4189, -1931, 4616, -2236, 2984, -1520, -3550,
    -4188, -1009, 5213, -205, 4544, -4102, 3012, 2790, 2413, -1085, -341, -2565, 730, -4379, -5063, -1284,
    1018, 1284, 5063, 4379, -730, 2565, 341, 1085, -2413, -2790, -3012, 4102, -4544, 205, -5213, 1009,
    4188, 3550, 1520, -2984, 2236, -4616, 1931, 4189, -357, -3091, 918, 4876, 3784, 1287, 4095, 1299,
    223, -268, 4035, -847, -2695, 2178, -3823, 544, 3686, -2935, 4347, -4742, -425, 4513, 2629, -2388,
    -3688, -4, 4875, -3062, -4855, 193, -1341, 2576, 376, 4129, -2503, 4744, 3364, -2982, 5175, -3085,
    1018, 5116, 3085, -3615, -5175, 400, 2982, 3198, -3364, 2234, -4744, -4828, 2503, 326, -4129, -512,
    -376, 1068, -2576, -4580, 1341, 3169, -193, -2998, 4855, -635, 3062, -4808, -4875, -2740, 4, 675,
    3688, -1324, 2388, 5114, -2629, 5294, -4513, -794, 425, -864, 4742, -886, -4347, 336, 2935, -2045,
    -3686, -3715, -544, 4977, 3823, -2737, -2178, 3441, 2695, 467, 847, 454, -4035, -779, 268, 2213,
    1018, 1615, 1284, 2206, 5063, 5064, 4379, 472, -730, -5341, 2565, -4286, 341, 2981, 1085, -1268,
    -2413, -3057, -2790, -2884, -3012, -1356, 4102, -3337, -4544, 5023, 205, -636, -5213, 909, 1009, -2973,
    4188, 2271, 3550, -1572, 1520, 1841, -2984, 970, 2236, -4734, -4616, 578, 1931, -116, 4189, 1586,
    -357, -2774, -3091, -1006, 918, -5156, 4876, 4123, 3784, -567, 1287, 151, 4095, 1458, 1299, 2684,
    1018, -3260, 5116, -1722, 3085, 5120, -3615, 3760, -5175, 73, 400, 4254, 2982, 2788, 3198, -2657,
    -3364, 569, 2234, 1930, -4744, -2279, -4828, 5215, 2503, -4403, 326, 1639, -4129, 5068, -512, -5015,
    -376, -4859, 1068, -40, -2576, 4003, -4580, -4621, 1341, 2487, 3169, -2374, -193, 2625, -2998, 4784,
    4855, 825, -635, 2118, 3062, -2813, -4808, -4250, -4875, -2113, -2740, -4408, 4, -1893, 675, 458,
    1018, 5120, 400, -2657, -4744, -4403, -512, -40, 1341, 2625, -635, -4250, 4, -3360, 5114, -5313,
    425, -2151, 336, -2662, -544, 5334, 3441, 2117, -4035, 2205, -2684, -3570, -1287, -4973, 5156, 2419,
    357, 1204, -578, 1635, 2984, -1111, -2271, 4359, 5213, -2449, 3337, 3453, 2790, 554, -2981, -1409,
    730, -279, -2206, 3524, -3085, -73, -3198, -1930, -2503, -5068, -1068, 4621, 193, -825, 4808, 4408,
    1018, 4428, 5064, -4000, 2565, 573, -1268, 3125, -3012, -4144, 5023, 1927, 1009, -2139, -1572, 3535,
    2236, 663, -116, 4967, -3091, -854, 4123, 1160, 4095, -1349, -2213, 1782, -847, 2062, 2737, 624,
    3686, -2283, 886, 4889, 4513, -4601, 1324, 1893, 4875, -2118, 2998, -2487, 2576, 5015, -326, 2279,
    3364, -4254, 3615, 3260, -1284, -1381, -472, -3891, -341, 2087, 3057, 4720, -4102, 3410, 636, 1689,
    1018, -3524, 1615, 5268, 1284, 4428, 2206, -834, 5063, 1381, 5064, 279, 4379, 2439, 472, -4000,
    -730, -2015, -5341, 3891, 2565, 1409, -4286, 2605, 341, 573, 2981, 5356, 1085, -2087, -1268, -554,
    -2413, 3135, -3057, 3125, -2790, -778, -2884, -4720, -3012, -3453, -1356, -355, 4102, -4144, -3337, -152,
    -4544, -3410, 5023, 2449, 205, -97, -636, 1927, -5213, 2624, 909, -1689, 1009, -4359, -2973, -3419,
    10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753, 10753,
    -6, -6, -6, -6, -408, -408, -408, -408, -6, -6, -6, -6, -408, -408, -408, -408,
    -27359, -27359, -27359, -27359, 1956, 1956, 1956, 1956, -27359, -27359, -27359, -27359, 1956, 1956, 1956, 1956,
    -6, -6, -6, -6, -1956, -1956, -1956, -1956, -6, -6, -6, -6, -1956, -1956, -1956, -1956,
    27359, 27359, 27359, 27359, 408, 408, 408, 408, 27359, 27359, 27359, 27359, 408, 408, 408, 408,
    -6, -6, -6, -6, -20856, -20856, -20856, -20856, -6, -6, -6, -6, -20856, -20856, -20856, -20856,
    -408, -408, -408, -408, -21094, -21094, -21094, -21094, -408, -408, -408, -408, -21094, -21094, -21094, -21094,
    -6, -6, -6, -6, -10093, -10093, -10093, -10093, -6, -6, -6, -6, -10093, -10093, -10093, -10093,
    -1956, -1956, -1956, -1956, -28517, -28517, -28517, -28517, -1956, -1956, -1956, -1956, -28517, -28517, -28517, -28517,
    -6, -9508, -20856, -29449, -408, 18345, -21094, -7033, -6, -9508, -20856, -29449, -408, 18345, -21094, -7033,
    -27359, -16072, 28517, -12476, 1956, -28224, 10093, 16090, -27359, -16072, 28517, -12476, 1956, -28224, 10093, 16090,
    -6, -16090, -10093, 28224, -1956, 12476, -28517, 16072, -6, -16090, -10093, 28224, -1956, 12476, -28517, 16072,
    27359, 7033, 21094, -18345, 408, 29449, 20856, 9508, 27359, 7033, 21094, -18345, 408, 29449, 20856, 9508,
    -6, -3639, -9508, 25543, -20856, 829, -29449, -17675, -6, -3639, -9508, 25543, -20856, 829, -29449, -17675,
    -408, 18363, 18345, 7429, -21094, -10001, -7033, -4547, -408, 18363, 18345, 7429, -21094, -10001, -7033, -4547,
    -6, 28103, -16090, 3925, -10093, 7228, 28224, 11683, -6, 28103, -16090, 3925, -10093, 7228, 28224, 11683,
    -1956, -23056, 12476, 14731, -28517, 26518, 16072, 14847, -1956, -23056, 12476, 14731, -28517, 26518, 16072, 14847,
    -6, -5619, -3639, -12378, -9508, 15736, 25543, 23007, -20856, -27152, 829, -22209, -29449, -20490, -17675, 22532,
    -408, 16724, 18363, 22623, 18345, 5766, 7429, -31369, -21094, 15840, -10001, 19326, -7033, 3407, -4547, 2316,
    -27359, 6381, -14847, 8441, -16072, -6924, -26518, -4589, 28517, 12707, -14731, -15864, -12476, 31656, 23056, 24098,
    1956, -31217, -11683, -24269, -28224, -5126, -7228, 20198, 10093, -573, -3925, -14341, 16090, 23781, -28103, -23812,
    -6, 23812, 28103, -23781, -16090, 14341, 3925, 573, -10093, -20198, 7228, 5126, 28224, 24269, 11683, 31217,
    -1956, -24098, -23056, -31656, 12476, 15864, 14731, -12707, -28517, 4589, 26518, 6924, 16072, -8441, 14847, -6381,
    27359, -2316, 4547, -3407, 7033, -19326, 10001, -15840, 21094, 31369, -7429, -5766, -18345, -22623, -18363, -16724,
    408, -22532, 17675, 20490, 29449, 22209, -829, 27152, 20856, -23007, -25543, -15736, 9508, 12378, 3639, 5619,
    -6, -17412, -5619, 2017, -3639, 24976, -12378, 24702, -9508, -31558, 15736, 1316, 25543, -31418, 23007, -512,
    -20856, -13268, -27152, 22044, 829, 8801, -22209, -12214, -29449, 11141, -20490, -17096, -17675, 32076, 22532, 17571,
    -408, 13012, 16724, 4090, 18363, -30546, 22623, 16614, 18345, -17248, 5766, 22666, 7429, -7856, -31369, 31235,
    -21094, 28541, 15840, -30351, -10001, -177, 19326, -31887, -7033, 25555, 3407, -31290, -4547, -13579, 2316, -2395,
    -6, 4175, 23812, 7326, 28103, 17352, -23781, -28200, -16090, 11555, 14341, 6978, 3925, -1627, 573, 780,
    -10093, 32271, -20198, 7356, 7228, 29364, 5126, 27895, 28224, -609, 24269, 21892, 11683, -7795, 31217, -18845,
    -1956, 29407, -24098, -7716, -23056, -719, -31656, -8246, 12476, -26238, 15864, 11842, 14731, 1932, -12707, -11726,
    -28517, 4394, 4589, 2066, 26518, -11300, 6924, -24037, 16072, 969, -8441, 14999, 14847, -11854, -6381, -19844,
    -6, -13500, -17412, 32070, -5619, 5120, 2017, 11952, -3639, 1609, 24976, 9374, -12378, -23836, 24702, -8289,
    -9508, -22471, -31558, 25482, 15736, -8935, 1316, 32351, 25543, 19661, -31418, 8295, 23007, -25652, -512, -19863,
    -20856, 6917, -13268, -28712, -27152, 20899, 22044, 4083, 829, 951, 8801, 29370, -22209, 24641, -12214, 12976,
    -29449, -22215, 11141, -29626, -20490, 30467, -17096, 13158, -17675, -24129, 32076, 7880, 22532, -30053, 17571, -8758,
    -6, 5120, 24976, -8289, 15736, 19661, -512, -28712, 829, 24641, 11141, 13158, 22532, 13024, 4090, -27329,
    18345, -8807, -7856, -20070, 15840, -1834, -31887, -18875, -4547, 18077, 19844, -23026, 8441, -12653, 11300, 11123,
    28517, 31924, -11842, -14237, 31656, 16809, -29407, -5369, -11683, -16273, -27895, -29827, 20198, 7722, 1627, 9343,
    16090, -15127, -7326, -6716, 5619, -1609, -24702, -25482, -25543, 25652, 13268, -4083, 22209, 22215, 17096, -7880,
    -6, -26292, 17352, 12384, 14341, 61, 780, 23093, 7228, -12336, -609, -7801, 31217, -6747, -7716, 6095,
    12476, 15511, 1932, 11623, 4589, 6314, -24037, -19320, 14847, 19643, 2395, -21770, -3407, -17394, 177, -23952,
    21094, -31467, -22666, -1767, -22623, -14329, -13012, 30053, 17675, 29626, 12214, -951, 27152, 19863, 31418, 8935,
    9508, -9374, -2017, 13500, -23812, -29541, 28200, 20173, -3925, -24025, -32271, -19856, -5126, -26286, -21892, -4967,
    -6, 6716, 4175, -13164, 23812, -26292, 7326, -12098, 28103, 29541, 17352, 15127, -23781, -7289, -28200, 12384,
    -16090, -29151, 11555, -20173, 14341, -9343, 6978, -22483, 3925, 61, -1627, 23788, 573, 24025, 780, -7722,
    -10093, -18881, 32271, 23093, -20198, -24330, 7356, 19856, 7228, 29827, 29364, 15517, 5126, -12336, 27895, -4248,
    28224, 26286, -609, 16273, 24269, -5729, 21892, -7801, 11683, -30144, -7795, 4967, 31217, 5369, -18845, -8027,
    -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359, -27359,
    27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359, 27359,
    -408, -408, -408, -408, -408, -408, -408, -408, -408, -408, -408, -408, -408, -408, -408, -408,
    -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956, -1956,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    -223, -223, -223, -223, -223, -223, -223, -223, -223, -223, -223, -223, -223, -223, -223, -223,
    223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223, 223,
    3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688, 3688,
    4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188, 4188,
];
