//! Generated variable-radix codecs for p = 761, ported from the reference's
//! auto-generated `crypto_decode_761x1531` and friends.
//!
//! Profiling liboqs directly (2026-08-05) showed its codecs run 9-16x faster
//! than our generic implementation — `crypto_decode_761x1531` in 0.13 us
//! against our 2.14 us — because they are vectorized at *every* radix level,
//! while ours only vectorizes levels whose moduli happen to be uniform.
//!
//! These are mechanical translations of generated C. Like `rq::ntt`, they are
//! p = 761 specific (the radix chain depends on p and q); the generic codec in
//! the parent module remains the path for every other parameter set, and is the
//! differential oracle in tests.
// Machine-translated from generated C: the upstream naming (R0, A0, S1) and
// parenthesisation are preserved deliberately so the port can be diffed against
// its source. Regenerate rather than hand-edit.
// The sign-losing and truncating casts below are not accidents: they reproduce
// C's `int16`/`uint16` wrapping semantics, which the radix decomposition relies
// on. Silencing them module-wide is deliberate for this generated translation
// and must not be copied into hand-written code.
#![allow(
    unsafe_code,
    unused_parens,
    unused_assignments,
    non_snake_case,
    clippy::all,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]

use core::arch::x86_64::*;

/// C `int16` truncation: assignments to an `int16` wrap.
#[inline(always)]
fn trunc(x: i32) -> i32 {
    x as i16 as i32
}

#[inline(always)]
fn mullo(x: i32, y: i32) -> i32 {
    (x as i16).wrapping_mul(y as i16) as i32
}

#[inline(always)]
fn mulhi(x: i32, y: i32) -> i32 {
    (((x as i16 as i32) * (y as i16 as i32)) >> 16) as i16 as i32
}

#[inline]
#[target_feature(enable = "avx2")]
fn add(x: __m256i, y: __m256i) -> __m256i {
    _mm256_add_epi16(x, y)
}

#[inline]
#[target_feature(enable = "avx2")]
fn sub(x: __m256i, y: __m256i) -> __m256i {
    _mm256_sub_epi16(x, y)
}

#[inline]
#[target_feature(enable = "avx2")]
fn mulloconst(x: __m256i, y: i16) -> __m256i {
    _mm256_mullo_epi16(x, _mm256_set1_epi16(y))
}

#[inline]
#[target_feature(enable = "avx2")]
fn mulhiconst(x: __m256i, y: i16) -> __m256i {
    _mm256_mulhi_epi16(x, _mm256_set1_epi16(y))
}

#[inline]
#[target_feature(enable = "avx2")]
fn shiftleftconst<const N: i32>(x: __m256i) -> __m256i {
    _mm256_slli_epi16::<N>(x)
}

#[inline]
#[target_feature(enable = "avx2")]
fn subconst(x: __m256i, y: i16) -> __m256i {
    sub(x, _mm256_set1_epi16(y))
}

#[inline]
#[target_feature(enable = "avx2")]
fn ifgesubconst(x: __m256i, y: i16) -> __m256i {
    let y16 = _mm256_set1_epi16(y);
    let top16 = _mm256_set1_epi16(y.wrapping_sub(1));
    sub(x, _mm256_and_si256(_mm256_cmpgt_epi16(x, top16), y16))
}

#[inline]
#[target_feature(enable = "avx2")]
fn ifnegaddconst(x: __m256i, y: i16) -> __m256i {
    add(
        x,
        _mm256_and_si256(_mm256_srai_epi16::<15>(x), _mm256_set1_epi16(y)),
    )
}

#[inline]
#[target_feature(enable = "avx2")]
fn ldu(s: &[u8], at: isize) -> __m256i {
    unsafe { _mm256_loadu_si256(s.as_ptr().offset(at) as *const __m256i) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn ldu8(s: &[u8], at: isize) -> __m256i {
    unsafe { _mm256_cvtepu8_epi16(_mm_loadu_si128(s.as_ptr().offset(at) as *const __m128i)) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn ldr(r: &[i16], at: isize) -> __m256i {
    unsafe { _mm256_loadu_si256(r.as_ptr().offset(at) as *const __m256i) }
}

#[inline]
#[target_feature(enable = "avx2")]
fn str_(r: &mut [i16], at: isize, v: __m256i) {
    unsafe { _mm256_storeu_si256(r.as_mut_ptr().offset(at) as *mut __m256i, v) }
}

/// Decode the rounded (761 x 1531) ciphertext representation into `R0[..761]`.
#[target_feature(enable = "avx2")]
pub fn decode_761x1531(r0: &mut [i16], s: &[u8]) {
    let mut R0 = &mut *r0;
    let mut R1 = [0i16; 381];
    let mut R2 = [0i16; 191];
    let mut R3 = [0i16; 96];
    let mut R4 = [0i16; 48];
    let mut R5 = [0i16; 24];
    let mut R6 = [0i16; 12];
    let mut R7 = [0i16; 6];
    let mut R8 = [0i16; 3];
    let mut R9 = [0i16; 2];
    let mut R10 = [0i16; 1];
    let (mut A0, mut A1, mut A2): (__m256i, __m256i, __m256i);
    let (mut S0, mut S1): (__m256i, __m256i);
    let (mut B0, mut B1, mut C0, mut C1): (__m256i, __m256i, __m256i, __m256i);
    let mut i: isize;
    let (mut a0, mut a1, mut a2): (i32, i32, i32) = (0, 0, 0);

    let mut si: isize = 1007;
    a1 = 0;
    a1 += {
        si -= 1;
        s[si as usize] as i32
    };
    a1 = mulhi(a1, -84) - mulhi(mullo(a1, -4828), 3475);
    a1 += {
        si -= 1;
        s[si as usize] as i32
    };
    a1 += (a1 >> 15) & 3475;
    R10[0] = a1 as i16;

    // R10 ------> R9: reconstruct mod 1*[593]+[1500]

    i = 0;
    si -= 1;
    a0 = R10[0] as i32;
    a2 = a0;
    a0 = mulhi(a0, 60) - mulhi(mullo(a0, -28292), 593);
    a0 += (s[(si + (1 * i + 0)) as usize] as i32);
    a0 += (a0 >> 15) & 593;
    a1 = trunc((a2 << 8) + (s[(si + (i)) as usize] as i32) - a0);
    a1 = mullo(a1, -31055);

    // invalid inputs might need reduction mod 1500
    a1 -= 1500;
    a1 += (a1 >> 15) & 1500;

    R9[0] = a0 as i16;
    R9[1] = a1 as i16;
    si -= 0;

    // R9 ------> R8: reconstruct mod 2*[6232]+[1500]

    R8[2] = R9[1];
    si -= 2;
    i = 0;
    while i >= 0 {
        a0 = R9[(i) as usize] as i32;
        a2 = a0;
        a0 = mulhi(a0, 672) - mulhi(mullo(a0, -2692), 6232);
        a0 += (s[(si + (2 * i + 1)) as usize] as i32);
        a0 = mulhi(a0, 672) - mulhi(mullo(a0, -2692), 6232);
        a0 += (s[(si + (2 * i + 0)) as usize] as i32);
        a0 += (a0 >> 15) & 6232;
        a1 = trunc(
            (a2 << 13)
                + ((s[(si + (2 * i + 1)) as usize] as i32) << 5)
                + (((s[(si + (2 * i)) as usize] as i32) - a0) >> 3),
        );
        a1 = mullo(a1, 12451);

        // invalid inputs might need reduction mod 6232
        a1 -= 6232;
        a1 += (a1 >> 15) & 6232;

        R8[(2 * i) as usize] = a0 as i16;
        R8[(2 * i + 1) as usize] = a1 as i16;
        i -= 1;
    }

    // R8 ------> R7: reconstruct mod 5*[1263]+[304]

    i = 0;
    si -= 1;
    a0 = R8[2] as i32;
    a2 = a0;
    a0 = mulhi(a0, -476) - mulhi(mullo(a0, -13284), 1263);
    a0 += (s[(si + (1 * i + 0)) as usize] as i32);
    a0 += (a0 >> 15) & 1263;
    a1 = trunc((a2 << 8) + (s[(si + (i)) as usize] as i32) - a0);
    a1 = mullo(a1, -22001);

    // invalid inputs might need reduction mod 304
    a1 -= 304;
    a1 += (a1 >> 15) & 304;

    R7[4] = a0 as i16;
    R7[5] = a1 as i16;
    si -= 2;
    i = 1;
    while i >= 0 {
        a0 = R8[(i) as usize] as i32;
        a2 = a0;
        a0 = mulhi(a0, -476) - mulhi(mullo(a0, -13284), 1263);
        a0 += (s[(si + (1 * i + 0)) as usize] as i32);
        a0 += (a0 >> 15) & 1263;
        a1 = trunc((a2 << 8) + (s[(si + (i)) as usize] as i32) - a0);
        a1 = mullo(a1, -22001);

        // invalid inputs might need reduction mod 1263
        a1 -= 1263;
        a1 += (a1 >> 15) & 1263;

        R7[(2 * i) as usize] = a0 as i16;
        R7[(2 * i + 1) as usize] = a1 as i16;
        i -= 1;
    }

    // R7 ------> R6: reconstruct mod 11*[9097]+[2188]

    i = 0;
    si -= 2;
    a0 = R7[5] as i32;
    a0 = mulhi(a0, 2348) - mulhi(mullo(a0, -1844), 9097);
    a0 += (s[(si + (2 * i + 1)) as usize] as i32);
    a0 = mulhi(a0, 2348) - mulhi(mullo(a0, -1844), 9097);
    a0 += (s[(si + (2 * i + 0)) as usize] as i32);
    a0 += (a0 >> 15) & 9097;
    a1 = trunc(
        ((s[(si + (2 * i + 1)) as usize] as i32) << 8) + (s[(si + (2 * i)) as usize] as i32) - a0,
    );
    a1 = mullo(a1, 17081);

    // invalid inputs might need reduction mod 2188
    a1 -= 2188;
    a1 += (a1 >> 15) & 2188;

    R6[10] = a0 as i16;
    R6[11] = a1 as i16;
    si -= 10;
    i = 4;
    while i >= 0 {
        a0 = R7[(i) as usize] as i32;
        a0 = mulhi(a0, 2348) - mulhi(mullo(a0, -1844), 9097);
        a0 += (s[(si + (2 * i + 1)) as usize] as i32);
        a0 = mulhi(a0, 2348) - mulhi(mullo(a0, -1844), 9097);
        a0 += (s[(si + (2 * i + 0)) as usize] as i32);
        a0 += (a0 >> 15) & 9097;
        a1 = trunc(
            ((s[(si + (2 * i + 1)) as usize] as i32) << 8) + (s[(si + (2 * i)) as usize] as i32)
                - a0,
        );
        a1 = mullo(a1, 17081);

        // invalid inputs might need reduction mod 9097
        a1 -= 9097;
        a1 += (a1 >> 15) & 9097;

        R6[(2 * i) as usize] = a0 as i16;
        R6[(2 * i + 1) as usize] = a1 as i16;
        i -= 1;
    }

    // R6 ------> R5: reconstruct mod 23*[1526]+[367]

    i = 0;
    si -= 1;
    a0 = R6[11] as i32;
    a2 = a0;
    a0 = mulhi(a0, 372) - mulhi(mullo(a0, -10994), 1526);
    a0 += (s[(si + (1 * i + 0)) as usize] as i32);
    a0 += (a0 >> 15) & 1526;
    a1 = trunc((a2 << 7) + (((s[(si + (i)) as usize] as i32) - a0) >> 1));
    a1 = mullo(a1, -18381);

    // invalid inputs might need reduction mod 367
    a1 -= 367;
    a1 += (a1 >> 15) & 367;

    R5[22] = a0 as i16;
    R5[23] = a1 as i16;
    si -= 11;
    i = 10;
    while i >= 0 {
        a0 = R6[(i) as usize] as i32;
        a2 = a0;
        a0 = mulhi(a0, 372) - mulhi(mullo(a0, -10994), 1526);
        a0 += (s[(si + (1 * i + 0)) as usize] as i32);
        a0 += (a0 >> 15) & 1526;
        a1 = trunc((a2 << 7) + (((s[(si + (i)) as usize] as i32) - a0) >> 1));
        a1 = mullo(a1, -18381);

        // invalid inputs might need reduction mod 1526
        a1 -= 1526;
        a1 += (a1 >> 15) & 1526;

        R5[(2 * i) as usize] = a0 as i16;
        R5[(2 * i + 1) as usize] = a1 as i16;
        i -= 1;
    }

    // R5 ------> R4: reconstruct mod 47*[625]+[150]

    i = 0;
    si -= 1;
    a0 = R5[23] as i32;
    a2 = a0;
    a0 = mulhi(a0, -284) - mulhi(mullo(a0, -26844), 625);
    a0 += (s[(si + (1 * i + 0)) as usize] as i32);
    a0 += (a0 >> 15) & 625;
    a1 = trunc((a2 << 8) + (s[(si + (i)) as usize] as i32) - a0);
    a1 = mullo(a1, 32401);

    // invalid inputs might need reduction mod 150
    a1 -= 150;
    a1 += (a1 >> 15) & 150;

    R4[46] = a0 as i16;
    R4[47] = a1 as i16;
    si -= 23;
    i = 7;
    loop {
        A0 = ldr(&R5, (i));
        A2 = A0;
        S0 = ldu8(s, si + (i));
        A0 = sub(
            mulhiconst(A0, -284),
            mulhiconst(mulloconst(A0, -26844), 625),
        );
        A0 = add(A0, S0);
        A0 = ifnegaddconst(A0, 625);
        A1 = add(shiftleftconst::<8>(A2), sub(S0, A0));
        A1 = mulloconst(A1, 32401);

        // invalid inputs might need reduction mod 625
        A1 = ifgesubconst(A1, 625);

        // A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30
        // A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31
        B0 = _mm256_unpacklo_epi16(A0, A1);
        B1 = _mm256_unpackhi_epi16(A0, A1);
        // B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23
        // B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31
        C0 = _mm256_permute2x128_si256(B0, B1, 0x20);
        C1 = _mm256_permute2x128_si256(B0, B1, 0x31);
        // C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15
        // C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31
        str_(&mut R4, (2 * i), C0);
        str_(&mut R4, (2 * i) + 16, C1);
        if i == 0 {
            break;
        }
        i = -16 - ((!15) & -i);
    }

    // R4 ------> R3: reconstruct mod 95*[6400]+[1531]

    i = 0;
    si -= 2;
    a0 = R4[47] as i32;
    a2 = a0;
    a0 = mulhi(a0, 2816) - mulhi(mullo(a0, -2621), 6400);
    a0 += (s[(si + (2 * i + 1)) as usize] as i32);
    a0 = mulhi(a0, 2816) - mulhi(mullo(a0, -2621), 6400);
    a0 += (s[(si + (2 * i + 0)) as usize] as i32);
    a0 += (a0 >> 15) & 6400;
    a1 = trunc(
        (a2 << 8)
            + (s[(si + (2 * i + 1)) as usize] as i32)
            + (((s[(si + (2 * i)) as usize] as i32) - a0) >> 8),
    );
    a1 = mullo(a1, 23593);

    // invalid inputs might need reduction mod 1531
    a1 -= 1531;
    a1 += (a1 >> 15) & 1531;

    R3[94] = a0 as i16;
    R3[95] = a1 as i16;
    si -= 94;
    i = 31;
    loop {
        A0 = ldr(&R4, (i));
        A2 = A0;
        S0 = ldu(s, si + (2 * i));
        S1 = _mm256_srli_epi16::<8>(S0);
        S0 = _mm256_and_si256(S0, _mm256_set1_epi16(255));
        A0 = sub(
            mulhiconst(A0, 2816),
            mulhiconst(mulloconst(A0, -2621), 6400),
        );
        A0 = add(A0, S1);
        A0 = sub(
            mulhiconst(A0, 2816),
            mulhiconst(mulloconst(A0, -2621), 6400),
        );
        A0 = add(A0, S0);
        A0 = ifnegaddconst(A0, 6400);
        A1 = add(
            add(shiftleftconst::<8>(A2), S1),
            _mm256_srai_epi16::<8>(sub(S0, A0)),
        );
        A1 = mulloconst(A1, 23593);

        // invalid inputs might need reduction mod 6400
        A1 = ifgesubconst(A1, 6400);

        // A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30
        // A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31
        B0 = _mm256_unpacklo_epi16(A0, A1);
        B1 = _mm256_unpackhi_epi16(A0, A1);
        // B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23
        // B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31
        C0 = _mm256_permute2x128_si256(B0, B1, 0x20);
        C1 = _mm256_permute2x128_si256(B0, B1, 0x31);
        // C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15
        // C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31
        str_(&mut R3, (2 * i), C0);
        str_(&mut R3, (2 * i) + 16, C1);
        if i == 0 {
            break;
        }
        i = -16 - ((!15) & -i);
    }

    // R3 ------> R2: reconstruct mod 190*[1280]+[1531]

    R2[190] = R3[95];
    si -= 95;
    i = 79;
    loop {
        A0 = ldr(&R3, (i));
        A2 = A0;
        S0 = ldu8(s, si + (i));
        A0 = sub(
            mulhiconst(A0, 256),
            mulhiconst(mulloconst(A0, -13107), 1280),
        );
        A0 = add(A0, S0);
        A0 = ifnegaddconst(A0, 1280);
        A1 = add(A2, _mm256_srai_epi16::<8>(sub(S0, A0)));
        A1 = mulloconst(A1, -13107);

        // invalid inputs might need reduction mod 1280
        A1 = ifgesubconst(A1, 1280);

        // A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30
        // A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31
        B0 = _mm256_unpacklo_epi16(A0, A1);
        B1 = _mm256_unpackhi_epi16(A0, A1);
        // B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23
        // B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31
        C0 = _mm256_permute2x128_si256(B0, B1, 0x20);
        C1 = _mm256_permute2x128_si256(B0, B1, 0x31);
        // C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15
        // C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31
        str_(&mut R2, (2 * i), C0);
        str_(&mut R2, (2 * i) + 16, C1);
        if i == 0 {
            break;
        }
        i = -16 - ((!15) & -i);
    }

    // R2 ------> R1: reconstruct mod 380*[9157]+[1531]

    R1[380] = R2[190];
    si -= 380;
    i = 174;
    loop {
        A0 = ldr(&R2, (i));
        S0 = ldu(s, si + (2 * i));
        S1 = _mm256_srli_epi16::<8>(S0);
        S0 = _mm256_and_si256(S0, _mm256_set1_epi16(255));
        A0 = sub(
            mulhiconst(A0, 1592),
            mulhiconst(mulloconst(A0, -1832), 9157),
        );
        A0 = add(A0, S1);
        A0 = sub(
            mulhiconst(A0, 1592),
            mulhiconst(mulloconst(A0, -1832), 9157),
        );
        A0 = add(A0, S0);
        A0 = ifnegaddconst(A0, 9157);
        A1 = add(shiftleftconst::<8>(S1), sub(S0, A0));
        A1 = mulloconst(A1, 25357);

        // invalid inputs might need reduction mod 9157
        A1 = ifgesubconst(A1, 9157);

        // A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30
        // A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31
        B0 = _mm256_unpacklo_epi16(A0, A1);
        B1 = _mm256_unpackhi_epi16(A0, A1);
        // B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23
        // B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31
        C0 = _mm256_permute2x128_si256(B0, B1, 0x20);
        C1 = _mm256_permute2x128_si256(B0, B1, 0x31);
        // C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15
        // C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31
        str_(&mut R1, (2 * i), C0);
        str_(&mut R1, (2 * i) + 16, C1);
        if i == 0 {
            break;
        }
        i = -16 - ((!15) & -i);
    }

    // R1 ------> R0: reconstruct mod 761*[1531]

    R0[760] = trunc(3 * R1[380] as i32 - 2295) as i16;
    si -= 380;
    i = 364;
    loop {
        A0 = ldr(&R1, (i));
        A2 = A0;
        S0 = ldu8(s, si + (i));
        A0 = sub(
            mulhiconst(A0, 518),
            mulhiconst(mulloconst(A0, -10958), 1531),
        );
        A0 = add(A0, S0);
        A0 = ifnegaddconst(A0, 1531);
        A1 = add(shiftleftconst::<8>(A2), sub(S0, A0));
        A1 = mulloconst(A1, 15667);

        // invalid inputs might need reduction mod 1531
        A1 = ifgesubconst(A1, 1531);

        A0 = mulloconst(A0, 3);
        A1 = mulloconst(A1, 3);
        A0 = subconst(A0, 2295);
        A1 = subconst(A1, 2295);
        // A0: r0r2r4r6r8r10r12r14 r16r18r20r22r24r26r28r30
        // A1: r1r3r5r7r9r11r13r15 r17r19r21r23r25r27r29r31
        B0 = _mm256_unpacklo_epi16(A0, A1);
        B1 = _mm256_unpackhi_epi16(A0, A1);
        // B0: r0r1r2r3r4r5r6r7 r16r17r18r19r20r21r22r23
        // B1: r8r9r10r11r12r13r14r15 r24r25r26r27r28r29r30r31
        C0 = _mm256_permute2x128_si256(B0, B1, 0x20);
        C1 = _mm256_permute2x128_si256(B0, B1, 0x31);
        // C0: r0r1r2r3r4r5r6r7 r8r9r10r11r12r13r14r15
        // C1: r16r17r18r19r20r21r22r23 r24r25r26r27r28r29r30r31
        str_(&mut R0, (2 * i), C0);
        str_(&mut R0, (2 * i) + 16, C1);
        if i == 0 {
            break;
        }
        i = -16 - ((!15) & -i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SNTRUP761;

    /// The ported generated decoder must agree exactly with the generic
    /// variable-radix implementation on every input, including the ciphertexts
    /// the KEM actually produces and adversarial random byte strings.
    #[test]
    fn decode_761x1531_matches_generic() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let params = &SNTRUP761;
        let len = params.rounded_encode_size;
        let mut state = 0x2468_ace0_1357_9bdfu64 | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for trial in 0..64 {
            let s: Vec<u8> = (0..len)
                .map(|_| match trial % 4 {
                    0 => (next() & 0xff) as u8,
                    1 => 0,
                    2 => 0xff,
                    _ => (next() % 3) as u8,
                })
                .collect();
            let mut want = vec![0i16; params.p];
            crate::rq::encoding::rounded_decode_into(&s, &mut want, params);
            let mut got = vec![0i16; params.p];
            // SAFETY: AVX2 confirmed above.
            unsafe { decode_761x1531(&mut got, &s) };
            assert_eq!(got, want, "decode_761x1531 mismatch, trial {trial}");
        }
    }
}

// ---------------------------------------------------------------------------
// crypto_encode_761x1531round
// ---------------------------------------------------------------------------
//
// The reference emits this as six near-identical loops over two shapes, walking
// `reading`/`writing`/`out` pointers with a mid-loop back-off on the final
// iteration (the same overlapping-tail trick the decoder uses). Both shapes are
// factored into helpers here and instantiated per radix level; the back-off is
// passed in rather than duplicated.

/// Shuffle that splits each 32-bit lane into "two bytes out, two bytes carried".
#[inline]
#[target_feature(enable = "avx2")]
fn shuf_carry2() -> __m256i {
    _mm256_set_epi8(
        15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0, 15, 14, 11, 10, 7, 6, 3, 2, 13, 12,
        9, 8, 5, 4, 1, 0,
    )
}

/// Shuffle that splits each 32-bit lane into "one byte out, two bytes carried".
#[inline]
#[target_feature(enable = "avx2")]
fn shuf_carry1() -> __m256i {
    _mm256_set_epi8(
        12, 8, 4, 0, 12, 8, 4, 0, 14, 13, 10, 9, 6, 5, 2, 1, 12, 8, 4, 0, 12, 8, 4, 0, 14, 13, 10,
        9, 6, 5, 2, 1,
    )
}

/// Shape A: 16 u16 in -> 8 u16 carried + 8 bytes emitted, per iteration.
#[target_feature(enable = "avx2")]
unsafe fn enc_pass_a(
    rd_base: *const u16,
    wr_base: *mut u16,
    out: *mut u8,
    iters: usize,
    m: i32,
    back: (usize, usize, usize),
    round: bool,
) -> usize {
    unsafe {
        let (mut rd, mut wr, mut o) = (0isize, 0isize, 0isize);
        let mut i = iters;
        while i > 0 {
            i -= 1;
            if i == 0 {
                rd -= back.0 as isize;
                wr -= back.1 as isize;
                o -= back.2 as isize;
            }
            let mut x = _mm256_loadu_si256(rd_base.offset(rd) as *const __m256i);
            if round {
                // round-to-nearest-multiple-of-3, recentre, then divide by 3
                x = _mm256_mulhrs_epi16(x, _mm256_set1_epi16(10923));
                x = _mm256_add_epi16(x, _mm256_add_epi16(x, x));
                x = _mm256_add_epi16(x, _mm256_set1_epi16(2295));
                x = _mm256_and_si256(x, _mm256_set1_epi16(16383));
                x = _mm256_mulhi_epi16(x, _mm256_set1_epi16(21846));
            }
            let y = _mm256_and_si256(x, _mm256_set1_epi32(65535));
            let hi = _mm256_mullo_epi32(_mm256_srli_epi32::<16>(x), _mm256_set1_epi32(m));
            let x = _mm256_permute4x64_epi64::<0xd8>(_mm256_shuffle_epi8(
                _mm256_add_epi32(y, hi),
                shuf_carry1(),
            ));
            _mm_storeu_si128(
                wr_base.offset(wr) as *mut __m128i,
                _mm256_castsi256_si128(x),
            );
            let mut s0 = _mm256_extract_epi32::<4>(x) as u32;
            for k in 0..4 {
                *out.offset(o + k) = s0 as u8;
                s0 >>= 8;
            }
            let mut s0 = _mm256_extract_epi32::<6>(x) as u32;
            for k in 0..4 {
                *out.offset(o + 4 + k) = s0 as u8;
                s0 >>= 8;
            }
            rd += 16;
            wr += 8;
            o += 8;
        }
        o as usize
    }
}

/// Shape B: 32 u16 in -> 16 u16 carried + 32 bytes emitted, per iteration.
#[target_feature(enable = "avx2")]
unsafe fn enc_pass_b(
    rd_base: *const u16,
    wr_base: *mut u16,
    out: *mut u8,
    iters: usize,
    m: i32,
    back: (usize, usize, usize),
) -> usize {
    unsafe {
        let (mut rd, mut wr, mut o) = (0isize, 0isize, 0isize);
        let mut i = iters;
        while i > 0 {
            i -= 1;
            if i == 0 {
                rd -= back.0 as isize;
                wr -= back.1 as isize;
                o -= back.2 as isize;
            }
            let comb = |v: __m256i| -> __m256i {
                let y = _mm256_and_si256(v, _mm256_set1_epi32(65535));
                let hi = _mm256_mullo_epi32(_mm256_srli_epi32::<16>(v), _mm256_set1_epi32(m));
                _mm256_permute4x64_epi64::<0xd8>(_mm256_shuffle_epi8(
                    _mm256_add_epi32(y, hi),
                    shuf_carry2(),
                ))
            };
            let x = comb(_mm256_loadu_si256(rd_base.offset(rd) as *const __m256i));
            let x2 = comb(_mm256_loadu_si256(rd_base.offset(rd + 16) as *const __m256i));
            _mm256_storeu_si256(
                wr_base.offset(wr) as *mut __m256i,
                _mm256_permute2f128_si256::<0x31>(x, x2),
            );
            _mm256_storeu_si256(
                out.offset(o) as *mut __m256i,
                _mm256_permute2f128_si256::<0x20>(x, x2),
            );
            rd += 32;
            wr += 16;
            o += 32;
        }
        o as usize
    }
}

/// Round each coefficient to a multiple of 3 and encode the 761 x 1531
/// representation into `out[..1007]`.
#[target_feature(enable = "avx2")]
pub fn encode_761x1531round(out: &mut [u8], r0: &[i16]) {
    unsafe {
        let mut r = [0u16; 381];
        // Level 0 reads the caller's coefficients and writes carries into `r`;
        // every later level reads and writes `r` in place.
        let rp = r.as_mut_ptr();
        let op = out.as_mut_ptr();

        // Level 0 reads the caller's coefficients; every later level reads and
        // writes `r` in place, exactly as the reference aliases its buffers.
        let mut o = enc_pass_a(r0.as_ptr().cast::<u16>(), rp, op, 48, 1531, (8, 4, 4), true);
        r[380] = ((((3 * ((10923 * i32::from(r0[760]) + 16384) >> 15) + 2295) & 16383) * 10923)
            >> 15) as u16;

        o += enc_pass_b(rp, rp, op.add(o), 12, 9157, (4, 2, 4));
        r[190] = r[380];
        o += enc_pass_a(rp, rp, op.add(o), 12, 1280, (2, 1, 1), false);
        r[95] = r[190];
        o += enc_pass_b(rp, rp, op.add(o), 3, 6400, (0, 0, 0));
        o += enc_pass_a(rp, rp, op.add(o), 3, 625, (0, 0, 0), false);
        o += enc_pass_a(rp, rp, op.add(o), 2, 1526, (8, 4, 4), false);

        // Scalar tail: the last four radix levels are too small to vectorize.
        for i in 0..6 {
            let r2 = u32::from(r[2 * i]) + u32::from(r[2 * i + 1]) * 9097;
            *op.add(o) = r2 as u8;
            *op.add(o + 1) = (r2 >> 8) as u8;
            o += 2;
            r[i] = (r2 >> 16) as u16;
        }
        for i in 0..3 {
            let r2 = u32::from(r[2 * i]) + u32::from(r[2 * i + 1]) * 1263;
            *op.add(o) = r2 as u8;
            o += 1;
            r[i] = (r2 >> 8) as u16;
        }
        let r2 = u32::from(r[0]) + u32::from(r[1]) * 6232;
        *op.add(o) = r2 as u8;
        *op.add(o + 1) = (r2 >> 8) as u8;
        o += 2;
        r[0] = (r2 >> 16) as u16;
        r[1] = r[2];
        let r2 = u32::from(r[0]) + u32::from(r[1]) * 593;
        *op.add(o) = r2 as u8;
        o += 1;
        r[0] = (r2 >> 8) as u16;
        *op.add(o) = r[0] as u8;
        *op.add(o + 1) = (r[0] >> 8) as u8;
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use crate::params::SNTRUP761;

    /// The ported encoder must agree byte-for-byte with the generic
    /// implementation on the coefficient ranges decapsulation actually produces.
    #[test]
    fn encode_761x1531round_matches_generic() {
        if !crate::cpu::has_avx2() {
            return;
        }
        let params = &SNTRUP761;
        let hq = params.q12 as i16;
        let mut state = 0x1357_9bdf_2468_ace0u64 | 1;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for trial in 0..32 {
            let f: Vec<i16> = (0..params.p)
                .map(|_| match trial % 4 {
                    0 => ((next() % (2 * hq as u64 + 1)) as i32 - i32::from(hq)) as i16,
                    1 => hq,
                    2 => -hq,
                    _ => 0,
                })
                .collect();
            // The reference's `..._round` rounds internally; our generic encoder
            // expects input that `round3` has already processed. Compare like
            // for like by rounding only on the generic side.
            let mut rounded = f.clone();
            crate::rq::round3(&mut rounded, params);
            let mut want = vec![0u8; params.rounded_encode_size];
            crate::rq::encoding::rounded_encode_into(&rounded, &mut want, params);
            let mut got = vec![0u8; params.rounded_encode_size];
            // SAFETY: AVX2 confirmed above.
            unsafe { encode_761x1531round(&mut got, &f) };
            assert_eq!(got, want, "encode mismatch, trial {trial}");
        }
    }
}
