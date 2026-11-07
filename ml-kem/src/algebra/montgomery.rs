//! Signed 16-bit Montgomery arithmetic for the NTT and for products in the NTT domain.
//!
//! The generic `Elem` operators fully reduce after every addition, subtraction and
//! multiplication, using a hardened conditional subtraction. The kernels here instead keep
//! coefficients as partially reduced `i16` values and only use Montgomery and Barrett reductions,
//! which are pure arithmetic (multiply, shift, add). There are no selects, and so nothing that
//! depends on secret data for the compiler to turn into a branch. Each kernel converts its result
//! back to the canonical range `[0, q)` exactly once, at the end.
//!
//! Every bound below is stated for the inputs the kernels receive. Tests check the reductions
//! exhaustively over those domains, and debug builds check every addition for overflow.

use super::{Elem, GAMMA, NttPolynomial, NttVector, ZETA_POW_BITREV};
use array::{Array, ArraySize, typenum::U256};

/// The modulus `q`.
pub(super) const Q: i16 = 3329;

/// `q^-1 mod 2^16`, as a signed value.
const QINV: i16 = -3327;

/// The Montgomery radix `R = 2^16`, reduced mod `q`.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const R_MOD_Q: i32 = (1 << 16) % Q as i32;

/// `R^2 mod q`. Montgomery multiplication by this constant maps `x` to `x * R mod q`.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const R2: i16 = centered((R_MOD_Q * R_MOD_Q) % Q as i32);

/// `R / 128 mod q`. Montgomery multiplication by this constant divides by 128, which is the
/// final scaling step of `NTT^-1`.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const INV_NTT_SCALE: i16 = centered((3303 * R_MOD_Q) % Q as i32);

/// Map a value in `[0, q)` to its representative in `[-(q-1)/2, (q-1)/2]`.
#[allow(clippy::cast_possible_truncation, reason = "the value is below q")]
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const fn centered(x: i32) -> i16 {
    if x > (Q as i32 - 1) / 2 {
        (x - Q as i32) as i16
    } else {
        x as i16
    }
}

/// `ZETA_POW_BITREV` in the Montgomery domain: `zeta^BitRev7(i) * R mod q`, centered.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const ZETAS: [i16; 128] = {
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = centered((ZETA_POW_BITREV[i].0 as i32 * R_MOD_Q) % Q as i32);
        i += 1;
    }
    out
};

/// `qinv_multiple` of each of `ZETAS`.
const ZETAS_QINV: [i16; 128] = {
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = qinv_multiple(ZETAS[i]);
        i += 1;
    }
    out
};

/// `GAMMA` scaled by `R^2`: `zeta^(2 BitRev7(i) + 1) * R^2 mod q`, centered. Montgomery
/// multiplication of `x` by `GAMMAS_R2[i]` gives `x * GAMMA[i] * R mod q`.
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const GAMMAS_R2: [i16; 128] = {
    let r2 = (R_MOD_Q * R_MOD_Q) % Q as i32;
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = centered((GAMMA[i].0 as i32 * r2) % Q as i32);
        i += 1;
    }
    out
};

/// `qinv_multiple` of each of `GAMMAS_R2`.
const GAMMAS_R2_QINV: [i16; 128] = {
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = qinv_multiple(GAMMAS_R2[i]);
        i += 1;
    }
    out
};

/// Montgomery reduction: for `|a| < q * 2^15`, returns `r ≡ a * R^-1 (mod q)` with `|r| < q`.
#[inline(always)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "truncation mod 2^16 is intended"
)]
fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV);
    ((a - i32::from(t) * i32::from(Q)) >> 16) as i16
}

/// Montgomery multiplication: for `|a * b| < q * 2^15`, returns `r ≡ a * b * R^-1 (mod q)` with
/// `|r| < q`. Reference for [`fqmul_const`].
#[cfg(test)]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

/// The high 16 bits of the product of `a` and `b`.
#[inline(always)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "the high half of a product of two i16 values fits in i16"
)]
fn mulhi(a: i16, b: i16) -> i16 {
    ((i32::from(a) * i32::from(b)) >> 16) as i16
}

/// `b * q^-1 mod 2^16`, the second constant that [`fqmul_const`] needs for a multiplier `b`.
const fn qinv_multiple(b: i16) -> i16 {
    b.wrapping_mul(QINV)
}

/// Montgomery multiplication by a constant `b`, given `b_qinv = qinv_multiple(b)`. The result is
/// exactly `fqmul(a, b)`.
///
/// Montgomery reduction subtracts `t * q`, where `t = a * b * q^-1 mod 2^16`, from `a * b`. The
/// low 16 bits of the two products are equal, so the result is the difference of their high
/// halves (Seiler, ePrint 2018/039). Computed this way, every operation works on 16-bit lanes,
/// which compilers map onto SIMD instructions such as `pmulhw` and `pmullw`.
#[inline(always)]
fn fqmul_const(a: i16, b: i16, b_qinv: i16) -> i16 {
    mulhi(a, b) - mulhi(a.wrapping_mul(b_qinv), Q)
}

/// Barrett reduction: for any `a`, returns the representative of `a mod q` in
/// `[-(q-1)/2, (q-1)/2]`.
///
/// The quotient `round(a * V / 2^26)`, with `V = round(2^26 / q)`, is computed from the high half
/// of `a * V` as `(mulhi(a, V) + 2^9) >> 10`, which is equal because nested floors of divisions
/// by integers collapse. The quotient has absolute value at most 10, and the result fits in
/// `i16`, so the wrapping operations below are exact.
#[inline(always)]
#[allow(clippy::cast_possible_truncation, reason = "V is below 2^15")]
fn barrett_reduce(a: i16) -> i16 {
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const V: i16 = (((1 << 26) + Q as i32 / 2) / Q as i32) as i16;
    let t = (mulhi(a, V) + (1 << 9)) >> 10;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Map coefficients in `[-q, q)` to their canonical representatives in `[0, q)`.
///
/// Adding `q` to the negative coefficients is done with an arithmetic sign mask. LLVM recognizes
/// `(a >> 15) & q` as a select on the sign of `a`, and on targets without conditional moves (for
/// example `thumbv6m`) it lowers that select to a branch on the secret coefficient. The masks for
/// the whole polynomial are therefore passed through a single optimization barrier before they are
/// applied, which hides their origin while keeping both loops vectorizable.
///
/// Every kernel ends with this pass, so it is kept out of line: inlining it everywhere costs about
/// 10 KiB of code on thumbv7em and is not measurably faster.
#[inline(never)]
#[allow(clippy::cast_sign_loss, reason = "the result is in [0, q)")]
pub(super) fn canonicalize(f: &[i16; 256]) -> Array<Elem, U256> {
    let mut masks: [i16; 256] = core::array::from_fn(|i| f[i] >> 15);
    core::hint::black_box(&mut masks);
    Array::from_fn(|i| Elem::new((f[i] + (masks[i] & Q)) as u16))
}

/// Coefficient-wise `a + b`, for coefficients in `[0, q)`.
pub(super) fn add(a: &Array<Elem, U256>, b: &Array<Elem, U256>) -> Array<Elem, U256> {
    // `a + b - q` is in `[-q, q - 2]`.
    let f: [i16; 256] = core::array::from_fn(|i| signed(a[i]) + signed(b[i]) - Q);
    canonicalize(&f)
}

/// Coefficient-wise `a - b`, for coefficients in `[0, q)`.
pub(super) fn sub(a: &Array<Elem, U256>, b: &Array<Elem, U256>) -> Array<Elem, U256> {
    // `a - b` is in `(-q, q)`.
    let f: [i16; 256] = core::array::from_fn(|i| signed(a[i]) - signed(b[i]));
    canonicalize(&f)
}

/// Read a canonical coefficient in `[0, q)` as `i16`.
#[inline(always)]
#[allow(clippy::cast_possible_wrap, reason = "the value is below q")]
fn signed(x: Elem) -> i16 {
    x.0 as i16
}

/// One layer of the forward NTT (Algorithm 9).
///
/// Each layer adds at most `q` to the magnitude of a coefficient, since `fqmul` returns values
/// below `q` in absolute value. Inputs below `q` therefore stay below `8q < 2^15` after seven
/// layers, and no intermediate reduction is needed.
#[inline(always)]
fn ntt_layer<const LEN: usize, const ITERATIONS: usize>(f: &mut [i16; 256], k: &mut usize) {
    for block in f.chunks_exact_mut(2 * LEN).take(ITERATIONS) {
        let (zeta, zeta_qinv) = (ZETAS[*k], ZETAS_QINV[*k]);
        *k += 1;

        let (lo, hi) = block.split_at_mut(LEN);
        for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
            let t = fqmul_const(*b, zeta, zeta_qinv);
            *b = *a - t;
            *a += t;
        }
    }
}

/// Algorithm 9: `NTT`, on coefficients in `[0, q)`. Returns coefficients in `[0, q)`.
pub(super) fn ntt(input: &Array<Elem, U256>) -> NttPolynomial {
    let mut f: [i16; 256] = core::array::from_fn(|i| signed(input[i]));
    let mut k = 1;

    ntt_layer::<128, 1>(&mut f, &mut k);
    ntt_layer::<64, 2>(&mut f, &mut k);
    ntt_layer::<32, 4>(&mut f, &mut k);
    ntt_layer::<16, 8>(&mut f, &mut k);
    ntt_layer::<8, 16>(&mut f, &mut k);
    ntt_layer::<4, 32>(&mut f, &mut k);
    ntt_layer::<2, 64>(&mut f, &mut k);

    for x in &mut f {
        *x = barrett_reduce(*x);
    }
    NttPolynomial::new(canonicalize(&f))
}

/// One layer of the inverse NTT (Algorithm 10).
///
/// Inputs are below `q` in absolute value. Sums and differences are below `2q`. The sum is
/// Barrett-reduced and the difference is Montgomery-multiplied, so outputs are again below `q`.
#[inline(always)]
fn ntt_inverse_layer<const LEN: usize, const ITERATIONS: usize>(f: &mut [i16; 256], k: &mut usize) {
    for block in f.chunks_exact_mut(2 * LEN).take(ITERATIONS) {
        let (zeta, zeta_qinv) = (ZETAS[*k], ZETAS_QINV[*k]);
        *k -= 1;

        let (lo, hi) = block.split_at_mut(LEN);
        for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
            let t = *a;
            *a = barrett_reduce(t + *b);
            *b = fqmul_const(*b - t, zeta, zeta_qinv);
        }
    }
}

/// Algorithm 10: `NTT^-1`, on coefficients in `[0, q)`. Returns coefficients in `[0, q)`.
pub(super) fn ntt_inverse(input: &Array<Elem, U256>) -> Array<Elem, U256> {
    let mut f: [i16; 256] = core::array::from_fn(|i| signed(input[i]));
    let mut k = 127;

    ntt_inverse_layer::<2, 64>(&mut f, &mut k);
    ntt_inverse_layer::<4, 32>(&mut f, &mut k);
    ntt_inverse_layer::<8, 16>(&mut f, &mut k);
    ntt_inverse_layer::<16, 8>(&mut f, &mut k);
    ntt_inverse_layer::<32, 4>(&mut f, &mut k);
    ntt_inverse_layer::<64, 2>(&mut f, &mut k);
    ntt_inverse_layer::<128, 1>(&mut f, &mut k);

    // Multiply by 128^-1. The result is below q in absolute value.
    for x in &mut f {
        *x = fqmul_const(*x, INV_NTT_SCALE, qinv_multiple(INV_NTT_SCALE));
    }
    canonicalize(&f)
}

/// The right-hand operand of `MultiplyNTTs` (Algorithm 11), prepared once so that it can be
/// multiplied by several left-hand operands.
///
/// For each degree-one factor `b0 + b1 X` this stores `b0 * R`, `b1 * R` and `b1 * gamma * R`
/// (mod q, below q in absolute value). Products with canonical coefficients then need a single
/// Montgomery reduction, which removes the factor `R`, and `b1 * gamma` is computed once rather
/// than once per left-hand operand.
#[derive(Clone)]
pub(crate) struct PreparedNtt {
    b0: [i16; 128],
    b1: [i16; 128],
    b1_gamma: [i16; 128],
}

impl PreparedNtt {
    pub(crate) fn new(b: &NttPolynomial) -> Self {
        let mut out = Self {
            b0: [0; 128],
            b1: [0; 128],
            b1_gamma: [0; 128],
        };

        for (i, pair) in b.0.chunks_exact(2).enumerate() {
            let r2_qinv = qinv_multiple(R2);
            out.b0[i] = fqmul_const(signed(pair[0]), R2, r2_qinv);
            out.b1[i] = fqmul_const(signed(pair[1]), R2, r2_qinv);
            out.b1_gamma[i] = fqmul_const(signed(pair[1]), GAMMAS_R2[i], GAMMAS_R2_QINV[i]);
        }

        out
    }
}

/// Prepare every polynomial of a vector (see [`PreparedNtt`]).
pub(crate) fn prepare<K: ArraySize>(v: &NttVector<K>) -> Array<PreparedNtt, K> {
    Array::from_fn(|i| PreparedNtt::new(&v.0[i]))
}

/// Algorithms 11 and 12 (`MultiplyNTTs` and `BaseCaseMultiply`), summed over a vector:
/// `sum_j a[j] * b[j]` in `T_q`.
///
/// Products are accumulated in `i32` and reduced once per output coefficient. Coefficients of `a`
/// are in `[0, q)` and prepared values are below `q` in absolute value, so each output
/// coefficient gains less than `2 q^2` per term. With `K <= 4` terms the sum stays below
/// `8 q^2 < q * 2^15`, which is the input domain of `montgomery_reduce`.
pub(crate) fn multiply_accumulate<K: ArraySize>(
    a: &NttVector<K>,
    b: &Array<PreparedNtt, K>,
) -> NttPolynomial {
    debug_assert!(K::USIZE <= 4);
    accumulate(a.0.iter().zip(b.iter()))
}

/// The sum of the products of `(a, b)` pairs in `T_q`, for at most four pairs. See
/// [`multiply_accumulate`] for the bounds.
fn accumulate<'a>(
    terms: impl Iterator<Item = (&'a NttPolynomial, &'a PreparedNtt)>,
) -> NttPolynomial {
    let mut c0 = [0i32; 128];
    let mut c1 = [0i32; 128];

    for (a, b) in terms {
        for (i, pair) in a.0.chunks_exact(2).enumerate() {
            let a0 = i32::from(pair[0].0);
            let a1 = i32::from(pair[1].0);
            c0[i] += a0 * i32::from(b.b0[i]) + a1 * i32::from(b.b1_gamma[i]);
            c1[i] += a0 * i32::from(b.b1[i]) + a1 * i32::from(b.b0[i]);
        }
    }

    let mut out = [0i16; 256];
    for (i, pair) in out.chunks_exact_mut(2).enumerate() {
        pair[0] = montgomery_reduce(c0[i]);
        pair[1] = montgomery_reduce(c1[i]);
    }
    NttPolynomial::new(canonicalize(&out))
}

/// Multiply a `K x K` matrix, given by its rows, by a prepared vector in `T_q`.
pub(crate) fn matrix_multiply<K: ArraySize>(
    rows: &Array<NttVector<K>, K>,
    v: &Array<PreparedNtt, K>,
) -> NttVector<K> {
    NttVector::new(Array::from_fn(|i| multiply_accumulate(&rows[i], v)))
}

/// Multiply the transpose of a `K x K` matrix, given by its rows, by a prepared vector in `T_q`.
pub(crate) fn matrix_transpose_multiply<K: ArraySize>(
    rows: &Array<NttVector<K>, K>,
    v: &Array<PreparedNtt, K>,
) -> NttVector<K> {
    debug_assert!(K::USIZE <= 4);
    NttVector::new(Array::from_fn(|i| {
        accumulate(rows.iter().map(|row| &row.0[i]).zip(v.iter()))
    }))
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "tests"
)]
#[allow(
    clippy::integer_division_remainder_used,
    reason = "test oracle on public values"
)]
mod tests {
    use super::*;
    use crate::algebra::BaseField;
    use module_lattice::Field;

    fn modq(x: i64) -> i64 {
        x.rem_euclid(i64::from(Q))
    }

    #[test]
    fn constants() {
        assert_eq!(i32::from(Q), i32::from(BaseField::Q));
        assert_eq!((i32::from(Q) * i32::from(QINV)) & 0xffff, 1);
        assert_eq!(modq(i64::from(R2)), modq(1 << 32));
        assert_eq!(modq(i64::from(INV_NTT_SCALE) * 128), modq(1 << 16));
        for i in 0..128 {
            let z = i64::from(ZETA_POW_BITREV[i].0);
            let g = i64::from(GAMMA[i].0);
            assert_eq!(modq(i64::from(ZETAS[i])), modq(z << 16));
            assert_eq!(modq(i64::from(GAMMAS_R2[i])), modq(modq(g << 16) << 16));
            assert!(ZETAS[i].abs() <= (Q - 1) / 2);
            assert!(GAMMAS_R2[i].abs() <= (Q - 1) / 2);
        }
    }

    /// `montgomery_reduce` over its whole documented domain, with a stride that keeps the test
    /// fast in debug builds, plus both ends of the domain.
    #[test]
    fn montgomery_reduce_domain() {
        let bound = i32::from(Q) << 15;
        let check = |a: i32| {
            let r = montgomery_reduce(a);
            assert!(r.abs() < Q, "a = {a}");
            assert_eq!(modq(i64::from(r) << 16), modq(i64::from(a)), "a = {a}");
        };
        let mut a = -bound + 1;
        while a < bound {
            check(a);
            a += 97;
        }
        for a in [-bound + 1, -bound + 2, -1, 0, 1, bound - 2, bound - 1] {
            check(a);
        }
    }

    /// `fqmul` for every multiplier used by the kernels and every input magnitude they can see.
    #[test]
    fn fqmul_all_constants() {
        let constants = ZETAS
            .iter()
            .chain(GAMMAS_R2.iter())
            .chain([R2, INV_NTT_SCALE].iter());
        for &c in constants {
            for a in (-8 * i32::from(Q) + 1)..(8 * i32::from(Q)) {
                let a = a as i16;
                let r = fqmul(a, c);
                assert_eq!(fqmul_const(a, c, qinv_multiple(c)), r);
                assert!(r.abs() < Q);
                assert_eq!(modq(i64::from(r) << 16), modq(i64::from(a) * i64::from(c)));
            }
        }
    }

    #[test]
    fn barrett_reduce_exhaustive() {
        for a in i16::MIN..=i16::MAX {
            let r = barrett_reduce(a);
            let t = (20159 * i32::from(a) + (1 << 25)) >> 26;
            assert_eq!(i32::from(r), i32::from(a) - t * i32::from(Q), "a = {a}");
            assert!(r.abs() <= (Q - 1) / 2, "a = {a}");
            assert_eq!(modq(i64::from(r)), modq(i64::from(a)), "a = {a}");
        }
    }

    #[test]
    fn canonicalize_exhaustive() {
        let inputs: [i16; 2 * Q as usize - 1] = core::array::from_fn(|i| i as i16 - Q + 1);
        for chunk in inputs.chunks(256) {
            let mut f = [0i16; 256];
            f[..chunk.len()].copy_from_slice(chunk);
            let out = canonicalize(&f);
            for (a, r) in f.iter().zip(out.iter()) {
                assert!(r.0 < BaseField::Q);
                assert_eq!(i64::from(r.0), modq(i64::from(*a)));
            }
        }
    }

    /// `add` and `sub` agree with the `Elem` operators for every pair of field elements.
    #[test]
    fn add_sub_exhaustive() {
        for a in 0..BaseField::Q {
            let lhs = Array::from_fn(|_| Elem::new(a));
            for chunk in 0..BaseField::Q.div_ceil(256) {
                let rhs: Array<Elem, U256> =
                    Array::from_fn(|i| Elem::new((chunk * 256 + i as u16) % BaseField::Q));
                let sum = add(&lhs, &rhs);
                let difference = sub(&lhs, &rhs);
                for i in 0..256 {
                    assert_eq!(sum[i], lhs[i] + rhs[i]);
                    assert_eq!(difference[i], lhs[i] - rhs[i]);
                }
            }
        }
    }

    /// The largest possible accumulated product stays inside the Montgomery domain.
    #[test]
    fn multiply_accumulate_extremes() {
        use array::typenum::U4;

        let max = Elem::new(BaseField::Q - 1);
        let a: NttVector<U4> = NttVector::new(Array::from_fn(|_| {
            NttPolynomial::new(Array::from_fn(|_| max))
        }));
        for b in [max, Elem::new(1), Elem::new(0), Elem::new(1665)] {
            let v: NttVector<U4> = NttVector::new(Array::from_fn(|_| {
                NttPolynomial::new(Array::from_fn(|_| b))
            }));
            let fast = multiply_accumulate(&a, &prepare(&v));
            let slow = super::super::test::multiply_accumulate_reference(&a, &v);
            assert_eq!(fast, slow);
        }
    }
}
