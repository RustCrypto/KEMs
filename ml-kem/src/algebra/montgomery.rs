//! ML-KEM on the shared `module-lattice` Montgomery kernels, plus the FIPS 203 base-case multiply.

use super::{BaseField, Elem, GAMMA, NttPolynomial, NttVector};
use array::{Array, ArraySize, typenum::U256};
use module_lattice::{
    Field,
    montgomery::{self, MontgomeryField, Params, Zetas},
};

pub(super) use module_lattice::montgomery::{add, canonicalize, sub};

impl MontgomeryField for BaseField {
    type Lane = i16;

    const MONTGOMERY: Params<i16> = Params::<i16>::new(<Self as Field>::Q);

    fn reduce(a: i16) -> i16 {
        barrett_reduce(a)
    }
}

const Q: i16 = BaseField::MONTGOMERY.q();

const R2: i16 = BaseField::MONTGOMERY.r2();

/// FIPS 203 `zeta = 17`.
const ZETAS: Zetas<i16, 128> = Zetas::<i16, 128>::new(BaseField::MONTGOMERY, 17);

/// Maps `[0, q)` to `[-(q-1)/2, (q-1)/2]`.
#[allow(clippy::cast_possible_truncation, reason = "the value is below q")]
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const fn centered(x: i32) -> i16 {
    if x > (Q as i32 - 1) / 2 {
        (x - Q as i32) as i16
    } else {
        x as i16
    }
}

/// `GAMMA[i] * R^2 mod q`, centered.
#[allow(clippy::cast_lossless, reason = "`i32::from` is not const")]
#[allow(clippy::integer_division_remainder_used, reason = "constant")]
const GAMMAS_R2: [i16; 128] = {
    let r = BaseField::MONTGOMERY.r_mod_q() as i32;
    let r2 = (r * r) % Q as i32;
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = centered((GAMMA[i].0 as i32 * r2) % Q as i32);
        i += 1;
    }
    out
};

const GAMMAS_R2_QINV: [i16; 128] = {
    let mut out = [0; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = BaseField::MONTGOMERY.qinv_multiple(GAMMAS_R2[i]);
        i += 1;
    }
    out
};

/// `a mod q` in `[-(q-1)/2, (q-1)/2]`, exact for every `i16`.
#[inline(always)]
#[allow(
    clippy::cast_possible_truncation,
    reason = "V and the high half fit in i16"
)]
fn barrett_reduce(a: i16) -> i16 {
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const V: i16 = (((1 << 26) + Q as i32 / 2) / Q as i32) as i16;
    let t = ((i32::from(a) * i32::from(V)) >> 16) as i16;
    let t = (t + (1 << 9)) >> 10;
    a.wrapping_sub(t.wrapping_mul(Q))
}

/// Algorithm 9: `NTT`.
pub(super) fn ntt(input: &Array<Elem, U256>) -> NttPolynomial {
    NttPolynomial::new(montgomery::ntt(input, &ZETAS))
}

/// Algorithm 10: `NTT^-1`.
pub(super) fn ntt_inverse(input: &Array<Elem, U256>) -> Array<Elem, U256> {
    montgomery::ntt_inverse(input, &ZETAS)
}

/// Right operand of Algorithm 11 as `b0 * R`, `b1 * R` and `b1 * gamma * R`, computed once and
/// reused across matrix rows.
#[derive(Clone)]
pub(crate) struct PreparedNtt {
    b0: [i16; 128],
    b1: [i16; 128],
    b1_gamma: [i16; 128],
}

impl PreparedNtt {
    pub(crate) fn new(b: &NttPolynomial) -> Self {
        const R2_QINV: i16 = BaseField::MONTGOMERY.qinv_multiple(R2);
        let mut out = Self {
            b0: [0; 128],
            b1: [0; 128],
            b1_gamma: [0; 128],
        };

        for (i, pair) in b.0.chunks_exact(2).enumerate() {
            let (b0, b1) = (montgomery::signed(pair[0]), montgomery::signed(pair[1]));
            out.b0[i] = montgomery::fqmul::<BaseField>(b0, R2, R2_QINV);
            out.b1[i] = montgomery::fqmul::<BaseField>(b1, R2, R2_QINV);
            out.b1_gamma[i] = montgomery::fqmul::<BaseField>(b1, GAMMAS_R2[i], GAMMAS_R2_QINV[i]);
        }

        out
    }
}

pub(crate) fn prepare<K: ArraySize>(v: &NttVector<K>) -> Array<PreparedNtt, K> {
    Array::from_fn(|i| PreparedNtt::new(&v.0[i]))
}

/// Algorithms 11 and 12 summed over a vector: `sum_j a[j] * b[j]`.
///
/// One reduction per coefficient: with `K <= 4` the `i32` sum stays below `8 q^2 < q * 2^15`.
pub(crate) fn multiply_accumulate<K: ArraySize>(
    a: &NttVector<K>,
    b: &Array<PreparedNtt, K>,
) -> NttPolynomial {
    const { assert!(K::USIZE <= 4) };
    accumulate(a.0.iter().zip(b.iter()))
}

/// Sum of products of at most four `(a, b)` pairs.
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
        pair[0] = montgomery::montgomery_reduce::<BaseField>(c0[i]);
        pair[1] = montgomery::montgomery_reduce::<BaseField>(c1[i]);
    }
    NttPolynomial::new(canonicalize(&out))
}

/// `A * v`, for `A` given by rows.
pub(crate) fn matrix_multiply<K: ArraySize>(
    rows: &Array<NttVector<K>, K>,
    v: &Array<PreparedNtt, K>,
) -> NttVector<K> {
    NttVector::new(Array::from_fn(|i| multiply_accumulate(&rows[i], v)))
}

/// `A^T * v`, for `A` given by rows.
pub(crate) fn matrix_transpose_multiply<K: ArraySize>(
    rows: &Array<NttVector<K>, K>,
    v: &Array<PreparedNtt, K>,
) -> NttVector<K> {
    const { assert!(K::USIZE <= 4) };
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

    fn modq(x: i64) -> i64 {
        x.rem_euclid(i64::from(Q))
    }

    #[test]
    fn constants() {
        assert_eq!(modq(i64::from(R2)), modq(1 << 32));
        for i in 0..128 {
            let g = i64::from(GAMMA[i].0);
            assert_eq!(modq(i64::from(GAMMAS_R2[i])), modq(modq(g << 16) << 16));
            assert!(GAMMAS_R2[i].abs() <= (Q - 1) / 2);
        }
    }

    #[test]
    fn centered_boundaries() {
        assert_eq!(centered(0), 0);
        assert_eq!(centered(1664), 1664);
        assert_eq!(centered(1665), -1664);
        assert_eq!(centered(3328), -1);
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

    /// Largest possible sums stay inside the Montgomery domain.
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
