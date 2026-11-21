//! Signed Montgomery arithmetic for NTTs, shared by ML-KEM and ML-DSA.
//!
//! Lanes are `i16` (`R = 2^16`) or `i32` (`R = 2^32`). Reduction is multiply, shift and add only,
//! with no secret-dependent select or branch. Kernels take and return canonical [`Elem`]s.

use crate::algebra::{Elem, Field, NttPolynomial};
use array::{Array, typenum::U256};
use core::fmt::Debug;
use core::ops::{Add, BitAnd, Sub};

mod sealed {
    pub trait Sealed {}

    impl Sealed for i16 {}
    impl Sealed for i32 {}
}

/// Signed coefficient lane with radix `R = 2^BITS`.
pub trait Lane:
    sealed::Sealed
    + Copy
    + Debug
    + Default
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + BitAnd<Output = Self>
{
    /// Storage type of canonical elements.
    type Unsigned: Copy + Debug + Eq;
    /// Product type.
    type Wide: Copy;

    /// `log2(R)`.
    const BITS: u32;
    /// `2^(BITS - 1)`.
    const LIMIT: i64;

    /// Cast of a value below `2^(BITS - 1)`.
    fn from_unsigned(x: Self::Unsigned) -> Self;
    /// Cast of a non-negative value.
    fn to_unsigned(self) -> Self::Unsigned;
    /// All ones if negative, else zero.
    #[must_use]
    fn sign_mask(self) -> Self;
    /// Full product.
    fn widening_mul(a: Self, b: Self) -> Self::Wide;
    /// `a * R^-1 mod q` in `(-q, q)`, for `|a| < q * 2^(BITS - 1)`.
    fn montgomery_reduce(a: Self::Wide, q: Self, qinv: Self) -> Self;
    /// `a * b * R^-1 mod q` in `(-q, q)`, for `|b| <= (q - 1) / 2` and `b_qinv = b * q^-1 mod R`.
    /// Lane-width multiplies only (Seiler, ePrint 2018/039).
    fn fqmul(a: Self, b: Self, b_qinv: Self, q: Self) -> Self;
}

macro_rules! impl_lane {
    ($lane:ty, $unsigned:ty, $wide:ty) => {
        impl Lane for $lane {
            type Unsigned = $unsigned;
            type Wide = $wide;

            const BITS: u32 = <$lane>::BITS;
            const LIMIT: i64 = 1 << (<$lane>::BITS - 1);

            #[inline(always)]
            #[allow(clippy::cast_possible_wrap, reason = "below 2^(BITS - 1)")]
            fn from_unsigned(x: $unsigned) -> Self {
                x as $lane
            }

            #[inline(always)]
            #[allow(clippy::cast_sign_loss, reason = "non-negative")]
            fn to_unsigned(self) -> $unsigned {
                self as $unsigned
            }

            #[inline(always)]
            fn sign_mask(self) -> Self {
                self >> (<$lane>::BITS - 1)
            }

            #[inline(always)]
            fn widening_mul(a: Self, b: Self) -> $wide {
                <$wide>::from(a) * <$wide>::from(b)
            }

            #[inline(always)]
            #[allow(
                clippy::cast_possible_truncation,
                reason = "mod R by design, and the quotient fits"
            )]
            fn montgomery_reduce(a: $wide, q: Self, qinv: Self) -> Self {
                let t = (a as $lane).wrapping_mul(qinv);
                ((a - <$wide>::from(t) * <$wide>::from(q)) >> <$lane>::BITS) as $lane
            }

            #[inline(always)]
            #[allow(clippy::cast_possible_truncation, reason = "the high half fits")]
            fn fqmul(a: Self, b: Self, b_qinv: Self, q: Self) -> Self {
                let mulhi = |x: $lane, y: $lane| {
                    ((<$wide>::from(x) * <$wide>::from(y)) >> <$lane>::BITS) as $lane
                };
                mulhi(a, b) - mulhi(a.wrapping_mul(b_qinv), q)
            }
        }
    };
}

impl_lane!(i16, u16, i32);
impl_lane!(i32, u32, i64);

/// Montgomery constants for one modulus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params<L: Lane> {
    q: L,
    /// `q^-1 mod R`.
    qinv: L,
    /// `R mod q`, canonical.
    r_mod_q: L::Unsigned,
    /// `R^2 mod q`, centered.
    r2: L,
    r2_qinv: L,
    q_i64: i64,
}

/// Twiddles `zeta^BitRev(i) * R mod q` and the inverse NTT scale. `N = 128` is the 7-layer NTT
/// of FIPS 203, `N = 256` the 8-layer NTT of FIPS 204.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Zetas<L: Lane, const N: usize> {
    q: L,
    zetas: [L; N],
    zetas_qinv: [L; N],
    /// `2^-layers * R mod q`.
    inv_scale: L,
    inv_scale_qinv: L,
}

/// `x mod q` in `[-(q - 1) / 2, (q - 1) / 2]`, for `x < q`.
#[allow(clippy::cast_possible_wrap, reason = "q is below 2^30")]
#[allow(clippy::integer_division_remainder_used, reason = "public constant")]
const fn centered(x: u64, q: u64) -> i64 {
    assert!(x < q);
    if x > (q - 1) / 2 {
        x as i64 - q as i64
    } else {
        x as i64
    }
}

/// `x` with its low `bits` bits reversed.
const fn bitrev(x: usize, bits: u32) -> usize {
    assert!(x < 1 << bits);
    let mut out = 0;
    let mut i = 0;
    while i < bits {
        out |= ((x >> i) & 1) << (bits - 1 - i);
        i += 1;
    }
    out
}

macro_rules! impl_tables {
    ($lane:ty, $unsigned:ty) => {
        impl Params<$lane> {
            /// Constants for an odd prime `3 <= q < 2^(BITS - 2)`. Primality is not checked.
            ///
            /// # Panics
            ///
            /// If `q` is even or out of range.
            #[must_use]
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                reason = "below q, or mod R by design"
            )]
            #[allow(clippy::integer_division_remainder_used, reason = "public constant")]
            pub const fn new(q: $unsigned) -> Self {
                let q64 = q as u64;
                assert!(q64 % 2 == 1, "q must be odd");
                assert!(q64 >= 3, "q must be at least 3");
                assert!(
                    q64 < 1 << (<$lane>::BITS - 2),
                    "q must be below 2^(BITS - 2)"
                );

                // Newton: `q` is its own inverse mod 8, and each step doubles the correct bits.
                let mut inv = q64;
                let mut i = 0;
                while i < 5 {
                    inv = inv.wrapping_mul(2u64.wrapping_sub(q64.wrapping_mul(inv)));
                    i += 1;
                }
                let qinv = inv as $lane;
                assert!(
                    (q as $lane).wrapping_mul(qinv) == 1,
                    "q * q^-1 must be 1 mod R"
                );

                let r_mod_q = (1u64 << <$lane>::BITS) % q64;
                let r2 = centered((r_mod_q * r_mod_q) % q64, q64) as $lane;
                Self {
                    q: q as $lane,
                    qinv,
                    r_mod_q: r_mod_q as $unsigned,
                    r2,
                    r2_qinv: r2.wrapping_mul(qinv),
                    q_i64: q64 as i64,
                }
            }

            /// `q`.
            #[must_use]
            pub const fn q(self) -> $lane {
                self.q
            }

            /// `q^-1 mod R`.
            #[must_use]
            pub const fn qinv(self) -> $lane {
                self.qinv
            }

            /// `R mod q`, canonical.
            #[must_use]
            pub const fn r_mod_q(self) -> $unsigned {
                self.r_mod_q
            }

            /// `R^2 mod q`, centered.
            #[must_use]
            pub const fn r2(self) -> $lane {
                self.r2
            }

            /// `b * q^-1 mod R`, for [`Lane::fqmul`].
            #[must_use]
            pub const fn qinv_multiple(self, b: $lane) -> $lane {
                b.wrapping_mul(self.qinv)
            }
        }

        impl<const N: usize> Zetas<$lane, N> {
            /// Tables for a primitive `2N`-th root of unity `zeta`.
            ///
            /// # Panics
            ///
            /// If `N` is not 128 or 256, or `zeta^N != -1 mod q`.
            #[must_use]
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "values are below q"
            )]
            #[allow(clippy::integer_division_remainder_used, reason = "public constant")]
            pub const fn new(params: Params<$lane>, zeta: $unsigned) -> Self {
                assert!(N == 128 || N == 256, "N must be 128 or 256");
                let q = params.q_i64 as u64;
                let zeta = zeta as u64;
                assert!(zeta > 1 && zeta < q, "zeta must be in (1, q)");
                let layers = N.trailing_zeros();

                let mut pow = [0u64; N];
                let mut acc = 1;
                let mut i = 0;
                while i < N {
                    pow[i] = acc;
                    acc = (acc * zeta) % q;
                    i += 1;
                }
                // `2N` is a power of two, so the order is exactly `2N`.
                assert!(acc == q - 1, "zeta^N must be -1 mod q");

                let r = params.r_mod_q as u64;
                let mut zetas = [0; N];
                let mut zetas_qinv = [0; N];
                let mut i = 0;
                while i < N {
                    zetas[i] = centered((pow[bitrev(i, layers)] * r) % q, q) as $lane;
                    zetas_qinv[i] = params.qinv_multiple(zetas[i]);
                    i += 1;
                }

                // `2^-1 = (q + 1) / 2`.
                let mut scale = 1;
                let mut i = 0;
                while i < layers {
                    scale = (scale * q.div_ceil(2)) % q;
                    i += 1;
                }
                let inv_scale = centered((scale * r) % q, q) as $lane;

                Self {
                    q: params.q,
                    zetas,
                    zetas_qinv,
                    inv_scale,
                    inv_scale_qinv: params.qinv_multiple(inv_scale),
                }
            }
        }
    };
}

impl_tables!(i16, u16);
impl_tables!(i32, u32);

/// A prime field with signed Montgomery arithmetic.
pub trait MontgomeryField: Field {
    /// Coefficient lane.
    type Lane: Lane<Unsigned = Self::Int>;

    /// `Params::new(Self::Q)`.
    const MONTGOMERY: Params<Self::Lane>;

    /// `a mod q` with `|result| < q`, for `|a| < 9q`.
    fn reduce(a: Self::Lane) -> Self::Lane;
}

/// `F::MONTGOMERY`, checked against `F::Q`. The check folds away.
#[inline(always)]
fn params<F: MontgomeryField>() -> Params<F::Lane> {
    let params = F::MONTGOMERY;
    assert!(params.q == F::Lane::from_unsigned(F::Q));
    params
}

/// A canonical element as a lane.
#[inline(always)]
#[must_use]
pub fn signed<F: MontgomeryField>(x: Elem<F>) -> F::Lane {
    F::Lane::from_unsigned(x.0)
}

/// `a * R^-1 mod q` in `(-q, q)`, for `|a| < q * 2^(BITS - 1)`.
#[inline(always)]
#[must_use]
pub fn montgomery_reduce<F: MontgomeryField>(a: <F::Lane as Lane>::Wide) -> F::Lane {
    let params = params::<F>();
    F::Lane::montgomery_reduce(a, params.q, params.qinv)
}

/// [`Lane::fqmul`] for `F`.
#[inline(always)]
#[must_use]
pub fn fqmul<F: MontgomeryField>(a: F::Lane, b: F::Lane, b_qinv: F::Lane) -> F::Lane {
    F::Lane::fqmul(a, b, b_qinv, params::<F>().q)
}

/// Maps `[-q, q)` to `[0, q)`.
///
/// The barrier stops LLVM from branching on the masks where there is no conditional move
/// (thumbv6m).
#[inline(never)]
#[must_use]
pub fn canonicalize<F: MontgomeryField>(f: &[F::Lane; 256]) -> Array<Elem<F>, U256> {
    let q = params::<F>().q;
    let mut masks: [F::Lane; 256] = core::array::from_fn(|i| f[i].sign_mask());
    core::hint::black_box(&mut masks);
    Array::from_fn(|i| Elem::new((f[i] + (masks[i] & q)).to_unsigned()))
}

/// `a + b`. Out of line, or generic instances are inlined at every call site.
#[inline(never)]
#[must_use]
pub fn add<F: MontgomeryField>(
    a: &Array<Elem<F>, U256>,
    b: &Array<Elem<F>, U256>,
) -> Array<Elem<F>, U256> {
    let q = params::<F>().q;
    // In `[-q, q - 2]`.
    let f: [F::Lane; 256] = core::array::from_fn(|i| signed(a[i]) + signed(b[i]) - q);
    canonicalize::<F>(&f)
}

/// `a - b`. Out of line, like [`add`].
#[inline(never)]
#[must_use]
pub fn sub<F: MontgomeryField>(
    a: &Array<Elem<F>, U256>,
    b: &Array<Elem<F>, U256>,
) -> Array<Elem<F>, U256> {
    // In `(-q, q)`.
    let f: [F::Lane; 256] = core::array::from_fn(|i| signed(a[i]) - signed(b[i]));
    canonicalize::<F>(&f)
}

/// One forward layer: values grow by less than `q`.
#[inline(always)]
fn ntt_layer<F: MontgomeryField, const N: usize, const LEN: usize, const ITERATIONS: usize>(
    f: &mut [F::Lane; 256],
    zetas: &Zetas<F::Lane, N>,
    k: &mut usize,
) {
    let q = params::<F>().q;
    for block in f.chunks_exact_mut(2 * LEN).take(ITERATIONS) {
        let (zeta, zeta_qinv) = (zetas.zetas[*k], zetas.zetas_qinv[*k]);
        *k += 1;

        let (lo, hi) = block.split_at_mut(LEN);
        for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
            let t = F::Lane::fqmul(*b, zeta, zeta_qinv, q);
            *b = *a - t;
            *a = *a + t;
        }
    }
}

/// NTT: FIPS 203 Algorithm 9 (`N = 128`) or FIPS 204 Algorithm 41 (`N = 256`).
///
/// Values stay below `(layers + 1) q`. Always inlined so a `const` table folds into the
/// butterflies: call it from one wrapper per field.
///
/// # Panics
///
/// If `zetas` are for another modulus.
#[inline(always)]
#[must_use]
pub fn ntt<F: MontgomeryField, const N: usize>(
    input: &Array<Elem<F>, U256>,
    zetas: &Zetas<F::Lane, N>,
) -> Array<Elem<F>, U256> {
    const { assert!(N == 128 || N == 256) };
    const {
        assert!(
            (N.trailing_zeros() as i64 + 1) * F::MONTGOMERY.q_i64 < <F::Lane as Lane>::LIMIT,
            "lazy NTT values must fit in a lane"
        );
    };
    assert!(zetas.q == params::<F>().q, "zetas are for another modulus");

    let mut f: [F::Lane; 256] = core::array::from_fn(|i| signed(input[i]));
    let mut k = 1;

    ntt_layer::<F, N, 128, 1>(&mut f, zetas, &mut k);
    ntt_layer::<F, N, 64, 2>(&mut f, zetas, &mut k);
    ntt_layer::<F, N, 32, 4>(&mut f, zetas, &mut k);
    ntt_layer::<F, N, 16, 8>(&mut f, zetas, &mut k);
    ntt_layer::<F, N, 8, 16>(&mut f, zetas, &mut k);
    ntt_layer::<F, N, 4, 32>(&mut f, zetas, &mut k);
    ntt_layer::<F, N, 2, 64>(&mut f, zetas, &mut k);
    if N == 256 {
        ntt_layer::<F, N, 1, 128>(&mut f, zetas, &mut k);
    }
    assert!(k == N);

    for x in &mut f {
        *x = F::reduce(*x);
    }
    canonicalize::<F>(&f)
}

/// One inverse layer: values stay in `(-q, q)`.
#[inline(always)]
fn ntt_inverse_layer<
    F: MontgomeryField,
    const N: usize,
    const LEN: usize,
    const ITERATIONS: usize,
>(
    f: &mut [F::Lane; 256],
    zetas: &Zetas<F::Lane, N>,
    k: &mut usize,
) {
    let q = params::<F>().q;
    for block in f.chunks_exact_mut(2 * LEN).take(ITERATIONS) {
        let (zeta, zeta_qinv) = (zetas.zetas[*k], zetas.zetas_qinv[*k]);
        *k -= 1;

        let (lo, hi) = block.split_at_mut(LEN);
        for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
            let t = *a;
            *a = F::reduce(t + *b);
            *b = F::Lane::fqmul(*b - t, zeta, zeta_qinv, q);
        }
    }
}

/// Inverse NTT: FIPS 203 Algorithm 10 (`N = 128`) or FIPS 204 Algorithm 42 (`N = 256`).
///
/// # Panics
///
/// If `zetas` are for another modulus.
#[inline(always)]
#[must_use]
pub fn ntt_inverse<F: MontgomeryField, const N: usize>(
    input: &Array<Elem<F>, U256>,
    zetas: &Zetas<F::Lane, N>,
) -> Array<Elem<F>, U256> {
    const { assert!(N == 128 || N == 256) };
    let params = params::<F>();
    assert!(zetas.q == params.q, "zetas are for another modulus");

    let mut f: [F::Lane; 256] = core::array::from_fn(|i| signed(input[i]));
    let mut k = N - 1;

    if N == 256 {
        ntt_inverse_layer::<F, N, 1, 128>(&mut f, zetas, &mut k);
    }
    ntt_inverse_layer::<F, N, 2, 64>(&mut f, zetas, &mut k);
    ntt_inverse_layer::<F, N, 4, 32>(&mut f, zetas, &mut k);
    ntt_inverse_layer::<F, N, 8, 16>(&mut f, zetas, &mut k);
    ntt_inverse_layer::<F, N, 16, 8>(&mut f, zetas, &mut k);
    ntt_inverse_layer::<F, N, 32, 4>(&mut f, zetas, &mut k);
    ntt_inverse_layer::<F, N, 64, 2>(&mut f, zetas, &mut k);
    ntt_inverse_layer::<F, N, 128, 1>(&mut f, zetas, &mut k);
    assert!(k == 0);

    for x in &mut f {
        *x = F::Lane::fqmul(*x, zetas.inv_scale, zetas.inv_scale_qinv, params.q);
    }
    canonicalize::<F>(&f)
}

/// Term limit of [`pointwise_multiply_accumulate`]: `(2^(BITS - 1) - 1) / (q - 1)`.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "at most 2^31"
)]
#[allow(clippy::integer_division_remainder_used, reason = "public constant")]
pub const fn pointwise_max_terms<F: MontgomeryField>() -> usize {
    ((<F::Lane as Lane>::LIMIT - 1) / (F::MONTGOMERY.q_i64 - 1)) as usize
}

/// `sum_j a[j] * b[j]` with pointwise products (FIPS 204 Algorithm 45 over a row). Not for
/// FIPS 203, whose NTT needs a base-case multiply.
///
/// Each product is reduced, so there is no prepared copy and no wide accumulator.
///
/// # Panics
///
/// If the lengths differ or exceed [`pointwise_max_terms`].
#[must_use]
pub fn pointwise_multiply_accumulate<F: MontgomeryField>(
    a: &[NttPolynomial<F>],
    b: &[NttPolynomial<F>],
) -> NttPolynomial<F> {
    let params = params::<F>();
    assert_eq!(a.len(), b.len(), "operands must have the same length");
    assert!(a.len() <= pointwise_max_terms::<F>(), "too many terms");

    let mut acc = [F::Lane::default(); 256];
    for (a, b) in a.iter().zip(b) {
        for i in 0..256 {
            let product = F::Lane::widening_mul(signed(a.0[i]), signed(b.0[i]));
            acc[i] = acc[i] + F::Lane::montgomery_reduce(product, params.q, params.qinv);
        }
    }
    for x in &mut acc {
        *x = F::Lane::fqmul(*x, params.r2, params.r2_qinv, params.q);
    }
    NttPolynomial::new(canonicalize::<F>(&acc))
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division_remainder_used,
    reason = "test oracle on public values"
)]
#[allow(unreachable_pub, reason = "`define_field!` emits public items")]
mod tests {
    extern crate alloc;

    use super::*;
    use crate::Truncate;
    use alloc::vec::Vec;

    crate::define_field!(KemField, u16, u32, u64, 3329);
    crate::define_field!(DsaField, u32, u64, u128, 8_380_417);

    impl MontgomeryField for KemField {
        type Lane = i16;
        const MONTGOMERY: Params<i16> = Params::<i16>::new(3329);

        /// ml-kem's Barrett.
        fn reduce(a: i16) -> i16 {
            let t = ((i32::from(a) * 20159) >> 16) as i16;
            let t = (t + (1 << 9)) >> 10;
            a.wrapping_sub(t.wrapping_mul(3329))
        }
    }

    impl MontgomeryField for DsaField {
        type Lane = i32;
        const MONTGOMERY: Params<i32> = Params::<i32>::new(8_380_417);

        /// ml-dsa's shift-only Barrett.
        fn reduce(a: i32) -> i32 {
            let t = (a + (1 << 22)) >> 23;
            a - t * 8_380_417
        }
    }

    const KEM_ZETAS: Zetas<i16, 128> = Zetas::<i16, 128>::new(KemField::MONTGOMERY, 17);
    const DSA_ZETAS: Zetas<i32, 256> = Zetas::<i32, 256>::new(DsaField::MONTGOMERY, 1753);

    /// `i64` views for the reference arithmetic.
    trait Wide64: Lane {
        fn to_i64(self) -> i64;
        fn from_i64(x: i64) -> Self;
        fn wide_from_i64(x: i64) -> Self::Wide;
    }

    impl Wide64 for i16 {
        fn to_i64(self) -> i64 {
            self.into()
        }
        fn from_i64(x: i64) -> Self {
            Self::try_from(x).expect("value fits in i16")
        }
        fn wide_from_i64(x: i64) -> i32 {
            i32::try_from(x).expect("value fits in i32")
        }
    }

    impl Wide64 for i32 {
        fn to_i64(self) -> i64 {
            self.into()
        }
        fn from_i64(x: i64) -> Self {
            Self::try_from(x).expect("value fits in i32")
        }
        fn wide_from_i64(x: i64) -> i64 {
            x
        }
    }

    /// `SplitMix64`, seeded per test.
    struct Rng {
        state: u64,
    }

    impl Rng {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn range(&mut self, lo: i64, hi: i64) -> i64 {
            assert!(lo < hi);
            lo + (self.next_u64() % (hi - lo) as u64) as i64
        }

        fn poly<F: MontgomeryField>(&mut self) -> Array<Elem<F>, U256> {
            Array::from_fn(|_| elem::<F>(self.range(0, q::<F>())))
        }
    }

    fn q<F: MontgomeryField>() -> i64 {
        F::MONTGOMERY.q_i64
    }

    fn modq<F: MontgomeryField>(x: i128) -> i64 {
        x.rem_euclid(i128::from(q::<F>())) as i64
    }

    fn value<F: MontgomeryField>(x: Elem<F>) -> i64 {
        let x: u128 = x.0.into();
        x as i64
    }

    fn elem<F: MontgomeryField>(x: i64) -> Elem<F> {
        assert!((0..q::<F>()).contains(&x));
        Elem::new(Truncate::truncate(x as u128))
    }

    fn pow<F: MontgomeryField>(base: i64, exponent: usize) -> i64 {
        (0..exponent).fold(1, |acc, _| modq::<F>(i128::from(acc) * i128::from(base)))
    }

    /// Reference bit reversal.
    fn reversed(i: usize, bits: u32) -> usize {
        i.reverse_bits() >> (usize::BITS - bits)
    }

    /// Extremes plus seeded random inputs.
    fn ntt_inputs<F: MontgomeryField>(rng: &mut Rng) -> Vec<Array<Elem<F>, U256>> {
        let top = q::<F>() - 1;
        let mut inputs = Vec::from([
            Array::from_fn(|_| elem::<F>(top)),
            Array::from_fn(|_| elem::<F>(0)),
            Array::from_fn(|i| elem::<F>(if i == 0 { 1 } else { 0 })),
            Array::from_fn(|i| elem::<F>(if i % 2 == 0 { top } else { 0 })),
        ]);
        inputs.extend((0..6).map(|_| rng.poly::<F>()));
        inputs
    }

    fn check_params<F: MontgomeryField>()
    where
        F::Lane: Wide64,
    {
        let params = F::MONTGOMERY;
        let q = i128::from(params.q_i64);
        let r = 1i128 << F::Lane::BITS;
        let r_mod_q: u128 = params.r_mod_q.into();

        assert_eq!(params.q.to_i64(), params.q_i64);
        assert_eq!((q * i128::from(params.qinv.to_i64())).rem_euclid(r), 1);
        assert_eq!(r_mod_q as i128, r.rem_euclid(q));
        assert_eq!(
            i128::from(params.r2.to_i64()).rem_euclid(q),
            (r * r).rem_euclid(q)
        );
        assert!(params.r2.to_i64().abs() <= (params.q_i64 - 1) / 2);
    }

    #[test]
    fn params_match_reference() {
        check_params::<KemField>();
        check_params::<DsaField>();
    }

    #[test]
    #[should_panic(expected = "q must be odd")]
    fn params_reject_even_modulus() {
        let _ = Params::<i16>::new(3330);
    }

    #[test]
    #[should_panic(expected = "q must be below 2^(BITS - 2)")]
    fn params_reject_wide_modulus() {
        let _ = Params::<i16>::new(16_411);
    }

    fn check_zetas<F: MontgomeryField, const N: usize>(zetas: &Zetas<F::Lane, N>, zeta: i64)
    where
        F::Lane: Wide64,
    {
        let layers = N.trailing_zeros();
        let r = 1i128 << F::Lane::BITS;
        for i in 0..N {
            let expected = modq::<F>(i128::from(pow::<F>(zeta, reversed(i, layers))) * r);
            let actual = zetas.zetas[i].to_i64();
            assert_eq!(modq::<F>(actual.into()), expected, "i = {i}");
            assert!(actual.abs() <= (q::<F>() - 1) / 2, "i = {i}");
        }
        let scaled = i128::from(zetas.inv_scale.to_i64()) << layers;
        assert_eq!(modq::<F>(scaled), modq::<F>(r));
    }

    #[test]
    fn zetas_match_reference() {
        check_zetas::<KemField, 128>(&KEM_ZETAS, 17);
        check_zetas::<DsaField, 256>(&DSA_ZETAS, 1753);
    }

    #[test]
    #[should_panic(expected = "zeta^N must be -1 mod q")]
    fn zetas_reject_root_of_lower_order() {
        // Order 128, so `zeta^128 = 1`.
        let _ = Zetas::<i16, 128>::new(KemField::MONTGOMERY, 289);
    }

    #[test]
    #[should_panic(expected = "N must be 128 or 256")]
    fn zetas_reject_other_lengths() {
        let _ = Zetas::<i16, 64>::new(KemField::MONTGOMERY, 17);
    }

    #[test]
    #[should_panic(expected = "zetas are for another modulus")]
    fn ntt_rejects_zetas_of_another_modulus() {
        // `7681 = 30 * 256 + 1`.
        let other = Params::<i16>::new(7681);
        let zeta = (2..7681)
            .map(|g| modpow(g, 30, 7681))
            .find(|&z| modpow(z, 128, 7681) == 7680)
            .expect("primitive root exists");
        let zetas = Zetas::<i16, 128>::new(other, zeta as u16);
        let _ = ntt::<KemField, 128>(&Array::default(), &zetas);
    }

    fn modpow(base: i64, exponent: u32, modulus: i64) -> i64 {
        (0..exponent).fold(1, |acc, _| (acc * base) % modulus)
    }

    fn check_montgomery_reduce<F: MontgomeryField>(a: i64)
    where
        F::Lane: Wide64,
    {
        let r = montgomery_reduce::<F>(F::Lane::wide_from_i64(a)).to_i64();
        assert!(r.abs() < q::<F>(), "a = {a}");
        assert_eq!(
            modq::<F>(i128::from(r) << F::Lane::BITS),
            modq::<F>(a.into()),
            "a = {a}"
        );
    }

    #[test]
    fn montgomery_reduce_domain() {
        let bound = q::<KemField>() << 15;
        let mut a = -bound + 1;
        while a < bound {
            check_montgomery_reduce::<KemField>(a);
            a += 97;
        }
        for a in [-bound + 1, -bound + 2, -1, 0, 1, bound - 2, bound - 1] {
            check_montgomery_reduce::<KemField>(a);
        }

        let mut rng = Rng::new(0x6d6f_6e74_0001);
        let bound = q::<DsaField>() << 31;
        for a in [-bound + 1, -bound + 2, -1, 0, 1, bound - 2, bound - 1] {
            check_montgomery_reduce::<DsaField>(a);
        }
        for _ in 0..200_000 {
            let a = rng.range(-bound + 1, bound);
            check_montgomery_reduce::<DsaField>(a);
        }
    }

    /// All table constants with their `q^-1` multiples.
    fn constants<L: Lane, const N: usize>(zetas: &Zetas<L, N>, params: Params<L>) -> Vec<(L, L)> {
        let mut out: Vec<(L, L)> = zetas
            .zetas
            .iter()
            .copied()
            .zip(zetas.zetas_qinv.iter().copied())
            .collect();
        out.push((zetas.inv_scale, zetas.inv_scale_qinv));
        out.push((params.r2, params.r2_qinv));
        out
    }

    fn check_fqmul<F: MontgomeryField>(a: i64, b: F::Lane, b_qinv: F::Lane)
    where
        F::Lane: Wide64,
    {
        let r = fqmul::<F>(F::Lane::from_i64(a), b, b_qinv).to_i64();
        let reference = montgomery_reduce::<F>(F::Lane::wide_from_i64(a * b.to_i64())).to_i64();
        assert_eq!(r, reference, "a = {a}, b = {b:?}");
        assert!(r.abs() < q::<F>(), "a = {a}, b = {b:?}");
        assert_eq!(
            modq::<F>(i128::from(r) << F::Lane::BITS),
            modq::<F>(i128::from(a) * i128::from(b.to_i64())),
            "a = {a}, b = {b:?}"
        );
    }

    #[test]
    fn fqmul_matches_reference() {
        for (b, b_qinv) in constants(&KEM_ZETAS, KemField::MONTGOMERY) {
            for a in i16::MIN..=i16::MAX {
                check_fqmul::<KemField>(a.into(), b, b_qinv);
            }
        }

        let mut rng = Rng::new(0x6671_6d75_6c32);
        let edges = [
            i32::MIN,
            i32::MIN + 1,
            -8_380_417,
            -1,
            0,
            1,
            8_380_417,
            i32::MAX,
        ];
        for (b, b_qinv) in constants(&DSA_ZETAS, DsaField::MONTGOMERY) {
            for a in edges {
                check_fqmul::<DsaField>(a.into(), b, b_qinv);
            }
            for _ in 0..4_000 {
                let a = rng.range(i32::MIN.into(), i64::from(i32::MAX) + 1);
                check_fqmul::<DsaField>(a, b, b_qinv);
            }
        }
    }

    fn check_canonicalize<F: MontgomeryField>(inputs: &[i64])
    where
        F::Lane: Wide64,
    {
        for chunk in inputs.chunks(256) {
            let mut f = [F::Lane::default(); 256];
            for (lane, &x) in f.iter_mut().zip(chunk) {
                *lane = F::Lane::from_i64(x);
            }
            let out = canonicalize::<F>(&f);
            for (x, r) in f.iter().zip(out.iter()) {
                assert_eq!(value(*r), modq::<F>(x.to_i64().into()), "x = {x:?}");
            }
        }
    }

    #[test]
    fn canonicalize_matches_reference() {
        let q_kem = q::<KemField>();
        let all: Vec<i64> = (-q_kem..q_kem).collect();
        check_canonicalize::<KemField>(&all);

        let mut rng = Rng::new(0x6361_6e6f_6e31);
        let q_dsa = q::<DsaField>();
        let mut inputs = Vec::from([-q_dsa, -q_dsa + 1, -1, 0, 1, q_dsa - 1]);
        inputs.extend((0..64 * 256).map(|_| rng.range(-q_dsa, q_dsa)));
        check_canonicalize::<DsaField>(&inputs);
    }

    fn check_add_sub<F: MontgomeryField>(lhs: &Array<Elem<F>, U256>, rhs: &Array<Elem<F>, U256>) {
        let sum = add(lhs, rhs);
        let difference = sub(lhs, rhs);
        for i in 0..256 {
            assert_eq!(sum[i], lhs[i] + rhs[i], "{:?} + {:?}", lhs[i], rhs[i]);
            assert_eq!(
                difference[i],
                lhs[i] - rhs[i],
                "{:?} - {:?}",
                lhs[i],
                rhs[i]
            );
        }
    }

    #[test]
    fn add_sub_match_elem() {
        let q_kem = q::<KemField>();
        for a in 0..q_kem {
            let lhs = Array::from_fn(|_| elem::<KemField>(a));
            for chunk in 0..(q_kem as usize).div_ceil(256) {
                let rhs = Array::from_fn(|i| elem::<KemField>((chunk * 256 + i) as i64 % q_kem));
                check_add_sub(&lhs, &rhs);
            }
        }

        let mut rng = Rng::new(0x6164_6473_7562);
        let top = q::<DsaField>() - 1;
        let edges = Array::from_fn(|i| elem::<DsaField>([0, 1, top - 1, top][i % 4]));
        let edges_shifted = Array::from_fn(|i| elem::<DsaField>([0, 1, top - 1, top][(i / 4) % 4]));
        check_add_sub::<DsaField>(&edges, &edges_shifted);
        for _ in 0..512 {
            check_add_sub::<DsaField>(&rng.poly(), &rng.poly());
        }
    }

    /// NTT by definition: evaluation at `zeta^(2 BitRev(i) + 1)` (FIPS 204), or reduction mod
    /// `X^2 - zeta^(2 BitRev(i) + 1)` (FIPS 203).
    fn reference_ntt<F: MontgomeryField>(
        a: &Array<Elem<F>, U256>,
        zeta: i64,
        n: usize,
    ) -> [i64; 256] {
        let layers = n.trailing_zeros();
        let a: [i128; 256] = core::array::from_fn(|i| value(a[i]).into());
        let mut out = [0; 256];
        if n == 256 {
            for (i, out) in out.iter_mut().enumerate() {
                let point = pow::<F>(zeta, 2 * reversed(i, layers) + 1);
                let mut acc = 0i128;
                for &coefficient in a.iter().rev() {
                    acc = i128::from(modq::<F>(acc * i128::from(point))) + coefficient;
                }
                *out = modq::<F>(acc);
            }
        } else {
            for i in 0..128 {
                let gamma = pow::<F>(zeta, 2 * reversed(i, layers) + 1);
                let (mut even, mut odd) = (0i128, 0i128);
                for j in (0..128).rev() {
                    even = i128::from(modq::<F>(even * i128::from(gamma))) + a[2 * j];
                    odd = i128::from(modq::<F>(odd * i128::from(gamma))) + a[2 * j + 1];
                }
                out[2 * i] = modq::<F>(even);
                out[2 * i + 1] = modq::<F>(odd);
            }
        }
        out
    }

    fn check_ntt<F: MontgomeryField, const N: usize>(
        zetas: &Zetas<F::Lane, N>,
        zeta: i64,
        seed: u64,
    ) {
        let mut rng = Rng::new(seed);
        for input in ntt_inputs::<F>(&mut rng) {
            let transformed = ntt(&input, zetas);
            let expected = reference_ntt(&input, zeta, N);
            for i in 0..256 {
                assert_eq!(
                    value(transformed[i]),
                    expected[i],
                    "seed = {seed:#x}, i = {i}"
                );
            }
            assert_eq!(ntt_inverse(&transformed, zetas), input, "seed = {seed:#x}");
        }
    }

    #[test]
    fn ntt_matches_definition_and_inverts() {
        check_ntt::<KemField, 128>(&KEM_ZETAS, 17, 0x6e74_7431_3238);
        check_ntt::<DsaField, 256>(&DSA_ZETAS, 1753, 0x6e74_7432_3536);
    }

    fn check_pointwise<F: MontgomeryField>(a: &[NttPolynomial<F>], b: &[NttPolynomial<F>]) {
        let out = pointwise_multiply_accumulate(a, b);
        for i in 0..256 {
            let expected = a.iter().zip(b).fold(0i128, |acc, (a, b)| {
                acc + i128::from(value(a.0[i]) * value(b.0[i]))
            });
            assert_eq!(
                value(out.0[i]),
                modq::<F>(expected),
                "terms = {}, i = {i}",
                a.len()
            );
        }
    }

    fn check_pointwise_field<F: MontgomeryField>(seed: u64) {
        let mut rng = Rng::new(seed);
        let max = pointwise_max_terms::<F>();
        let top = NttPolynomial::new(Array::from_fn(|_| elem::<F>(q::<F>() - 1)));
        let tops = Vec::from_iter(core::iter::repeat_n(top, max));
        check_pointwise(&tops, &tops);
        check_pointwise::<F>(&[], &[]);
        for terms in [1, 2, max] {
            let a: Vec<_> = (0..terms)
                .map(|_| NttPolynomial::new(rng.poly::<F>()))
                .collect();
            let b: Vec<_> = (0..terms)
                .map(|_| NttPolynomial::new(rng.poly::<F>()))
                .collect();
            check_pointwise(&a, &b);
        }
    }

    #[test]
    fn pointwise_multiply_accumulate_matches_reference() {
        check_pointwise_field::<KemField>(0x7077_6d61_6331);
        check_pointwise_field::<DsaField>(0x7077_6d61_6332);
    }

    #[test]
    #[should_panic(expected = "operands must have the same length")]
    fn pointwise_rejects_mismatched_lengths() {
        let a = [NttPolynomial::<DsaField>::new(Array::default())];
        let _ = pointwise_multiply_accumulate::<DsaField>(&a, &[]);
    }

    #[test]
    fn centered_boundaries() {
        for q in [17u64, 3329, 8_380_417] {
            let half = (q - 1) / 2;
            assert_eq!(centered(0, q), 0);
            assert_eq!(centered(half, q), half as i64, "q = {q}");
            assert_eq!(centered(half + 1, q), half as i64 + 1 - q as i64, "q = {q}");
            assert_eq!(centered(q - 1, q), -1, "q = {q}");
        }
    }

    crate::define_field!(TinyField, u16, u32, u64, 17);

    /// Small `q`, so the term limit is testable at its edge.
    impl MontgomeryField for TinyField {
        type Lane = i16;
        const MONTGOMERY: Params<i16> = Params::<i16>::new(17);

        fn reduce(a: i16) -> i16 {
            a % 17
        }
    }

    /// `(2^15 - 1) / (17 - 1)`.
    const TINY_MAX_TERMS: usize = 2047;

    #[test]
    fn pointwise_accepts_the_term_bound() {
        let mut rng = Rng::new(0x7469_6e79_0001);
        let a: Vec<_> = (0..TINY_MAX_TERMS)
            .map(|_| NttPolynomial::new(rng.poly::<TinyField>()))
            .collect();
        let b: Vec<_> = (0..TINY_MAX_TERMS)
            .map(|_| NttPolynomial::new(rng.poly::<TinyField>()))
            .collect();
        check_pointwise(&a, &b);
    }

    #[test]
    #[should_panic(expected = "too many terms")]
    fn pointwise_rejects_one_term_past_the_bound() {
        let a = Vec::from_iter(core::iter::repeat_n(
            NttPolynomial::<TinyField>::new(Array::default()),
            TINY_MAX_TERMS + 1,
        ));
        let _ = pointwise_multiply_accumulate::<TinyField>(&a, &a);
    }
}
