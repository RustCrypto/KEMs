//! Proofs of the production arithmetic instantiated with the ML-KEM field.
//!
//! Preconditions apply to each primitive in isolation. These harnesses do not
//! establish that all higher-level callers satisfy those preconditions.

#![allow(
    clippy::integer_division_remainder_used,
    reason = "mathematical specifications"
)]

use super::{
    BaseField, Elem, Field, GAMMA, base_case_multiply, ntt_butterfly, ntt_inverse_butterfly,
    ntt_inverse_layer, ntt_layer,
};
use array::{Array, typenum::U256};

const Q: u32 = 3329;

fn coefficient() -> Elem {
    let x: u16 = kani::any();
    kani::assume(u32::from(x) < Q);
    Elem::new(x)
}

#[kani::proof]
fn small_reduce() {
    let x: u16 = kani::any();
    kani::assume(u32::from(x) < 2 * Q);
    let r = BaseField::small_reduce(x);
    assert!(u32::from(r) < Q);
    assert_eq!(u32::from(r), u32::from(x) % Q);
}

#[kani::proof]
fn barrett_reduce() {
    let x: u32 = kani::any();
    // Covers a product and the sum of two products in BaseCaseMultiply.
    kani::assume(x <= 2 * (Q - 1) * (Q - 1));
    let r = BaseField::barrett_reduce(x);
    assert!(u32::from(r) < Q);
    assert_eq!(u32::from(r), x % Q);
}

#[kani::proof]
fn add() {
    let a = coefficient();
    let b = coefficient();
    let r = a + b;
    assert!(u32::from(r.0) < Q);
    assert_eq!(u32::from(r.0), (u32::from(a.0) + u32::from(b.0)) % Q);
}

#[kani::proof]
fn subtract() {
    let a = coefficient();
    let b = coefficient();
    let r = a - b;
    assert!(u32::from(r.0) < Q);
    assert_eq!(u32::from(r.0), (u32::from(a.0) + Q - u32::from(b.0)) % Q);
}

#[kani::proof]
fn negate() {
    let a = coefficient();
    let r = -a;
    assert!(u32::from(r.0) < Q);
    assert_eq!(u32::from(r.0), (Q - u32::from(a.0)) % Q);
}

#[kani::proof]
fn multiply() {
    let a = coefficient();
    let b = coefficient();
    let r = a * b;
    assert!(u32::from(r.0) < Q);
    assert_eq!(u32::from(r.0), (u32::from(a.0) * u32::from(b.0)) % Q);
}

#[kani::proof]
fn forward_butterfly() {
    let a = coefficient();
    let b = coefficient();
    let zeta = coefficient();
    let (c0, c1) = ntt_butterfly(a, b, zeta);
    let t = u32::from(zeta.0) * u32::from(b.0) % Q;
    assert!(u32::from(c0.0) < Q);
    assert!(u32::from(c1.0) < Q);
    assert_eq!(u32::from(c0.0), (u32::from(a.0) + t) % Q);
    assert_eq!(u32::from(c1.0), (u32::from(a.0) + Q - t) % Q);
}

#[kani::proof]
fn inverse_butterfly() {
    let a = coefficient();
    let b = coefficient();
    let zeta = coefficient();
    let (c0, c1) = ntt_inverse_butterfly(a, b, zeta);
    assert!(u32::from(c0.0) < Q);
    assert!(u32::from(c1.0) < Q);
    assert_eq!(u32::from(c0.0), (u32::from(a.0) + u32::from(b.0)) % Q);
    assert_eq!(
        u32::from(c1.0),
        u32::from(zeta.0) * (u32::from(b.0) + Q - u32::from(a.0)) % Q
    );
}

#[kani::proof]
fn base_case() {
    let a0 = coefficient();
    let a1 = coefficient();
    let b0 = coefficient();
    let b1 = coefficient();
    let i: usize = kani::any();
    kani::assume(i < 128);
    let (c0, c1) = base_case_multiply(a0, a1, b0, b1, i);
    // Independent polynomial multiplication modulo X^2 - GAMMA[i].
    // Widen before multiplying: the unreduced triple product exceeds u32.
    let q = u64::from(Q);
    let expected0 = (u64::from(a0.0) * u64::from(b0.0)
        + u64::from(a1.0) * u64::from(b1.0) * u64::from(GAMMA[i].0))
        % q;
    let expected1 = (u64::from(a0.0) * u64::from(b1.0) + u64::from(a1.0) * u64::from(b0.0)) % q;
    assert!(u32::from(c0.0) < Q);
    assert!(u32::from(c1.0) < Q);
    assert_eq!(u64::from(c0.0), expected0);
    assert_eq!(u64::from(c1.0), expected1);
}

fn layer<const LEN: usize, const ITERATIONS: usize>() {
    let mut f: Array<Elem, U256> = Array::from_fn(|_| coefficient());
    // The forward transform starts this layer at twiddle 128 / LEN.
    let mut k = ITERATIONS;
    ntt_layer::<LEN, ITERATIONS>(&mut f, &mut k);
    assert_eq!(k, 2 * ITERATIONS);
    let index: usize = kani::any();
    kani::assume(index < 256);
    assert!(u32::from(f[index].0) < Q);
}

fn inverse_layer<const LEN: usize, const ITERATIONS: usize>() {
    let mut f: Array<Elem, U256> = Array::from_fn(|_| coefficient());
    // The inverse transform traverses the twiddles in reverse order.
    let mut k = 2 * ITERATIONS - 1;
    ntt_inverse_layer::<LEN, ITERATIONS>(&mut f, &mut k);
    assert_eq!(k, ITERATIONS - 1);
    let index: usize = kani::any();
    kani::assume(index < 256);
    assert!(u32::from(f[index].0) < Q);
}

macro_rules! layers {
    ($($forward:ident, $inverse:ident: $len:literal, $iterations:literal);+ $(;)?) => {$ (
        #[kani::proof]
        #[kani::unwind(257)]
        fn $forward() { layer::<$len, $iterations>(); }

        #[kani::proof]
        #[kani::unwind(257)]
        fn $inverse() { inverse_layer::<$len, $iterations>(); }
    )+};
}

layers! {
    layer_128, inverse_layer_128: 128, 1;
    layer_64, inverse_layer_64: 64, 2;
    layer_32, inverse_layer_32: 32, 4;
    layer_16, inverse_layer_16: 16, 8;
    layer_8, inverse_layer_8: 8, 16;
    layer_4, inverse_layer_4: 4, 32;
    layer_2, inverse_layer_2: 2, 64;
}
