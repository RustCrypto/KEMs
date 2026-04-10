//! Benchmarks for the NTT vector inner product.

#![allow(
    missing_docs,
    clippy::integer_division_remainder_used,
    clippy::cast_possible_truncation
)]

use array::typenum::{U2, U3, U4};
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use module_lattice::{Elem, MultiplyNtt, NttPolynomial, NttVector};

module_lattice::define_field!(KyberField, u16, u32, u64, 3329);

// MultiplyNtt is required by the `&NttVector * &NttVector` where clause even though
// the inner product body accumulates directly in Long integers and never calls this.
impl MultiplyNtt for KyberField {
    fn multiply_ntt(lhs: &NttPolynomial<Self>, rhs: &NttPolynomial<Self>) -> NttPolynomial<Self> {
        NttPolynomial::new(
            lhs.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&a, &b)| a * b)
                .collect(),
        )
    }
}

fn make_ntt_poly(base: u16) -> NttPolynomial<KyberField> {
    let coeffs: [Elem<KyberField>; 256] =
        core::array::from_fn(|i| Elem::new((base + i as u16) % 3329));
    NttPolynomial::new(coeffs.into())
}

fn bench_ntt_vector_inner_product(c: &mut Criterion) {
    // K=2 (ML-KEM-512)
    let a2: NttVector<KyberField, U2> =
        NttVector::new([make_ntt_poly(100), make_ntt_poly(200)].into());
    let b2: NttVector<KyberField, U2> =
        NttVector::new([make_ntt_poly(300), make_ntt_poly(400)].into());
    c.bench_function("ntt_vector_dot_k2", |bench| {
        bench.iter(|| black_box(black_box(&a2) * black_box(&b2)));
    });

    // K=3 (ML-KEM-768)
    let a3: NttVector<KyberField, U3> =
        NttVector::new([make_ntt_poly(100), make_ntt_poly(200), make_ntt_poly(300)].into());
    let b3: NttVector<KyberField, U3> =
        NttVector::new([make_ntt_poly(400), make_ntt_poly(500), make_ntt_poly(600)].into());
    c.bench_function("ntt_vector_dot_k3", |bench| {
        bench.iter(|| black_box(black_box(&a3) * black_box(&b3)));
    });

    // K=4 (ML-KEM-1024)
    let a4: NttVector<KyberField, U4> = NttVector::new(
        [
            make_ntt_poly(100),
            make_ntt_poly(200),
            make_ntt_poly(300),
            make_ntt_poly(400),
        ]
        .into(),
    );
    let b4: NttVector<KyberField, U4> = NttVector::new(
        [
            make_ntt_poly(500),
            make_ntt_poly(600),
            make_ntt_poly(700),
            make_ntt_poly(800),
        ]
        .into(),
    );
    c.bench_function("ntt_vector_dot_k4", |bench| {
        bench.iter(|| black_box(black_box(&a4) * black_box(&b4)));
    });
}

criterion_group!(benches, bench_ntt_vector_inner_product);
criterion_main!(benches);
