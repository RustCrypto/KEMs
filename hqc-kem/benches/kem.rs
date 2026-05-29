#![allow(missing_docs, unused_results)]
#![cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]

use criterion::{Criterion, criterion_group, criterion_main};
use hqc_kem::{hqc128, hqc192, hqc256};

fn bench_keygen(c: &mut Criterion) {
    let mut rng = rand::rng();

    c.bench_function("keygen_128", |b| b.iter(|| hqc128::generate_key(&mut rng)));
    c.bench_function("keygen_192", |b| b.iter(|| hqc192::generate_key(&mut rng)));
    c.bench_function("keygen_256", |b| b.iter(|| hqc256::generate_key(&mut rng)));
}

fn bench_encaps(c: &mut Criterion) {
    let mut rng = rand::rng();
    let (ek128, _) = hqc128::generate_key(&mut rng);
    let (ek192, _) = hqc192::generate_key(&mut rng);
    let (ek256, _) = hqc256::generate_key(&mut rng);

    c.bench_function("encaps_128", |b| b.iter(|| ek128.encapsulate(&mut rng)));
    c.bench_function("encaps_192", |b| b.iter(|| ek192.encapsulate(&mut rng)));
    c.bench_function("encaps_256", |b| b.iter(|| ek256.encapsulate(&mut rng)));
}

fn bench_decaps(c: &mut Criterion) {
    let mut rng = rand::rng();
    let (ek128, dk128) = hqc128::generate_key(&mut rng);
    let (ek192, dk192) = hqc192::generate_key(&mut rng);
    let (ek256, dk256) = hqc256::generate_key(&mut rng);
    let (ct128, _) = ek128.encapsulate(&mut rng);
    let (ct192, _) = ek192.encapsulate(&mut rng);
    let (ct256, _) = ek256.encapsulate(&mut rng);

    c.bench_function("decaps_128", |b| b.iter(|| dk128.decapsulate(&ct128)));
    c.bench_function("decaps_192", |b| b.iter(|| dk192.decapsulate(&ct192)));
    c.bench_function("decaps_256", |b| b.iter(|| dk256.decapsulate(&ct256)));
}

criterion_group!(benches, bench_keygen, bench_encaps, bench_decaps);
criterion_main!(benches);
