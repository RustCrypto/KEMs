#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use sntrup_kem::*;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    group.bench_function("sntrup761", |b| {
        let mut rng = rand::rng();
        b.iter(|| Sntrup761::generate_key(&mut rng));
    });

    group.bench_function("sntrup1277", |b| {
        let mut rng = rand::rng();
        b.iter(|| Sntrup1277::generate_key(&mut rng));
    });

    group.finish();
}

fn bench_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("encapsulate");

    group.bench_function("sntrup761", |b| {
        let mut rng = rand::rng();
        let (ek, _dk) = Sntrup761::generate_key(&mut rng);
        b.iter(|| ek.encapsulate(&mut rng));
    });

    group.bench_function("sntrup1277", |b| {
        let mut rng = rand::rng();
        let (ek, _dk) = Sntrup1277::generate_key(&mut rng);
        b.iter(|| ek.encapsulate(&mut rng));
    });

    group.finish();
}

fn bench_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("decapsulate");

    group.bench_function("sntrup761", |b| {
        let mut rng = rand::rng();
        let (ek, dk) = Sntrup761::generate_key(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng);
        b.iter(|| dk.decapsulate(&ct));
    });

    group.bench_function("sntrup1277", |b| {
        let mut rng = rand::rng();
        let (ek, dk) = Sntrup1277::generate_key(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng);
        b.iter(|| dk.decapsulate(&ct));
    });

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encapsulate, bench_decapsulate);
criterion_main!(benches);
