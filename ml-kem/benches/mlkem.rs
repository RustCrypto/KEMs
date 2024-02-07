use criterion::{criterion_group, criterion_main, Criterion};
use crypto_common::rand_core::CryptoRngCore;
use generic_array::{ArrayLength, GenericArray};
use ml_kem::*;

pub fn rand<L: ArrayLength>(rng: &mut impl CryptoRngCore) -> GenericArray<u8, L> {
    let mut val: GenericArray<u8, L> = Default::default();
    rng.fill_bytes(&mut val);
    val
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let d: B32 = rand(&mut rng);
    let z: B32 = rand(&mut rng);
    let m: B32 = rand(&mut rng);

    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    let dk_bytes = dk.as_bytes();
    let ek_bytes = ek.as_bytes();
    let (_sk, ct) = ek.encapsulate(&mut rng);

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let (dk, ek) = <MlKem768 as KemCore>::generate_deterministic(&d, &z);
            let _dk_bytes = dk.as_bytes();
            let _ek_bytes = ek.as_bytes();
        })
    });

    // Encapsulation
    c.bench_function("encapsulate", |b| {
        b.iter(|| {
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
            ek.encapsulate_deterministic(&m);
        })
    });

    // Decapsulation
    c.bench_function("decapsulate", |b| {
        b.iter(|| {
            let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_bytes);
            dk.decapsulate(&ct);
        })
    });

    // Round trip
    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let (dk, ek) = <MlKem768 as KemCore>::generate_deterministic(&d, &z);
            let (_sk, ct) = ek.encapsulate(&mut rng);
            dk.decapsulate(&ct);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
