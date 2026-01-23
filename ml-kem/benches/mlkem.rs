use ::kem::{Decapsulate, Decapsulator, Encapsulate, Generate};
use criterion::{Criterion, criterion_group, criterion_main};
use getrandom::SysRng;
use ml_kem::*;
use rand_core::TryRngCore;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = SysRng.unwrap_err();

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let dk = ml_kem_768::DecapsulationKey::generate_from_rng(&mut rng);
            let _dk_bytes = dk.to_encoded_bytes();
            let _ek_bytes = dk.encapsulator().to_encoded_bytes();
        })
    });

    let dk = ml_kem_768::DecapsulationKey::generate_from_rng(&mut rng);
    let dk_bytes = dk.to_encoded_bytes();
    let ek_bytes = dk.encapsulator().to_encoded_bytes();
    let ek = ml_kem_768::EncapsulationKey::from_encoded_bytes(&ek_bytes).unwrap();

    // Encapsulation
    c.bench_function("encapsulate", |b| {
        b.iter(|| ek.encapsulate_with_rng(&mut rng).unwrap())
    });
    let (ct, _ss) = ek.encapsulate_with_rng(&mut rng).unwrap();

    // Decapsulation
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_encoded_bytes(&dk_bytes).unwrap();

    c.bench_function("decapsulate", |b| {
        b.iter(|| {
            dk.decapsulate(&ct);
        })
    });

    // Round trip
    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let dk = ml_kem_768::DecapsulationKey::generate_from_rng(&mut rng);
            let ek = dk.encapsulator();
            let (ct, _sk) = ek.encapsulate_with_rng(&mut rng).unwrap();
            dk.decapsulate(&ct);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
