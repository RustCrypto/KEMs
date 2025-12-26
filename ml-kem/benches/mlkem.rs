use ::kem::{Decapsulate, Encapsulate, Generate};
use criterion::{Criterion, criterion_group, criterion_main};
use getrandom::SysRng;
use ml_kem::*;
use rand_core::TryRngCore;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = SysRng.unwrap_err();

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let dk = ml_kem_768::DecapsulationKey::from_rng(&mut rng);
            let _dk_bytes = dk.as_bytes();
            let _ek_bytes = dk.encapsulator().as_bytes();
        })
    });

    let dk = ml_kem_768::DecapsulationKey::from_rng(&mut rng);
    let dk_bytes = dk.as_bytes();
    let ek_bytes = dk.encapsulator().as_bytes();

    let ek = ml_kem_768::EncapsulationKey::from_bytes(&ek_bytes);
    // Encapsulation
    c.bench_function("encapsulate", |b| {
        b.iter(|| ek.encapsulate_with_rng(&mut rng).unwrap())
    });
    let (ct, _ss) = ek.encapsulate_with_rng(&mut rng).unwrap();

    // Decapsulation
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_bytes);
    c.bench_function("decapsulate", |b| {
        b.iter(|| {
            dk.decapsulate(&ct).unwrap();
        })
    });

    // Round trip
    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let dk = ml_kem_768::DecapsulationKey::from_rng(&mut rng);
            let ek = dk.encapsulator();
            let (ct, _sk) = ek.encapsulate_with_rng(&mut rng).unwrap();
            dk.decapsulate(&ct).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
