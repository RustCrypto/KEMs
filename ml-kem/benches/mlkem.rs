use ::kem::{Decapsulate, Encapsulate};
use criterion::{Criterion, criterion_group, criterion_main};
use ml_kem::*;

fn criterion_benchmark(c: &mut Criterion) {
    let mut rng = rand::rng();

    // Key generation
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let (dk, ek) = <MlKem768 as KemCore>::generate(&mut rng);
            let _dk_bytes = dk.as_bytes();
            let _ek_bytes = ek.as_bytes();
        })
    });

    let (dk, ek) = MlKem768::generate(&mut rng);
    let dk_bytes = dk.as_bytes();
    let ek_bytes = ek.as_bytes();

    let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);
    // Encapsulation
    c.bench_function("encapsulate", |b| {
        b.iter(|| ek.encapsulate(&mut rng).unwrap())
    });
    let (ct, _ss) = ek.encapsulate(&mut rng).unwrap();

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
            let (dk, ek) = <MlKem768 as KemCore>::generate(&mut rng);
            let (ct, _sk) = ek.encapsulate(&mut rng).unwrap();
            dk.decapsulate(&ct).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
