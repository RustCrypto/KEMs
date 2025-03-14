//! Benchmarking FrodoKEM against liboqs
use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use frodo_kem::*;
use rand_core::SeedableRng;

fn bench_keygen<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    group.bench_function("KeyGen 640Aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::EphemeralFrodoKem640Aes.generate_keypair(&mut rng);
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Aes).unwrap();
    group.bench_function("liboqs 640aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = kem.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen 976Aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::EphemeralFrodoKem976Aes.generate_keypair(&mut rng);
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Aes).unwrap();
    group.bench_function("liboqs 976aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = kem.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen 1344Aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::EphemeralFrodoKem1344Aes.generate_keypair(&mut rng);
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem1344Aes).unwrap();
    group.bench_function("liboqs 1344aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = kem.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen 640Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::EphemeralFrodoKem640Shake.generate_keypair(&mut rng);
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Shake).unwrap();
    group.bench_function("liboqs 640Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = kem.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen 976Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::EphemeralFrodoKem976Shake.generate_keypair(&mut rng);
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Shake).unwrap();
    group.bench_function("liboqs 976Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = kem.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen 1344Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::EphemeralFrodoKem1344Shake.generate_keypair(&mut rng);
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem1344Shake).unwrap();
    group.bench_function("liboqs 1344Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = kem.keypair().unwrap();
        });
    });
}

fn bench_encapsulate<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    let (pk, _sk) = Algorithm::EphemeralFrodoKem640Aes.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 640Aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::EphemeralFrodoKem640Aes
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Aes).unwrap();
    let (pk, _sk) = kem.keypair().unwrap();
    group.bench_function("liboqs encapsulate 640aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = kem.encapsulate(&pk).unwrap();
        });
    });

    let (pk, _sk) = Algorithm::EphemeralFrodoKem976Aes.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 976Aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::EphemeralFrodoKem976Aes
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Aes).unwrap();
    let (pk, _sk) = kem.keypair().unwrap();
    group.bench_function("liboqs encapsulate 976aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = kem.encapsulate(&pk).unwrap();
        });
    });

    let (pk, _sk) = Algorithm::EphemeralFrodoKem1344Aes.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 1344Aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::EphemeralFrodoKem1344Aes
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem1344Aes).unwrap();
    let (pk, _sk) = kem.keypair().unwrap();
    group.bench_function("liboqs encapsulate 1344aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = kem.encapsulate(&pk).unwrap();
        });
    });

    let (pk, _sk) = Algorithm::EphemeralFrodoKem640Shake.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 640Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::EphemeralFrodoKem640Shake
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Shake).unwrap();
    let (pk, _sk) = kem.keypair().unwrap();
    group.bench_function("liboqs encapsulate 640Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = kem.encapsulate(&pk).unwrap();
        });
    });

    let (pk, _sk) = Algorithm::EphemeralFrodoKem976Shake.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 976Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::EphemeralFrodoKem976Shake
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Shake).unwrap();
    let (pk, _sk) = kem.keypair().unwrap();
    group.bench_function("liboqs encapsulate 976Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = kem.encapsulate(&pk).unwrap();
        });
    });

    let (pk, _sk) = Algorithm::EphemeralFrodoKem1344Shake.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 1344Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::EphemeralFrodoKem1344Shake
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem1344Shake).unwrap();
    let (pk, _sk) = kem.keypair().unwrap();
    group.bench_function("liboqs encapsulate 1344Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = kem.encapsulate(&pk).unwrap();
        });
    });
}

fn bench_decapsulate<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    let (pk, sk) = Algorithm::EphemeralFrodoKem640Aes.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::EphemeralFrodoKem640Aes
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 640Aes", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::EphemeralFrodoKem640Aes
                .decapsulate(&sk, &ct)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Aes).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, _ss) = kem.encapsulate(&pk).unwrap();
    group.bench_function("liboqs decapsulate 640aes", |b| {
        b.iter(|| {
            let _ss = kem.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::EphemeralFrodoKem976Aes.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::EphemeralFrodoKem976Aes
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 976Aes", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::EphemeralFrodoKem976Aes
                .decapsulate(&sk, &ct)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Aes).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, _ss) = kem.encapsulate(&pk).unwrap();
    group.bench_function("liboqs decapsulate 976aes", |b| {
        b.iter(|| {
            let _ss = kem.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::EphemeralFrodoKem1344Aes.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::EphemeralFrodoKem1344Aes
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 1344Aes", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::EphemeralFrodoKem1344Aes
                .decapsulate(&sk, &ct)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem1344Aes).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, _ss) = kem.encapsulate(&pk).unwrap();
    group.bench_function("liboqs decapsulate 1344aes", |b| {
        b.iter(|| {
            let _ss = kem.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::EphemeralFrodoKem640Shake.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::EphemeralFrodoKem640Shake
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 640Shake", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::EphemeralFrodoKem640Shake
                .decapsulate(&sk, &ct)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem640Shake).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, _ss) = kem.encapsulate(&pk).unwrap();
    group.bench_function("liboqs decapsulate 640Shake", |b| {
        b.iter(|| {
            let _ss = kem.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::EphemeralFrodoKem976Shake.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::EphemeralFrodoKem976Shake
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 976Shake", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::EphemeralFrodoKem976Shake
                .decapsulate(&sk, &ct)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem976Shake).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, _ss) = kem.encapsulate(&pk).unwrap();
    group.bench_function("liboqs decapsulate 976Shake", |b| {
        b.iter(|| {
            let _ss = kem.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::EphemeralFrodoKem1344Shake.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::EphemeralFrodoKem1344Shake
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 1344Shake", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::EphemeralFrodoKem1344Shake
                .decapsulate(&sk, &ct)
                .unwrap();
        });
    });
    let kem = safe_oqs::kem::Kem::new(safe_oqs::kem::Algorithm::FrodoKem1344Shake).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    let (ct, _ss) = kem.encapsulate(&pk).unwrap();
    group.bench_function("liboqs decapsulate 1344Shake", |b| {
        b.iter(|| {
            let _ss = kem.decapsulate(&sk, &ct).unwrap();
        });
    });
}

fn bench_against_liboqs(c: &mut Criterion) {
    let mut group = c.benchmark_group("eFrodoKEM");
    bench_keygen(&mut group);
    bench_encapsulate(&mut group);
    bench_decapsulate(&mut group);
    group.finish();
}

criterion_group!(benches, bench_against_liboqs);
criterion_main!(benches);
