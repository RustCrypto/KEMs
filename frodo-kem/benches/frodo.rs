use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::Measurement,
};
use frodo_kem::*;
use rand_core::SeedableRng;

fn bench_keygen<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    group.bench_function("KeyGen 640Aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::FrodoKem640Aes.generate_keypair(&mut rng);
        });
    });

    group.bench_function("KeyGen 976Aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::FrodoKem976Aes.generate_keypair(&mut rng);
        });
    });

    group.bench_function("KeyGen 1344Aes", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::FrodoKem1344Aes.generate_keypair(&mut rng);
        });
    });

    group.bench_function("KeyGen 640Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::FrodoKem640Shake.generate_keypair(&mut rng);
        });
    });

    group.bench_function("KeyGen 976Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::FrodoKem976Shake.generate_keypair(&mut rng);
        });
    });

    group.bench_function("KeyGen 1344Shake", |b| {
        b.iter(|| {
            let (_pk, _sk) = Algorithm::FrodoKem1344Shake.generate_keypair(&mut rng);
        });
    });
}

fn bench_encapsulate<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    let (pk, _sk) = Algorithm::FrodoKem640Aes.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 640Aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::FrodoKem640Aes
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });

    let (pk, _sk) = Algorithm::FrodoKem976Aes.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 976Aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::FrodoKem976Aes
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });

    let (pk, _sk) = Algorithm::FrodoKem1344Aes.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 1344Aes", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::FrodoKem1344Aes
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });

    let (pk, _sk) = Algorithm::FrodoKem640Shake.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 640Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::FrodoKem640Shake
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });

    let (pk, _sk) = Algorithm::FrodoKem976Shake.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 976Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::FrodoKem976Shake
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });

    let (pk, _sk) = Algorithm::FrodoKem1344Shake.generate_keypair(&mut rng);
    group.bench_function("Encapsulate 1344Shake", |b| {
        b.iter(|| {
            let (_ct, _ss) = Algorithm::FrodoKem1344Shake
                .encapsulate_with_rng(&pk, &mut rng)
                .unwrap();
        });
    });
}

fn bench_decapsulate<M: Measurement>(group: &mut BenchmarkGroup<'_, M>) {
    let mut rng = rand_chacha::ChaCha8Rng::from_entropy();
    let (pk, sk) = Algorithm::FrodoKem640Aes.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::FrodoKem640Aes
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 640Aes", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::FrodoKem640Aes.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::FrodoKem976Aes.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::FrodoKem976Aes
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 976Aes", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::FrodoKem976Aes.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::FrodoKem1344Aes.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::FrodoKem1344Aes
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 1344Aes", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::FrodoKem1344Aes.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::FrodoKem640Shake.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::FrodoKem640Shake
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 640Shake", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::FrodoKem640Shake.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::FrodoKem976Shake.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::FrodoKem976Shake
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 976Shake", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::FrodoKem976Shake.decapsulate(&sk, &ct).unwrap();
        });
    });

    let (pk, sk) = Algorithm::FrodoKem1344Shake.generate_keypair(&mut rng);
    let (ct, _ss) = Algorithm::FrodoKem1344Shake
        .encapsulate_with_rng(&pk, &mut rng)
        .unwrap();
    group.bench_function("Decapsulate 1344Shake", |b| {
        b.iter(|| {
            let (_ss, _mu) = Algorithm::FrodoKem1344Shake.decapsulate(&sk, &ct).unwrap();
        });
    });
}

fn bench_against_liboqs(c: &mut Criterion) {
    let mut group = c.benchmark_group("FrodoKEM");
    bench_keygen(&mut group);
    bench_encapsulate(&mut group);
    bench_decapsulate(&mut group);
    group.finish();
}

criterion_group!(benches, bench_against_liboqs);
criterion_main!(benches);
