//! ML-KEM benchmarks.
//!
//! All inputs are fixed byte strings so that no RNG or system call runs inside a timed region,
//! and every output is passed through `black_box` so that no work can be optimized away.

#![allow(missing_docs, clippy::unwrap_used)]

use ::kem::{Decapsulate, KeyExport, KeyInit};
use core::hint::black_box;
use criterion::{Criterion, criterion_group, criterion_main};
use ml_kem::*;

/// Benchmark every public operation of one parameter set.
macro_rules! bench_parameter_set {
    ($c:expr, $name:literal, $module:ident) => {{
        type Dk = $module::DecapsulationKey;
        type Ek = $module::EncapsulationKey;

        let seed = Seed::from([0x5a; 64]);
        let m = B32::from([0xa5; 32]);

        let dk = Dk::new(&seed);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let ek = Ek::new(&ek_bytes).unwrap();
        let (ct, _) = ek.encapsulate_deterministic(&m);
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;

        let mut group = $c.benchmark_group($name);

        // Algorithm 19 (deterministic part): expand a seed into a decapsulation key.
        group.bench_function("keygen", |b| {
            b.iter(|| Dk::new(black_box(&seed)));
        });

        // FIPS 203 §7.2 input checks plus H(ek).
        group.bench_function("ek_parse", |b| {
            b.iter(|| Ek::new(black_box(&ek_bytes)).unwrap());
        });

        // Algorithm 17 with a fixed message.
        group.bench_function("encapsulate", |b| {
            b.iter(|| ek.encapsulate_deterministic(black_box(&m)));
        });

        // Algorithm 18 on a valid ciphertext.
        group.bench_function("decapsulate", |b| {
            b.iter(|| dk.decapsulate(black_box(&ct)));
        });

        // Algorithm 18 on an invalid ciphertext (implicit rejection). Must cost the same as the
        // valid case.
        group.bench_function("decapsulate_reject", |b| {
            b.iter(|| dk.decapsulate(black_box(&bad_ct)));
        });

        // One ephemeral exchange: key generation, encapsulation key parsing, encapsulation and
        // decapsulation.
        group.bench_function("round_trip", |b| {
            b.iter(|| {
                let dk = Dk::new(black_box(&seed));
                let ek = Ek::new(&dk.encapsulation_key().to_bytes()).unwrap();
                let (ct, k_send) = ek.encapsulate_deterministic(black_box(&m));
                (k_send, dk.decapsulate(&ct))
            });
        });

        group.finish();
    }};
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_parameter_set!(c, "ML-KEM-512", ml_kem_512);
    bench_parameter_set!(c, "ML-KEM-768", ml_kem_768);
    bench_parameter_set!(c, "ML-KEM-1024", ml_kem_1024);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
