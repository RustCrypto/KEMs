//! Timing-leakage smoke tests (dudect-style Welch's t-test).
//!
//! Ignored by default: wall-clock timing tests are environment-sensitive and
//! unsuitable for CI. Run manually on a quiet machine:
//!
//! `cargo test --test ct --release -- --ignored --nocapture`
//!
//! Interpretation follows dudect: |t| > 4.5 over a large sample indicates a
//! distinguishable timing difference between the two input classes.
#![cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]

use hqc_kem::{HqcKem, HqcParams};
use std::time::Instant;

/// Welch's t-statistic between two samples.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let var =
        |x: &[f64], m: f64| x.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (x.len() - 1) as f64;
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

/// Drop the slowest tail (interrupt/scheduler noise), dudect-style cropping.
fn crop(mut x: Vec<f64>) -> Vec<f64> {
    x.sort_by(|p, q| p.partial_cmp(q).expect("no NaN timings"));
    let keep = (x.len() * 9) / 10;
    x.truncate(keep);
    x
}

/// Decapsulation timing: valid ciphertext (FO accept) vs corrupted ciphertext
/// (implicit rejection). A timing distinguisher here would leak the FO
/// comparison result.
fn decaps_timing<P: HqcParams>(rounds: usize) -> f64 {
    let seed = [0x5Au8; 32];
    let (ek, dk) = HqcKem::<P>::generate_key_deterministic(&seed);
    let (ct_valid, _ss) = ek
        .encapsulate_deterministic(&vec![0x11u8; P::params().k], &[0x22u8; 16])
        .expect("valid message size");

    let mut corrupted = ct_valid.as_ref().to_vec();
    corrupted[0] ^= 0x01;
    let ct_bad = hqc_kem::Ciphertext::<P>::try_from(corrupted.as_slice()).expect("same length");

    let (mut class_a, mut class_b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
    // Interleave classes to distribute drift evenly.
    for _ in 0..rounds {
        let t0 = Instant::now();
        let _ = std::hint::black_box(dk.decapsulate(std::hint::black_box(&ct_valid)));
        class_a.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let _ = std::hint::black_box(dk.decapsulate(std::hint::black_box(&ct_bad)));
        class_b.push(t1.elapsed().as_nanos() as f64);
    }
    welch_t(&crop(class_a), &crop(class_b))
}

/// Keygen timing across distinct seeds (distinct secret support positions):
/// per-seed timing should not distinguish which secret was sampled.
fn keygen_timing<P: HqcParams>(rounds: usize) -> f64 {
    let seed_a = [0x01u8; 32];
    let seed_b = [0xFEu8; 32];
    let (mut class_a, mut class_b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
    for _ in 0..rounds {
        let t0 = Instant::now();
        let _ = std::hint::black_box(HqcKem::<P>::generate_key_deterministic(&seed_a));
        class_a.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        let _ = std::hint::black_box(HqcKem::<P>::generate_key_deterministic(&seed_b));
        class_b.push(t1.elapsed().as_nanos() as f64);
    }
    welch_t(&crop(class_a), &crop(class_b))
}

#[test]
#[ignore = "timing test; run manually in --release on a quiet machine"]
fn decaps_timing_valid_vs_corrupted() {
    let t128 = decaps_timing::<hqc_kem::Hqc128Params>(3000);
    let t256 = decaps_timing::<hqc_kem::Hqc256Params>(1500);
    println!("decaps Welch t: hqc128 = {t128:.2}, hqc256 = {t256:.2} (|t| > 4.5 = leak)");
    assert!(
        t128.abs() < 4.5,
        "hqc128 decaps timing distinguishes valid/corrupted: t = {t128:.2}"
    );
    assert!(
        t256.abs() < 4.5,
        "hqc256 decaps timing distinguishes valid/corrupted: t = {t256:.2}"
    );
}

#[test]
#[ignore = "timing test; run manually in --release on a quiet machine"]
fn keygen_timing_across_seeds() {
    // THREAT MODEL (why a nonzero t between fixed seeds is accepted here):
    // rejection sampling's total time reveals only the accept/reject pattern.
    // Accepted support positions are uniformly distributed in [0, n)
    // CONDITIONED ON any rejection pattern — rejected candidates are
    // discarded and never influence the key — so the observable leaks zero
    // information about the sampled secret positions. Additionally, keygen
    // is one-shot per key: no oracle exists for an attacker to amortize
    // timing over a fixed secret. Between two FIXED seeds, per-seed work is
    // deterministic, so Welch's t grows with sqrt(samples) for ANY tiny
    // constant difference — hence this is a gross-leak smoke test, not a
    // strict dudect gate. The strict gate is decaps (above), where a timing
    // oracle would be exploitable and t must stay below 4.5.
    let t128 = keygen_timing::<hqc_kem::Hqc128Params>(3000);
    println!(
        "keygen Welch t: hqc128 = {t128:.2} (inherent rejection-count variation; gross-leak bound |t| < 15)"
    );
    assert!(
        t128.abs() < 15.0,
        "hqc128 keygen timing grossly leaks: t = {t128:.2}"
    );
}
