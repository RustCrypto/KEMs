//! API-surface tests: byte-conversion validation and bounded-stack execution.
#![cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]

use hqc_kem::{Ciphertext, DecapsulationKey, EncapsulationKey, HqcKem, HqcParams, SharedSecret};

/// TryFrom must accept correct-length input and reject wrong-length input.
fn try_from_roundtrip<P: HqcParams>() {
    let seed = [0x42u8; 32];
    let (ek, dk) = HqcKem::<P>::generate_key_deterministic(&seed);
    let (ct, ss) = ek
        .encapsulate_deterministic(&vec![0xabu8; P::params().k], &[0xcdu8; 16])
        .expect("valid message size");

    // Correct length → Ok, contents preserved
    let ek2 = EncapsulationKey::<P>::try_from(ek.as_ref()).expect("correct-length pk accepted");
    assert_eq!(ek2.as_ref(), ek.as_ref());
    let dk2 = DecapsulationKey::<P>::try_from(dk.as_ref()).expect("correct-length sk accepted");
    assert_eq!(dk2.as_ref(), dk.as_ref());
    let ct2 = Ciphertext::<P>::try_from(ct.as_ref()).expect("correct-length ct accepted");
    assert_eq!(ct2.as_ref(), ct.as_ref());
    let ss2 = SharedSecret::<P>::try_from(ss.as_ref()).expect("correct-length ss accepted");
    assert_eq!(ss2.as_ref(), ss.as_ref());

    // Restored keys still work end-to-end
    let ss3 = dk2.decapsulate(&ct2);
    assert_eq!(ss3.as_ref(), ss.as_ref());

    // Wrong lengths → Err (truncated, extended, empty)
    for bad in [&ek.as_ref()[..P::PK_BYTES - 1], &[0u8; 0][..]] {
        assert!(
            EncapsulationKey::<P>::try_from(bad).is_err(),
            "wrong-length pk rejected"
        );
    }
    let mut too_long = ek.as_ref().to_vec();
    too_long.push(0);
    assert!(EncapsulationKey::<P>::try_from(too_long.as_slice()).is_err());

    assert!(DecapsulationKey::<P>::try_from(&dk.as_ref()[..P::SK_BYTES - 1]).is_err());
    assert!(Ciphertext::<P>::try_from(&ct.as_ref()[..P::CT_BYTES - 1]).is_err());
    assert!(SharedSecret::<P>::try_from(&ss.as_ref()[..31]).is_err());
}

#[test]
fn try_from_roundtrip_128() {
    try_from_roundtrip::<hqc_kem::Hqc128Params>();
}

#[test]
fn try_from_roundtrip_192() {
    try_from_roundtrip::<hqc_kem::Hqc192Params>();
}

#[test]
fn try_from_roundtrip_256() {
    try_from_roundtrip::<hqc_kem::Hqc256Params>();
}

/// All three operations complete inside a bounded-stack thread (no_alloc proof
/// of bounded memory). Bounds are documented Phase-1 budgets; Phase 2
/// (in-place accumulated Karatsuba) removes the 8n-word scratch and tightens
/// them substantially.
fn stack_probe<P: HqcParams + Send + 'static>(stack_bytes: usize) {
    // Budgets are calibrated for optimized builds. Debug builds use several
    // times more stack (no inlining, no stack-slot reuse) and overflow the
    // tight bounds, so scale them up — 16x is deliberate slack, not a measured
    // bound; the release-mode cross job still enforces the documented budgets.
    let stack_bytes = if cfg!(debug_assertions) {
        stack_bytes * 16
    } else {
        stack_bytes
    };
    std::thread::Builder::new()
        .stack_size(stack_bytes)
        .spawn(|| {
            let seed = [7u8; 32];
            let (ek, dk) = HqcKem::<P>::generate_key_deterministic(&seed);
            let (ct, ss1) = ek
                .encapsulate_deterministic(&vec![1u8; P::params().k], &[2u8; 16])
                .expect("valid message size");
            let ss2 = dk.decapsulate(&ct);
            assert_eq!(ss1.as_ref(), ss2.as_ref());
        })
        .expect("spawn probe thread")
        .join()
        .expect("bounded-stack run completed");
}

/// Corrupted ciphertext must trigger implicit rejection: no panic, no error,
/// and a shared secret different from the honest one.
fn implicit_rejection<P: HqcParams>() {
    let seed = [0x33u8; 32];
    let (ek, dk) = HqcKem::<P>::generate_key_deterministic(&seed);
    let (ct, ss_honest) = ek
        .encapsulate_deterministic(&vec![0x44u8; P::params().k], &[0x55u8; 16])
        .expect("valid message size");

    for tamper_at in [0usize, P::CT_BYTES / 2, P::CT_BYTES - 1] {
        let mut bad = ct.as_ref().to_vec();
        bad[tamper_at] ^= 0x01;
        let bad_ct = Ciphertext::<P>::try_from(bad.as_slice()).expect("same length");
        let ss_rej = dk.decapsulate(&bad_ct);
        assert_ne!(
            ss_rej.as_ref(),
            ss_honest.as_ref(),
            "tampered ct at byte {tamper_at} must not yield the honest secret"
        );
    }

    // Tampered dk_pke region yields a different secret for the honest ct.
    let mut bad_dk = dk.as_ref().to_vec();
    bad_dk[P::PK_BYTES] ^= 0x01; // dk_pke first byte
    let bad_dk = DecapsulationKey::<P>::try_from(bad_dk.as_slice()).expect("same length");
    let ss_wrong = bad_dk.decapsulate(&ct);
    assert_ne!(
        ss_wrong.as_ref(),
        ss_honest.as_ref(),
        "tampered dk_pke must change output"
    );
}

#[test]
fn implicit_rejection_128() {
    implicit_rejection::<hqc_kem::Hqc128Params>();
}

#[test]
fn implicit_rejection_192() {
    implicit_rejection::<hqc_kem::Hqc192Params>();
}

#[test]
fn implicit_rejection_256() {
    implicit_rejection::<hqc_kem::Hqc256Params>();
}

#[test]
fn stack_budget_128() {
    stack_probe::<hqc_kem::Hqc128Params>(96 * 1024);
}

#[test]
fn stack_budget_192() {
    stack_probe::<hqc_kem::Hqc192Params>(256 * 1024);
}

#[test]
fn stack_budget_256() {
    stack_probe::<hqc_kem::Hqc256Params>(384 * 1024);
}
