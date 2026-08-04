#![allow(missing_docs)]
#![cfg(feature = "dcap")]

use sntrup_kem::*;

/// IETF draft-josefsson-ntruprime-streamlined-00, test vector 0 (sntrup761).
#[test]
fn kat0_decapsulation_761() {
    let sk_hex = include_str!("data/kat0_sk.hex");
    let ct_hex = include_str!("data/kat0_ct.hex");
    let ss_hex = include_str!("data/kat0_ss.hex");

    let sk = sntrup761::DecapsulationKey::try_from(
        hex::decode(sk_hex.trim())
            .expect("invalid SK hex")
            .as_slice(),
    )
    .expect("SK size mismatch");

    let ct = sntrup761::Ciphertext::try_from(
        hex::decode(ct_hex.trim())
            .expect("invalid CT hex")
            .as_slice(),
    )
    .expect("CT size mismatch");

    let ss_expected = hex::decode(ss_hex.trim()).expect("invalid SS hex");
    let ss = sk.decapsulate(&ct);
    assert_eq!(ss.as_ref(), &ss_expected[..], "KAT0 shared secret mismatch");
}

/// IETF draft-josefsson-ntruprime-streamlined-00, test vector 1 (sntrup761).
#[test]
fn kat1_decapsulation_761() {
    let sk_hex = include_str!("data/kat1_sk.hex");
    let ct_hex = include_str!("data/kat1_ct.hex");
    let ss_hex = include_str!("data/kat1_ss.hex");

    let sk = sntrup761::DecapsulationKey::try_from(
        hex::decode(sk_hex.trim())
            .expect("invalid SK hex")
            .as_slice(),
    )
    .expect("SK size mismatch");

    let ct = sntrup761::Ciphertext::try_from(
        hex::decode(ct_hex.trim())
            .expect("invalid CT hex")
            .as_slice(),
    )
    .expect("CT size mismatch");

    let ss_expected = hex::decode(ss_hex.trim()).expect("invalid SS hex");
    let ss = sk.decapsulate(&ct);
    assert_eq!(ss.as_ref(), &ss_expected[..], "KAT1 shared secret mismatch");
}
