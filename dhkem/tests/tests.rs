#![cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "x25519"
))]

use kem::{Encapsulate, Generate, Kem, TryDecapsulate};

fn test_kem<K: Kem>() {
    let dk = K::DecapsulationKey::generate();
    let ek = dk.as_ref().clone();
    let (ek, ss1) = ek.encapsulate();
    let ss2 = dk.try_decapsulate(&ek).unwrap();
    assert_eq!(ss1.as_slice(), ss2.as_slice());
}

#[cfg(feature = "x25519")]
#[test]
fn test_x25519() {
    test_kem::<dhkem::X25519Kem>();
}

#[cfg(feature = "k256")]
#[test]
fn test_k256() {
    test_kem::<dhkem::Secp256k1Kem>();
}

#[cfg(feature = "p256")]
#[test]
fn test_p256() {
    test_kem::<dhkem::NistP256Kem>();
}

#[cfg(feature = "p384")]
#[test]
fn test_p384() {
    test_kem::<dhkem::NistP384Kem>();
}

#[cfg(feature = "p521")]
#[test]
fn test_p521() {
    test_kem::<dhkem::NistP521Kem>();
}
