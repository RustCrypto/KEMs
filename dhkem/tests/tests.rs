#![cfg(any(
    feature = "k256",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "x25519"
))]

use kem::{Decapsulator, Encapsulate, Generate, TryDecapsulate};

fn test_kem<DK: Decapsulator + Generate + TryDecapsulate>() {
    let dk = DK::generate();
    let ek = dk.encapsulator();
    let (ek, ss1) = ek.encapsulate();
    let ss2 = dk.try_decapsulate(&ek).unwrap();
    assert_eq!(ss1.as_slice(), ss2.as_slice());
}

#[cfg(feature = "x25519")]
#[test]
fn test_x25519() {
    test_kem::<dhkem::X25519DecapsulationKey>();
}

#[cfg(feature = "k256")]
#[test]
fn test_k256() {
    test_kem::<dhkem::Secp256k1DecapsulationKey>();
}

#[cfg(feature = "p256")]
#[test]
fn test_p256() {
    test_kem::<dhkem::NistP256DecapsulationKey>();
}

#[cfg(feature = "p384")]
#[test]
fn test_p384() {
    test_kem::<dhkem::NistP384DecapsulationKey>();
}

#[cfg(feature = "p521")]
#[test]
fn test_p521() {
    test_kem::<dhkem::NistP521DecapsulationKey>();
}
