use getrandom::SysRng;
use kem::{Decapsulator, Encapsulate, Generate, TryDecapsulate};

// we need this because if the crate is compiled with no features this function never
// gets used
#[allow(dead_code)]
fn test_kem<DK: Decapsulator + Generate + TryDecapsulate>() {
    let mut rng = SysRng;
    let dk = DK::try_generate_from_rng(&mut SysRng).unwrap();
    let ek = dk.encapsulator();
    let (ek, ss1) = ek.encapsulate_with_rng(&mut rng).unwrap();
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
