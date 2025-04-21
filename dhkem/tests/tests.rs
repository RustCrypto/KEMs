use dhkem::DhKem;
use kem::{Decapsulate, Encapsulate};
use rand::rng;

trait SecretBytes {
    fn as_slice(&self) -> &[u8];
}

#[cfg(feature = "x25519")]
impl SecretBytes for x25519::SharedSecret {
    fn as_slice(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }
}

#[cfg(feature = "ecdh")]
impl<C> SecretBytes for elliptic_curve::ecdh::SharedSecret<C>
where
    C: elliptic_curve::CurveArithmetic,
{
    fn as_slice(&self) -> &[u8] {
        self.raw_secret_bytes().as_slice()
    }
}

// we need this because if the crate is compiled with no features this function never
// gets used
#[allow(dead_code)]
fn test_kem<K: DhKem>()
where
    <K as DhKem>::SharedSecret: SecretBytes,
{
    let mut rng = rng();
    let (sk, pk) = K::random_keypair(&mut rng);
    let (ek, ss1) = pk.encapsulate(&mut rng).expect("never fails");
    let ss2 = sk.decapsulate(&ek).expect("never fails");

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
