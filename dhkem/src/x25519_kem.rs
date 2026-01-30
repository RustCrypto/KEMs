use crate::{DecapsulationKey, EncapsulationKey};
use kem::{
    Decapsulate, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeySizeUser, TryKeyInit,
    common::array::Array, consts::U32,
};
use rand_core::{CryptoRng, TryCryptoRng, UnwrapErr};
use x25519::{PublicKey, ReusableSecret};

/// Elliptic Curve Diffie-Hellman Decapsulation Key (i.e. secret decryption key)
///
/// Generic around an elliptic curve `C`.
pub type X25519DecapsulationKey = DecapsulationKey<ReusableSecret, PublicKey>;

/// Elliptic Curve Diffie-Hellman Encapsulation Key (i.e. public encryption key)
///
/// Generic around an elliptic curve `C`.
pub type X25519EncapsulationKey = EncapsulationKey<PublicKey>;

/// X25519 ciphertexts are compressed Montgomery x/u-coordinates.
type Ciphertext = Array<u8, U32>;

/// X25519 shared secrets are also compressed Montgomery x/u-coordinates.
type SharedKey = Array<u8, U32>;

/// X22519 Diffie-Hellman KEM adapter.
///
/// Implements a KEM interface that internally uses X25519 ECDH.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct X25519Kem;

impl Kem for X25519Kem {
    type DecapsulationKey = X25519DecapsulationKey;
    type EncapsulationKey = X25519EncapsulationKey;
    type CiphertextSize = U32;
    type SharedKeySize = U32;
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For X25519 and X448, the SerializePublicKey() and
/// > DeserializePublicKey() functions are the identity function, since
/// > these curves already use fixed-length byte strings for public keys.
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
impl KeySizeUser for X25519EncapsulationKey {
    type KeySize = U32;
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For X25519 and X448, the SerializePublicKey() and
/// > DeserializePublicKey() functions are the identity function, since
/// > these curves already use fixed-length byte strings for public keys.
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
impl TryKeyInit for X25519EncapsulationKey {
    fn new(encapsulation_key: &Key<Self>) -> Result<Self, InvalidKey> {
        Ok(Self(PublicKey::from(encapsulation_key.0)))
    }
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For X25519 and X448, the SerializePublicKey() and
/// > DeserializePublicKey() functions are the identity function, since
/// > these curves already use fixed-length byte strings for public keys.
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
impl KeyExport for X25519EncapsulationKey {
    fn to_bytes(&self) -> Key<Self> {
        self.0.to_bytes().into()
    }
}

impl Generate for X25519DecapsulationKey {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // TODO(tarcieri): don't panic! Fallible `ReusableSecret` generation?
        Ok(Self::from(ReusableSecret::random_from_rng(&mut UnwrapErr(
            rng,
        ))))
    }
}

impl Encapsulate<X25519Kem> for X25519EncapsulationKey {
    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext, SharedKey)
    where
        R: CryptoRng + ?Sized,
    {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);
        (pk.to_bytes().into(), ss.to_bytes().into())
    }
}

impl Decapsulate<X25519Kem> for X25519DecapsulationKey {
    fn decapsulate(&self, encapsulated_key: &Ciphertext) -> SharedKey {
        let public_key = PublicKey::from(encapsulated_key.0);
        self.dk.diffie_hellman(&public_key).to_bytes().into()
    }
}
