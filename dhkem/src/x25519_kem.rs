use crate::{DecapsulationKey, DhKem, EncapsulationKey};
use kem::{
    Decapsulate, Decapsulator, Encapsulate, Generate, InvalidKey, KemParams, Key, KeyExport,
    KeySizeUser, TryKeyInit, common::array::Array, consts::U32,
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
type SharedSecret = Array<u8, U32>;

/// X22519 Diffie-Hellman KEM adapter.
///
/// Implements a KEM interface that internally uses X25519 ECDH.
pub struct X25519Kem;

impl KemParams for EncapsulationKey<PublicKey> {
    type CiphertextSize = U32;
    type SharedSecretSize = U32;
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

impl Encapsulate for X25519EncapsulationKey {
    fn encapsulate_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret), R::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        // TODO(tarcieri): don't panic! Fallible `ReusableSecret` generation?
        let sk = ReusableSecret::random_from_rng(&mut UnwrapErr(rng));
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);
        Ok((pk.to_bytes().into(), ss.to_bytes().into()))
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

impl Decapsulate for X25519DecapsulationKey {
    fn decapsulate(&self, encapsulated_key: &Ciphertext) -> SharedSecret {
        let public_key = PublicKey::from(encapsulated_key.0);
        self.dk.diffie_hellman(&public_key).to_bytes().into()
    }
}

impl DhKem for X25519Kem {
    type DecapsulatingKey = X25519DecapsulationKey;
    type EncapsulatingKey = X25519EncapsulationKey;
    type EncapsulatedKey = Ciphertext;
    type SharedSecret = x25519::SharedSecret;

    fn random_keypair<R>(rng: &mut R) -> (Self::DecapsulatingKey, Self::EncapsulatingKey)
    where
        R: CryptoRng + ?Sized,
    {
        let dk = Self::DecapsulatingKey::generate_from_rng(rng);
        let ek = *dk.encapsulator();
        (dk, ek)
    }
}
