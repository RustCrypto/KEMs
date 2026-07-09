//! KEM which uses the X25519 Diffie-Hellman function.

use crate::{DecapsulationKey, EncapsulationKey, Error, HpkeKemId};
use ctutils::CtEq;
use kem::{
    Decapsulator, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeyInit, KeySizeUser,
    TryDecapsulate, TryKeyInit,
    common::array::{Array, sizes::U32},
};
use rand_core::{CryptoRng, TryCryptoRng};
use x25519::{PublicKey, StaticSecret};

#[cfg(doc)]
use crate::Expander;

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

impl HpkeKemId for X25519Kem {
    const KEM_ID: u16 = 0x20;
}

/// Elliptic Curve Diffie-Hellman Decapsulation Key (i.e. secret decryption key)
///
/// Generic around an elliptic curve `C`.
pub type X25519DecapsulationKey = DecapsulationKey<StaticSecret, PublicKey>;

impl Decapsulator for X25519DecapsulationKey {
    type Kem = X25519Kem;

    fn encapsulation_key(&self) -> &X25519EncapsulationKey {
        &self.ek
    }
}

impl KeySizeUser for X25519DecapsulationKey {
    type KeySize = U32;
}

/// From [RFC9810 §7.1.2]: `SerializePrivateKey` and `DeserializePrivateKey`:
///
/// > For X25519 and X448, private keys are identical to their byte string representation,
/// > so little processing has to be done. [...]
/// > DeserializePrivateKey() function MUST clamp its input
///
/// [RFC9810 §7.1.2]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.2
impl KeyInit for X25519DecapsulationKey {
    fn new(key: &Key<Self>) -> Self {
        StaticSecret::from(key.0).into()
    }
}

/// From [RFC9810 §7.1.2]: `SerializePrivateKey` and `DeserializePrivateKey`:
///
/// > For X25519 and X448, private keys are identical to their byte string representation,
/// > so little processing has to be done. The SerializePrivateKey() function MUST clamp its output
///
/// [RFC9810 §7.1.2]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.2
impl KeyExport for X25519DecapsulationKey {
    fn to_bytes(&self) -> Key<Self> {
        self.dk.to_bytes().into()
    }
}

impl Generate for X25519DecapsulationKey {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let key = Key::<Self>::try_generate_from_rng(rng)?;
        Ok(StaticSecret::from(key.0).into())
    }
}

/// <div class="warning">
/// <b><code>SharedKey</code> is non-uniform raw ECDH output!</b>
///
/// The resulting `SharedKey` is the non-uniform raw output of the Elliptic Curve Diffie-Hellman
/// operation (i.e. coordinate of an elliptic curve point).
///
/// To produce something suitable for e.g. symmetric key(s), use the [`Expander`] type to derive
/// output keys.
/// </div>
impl TryDecapsulate for X25519DecapsulationKey {
    type Error = Error;

    #[inline]
    fn try_decapsulate(&self, encapsulated_key: &Ciphertext) -> Result<SharedKey, Error> {
        let public_key = PublicKey::from(encapsulated_key.0);
        let sk = self.dk.diffie_hellman(&public_key).to_bytes();

        // From RFC9810 §7.1.4. Validation of Inputs and Outputs:
        // > For X25519 and X448, public keys and Diffie-Hellman outputs MUST be validated as
        // > described in RFC7748. In particular, recipients MUST check whether the Diffie-Hellman
        // > shared secret is the all-zero value and abort if so.
        if sk.ct_eq(&[0u8; 32]).into() {
            return Err(Error::Decapsulation);
        }

        Ok(sk.into())
    }
}

/// Elliptic Curve Diffie-Hellman Encapsulation Key (i.e. public encryption key)
///
/// Generic around an elliptic curve `C`.
pub type X25519EncapsulationKey = EncapsulationKey<PublicKey>;

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

/// <div class="warning">
/// <b><code>SharedKey</code> is non-uniform raw ECDH output!</b>
///
/// The resulting `SharedKey` is the non-uniform raw output of the Elliptic Curve Diffie-Hellman
/// operation (i.e. coordinate of an elliptic curve point).
///
/// To produce something suitable for e.g. symmetric key(s), use the [`Expander`] type to derive
/// output keys.
/// </div>
impl Encapsulate for X25519EncapsulationKey {
    type Kem = X25519Kem;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext, SharedKey)
    where
        R: CryptoRng + ?Sized,
    {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = StaticSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);
        (pk.to_bytes().into(), ss.to_bytes().into())
    }
}
