use crate::{DhDecapsulator, DhEncapsulator, DhKem};
use kem::{
    Decapsulate, Encapsulate, InvalidKey, Key, KeyExport, KeySizeUser, TryKeyInit, consts::U32,
};
use rand_core::{CryptoRng, TryCryptoRng, UnwrapErr};
use x25519::{PublicKey, ReusableSecret, SharedSecret};

/// X22519 Diffie-Hellman KEM adapter.
///
/// Implements a KEM interface that internally uses X25519 ECDH.
pub struct X25519Kem;

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For X25519 and X448, the SerializePublicKey() and
/// > DeserializePublicKey() functions are the identity function, since
/// > these curves already use fixed-length byte strings for public keys.
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
impl KeySizeUser for DhEncapsulator<PublicKey> {
    type KeySize = U32;
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For X25519 and X448, the SerializePublicKey() and
/// > DeserializePublicKey() functions are the identity function, since
/// > these curves already use fixed-length byte strings for public keys.
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
impl TryKeyInit for DhEncapsulator<PublicKey> {
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
impl KeyExport for DhEncapsulator<PublicKey> {
    fn to_bytes(&self) -> Key<Self> {
        self.0.to_bytes().into()
    }
}

impl Encapsulate<PublicKey, SharedSecret> for DhEncapsulator<PublicKey> {
    fn encapsulate_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey, SharedSecret), R::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = ReusableSecret::random_from_rng(&mut UnwrapErr(rng));
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);

        Ok((pk, ss))
    }
}

impl Decapsulate<PublicKey, SharedSecret> for DhDecapsulator<ReusableSecret> {
    type Encapsulator = DhEncapsulator<PublicKey>;

    fn decapsulate(&self, encapsulated_key: &PublicKey) -> SharedSecret {
        self.0.diffie_hellman(encapsulated_key)
    }

    fn encapsulator(&self) -> DhEncapsulator<PublicKey> {
        DhEncapsulator(PublicKey::from(&self.0))
    }
}

impl DhKem for X25519Kem {
    type DecapsulatingKey = DhDecapsulator<ReusableSecret>;
    type EncapsulatingKey = DhEncapsulator<PublicKey>;
    type EncapsulatedKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn random_keypair<R: CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);

        (DhDecapsulator(sk), DhEncapsulator(pk))
    }
}
