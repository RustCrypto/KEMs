use crate::{DhDecapsulator, DhEncapsulator, DhKem};
use core::convert::Infallible;
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRng;
use x25519::{PublicKey, ReusableSecret, SharedSecret};

/// X22519 Diffie-Hellman KEM adapter.
///
/// Implements a KEM interface that internally uses X25519 ECDH.
pub struct X25519Kem;

impl Encapsulate<PublicKey, SharedSecret> for DhEncapsulator<PublicKey> {
    type Error = Infallible;

    fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey, SharedSecret), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);

        Ok((pk, ss))
    }
}

impl Decapsulate<PublicKey, SharedSecret> for DhDecapsulator<ReusableSecret> {
    type Error = Infallible;

    fn decapsulate(&self, encapsulated_key: &PublicKey) -> Result<SharedSecret, Self::Error> {
        let ss = self.0.diffie_hellman(encapsulated_key);

        Ok(ss)
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
