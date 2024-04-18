use crate::{DhKem, DhKemProxy};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;
use x25519::{PublicKey, ReusableSecret, SharedSecret};

pub struct X25519;

impl Encapsulate<DhKemProxy<PublicKey>, DhKemProxy<SharedSecret>> for DhKemProxy<PublicKey> {
    type Error = ();

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(DhKemProxy<PublicKey>, DhKemProxy<SharedSecret>), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);

        Ok((DhKemProxy(pk), DhKemProxy(ss)))
    }
}

impl Decapsulate<DhKemProxy<PublicKey>, DhKemProxy<SharedSecret>> for DhKemProxy<ReusableSecret> {
    type Error = ();

    fn decapsulate(
        &self,
        encapsulated_key: &DhKemProxy<PublicKey>,
    ) -> Result<DhKemProxy<SharedSecret>, Self::Error> {
        let ss = self.0.diffie_hellman(&encapsulated_key.0);

        Ok(DhKemProxy(ss))
    }
}

impl DhKem for X25519 {
    type DecapsulatingKey = DhKemProxy<ReusableSecret>;
    type EncapsulatingKey = DhKemProxy<PublicKey>;
    type EncapsulatedKey = DhKemProxy<PublicKey>;
    type SharedSecret = DhKemProxy<SharedSecret>;

    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);

        (DhKemProxy(sk), DhKemProxy(pk))
    }
}
