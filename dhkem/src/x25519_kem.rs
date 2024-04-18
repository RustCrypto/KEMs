use crate::{Decapsulator, DhKem, Encapsulator};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;
use x25519::{PublicKey, ReusableSecret, SharedSecret};

pub struct X25519;

impl Encapsulate<PublicKey, SharedSecret> for Encapsulator<PublicKey> {
    type Error = ();

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(PublicKey, SharedSecret), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);

        Ok((pk, ss))
    }
}

impl Decapsulate<PublicKey, SharedSecret> for Decapsulator<ReusableSecret> {
    type Error = ();

    fn decapsulate(&self, encapsulated_key: &PublicKey) -> Result<SharedSecret, Self::Error> {
        let ss = self.0.diffie_hellman(&encapsulated_key);

        Ok(ss)
    }
}

impl DhKem for X25519 {
    type DecapsulatingKey = Decapsulator<ReusableSecret>;
    type EncapsulatingKey = Encapsulator<PublicKey>;
    type EncapsulatedKey = PublicKey;
    type SharedSecret = SharedSecret;

    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);

        (Decapsulator(sk), Encapsulator(pk))
    }
}

#[cfg(test)]
impl crate::SecretBytes for SharedSecret {
    fn as_slice(&self) -> &[u8] {
        self.as_bytes().as_slice()
    }
}
