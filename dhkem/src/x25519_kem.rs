use crate::{Decapsulator, DhKem, EncapsulatedKey, Encapsulator, SharedSecret};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;
use x25519::{PublicKey, ReusableSecret, SharedSecret as X25519Secret};

pub struct X25519;

impl Encapsulate<EncapsulatedKey<PublicKey>, SharedSecret<X25519Secret>>
    for Encapsulator<PublicKey>
{
    type Error = ();

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(EncapsulatedKey<PublicKey>, SharedSecret<X25519Secret>), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);
        let ss = sk.diffie_hellman(&self.0);

        Ok((EncapsulatedKey(pk), SharedSecret(ss)))
    }
}

impl Decapsulate<EncapsulatedKey<PublicKey>, SharedSecret<X25519Secret>>
    for Decapsulator<ReusableSecret>
{
    type Error = ();

    fn decapsulate(
        &self,
        encapsulated_key: &EncapsulatedKey<PublicKey>,
    ) -> Result<SharedSecret<X25519Secret>, Self::Error> {
        let ss = self.0.diffie_hellman(&encapsulated_key.0);

        Ok(SharedSecret(ss))
    }
}

impl DhKem for X25519 {
    type DecapsulatingKey = Decapsulator<ReusableSecret>;
    type EncapsulatingKey = Encapsulator<PublicKey>;
    type EncapsulatedKey = EncapsulatedKey<PublicKey>;
    type SharedSecret = SharedSecret<X25519Secret>;

    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = ReusableSecret::random_from_rng(rng);
        let pk = PublicKey::from(&sk);

        (Decapsulator(sk), Encapsulator(pk))
    }
}

#[cfg(test)]
impl crate::SecretBytes for SharedSecret<X25519Secret> {
    fn as_slice(&self) -> &[u8] {
        self.0.as_bytes().as_slice()
    }
}
