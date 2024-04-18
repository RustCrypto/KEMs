use crate::{Decapsulator, DhKem, Encapsulator};
use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret};
use elliptic_curve::{CurveArithmetic, PublicKey};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;
use std::marker::PhantomData;

pub struct ArithmeticKem<C: CurveArithmetic>(PhantomData<C>);

impl<C> Encapsulate<PublicKey<C>, SharedSecret<C>> for Encapsulator<PublicKey<C>>
where
    C: CurveArithmetic,
{
    type Error = ();

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(PublicKey<C>, SharedSecret<C>), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = EphemeralSecret::random(rng);
        let pk = sk.public_key();
        let ss = sk.diffie_hellman(&self.0);

        Ok((pk, ss))
    }
}

impl<C> Decapsulate<PublicKey<C>, SharedSecret<C>> for Decapsulator<EphemeralSecret<C>>
where
    C: CurveArithmetic,
{
    type Error = ();

    fn decapsulate(&self, encapsulated_key: &PublicKey<C>) -> Result<SharedSecret<C>, Self::Error> {
        let ss = self.0.diffie_hellman(&encapsulated_key);

        Ok(ss)
    }
}

impl<C> DhKem for ArithmeticKem<C>
where
    C: CurveArithmetic,
{
    type DecapsulatingKey = Decapsulator<EphemeralSecret<C>>;
    type EncapsulatingKey = Encapsulator<PublicKey<C>>;
    type EncapsulatedKey = PublicKey<C>;
    type SharedSecret = SharedSecret<C>;

    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = EphemeralSecret::random(rng);
        let pk = PublicKey::from(&sk);

        (Decapsulator(sk), Encapsulator(pk))
    }
}

#[cfg(test)]
impl<C> crate::SecretBytes for SharedSecret<C>
where
    C: CurveArithmetic,
{
    fn as_slice(&self) -> &[u8] {
        self.raw_secret_bytes().as_slice()
    }
}
