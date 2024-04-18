use crate::{DhKem, DhKemProxy};
use elliptic_curve::ecdh::{EphemeralSecret, SharedSecret};
use elliptic_curve::{CurveArithmetic, PublicKey};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;
use std::marker::PhantomData;

pub struct ArithmeticKem<C: CurveArithmetic>(PhantomData<C>);

impl<C> Encapsulate<DhKemProxy<PublicKey<C>>, DhKemProxy<SharedSecret<C>>>
    for DhKemProxy<PublicKey<C>>
where
    C: CurveArithmetic,
{
    type Error = ();

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(DhKemProxy<PublicKey<C>>, DhKemProxy<SharedSecret<C>>), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = EphemeralSecret::random(rng);
        let pk = sk.public_key();
        let ss = sk.diffie_hellman(&self.0);

        Ok((DhKemProxy(pk), DhKemProxy(ss)))
    }
}

impl<C> Decapsulate<DhKemProxy<PublicKey<C>>, DhKemProxy<SharedSecret<C>>>
    for DhKemProxy<EphemeralSecret<C>>
where
    C: CurveArithmetic,
{
    type Error = ();

    fn decapsulate(
        &self,
        encapsulated_key: &DhKemProxy<PublicKey<C>>,
    ) -> Result<DhKemProxy<SharedSecret<C>>, Self::Error> {
        let ss = self.0.diffie_hellman(&encapsulated_key.0);

        Ok(DhKemProxy(ss))
    }
}

impl<C> DhKem for ArithmeticKem<C>
where
    C: CurveArithmetic,
{
    type DecapsulatingKey = DhKemProxy<EphemeralSecret<C>>;
    type EncapsulatingKey = DhKemProxy<PublicKey<C>>;
    type EncapsulatedKey = DhKemProxy<PublicKey<C>>;
    type SharedSecret = DhKemProxy<SharedSecret<C>>;

    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = EphemeralSecret::random(rng);
        let pk = PublicKey::from(&sk);

        (DhKemProxy(sk), DhKemProxy(pk))
    }
}
