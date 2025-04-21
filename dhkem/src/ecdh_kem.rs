//! Generic Elliptic Curve Diffie-Hellman KEM adapter.

use crate::{DhDecapsulator, DhEncapsulator, DhKem};
use core::{convert::Infallible, marker::PhantomData};
use elliptic_curve::{
    CurveArithmetic, PublicKey,
    ecdh::{EphemeralSecret, SharedSecret},
};
use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRng;

/// Generic Elliptic Curve Diffie-Hellman KEM adapter compatible with curves implemented using
/// traits from the `elliptic-curve` crate.
///
/// Implements a KEM interface that internally uses ECDH.
pub struct EcdhKem<C: CurveArithmetic>(PhantomData<C>);

impl<C> Encapsulate<PublicKey<C>, SharedSecret<C>> for DhEncapsulator<PublicKey<C>>
where
    C: CurveArithmetic,
{
    type Error = Infallible;

    fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey<C>, SharedSecret<C>), Self::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = EphemeralSecret::random(rng);
        let pk = sk.public_key();
        let ss = sk.diffie_hellman(&self.0);

        Ok((pk, ss))
    }
}

impl<C> Decapsulate<PublicKey<C>, SharedSecret<C>> for DhDecapsulator<EphemeralSecret<C>>
where
    C: CurveArithmetic,
{
    type Error = Infallible;

    fn decapsulate(&self, encapsulated_key: &PublicKey<C>) -> Result<SharedSecret<C>, Self::Error> {
        let ss = self.0.diffie_hellman(encapsulated_key);

        Ok(ss)
    }
}

impl<C> DhKem for EcdhKem<C>
where
    C: CurveArithmetic,
{
    type DecapsulatingKey = DhDecapsulator<EphemeralSecret<C>>;
    type EncapsulatingKey = DhEncapsulator<PublicKey<C>>;
    type EncapsulatedKey = PublicKey<C>;
    type SharedSecret = SharedSecret<C>;

    fn random_keypair<R: CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        let sk = EphemeralSecret::random(rng);
        let pk = PublicKey::from(&sk);

        (DhDecapsulator(sk), DhEncapsulator(pk))
    }
}
