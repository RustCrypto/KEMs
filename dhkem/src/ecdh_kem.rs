//! Generic Elliptic Curve Diffie-Hellman KEM adapter.

use crate::{DecapsulationKey, EncapsulationKey};
use core::marker::PhantomData;
use elliptic_curve::{
    AffinePoint, CurveArithmetic, Error, FieldBytesSize, PublicKey,
    ecdh::EphemeralSecret,
    sec1::{
        FromEncodedPoint, ModulusSize, ToEncodedPoint, UncompressedPoint, UncompressedPointSize,
    },
};
use kem::{
    Ciphertext, Encapsulate, Generate, InvalidKey, Kem, KeyExport, KeySizeUser, SharedKey,
    TryDecapsulate, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};

/// Elliptic Curve Diffie-Hellman Decapsulation Key (i.e. secret decryption key)
///
/// Generic around an elliptic curve `C`.
pub type EcdhDecapsulationKey<C> = DecapsulationKey<EphemeralSecret<C>, PublicKey<C>>;

/// Elliptic Curve Diffie-Hellman Encapsulation Key (i.e. public encryption key)
///
/// Generic around an elliptic curve `C`.
pub type EcdhEncapsulationKey<C> = EncapsulationKey<PublicKey<C>>;

/// Generic Elliptic Curve Diffie-Hellman KEM adapter compatible with curves implemented using
/// traits from the `elliptic-curve` crate.
///
/// Implements a KEM interface that internally uses ECDH.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct EcdhKem<C: CurveArithmetic>(PhantomData<C>);

impl<C> Kem for EcdhKem<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    EcdhDecapsulationKey<C>: TryDecapsulate<Self> + Generate,
    EcdhEncapsulationKey<C>: Encapsulate<Self> + Clone,
{
    type DecapsulationKey = EcdhDecapsulationKey<C>;
    type EncapsulationKey = EcdhEncapsulationKey<C>;
    type CiphertextSize = UncompressedPointSize<C>;
    type SharedKeySize = FieldBytesSize<C>;
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For P-256, P-384, and P-521, the SerializePublicKey() function of the
/// > KEM performs the uncompressed Elliptic-Curve-Point-to-Octet-String
/// > conversion according to [SECG].
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
/// [SECG]: https://www.secg.org/sec1-v2.pdf
impl<C> KeySizeUser for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
{
    type KeySize = UncompressedPointSize<C>;
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > DeserializePublicKey() performs the uncompressed
/// > Octet-String-to-Elliptic-Curve-Point conversion.
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
impl<C> TryKeyInit for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn new(encapsulation_key: &UncompressedPoint<C>) -> Result<Self, InvalidKey> {
        PublicKey::<C>::from_sec1_bytes(encapsulation_key)
            .map(Into::into)
            .map_err(|_| InvalidKey)
    }
}

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For P-256, P-384, and P-521, the SerializePublicKey() function of the
/// > KEM performs the uncompressed Elliptic-Curve-Point-to-Octet-String
/// > conversion according to [SECG].
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
/// [SECG]: https://www.secg.org/sec1-v2.pdf
impl<C> KeyExport for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn to_bytes(&self) -> UncompressedPoint<C> {
        // TODO(tarcieri): self.0.to_uncompressed_point()
        let mut ret = UncompressedPoint::<C>::default();
        ret.copy_from_slice(self.to_encoded_point(false).as_bytes());
        ret
    }
}

impl<C> Generate for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Ok(EphemeralSecret::try_generate_from_rng(rng)?.into())
    }
}

impl<C> Encapsulate<EcdhKem<C>> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn encapsulate_with_rng<R>(
        &self,
        rng: &mut R,
    ) -> (Ciphertext<EcdhKem<C>>, SharedKey<EcdhKem<C>>)
    where
        R: CryptoRng + ?Sized,
    {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        let sk = EphemeralSecret::generate_from_rng(rng);
        let ss = sk.diffie_hellman(&self.0);

        let pk = sk.public_key().to_uncompressed_point();
        (pk, ss.raw_secret_bytes().clone())
    }
}

impl<C> TryDecapsulate<EcdhKem<C>> for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = Error;

    fn try_decapsulate(
        &self,
        encapsulated_key: &Ciphertext<EcdhKem<C>>,
    ) -> Result<SharedKey<EcdhKem<C>>, Error> {
        let encapsulated_key = PublicKey::<C>::from_sec1_bytes(encapsulated_key)?;
        let shared_secret = self.dk.diffie_hellman(&encapsulated_key);
        Ok(shared_secret.raw_secret_bytes().clone())
    }
}
