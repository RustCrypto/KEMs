//! Generic Elliptic Curve Diffie-Hellman KEM adapter.

use crate::{DecapsulationKey, EncapsulationKey};
use core::marker::PhantomData;
use elliptic_curve::{
    AffinePoint, CurveArithmetic, Error, FieldBytes, FieldBytesSize, PublicKey, SecretKey,
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

/// Elliptic Curve Diffie-Hellman Decapsulation Key (i.e. secret decryption key)
///
/// Generic around an elliptic curve `C`.
pub type EcdhDecapsulationKey<C> = DecapsulationKey<SecretKey<C>, PublicKey<C>>;

impl<C> KeySizeUser for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
{
    type KeySize = FieldBytesSize<C>;
}

/// From [RFC9810 §7.1.2]: `SerializePrivateKey` and `DeserializePrivateKey`:
///
/// > DeserializePrivateKey() performs the Octet-String-to-Field-Element conversion
/// > according to [SECG].
///
/// [RFC9810 §7.1.2]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.2
/// [SECG]: https://www.secg.org/sec1-v2.pdf
impl<C> TryKeyInit for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
{
    fn new(key: &FieldBytes<C>) -> Result<Self, InvalidKey> {
        SecretKey::from_bytes(key)
            .map(Into::into)
            .map_err(|_| InvalidKey)
    }
}

/// From [RFC9810 §7.1.2]: `SerializePrivateKey` and `DeserializePrivateKey`:
///
/// > the SerializePrivateKey() function of the KEM performs the Field-Element-to-Octet-String
/// > conversion according to [SECG]. If the private key is an integer outside the range
/// > `[0, order-1]`, where order is the order of the curve being used, the private key MUST be
/// > reduced to its representative in `[0, order-1]` before being serialized.
///
/// [RFC9810 §7.1.2]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.2
/// [SECG]: https://www.secg.org/sec1-v2.pdf
impl<C> KeyExport for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
{
    fn to_bytes(&self) -> FieldBytes<C> {
        self.dk.to_bytes()
    }
}

impl<C> Generate for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Ok(SecretKey::try_generate_from_rng(rng)?.into())
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

/// Elliptic Curve Diffie-Hellman Encapsulation Key (i.e. public encryption key)
///
/// Generic around an elliptic curve `C`.
pub type EcdhEncapsulationKey<C> = EncapsulationKey<PublicKey<C>>;

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For P-256, P-384, and P-521, the SerializePublicKey() function of the
/// > KEM performs the uncompressed Elliptic-Curve-Point-to-Octet-String
/// > conversion according to [SECG].
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.1
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
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.1
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
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#section-7.1.1
/// [SECG]: https://www.secg.org/sec1-v2.pdf
impl<C> KeyExport for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn to_bytes(&self) -> UncompressedPoint<C> {
        self.0.to_uncompressed_point()
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
