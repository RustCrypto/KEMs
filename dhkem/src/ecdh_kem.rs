//! Generic Elliptic Curve Diffie-Hellman KEM adapter.

use crate::{DecapsulationKey, EncapsulationKey, Error, HpkeKemId};
use core::marker::PhantomData;
use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytes, FieldBytesSize, PublicKey, SecretKey, bigint,
    ecdh::EphemeralSecret,
    sec1,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point, UncompressedPoint, UncompressedPointSize},
};
use kem::{
    Ciphertext, Decapsulator, Encapsulate, Generate, InvalidKey, Kem, KeyExport, KeySizeUser,
    SharedKey, TryDecapsulate, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};

#[cfg(doc)]
use crate::Expander;

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
    EcdhDecapsulationKey<C>: TryDecapsulate<Kem = Self> + Generate,
    EcdhEncapsulationKey<C>: Encapsulate<Kem = Self> + Clone,
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

impl<C> Decapsulator for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    type Kem = EcdhKem<C>;

    fn encapsulation_key(&self) -> &EcdhEncapsulationKey<C> {
        &self.ek
    }
}

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

/// <div class="warning">
/// <b><code>SharedKey</code> is non-uniform raw ECDH output!</b>
///
/// The resulting [`SharedKey`] is the non-uniform raw output of the Elliptic Curve Diffie-Hellman
/// operation (i.e. coordinate of an elliptic curve point).
///
/// To produce something suitable for e.g. symmetric key(s), use the [`Expander`] type to derive
/// output keys.
/// </div>
impl<C> TryDecapsulate for EcdhDecapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    type Error = Error;

    #[inline]
    fn try_decapsulate(
        &self,
        encapsulated_key: &Ciphertext<EcdhKem<C>>,
    ) -> Result<SharedKey<EcdhKem<C>>, Error> {
        let encapsulated_key =
            PublicKey::<C>::from_sec1_bytes(encapsulated_key).map_err(|_| Error::Decapsulation)?;

        let shared_secret = self.dk.diffie_hellman(&encapsulated_key);
        Ok(*shared_secret.raw_secret_bytes())
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
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
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
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    fn to_bytes(&self) -> UncompressedPoint<C> {
        self.0.to_uncompressed_point()
    }
}

/// <div class="warning">
/// <b><code>SharedKey</code> is non-uniform raw ECDH output!</b>
///
/// The resulting [`SharedKey`] is the non-uniform raw output of the Elliptic Curve Diffie-Hellman
/// operation (i.e. coordinate of an elliptic curve point).
///
/// To produce something suitable for e.g. symmetric key(s), use the [`Expander`] type to derive
/// output keys.
/// </div>
impl<C> Encapsulate for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
{
    type Kem = EcdhKem<C>;

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
        (pk, *ss.raw_secret_bytes())
    }
}

impl<C> FromSec1Point<C> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    PublicKey<C>: FromSec1Point<C>,
{
    fn from_sec1_point(point: &sec1::Sec1Point<C>) -> bigint::CtOption<Self> {
        PublicKey::<C>::from_sec1_point(point).map(Into::into)
    }
}

impl<C> ToSec1Point<C> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: ModulusSize,
    PublicKey<C>: ToSec1Point<C>,
{
    fn to_sec1_point(&self, compress: bool) -> sec1::Sec1Point<C> {
        self.0.to_sec1_point(compress)
    }
}

/// NIST P-256 ECDH Decapsulation Key.
#[cfg(feature = "p256")]
pub type NistP256DecapsulationKey = EcdhDecapsulationKey<p256::NistP256>;
/// NIST P-256 ECDH Encapsulation Key.
#[cfg(feature = "p256")]
pub type NistP256EncapsulationKey = EcdhEncapsulationKey<p256::NistP256>;
/// NIST P-256 DHKEM.
#[cfg(feature = "p256")]
pub type NistP256Kem = EcdhKem<p256::NistP256>;
#[cfg(feature = "p256")]
impl HpkeKemId for NistP256Kem {
    const KEM_ID: u16 = 0x10;
}

/// NIST P-384 ECDH Decapsulation Key.
#[cfg(feature = "p384")]
pub type NistP384DecapsulationKey = EcdhDecapsulationKey<p384::NistP384>;
/// NIST P-384 ECDH Encapsulation Key.
#[cfg(feature = "p384")]
pub type NistP384EncapsulationKey = EcdhEncapsulationKey<p384::NistP384>;
/// NIST P-384 DHKEM.
#[cfg(feature = "p384")]
pub type NistP384Kem = EcdhKem<p384::NistP384>;
#[cfg(feature = "p384")]
impl HpkeKemId for NistP384Kem {
    const KEM_ID: u16 = 0x11;
}

/// NIST P-521 ECDH Decapsulation Key.
#[cfg(feature = "p521")]
pub type NistP521DecapsulationKey = EcdhDecapsulationKey<p521::NistP521>;
/// NIST P-521 ECDH Encapsulation Key.
#[cfg(feature = "p521")]
pub type NistP521EncapsulationKey = EcdhEncapsulationKey<p521::NistP521>;
/// NIST P-521 DHKEM.
#[cfg(feature = "p521")]
pub type NistP521Kem = EcdhKem<p521::NistP521>;
#[cfg(feature = "p521")]
impl HpkeKemId for NistP521Kem {
    const KEM_ID: u16 = 0x12;
}

/// secp256k1 ECDH Decapsulation Key.
#[cfg(feature = "k256")]
pub type Secp256k1DecapsulationKey = EcdhDecapsulationKey<k256::Secp256k1>;
/// secp256k1 ECDH Encapsulation Key.
#[cfg(feature = "k256")]
pub type Secp256k1EncapsulationKey = EcdhEncapsulationKey<k256::Secp256k1>;
/// secp256k1 DHKEM.
#[cfg(feature = "k256")]
pub type Secp256k1Kem = EcdhKem<k256::Secp256k1>;
