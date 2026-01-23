//! Generic Elliptic Curve Diffie-Hellman KEM adapter.

use crate::{DhDecapsulator, DhEncapsulator, DhKem};
use core::marker::PhantomData;
use elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, Generate, PublicKey,
    ecdh::{EphemeralSecret, SharedSecret},
    sec1::{
        FromEncodedPoint, ModulusSize, ToEncodedPoint, UncompressedPoint, UncompressedPointSize,
    },
};
use kem::{Decapsulate, Encapsulate, InvalidKey, KeyExport, KeySizeUser, TryKeyInit};
use rand_core::{CryptoRng, TryCryptoRng};

/// Generic Elliptic Curve Diffie-Hellman KEM adapter compatible with curves implemented using
/// traits from the `elliptic-curve` crate.
///
/// Implements a KEM interface that internally uses ECDH.
pub struct EcdhKem<C: CurveArithmetic>(PhantomData<C>);

/// From [RFC9810 §7.1.1]: `SerializePublicKey` and `DeserializePublicKey`:
///
/// > For P-256, P-384, and P-521, the SerializePublicKey() function of the
/// > KEM performs the uncompressed Elliptic-Curve-Point-to-Octet-String
/// > conversion according to [SECG].
///
/// [RFC9810 §7.1.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-serializepublickey-and-dese
/// [SECG]: https://www.secg.org/sec1-v2.pdf
impl<C> KeySizeUser for DhEncapsulator<PublicKey<C>>
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
impl<C> TryKeyInit for DhEncapsulator<PublicKey<C>>
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
impl<C> KeyExport for DhEncapsulator<PublicKey<C>>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn to_bytes(&self) -> UncompressedPoint<C> {
        // TODO(tarcieri): use `ToEncodedPoint::to_uncompressed_point` (RustCrypto/traits#2221)
        let mut ret = UncompressedPoint::<C>::default();
        ret.copy_from_slice(self.0.to_encoded_point(false).as_bytes());
        ret
    }
}

impl<C> Encapsulate<PublicKey<C>, SharedSecret<C>> for DhEncapsulator<PublicKey<C>>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn encapsulate_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey<C>, SharedSecret<C>), R::Error> {
        // ECDH encapsulation involves creating a new ephemeral key pair and then doing DH
        // TODO(tarcieri): propagate RNG errors
        let sk = EphemeralSecret::try_generate_from_rng(rng).expect("RNG failure");
        let pk = sk.public_key();
        let ss = sk.diffie_hellman(&self.0);

        Ok((pk, ss))
    }
}

impl<C> Decapsulate<PublicKey<C>, SharedSecret<C>> for DhDecapsulator<EphemeralSecret<C>>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Encapsulator = DhEncapsulator<PublicKey<C>>;

    fn decapsulate(&self, encapsulated_key: &PublicKey<C>) -> SharedSecret<C> {
        self.0.diffie_hellman(encapsulated_key)
    }

    fn encapsulator(&self) -> DhEncapsulator<PublicKey<C>> {
        DhEncapsulator(self.0.public_key())
    }
}

impl<C> DhKem for EcdhKem<C>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type DecapsulatingKey = DhDecapsulator<EphemeralSecret<C>>;
    type EncapsulatingKey = DhEncapsulator<PublicKey<C>>;
    type EncapsulatedKey = PublicKey<C>;
    type SharedSecret = SharedSecret<C>;

    fn random_keypair<R: CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey) {
        // TODO(tarcieri): propagate RNG errors
        let sk = EphemeralSecret::try_generate_from_rng(rng).expect("RNG failure");
        let pk = PublicKey::from(&sk);

        (DhDecapsulator(sk), DhEncapsulator(pk))
    }
}
