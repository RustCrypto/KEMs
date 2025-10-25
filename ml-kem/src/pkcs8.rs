//! PKCS#8 encoding support.

#![cfg(feature = "pkcs8")]

pub use ::pkcs8::spki::AssociatedAlgorithmIdentifier;
pub use const_oid::AssociatedOid;

use crate::{
    MlKem512Params, MlKem768Params, MlKem1024Params,
    kem::{DecapsulationKey, EncapsulationKey},
    param::{EncapsulationKeySize, KemParams},
    pke::EncryptionKey,
};
use ::pkcs8::{
    der::{AnyRef, asn1::OctetStringRef},
    spki,
};
use hybrid_array::Array;

#[cfg(feature = "alloc")]
use {
    crate::EncodedSizeUser,
    ::pkcs8::der::{Encode, asn1::BitStringRef},
};

impl AssociatedOid for MlKem512Params {
    const OID: ::pkcs8::ObjectIdentifier = const_oid::db::fips203::ID_ALG_ML_KEM_512;
}

impl AssociatedOid for MlKem768Params {
    const OID: ::pkcs8::ObjectIdentifier = const_oid::db::fips203::ID_ALG_ML_KEM_768;
}

impl AssociatedOid for MlKem1024Params {
    const OID: ::pkcs8::ObjectIdentifier = const_oid::db::fips203::ID_ALG_ML_KEM_1024;
}

impl AssociatedAlgorithmIdentifier for MlKem512Params {
    type Params = ::pkcs8::der::AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        spki::AlgorithmIdentifier {
            oid: Self::OID,
            parameters: None,
        };
}

impl AssociatedAlgorithmIdentifier for MlKem768Params {
    type Params = ::pkcs8::der::AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        spki::AlgorithmIdentifier {
            oid: Self::OID,
            parameters: None,
        };
}

impl AssociatedAlgorithmIdentifier for MlKem1024Params {
    type Params = ::pkcs8::der::AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        spki::AlgorithmIdentifier {
            oid: Self::OID,
            parameters: None,
        };
}

/// The serialization of the private key is a choice between three different formats
/// [according to PKCS#8](https://lamps-wg.github.io/kyber-certificates/draft-ietf-lamps-kyber-certificates.html#name-private-key-format).
///
/// “For ML-KEM private keys, the privateKey field in `OneAsymmetricKey`
/// contains one of the following DER-encoded `CHOICE` structures.
/// The seed format is a fixed 64-byte `OCTET STRING` (66 bytes total
/// with the 0x8040 tag and length) for all security levels,
/// while the expandedKey and both formats vary in size by security level”
#[derive(Clone, Debug, pkcs8::der::Choice)]
pub enum PrivateKeyChoice<'o> {
    /// FIPS 203 format for an ML-KEM private key: a 64-octet seed
    #[asn1(tag_mode = "IMPLICIT", context_specific = "0")]
    Seed(OctetStringRef<'o>),
}

impl<P> AssociatedAlgorithmIdentifier for EncapsulationKey<P>
where
    P: KemParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = P::Params;

    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> = P::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "alloc")]
impl<P> pkcs8::EncodePublicKey for EncapsulationKey<P>
where
    P: KemParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    /// Serialize the given `EncapsulationKey` into DER format.
    /// Returns a `Document` which wraps the DER document in case of success.
    fn to_public_key_der(&self) -> spki::Result<pkcs8::Document> {
        let public_key = self.as_bytes();
        let subject_public_key = BitStringRef::new(0, &public_key)?;

        ::pkcs8::SubjectPublicKeyInfo {
            algorithm: P::ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
        .try_into()
    }
}

impl<P> TryFrom<::pkcs8::SubjectPublicKeyInfoRef<'_>> for EncapsulationKey<P>
where
    P: KemParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = spki::Error;

    /// Deserialize the encapsulation key from DER format found in `spki.subject_public_key`.
    /// Returns an `EncapsulationKey` containing `ek_{pke}` and `h` in case of success.
    fn try_from(spki: ::pkcs8::SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        if spki.algorithm.oid != P::ALGORITHM_IDENTIFIER.oid {
            return Err(spki::Error::OidUnknown {
                oid: P::ALGORITHM_IDENTIFIER.oid,
            });
        }

        let bitstring_of_encapsulation_key = spki.subject_public_key;
        let enc_key = match bitstring_of_encapsulation_key.as_bytes() {
            Some(bytes) => {
                let arr: Array<u8, EncapsulationKeySize<P>> = match bytes.try_into() {
                    Ok(array) => array,
                    Err(_) => return Err(spki::Error::KeyMalformed),
                };
                EncryptionKey::from_bytes(&arr)
            }
            None => return Err(spki::Error::KeyMalformed),
        };

        Ok(Self::new(enc_key))
    }
}

impl<P> AssociatedAlgorithmIdentifier for DecapsulationKey<P>
where
    P: KemParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = P::Params;

    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> = P::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "alloc")]
impl<P> pkcs8::EncodePrivateKey for DecapsulationKey<P>
where
    P: KemParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    /// Serialize the given `DecapsulationKey` into DER format.
    /// Returns a `SecretDocument` which wraps the DER document in case of success.
    fn to_pkcs8_der(&self) -> ::pkcs8::Result<pkcs8::SecretDocument> {
        let decaps_key_bytes = self.to_seed().ok_or(pkcs8::Error::KeyMalformed)?;
        let pk_key_der =
            PrivateKeyChoice::Seed(OctetStringRef::new(decaps_key_bytes.as_slice())?).to_der()?;
        let pk_key_octetstr: OctetStringRef<'_> = OctetStringRef::new(&pk_key_der)?;

        let private_key_info =
            pkcs8::PrivateKeyInfoRef::new(P::ALGORITHM_IDENTIFIER, pk_key_octetstr);
        pkcs8::SecretDocument::encode_msg(&private_key_info).map_err(pkcs8::Error::Asn1)
    }
}

impl<P> TryFrom<::pkcs8::PrivateKeyInfoRef<'_>> for DecapsulationKey<P>
where
    P: KemParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = ::pkcs8::Error;

    /// Deserialize the decapsulation key from DER format found in `spki.private_key`.
    /// Returns a `DecapsulationKey` containing `dk_{pke}`, `ek`, and `z` in case of success.
    fn try_from(private_key_info_ref: ::pkcs8::PrivateKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        private_key_info_ref
            .algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        let decaps_key = match private_key_info_ref
            .private_key
            .decode_into::<PrivateKeyChoice>()
        {
            Ok(PrivateKeyChoice::Seed(seed)) => Self::from_seed(
                seed.as_bytes()
                    .try_into()
                    .map_err(|_| pkcs8::Error::KeyMalformed)?,
            ),
            Err(_) => return Err(pkcs8::Error::KeyMalformed),
        };

        Ok(decaps_key)
    }
}
