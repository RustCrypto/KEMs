//! PKCS#8 encoding support for HQC-KEM keys.
//!
//! When the `pkcs8` feature is enabled, [`pkcs8::DecodePrivateKey`] is impl'd for
//! [`DecapsulationKey`], and [`pkcs8::DecodePublicKey`] is impl'd for [`EncapsulationKey`].
//!
//! When both `pkcs8` and `alloc` features are enabled, [`EncodePrivateKey`] is impl'd
//! for [`DecapsulationKey`], and [`EncodePublicKey`] is impl'd for [`EncapsulationKey`].

pub use ::pkcs8::spki::AssociatedAlgorithmIdentifier;
pub use const_oid::AssociatedOid;

use crate::{
    params::{Hqc128Params, Hqc192Params, Hqc256Params, HqcParams, SEED_BYTES},
    types::{DecapsulationKey, EncapsulationKey},
};
use ::pkcs8::{
    der::{
        AnyRef, Reader, SliceReader, TagNumber,
        asn1::{ContextSpecific, OctetStringRef},
    },
    spki,
};

#[cfg(feature = "alloc")]
use ::pkcs8::der::{Encode, TagMode, asn1::BitStringRef};

#[cfg(feature = "alloc")]
use ::pkcs8::{EncodePrivateKey, EncodePublicKey};

/// Tag number for the seed value (matches ml-kem convention).
const SEED_TAG_NUMBER: TagNumber = TagNumber(0);

/// HQC seed serialized as ASN.1.
type SeedString<'a> = ContextSpecific<&'a OctetStringRef>;

// ---------------------------------------------------------------------------
// Provisional OIDs for HQC-KEM
//
// FIPS 207 does not yet have assigned OIDs. These are provisional placeholders
// in the NIST KEM arc (2.16.840.1.101.3.4.4.x). ML-KEM uses .1/.2/.3.
// These WILL change when NIST assigns official OIDs.
// ---------------------------------------------------------------------------

impl AssociatedOid for Hqc128Params {
    const OID: ::pkcs8::ObjectIdentifier =
        ::pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.4");
}

impl AssociatedOid for Hqc192Params {
    const OID: ::pkcs8::ObjectIdentifier =
        ::pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.5");
}

impl AssociatedOid for Hqc256Params {
    const OID: ::pkcs8::ObjectIdentifier =
        ::pkcs8::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.6");
}

// AssociatedAlgorithmIdentifier for parameter types

impl AssociatedAlgorithmIdentifier for Hqc128Params {
    type Params = AnyRef<'static>;
    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        spki::AlgorithmIdentifier {
            oid: Self::OID,
            parameters: None,
        };
}

impl AssociatedAlgorithmIdentifier for Hqc192Params {
    type Params = AnyRef<'static>;
    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        spki::AlgorithmIdentifier {
            oid: Self::OID,
            parameters: None,
        };
}

impl AssociatedAlgorithmIdentifier for Hqc256Params {
    type Params = AnyRef<'static>;
    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> =
        spki::AlgorithmIdentifier {
            oid: Self::OID,
            parameters: None,
        };
}

// AssociatedAlgorithmIdentifier for key types (delegating to P)

impl<P> AssociatedAlgorithmIdentifier for EncapsulationKey<P>
where
    P: HqcParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = P::Params;
    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> = P::ALGORITHM_IDENTIFIER;
}

impl<P> AssociatedAlgorithmIdentifier for DecapsulationKey<P>
where
    P: HqcParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = P::Params;
    const ALGORITHM_IDENTIFIER: spki::AlgorithmIdentifier<Self::Params> = P::ALGORITHM_IDENTIFIER;
}

// ---------------------------------------------------------------------------
// EncodePublicKey (requires alloc)
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
impl<P> EncodePublicKey for EncapsulationKey<P>
where
    P: HqcParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_public_key_der(&self) -> spki::Result<pkcs8::Document> {
        let public_key = self.as_ref();
        let subject_public_key = BitStringRef::new(0, public_key)?;

        ::pkcs8::SubjectPublicKeyInfo {
            algorithm: P::ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
        .try_into()
    }
}

// ---------------------------------------------------------------------------
// DecodePublicKey (via TryFrom<SubjectPublicKeyInfoRef>)
// ---------------------------------------------------------------------------

impl<P> TryFrom<::pkcs8::SubjectPublicKeyInfoRef<'_>> for EncapsulationKey<P>
where
    P: HqcParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = spki::Error;

    fn try_from(spki: ::pkcs8::SubjectPublicKeyInfoRef<'_>) -> Result<Self, spki::Error> {
        if spki.algorithm.oid != P::ALGORITHM_IDENTIFIER.oid {
            return Err(spki::Error::OidUnknown {
                oid: P::ALGORITHM_IDENTIFIER.oid,
            });
        }

        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(spki::Error::KeyMalformed)?;

        if bytes.len() != P::PK_BYTES {
            return Err(spki::Error::KeyMalformed);
        }

        Ok(EncapsulationKey::from_vec(bytes.to_vec()))
    }
}

// ---------------------------------------------------------------------------
// EncodePrivateKey (requires alloc)
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
impl<P> EncodePrivateKey for DecapsulationKey<P>
where
    P: HqcParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> ::pkcs8::Result<pkcs8::SecretDocument> {
        let sk = self.as_ref();
        let seed = &sk[sk.len() - SEED_BYTES..];

        let seed_der = SeedString {
            tag_mode: TagMode::Implicit,
            tag_number: SEED_TAG_NUMBER,
            value: OctetStringRef::new(seed)?,
        }
        .to_der()?;

        let private_key = OctetStringRef::new(&seed_der)?;
        let private_key_info = pkcs8::PrivateKeyInfoRef::new(P::ALGORITHM_IDENTIFIER, private_key);
        pkcs8::SecretDocument::encode_msg(&private_key_info).map_err(pkcs8::Error::Asn1)
    }
}

// ---------------------------------------------------------------------------
// DecodePrivateKey (via TryFrom<PrivateKeyInfoRef>)
// ---------------------------------------------------------------------------

impl<P> TryFrom<::pkcs8::PrivateKeyInfoRef<'_>> for DecapsulationKey<P>
where
    P: HqcParams + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = ::pkcs8::Error;

    fn try_from(private_key_info_ref: ::pkcs8::PrivateKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        let _ = private_key_info_ref
            .algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        let mut reader = SliceReader::new(private_key_info_ref.private_key.as_bytes())?;
        let seed_string = SeedString::decode_implicit(&mut reader, SEED_TAG_NUMBER)?
            .ok_or(pkcs8::Error::KeyMalformed)?;
        let seed: [u8; SEED_BYTES] = seed_string
            .value
            .as_bytes()
            .try_into()
            .map_err(|_| pkcs8::Error::KeyMalformed)?;
        reader.finish()?;

        let (_pk, sk) = crate::kem::keygen_deterministic(&seed, P::params());
        Ok(DecapsulationKey::from_vec(sk))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use ::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};

    macro_rules! pkcs8_roundtrip_test {
        ($name:ident, $params:ty) => {
            #[test]
            fn $name() {
                let mut rng = rand::rng();
                let (ek, dk) = crate::HqcKem::<$params>::generate_key(&mut rng);

                // Public key roundtrip
                let pk_der = ek.to_public_key_der().expect("encode public key");
                let ek2 = EncapsulationKey::<$params>::from_public_key_der(pk_der.as_bytes())
                    .expect("decode public key");
                assert_eq!(ek.as_ref(), ek2.as_ref());

                // Private key roundtrip
                let sk_der = dk.to_pkcs8_der().expect("encode private key");
                let dk2 = DecapsulationKey::<$params>::from_pkcs8_der(sk_der.as_bytes())
                    .expect("decode private key");

                // Verify deterministic reconstruction: same EK
                assert_eq!(
                    dk.encapsulation_key().as_ref(),
                    dk2.encapsulation_key().as_ref()
                );

                // Verify encaps/decaps works with reconstructed keys
                let (ct, ss1) = ek2.encapsulate(&mut rng);
                let ss2 = dk2.decapsulate(&ct);
                assert_eq!(ss1, ss2);
            }
        };
    }

    pkcs8_roundtrip_test!(pkcs8_roundtrip_128, Hqc128Params);
    pkcs8_roundtrip_test!(pkcs8_roundtrip_192, Hqc192Params);
    pkcs8_roundtrip_test!(pkcs8_roundtrip_256, Hqc256Params);
}
