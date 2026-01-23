#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs)]

//! # Diffie-Hellman (DH) based Key Encapsulation Mechanisms (KEM)
//!
//! This crate provides a KEM interface for DH protocols as specified in [RFC9180]
//! without the shared secret extraction process.
//!
//! In particular, `Encaps(pk)` in the RFC returns the encapsulated key and an extracted shared
//! secret, while our implementation leaves the extraction process up to the user.
//!
//! This type of KEM construction is currently being used in HPKE, as per the RFC, and in the
//! current draft of the [TLS KEM combiner].
//!
//! ## Supported elliptic curves
//!
//! Support for specific elliptic curves is gated behind the following features:
//!
//! - `k256`: secp256k1
//! - `p256`: NIST P-256
//! - `p384`: NIST P-384
//! - `p521`: NIST P-521
//!
//! [RFC9180]: https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem
//! [TLS KEM combiner]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-10

pub use kem::{self, Decapsulator, Encapsulate, Generate, KemParams, TryDecapsulate};

#[cfg(feature = "ecdh")]
mod ecdh_kem;
#[cfg(feature = "x25519")]
mod x25519_kem;

#[cfg(feature = "ecdh")]
pub use ecdh_kem::{EcdhDecapsulationKey, EcdhEncapsulationKey, EcdhKem};
#[cfg(feature = "x25519")]
pub use x25519_kem::{X25519DecapsulationKey, X25519EncapsulationKey, X25519Kem};

use rand_core::CryptoRng;

#[cfg(feature = "ecdh")]
use elliptic_curve::{
    CurveArithmetic, PublicKey, bigint,
    sec1::{self, FromEncodedPoint, ToEncodedPoint},
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Newtype for a piece of data that may be decapsulated
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Default)]
pub struct DecapsulationKey<DK, EK> {
    /// Decapsulation key
    dk: DK,
    /// Encapsulation key
    ek: EncapsulationKey<EK>,
}

impl<DK, EK> Decapsulator for DecapsulationKey<DK, EK>
where
    EncapsulationKey<EK>: Encapsulate + Clone,
{
    type Encapsulator = EncapsulationKey<EK>;

    fn encapsulator(&self) -> &EncapsulationKey<EK> {
        &self.ek
    }
}

impl<DK, EK> From<DK> for DecapsulationKey<DK, EK>
where
    EK: for<'a> From<&'a DK>,
    EncapsulationKey<EK>: KemParams,
{
    fn from(dk: DK) -> Self {
        let ek = EncapsulationKey(EK::from(&dk));
        Self { dk, ek }
    }
}

impl<DK, EK> DecapsulationKey<DK, EK> {
    /// Consumes `self` and returns the wrapped value
    pub fn into_inner(self) -> DK {
        self.dk
    }
}

/// Newtype for a piece of data that may be encapsulated
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Default)]
pub struct EncapsulationKey<EK>(EK);

impl<EK> From<EK> for EncapsulationKey<EK> {
    fn from(inner: EK) -> Self {
        Self(inner)
    }
}

impl<X> EncapsulationKey<X> {
    /// Consumes `self` and returns the wrapped value
    pub fn into_inner(self) -> X {
        self.0
    }
}

#[cfg(feature = "ecdh")]
impl<C> FromEncodedPoint<C> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: sec1::ModulusSize,
    PublicKey<C>: FromEncodedPoint<C>,
{
    fn from_encoded_point(point: &sec1::EncodedPoint<C>) -> bigint::CtOption<Self> {
        PublicKey::<C>::from_encoded_point(point).map(Into::into)
    }
}

#[cfg(feature = "ecdh")]
impl<C> ToEncodedPoint<C> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: sec1::ModulusSize,
    PublicKey<C>: ToEncodedPoint<C>,
{
    fn to_encoded_point(&self, compress: bool) -> sec1::EncodedPoint<C> {
        self.0.to_encoded_point(compress)
    }
}

#[cfg(feature = "zeroize")]
impl<DK: Zeroize, EK> Zeroize for DecapsulationKey<DK, EK> {
    fn zeroize(&mut self) {
        self.dk.zeroize()
    }
}

#[cfg(feature = "zeroize")]
impl<DK: ZeroizeOnDrop, EK> ZeroizeOnDrop for DecapsulationKey<DK, EK> {}

/// This is a trait that all KEM models should implement, and should probably be
/// promoted to the kem crate itself. It specifies the types of encapsulating and
/// decapsulating keys created by key generation, the shared secret type, and the
/// encapsulated key type
pub trait DhKem {
    /// The type that will implement [`TryDecapsulate`]
    type DecapsulatingKey: Decapsulator + Generate + TryDecapsulate;

    /// The type that will implement [`Encapsulate`]
    type EncapsulatingKey: Encapsulate;

    /// The type of the encapsulated key
    type EncapsulatedKey;

    /// The type of the shared secret
    type SharedSecret;

    /// Generates a new (decapsulating key, encapsulating key) keypair for the KEM
    /// model
    fn random_keypair<R: CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey);
}

/// NIST P-256 ECDH Decapsulation Key.
#[cfg(feature = "p256")]
pub type NistP256DecapsulationKey = EcdhDecapsulationKey<p256::NistP256>;
/// NIST P-256 ECDH Encapsulation Key.
#[cfg(feature = "p256")]
pub type NistP256EncapsulationKey = EcdhEncapsulationKey<p256::NistP256>;

/// NIST P-384 ECDH Decapsulation Key.
#[cfg(feature = "p384")]
pub type NistP384DecapsulationKey = EcdhDecapsulationKey<p384::NistP384>;
/// NIST P-384 ECDH Encapsulation Key.
#[cfg(feature = "p384")]
pub type NistP384EncapsulationKey = EcdhEncapsulationKey<p384::NistP384>;

/// NIST P-521 ECDH Decapsulation Key.
#[cfg(feature = "p521")]
pub type NistP521DecapsulationKey = EcdhDecapsulationKey<p521::NistP521>;
/// NIST P-521 ECDH Encapsulation Key.
#[cfg(feature = "p521")]
pub type NistP521EncapsulationKey = EcdhEncapsulationKey<p521::NistP521>;

/// secp256k1 ECDH Decapsulation Key.
#[cfg(feature = "k256")]
pub type Secp256k1DecapsulationKey = EcdhDecapsulationKey<k256::Secp256k1>;
/// secp256k1 ECDH Encapsulation Key.
#[cfg(feature = "k256")]
pub type Secp256k1EncapsulationKey = EcdhEncapsulationKey<k256::Secp256k1>;
