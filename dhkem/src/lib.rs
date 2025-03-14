#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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

#[cfg(feature = "ecdh")]
mod ecdh_kem;
#[cfg(feature = "x25519")]
mod x25519_kem;

#[cfg(feature = "ecdh")]
pub use ecdh_kem::EcdhKem;
#[cfg(feature = "x25519")]
pub use x25519_kem::X25519Kem;

use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRng;

#[cfg(feature = "ecdh")]
use elliptic_curve::{
    CurveArithmetic, PublicKey,
    sec1::{self, ToEncodedPoint},
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Newtype for a piece of data that may be encapsulated
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Default)]
pub struct DhEncapsulator<X>(X);
/// Newtype for a piece of data that may be decapsulated
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Default)]
pub struct DhDecapsulator<X>(X);

impl<X> AsRef<X> for DhEncapsulator<X> {
    fn as_ref(&self) -> &X {
        &self.0
    }
}

impl<X> From<X> for DhEncapsulator<X> {
    fn from(value: X) -> Self {
        Self(value)
    }
}

impl<X> AsRef<X> for DhDecapsulator<X> {
    fn as_ref(&self) -> &X {
        &self.0
    }
}

impl<X> From<X> for DhDecapsulator<X> {
    fn from(value: X) -> Self {
        Self(value)
    }
}

impl<X> DhEncapsulator<X> {
    /// Consumes `self` and returns the wrapped value
    pub fn into_inner(self) -> X {
        self.0
    }
}

impl<X> DhDecapsulator<X> {
    /// Consumes `self` and returns the wrapped value
    pub fn into_inner(self) -> X {
        self.0
    }
}

#[cfg(feature = "ecdh")]
impl<C> ToEncodedPoint<C> for DhEncapsulator<PublicKey<C>>
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
impl<X: Zeroize> Zeroize for DhEncapsulator<X> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

#[cfg(feature = "zeroize")]
impl<X: Zeroize> Zeroize for DhDecapsulator<X> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

#[cfg(feature = "zeroize")]
impl<X: ZeroizeOnDrop> ZeroizeOnDrop for DhEncapsulator<X> {}

#[cfg(feature = "zeroize")]
impl<X: ZeroizeOnDrop> ZeroizeOnDrop for DhDecapsulator<X> {}

/// This is a trait that all KEM models should implement, and should probably be
/// promoted to the kem crate itself. It specifies the types of encapsulating and
/// decapsulating keys created by key generation, the shared secret type, and the
/// encapsulated key type
pub trait DhKem {
    /// The type that will implement [`Decapsulate`]
    type DecapsulatingKey: Decapsulate<Self::EncapsulatedKey, Self::SharedSecret>;

    /// The type that will implement [`Encapsulate`]
    type EncapsulatingKey: Encapsulate<Self::EncapsulatedKey, Self::SharedSecret>;

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

/// secp256k1 ECDH KEM.
#[cfg(feature = "k256")]
pub type Secp256k1Kem = EcdhKem<k256::Secp256k1>;

/// NIST P-256 ECDH KEM.
#[cfg(feature = "p256")]
pub type NistP256Kem = EcdhKem<p256::NistP256>;

/// NIST P-384 ECDH KEM.
#[cfg(feature = "p384")]
pub type NistP384Kem = EcdhKem<p384::NistP384>;

/// NIST P-521 ECDH KEM.
#[cfg(feature = "p521")]
pub type NistP521Kem = EcdhKem<p521::NistP521>;
