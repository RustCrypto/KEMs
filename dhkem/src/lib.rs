#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]

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

mod expander;

pub use expander::{Expander, InvalidLength};
pub use kem::{self, Encapsulate, Generate, Kem, TryDecapsulate};

#[cfg(feature = "ecdh")]
mod ecdh_kem;
#[cfg(feature = "x25519")]
mod x25519_kem;

#[cfg(feature = "ecdh")]
pub use ecdh_kem::{EcdhDecapsulationKey, EcdhEncapsulationKey, EcdhKem};
#[cfg(feature = "x25519")]
pub use x25519_kem::{X25519DecapsulationKey, X25519EncapsulationKey, X25519Kem};

#[cfg(feature = "ecdh")]
use elliptic_curve::{
    CurveArithmetic, PublicKey, bigint,
    sec1::{self, FromSec1Point, ToSec1Point},
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

impl<DK, EK> AsRef<EncapsulationKey<EK>> for DecapsulationKey<DK, EK> {
    fn as_ref(&self) -> &EncapsulationKey<EK> {
        &self.ek
    }
}

impl<DK, EK> From<DK> for DecapsulationKey<DK, EK>
where
    EK: for<'a> From<&'a DK>,
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

impl<EK> EncapsulationKey<EK> {
    /// Consumes `self` and returns the wrapped value
    pub fn into_inner(self) -> EK {
        self.0
    }
}

impl<EK> From<EK> for EncapsulationKey<EK> {
    fn from(inner: EK) -> Self {
        Self(inner)
    }
}

#[cfg(feature = "ecdh")]
impl<C> FromSec1Point<C> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: sec1::ModulusSize,
    PublicKey<C>: FromSec1Point<C>,
{
    fn from_sec1_point(point: &sec1::Sec1Point<C>) -> bigint::CtOption<Self> {
        PublicKey::<C>::from_sec1_point(point).map(Into::into)
    }
}

#[cfg(feature = "ecdh")]
impl<C> ToSec1Point<C> for EcdhEncapsulationKey<C>
where
    C: CurveArithmetic,
    C::FieldBytesSize: sec1::ModulusSize,
    PublicKey<C>: ToSec1Point<C>,
{
    fn to_sec1_point(&self, compress: bool) -> sec1::Sec1Point<C> {
        self.0.to_sec1_point(compress)
    }
}

#[cfg(feature = "zeroize")]
impl<DK: Zeroize, EK> Zeroize for DecapsulationKey<DK, EK> {
    fn zeroize(&mut self) {
        self.dk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<DK: ZeroizeOnDrop, EK> ZeroizeOnDrop for DecapsulationKey<DK, EK> {}

/// NIST P-256 DHKEM.
#[cfg(feature = "p256")]
pub type NistP256Kem = EcdhKem<p256::NistP256>;
/// NIST P-256 ECDH Decapsulation Key.
#[cfg(feature = "p256")]
pub type NistP256DecapsulationKey = EcdhDecapsulationKey<p256::NistP256>;
/// NIST P-256 ECDH Encapsulation Key.
#[cfg(feature = "p256")]
pub type NistP256EncapsulationKey = EcdhEncapsulationKey<p256::NistP256>;

/// NIST P-256 DHKEM.
#[cfg(feature = "p384")]
pub type NistP384Kem = EcdhKem<p384::NistP384>;
/// NIST P-384 ECDH Decapsulation Key.
#[cfg(feature = "p384")]
pub type NistP384DecapsulationKey = EcdhDecapsulationKey<p384::NistP384>;
/// NIST P-384 ECDH Encapsulation Key.
#[cfg(feature = "p384")]
pub type NistP384EncapsulationKey = EcdhEncapsulationKey<p384::NistP384>;

/// NIST P-521 DHKEM.
#[cfg(feature = "p521")]
pub type NistP521Kem = EcdhKem<p521::NistP521>;
/// NIST P-521 ECDH Decapsulation Key.
#[cfg(feature = "p521")]
pub type NistP521DecapsulationKey = EcdhDecapsulationKey<p521::NistP521>;
/// NIST P-521 ECDH Encapsulation Key.
#[cfg(feature = "p521")]
pub type NistP521EncapsulationKey = EcdhEncapsulationKey<p521::NistP521>;

/// secp256k1 DHKEM.
#[cfg(feature = "p521")]
pub type Secp256k1Kem = EcdhKem<k256::Secp256k1>;
/// secp256k1 ECDH Decapsulation Key.
#[cfg(feature = "k256")]
pub type Secp256k1DecapsulationKey = EcdhDecapsulationKey<k256::Secp256k1>;
/// secp256k1 ECDH Encapsulation Key.
#[cfg(feature = "k256")]
pub type Secp256k1EncapsulationKey = EcdhEncapsulationKey<k256::Secp256k1>;
