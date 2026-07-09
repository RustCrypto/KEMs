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

mod error;
mod expander;

pub use crate::{
    error::Error,
    expander::{EagerHash, Expander, HpkeKemId, InvalidLength},
};
pub use kem::{self, Ciphertext, Decapsulator, Encapsulate, Generate, Kem, TryDecapsulate};
use rand_core::CryptoRng;

#[cfg(feature = "ecdh")]
mod ecdh_kem;
#[cfg(feature = "x25519")]
mod x25519_kem;

#[cfg(feature = "ecdh")]
pub use ecdh_kem::*;
#[cfg(feature = "x25519")]
pub use x25519_kem::*;

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

impl<DK, EK> DecapsulationKey<DK, EK> {
    /// Perform decapsulation and initialize an [`Expander`] using the resulting shared secret.
    ///
    /// # Errors
    /// - Returns [`Error::Decapsulation`] if the decapsulation operation failed.
    /// - Returns [`Error::Length`] if `salt` or `label` are too long.
    pub fn decapsulate_and_expand<D>(
        &self,
        salt: &[u8],
        label: &[u8],
        ciphertext: &Ciphertext<<Self as Decapsulator>::Kem>,
    ) -> Result<Expander<D>, Error>
    where
        Self: TryDecapsulate<Error = Error> + Decapsulator<Kem: HpkeKemId>,
        D: EagerHash,
    {
        let ikm = self.try_decapsulate(ciphertext)?;
        let ex = Expander::new_labeled_hpke::<<Self as Decapsulator>::Kem>(salt, label, &ikm)?;
        Ok(ex)
    }

    /// Consumes `self` and returns the inner decapsulation key.
    pub fn into_inner(self) -> DK {
        self.dk
    }
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

/// Newtype for a piece of data that may be encapsulated
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Default)]
pub struct EncapsulationKey<EK>(EK);

impl<EK> EncapsulationKey<EK> {
    /// Consumes `self` and returns the inner encapsulation key.
    pub fn into_inner(self) -> EK {
        self.0
    }
}

impl<EK> EncapsulationKey<EK>
where
    Self: Encapsulate<Kem: HpkeKemId>,
{
    /// Generate a new shared secret from the system's RNG, then encrypt it, returning its
    /// ciphertext and an [`Expander`] which has been initialized with it.
    ///
    /// # Errors
    /// Returns [`Error::Length`] if `salt` or `label` are too long.
    #[cfg(feature = "getrandom")]
    pub fn encapsulate_and_expand<D: EagerHash>(
        &self,
        salt: &[u8],
        label: &[u8],
    ) -> Result<(Ciphertext<<Self as Encapsulate>::Kem>, Expander<D>), InvalidLength> {
        let (ct, ikm) = self.encapsulate();
        let expander = Expander::new_labeled_hpke::<<Self as Encapsulate>::Kem>(salt, label, &ikm)?;
        Ok((ct, expander))
    }

    /// Generate a new shared secret from the provided `rng`, then encrypt it, returning its
    /// ciphertext and an [`Expander`] which has been initialized with it.
    ///
    /// # Errors
    /// Returns [`Error::Length`] if `salt` or `label` are too long.
    pub fn encapsulate_with_rng_and_expand<D: EagerHash, R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        salt: &[u8],
        label: &[u8],
    ) -> Result<(Ciphertext<<Self as Encapsulate>::Kem>, Expander<D>), InvalidLength> {
        let (ct, ikm) = self.encapsulate_with_rng(rng);
        let expander = Expander::new_labeled_hpke::<<Self as Encapsulate>::Kem>(salt, label, &ikm)?;
        Ok((ct, expander))
    }
}

impl<EK> From<EK> for EncapsulationKey<EK> {
    fn from(inner: EK) -> Self {
        Self(inner)
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
