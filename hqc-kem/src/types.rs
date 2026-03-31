//! Generic HQC-KEM types parameterized by security level.

use crate::error::Error;
use crate::params::HqcParams;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// HQC encapsulation key (public key).
#[derive(Clone)]
pub struct EncapsulationKey<P: HqcParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// HQC decapsulation key (secret key).
#[derive(Clone)]
pub struct DecapsulationKey<P: HqcParams> {
    bytes: Vec<u8>,
    ek: EncapsulationKey<P>,
    _marker: PhantomData<P>,
}

/// HQC ciphertext.
#[derive(Clone)]
pub struct Ciphertext<P: HqcParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// HQC shared secret.
#[derive(Clone)]
pub struct SharedSecret<P: HqcParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// HQC Key Encapsulation Mechanism parameterized by security level.
///
/// Zero-sized marker type providing [`generate_key`](HqcKem::generate_key).
/// Use the type aliases [`Hqc128`](crate::Hqc128),
/// [`Hqc192`](crate::Hqc192), [`Hqc256`](crate::Hqc256).
#[derive(Debug, Clone, Copy)]
pub struct HqcKem<P: HqcParams>(PhantomData<P>);

// ---------------------------------------------------------------------------
// Internal constructors (crate-only)
// ---------------------------------------------------------------------------

impl<P: HqcParams> EncapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::PK_BYTES);
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<P: HqcParams> DecapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::SK_BYTES);
        let ek = EncapsulationKey::from_vec(bytes[..P::PK_BYTES].to_vec());
        Self {
            bytes,
            ek,
            _marker: PhantomData,
        }
    }

    /// Get the encapsulation (public) key corresponding to this decapsulation key.
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }
}

impl<P: HqcParams> Ciphertext<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::CT_BYTES);
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

impl<P: HqcParams> SharedSecret<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::SS_BYTES);
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

impl<P: HqcParams> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::EncapsulationKey", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::PK_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: HqcParams> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::DecapsulationKey", P::NAME);
        f.debug_struct(&name).finish()
    }
}

impl<P: HqcParams> core::fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::Ciphertext", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::CT_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: HqcParams> core::fmt::Debug for SharedSecret<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::SharedSecret", P::NAME);
        f.debug_struct(&name).finish()
    }
}

// ---------------------------------------------------------------------------
// AsRef<[u8]>
// ---------------------------------------------------------------------------

impl<P: HqcParams> AsRef<[u8]> for EncapsulationKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: HqcParams> AsRef<[u8]> for DecapsulationKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: HqcParams> AsRef<[u8]> for Ciphertext<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: HqcParams> AsRef<[u8]> for SharedSecret<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// TryFrom<&[u8]>
// ---------------------------------------------------------------------------

impl<P: HqcParams> TryFrom<&[u8]> for EncapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::PK_BYTES {
            return Err(Error::InvalidPublicKeySize {
                expected: P::PK_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: HqcParams> TryFrom<&[u8]> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::SK_BYTES {
            return Err(Error::InvalidSecretKeySize {
                expected: P::SK_BYTES,
                got: bytes.len(),
            });
        }
        let ek = EncapsulationKey::from_vec(bytes[..P::PK_BYTES].to_vec());
        Ok(Self {
            bytes: bytes.to_vec(),
            ek,
            _marker: PhantomData,
        })
    }
}

impl<P: HqcParams> TryFrom<&[u8]> for Ciphertext<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::CT_BYTES {
            return Err(Error::InvalidCiphertextSize {
                expected: P::CT_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// PartialEq / Eq (EncapsulationKey, Ciphertext)
// ---------------------------------------------------------------------------

impl<P: HqcParams> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: HqcParams> Eq for EncapsulationKey<P> {}

impl<P: HqcParams> PartialEq for Ciphertext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: HqcParams> Eq for Ciphertext<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (SharedSecret only)
// ---------------------------------------------------------------------------

impl<P: HqcParams> ConstantTimeEq for SharedSecret<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: HqcParams> PartialEq for SharedSecret<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: HqcParams> Eq for SharedSecret<P> {}

// ---------------------------------------------------------------------------
// Zeroize + Drop (secret types)
// ---------------------------------------------------------------------------

impl<P: HqcParams> Zeroize for DecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: HqcParams> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: HqcParams> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: HqcParams> Drop for SharedSecret<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// KEM operations (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
impl<P: HqcParams> HqcKem<P> {
    /// Generate an HQC key pair.
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::kem::keygen(P::params(), rng);
        (
            EncapsulationKey::from_vec(pk),
            DecapsulationKey::from_vec(sk),
        )
    }

    /// Generate an HQC key pair deterministically from a 32-byte seed.
    ///
    /// The seed is expanded via SHAKE256 to derive the PKE key pair and sigma.
    /// Identical seeds always produce identical key pairs.
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::kem::keygen_deterministic(seed, P::params());
        (
            EncapsulationKey::from_vec(pk),
            DecapsulationKey::from_vec(sk),
        )
    }
}

#[cfg(feature = "ecap")]
impl<P: HqcParams> EncapsulationKey<P> {
    /// Encapsulate: produce a ciphertext and shared secret.
    pub fn encapsulate(&self, rng: &mut impl rand::CryptoRng) -> (Ciphertext<P>, SharedSecret<P>) {
        let (ss, ct) = crate::kem::encaps(&self.bytes, P::params(), rng);
        (Ciphertext::from_vec(ct), SharedSecret::from_vec(ss))
    }

    /// Encapsulate deterministically from a message and salt.
    ///
    /// `m` must be exactly the message size for this security level
    /// (16 bytes for HQC-128, 24 for HQC-192, 32 for HQC-256).
    /// `salt` is always 16 bytes.
    ///
    /// Identical inputs always produce identical ciphertext and shared secret.
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8],
        salt: &[u8; 16],
    ) -> Result<(Ciphertext<P>, SharedSecret<P>), Error> {
        let p = P::params();
        if m.len() != p.k {
            return Err(Error::InvalidMessageSize {
                expected: p.k,
                got: m.len(),
            });
        }
        let (ss, ct) = crate::kem::encaps_deterministic(&self.bytes, m, salt, p);
        Ok((Ciphertext::from_vec(ct), SharedSecret::from_vec(ss)))
    }
}

#[cfg(feature = "dcap")]
impl<P: HqcParams> DecapsulationKey<P> {
    /// Decapsulate: recover shared secret from ciphertext.
    pub fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedSecret<P> {
        let ss = crate::kem::decaps(&self.bytes, &ct.bytes, P::params());
        SharedSecret::from_vec(ss)
    }
}

// ---------------------------------------------------------------------------
// Serde (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    impl<P: HqcParams> serde::Serialize for EncapsulationKey<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: HqcParams> serde::Deserialize<'de> for EncapsulationKey<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::PK_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }

    impl<P: HqcParams> serde::Serialize for DecapsulationKey<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: HqcParams> serde::Deserialize<'de> for DecapsulationKey<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::SK_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            let ek = EncapsulationKey::from_vec(buf[..P::PK_BYTES].to_vec());
            Ok(Self {
                bytes: buf,
                ek,
                _marker: PhantomData,
            })
        }
    }

    impl<P: HqcParams> serde::Serialize for Ciphertext<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: HqcParams> serde::Deserialize<'de> for Ciphertext<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::CT_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }

    impl<P: HqcParams> serde::Serialize for SharedSecret<P> {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
        }
    }

    impl<'de, P: HqcParams> serde::Deserialize<'de> for SharedSecret<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::SS_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            Ok(Self {
                bytes: buf,
                _marker: PhantomData,
            })
        }
    }
}
