//! Generic HQC-KEM types parameterized by security level.

use crate::error::Error;
use crate::params::HqcParams;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

macro_rules! from_bytes {
    ($name:ident, $bytes:expr, $err:ident) => {
        impl<P: HqcParams> TryFrom<&[u8]> for $name<P> {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() == $bytes {
                    return Err(Error::$err {
                        expected: $bytes,
                        got: bytes.len(),
                    });
                }
                Ok(Self {
                    bytes: bytes.to_vec(),
                    _marker: PhantomData,
                })
            }
        }

        basic_bytes!($name, $bytes, $err);
    };
}

macro_rules! basic_bytes {
    ($name:ident, $bytes:expr, $err:ident) => {
        impl<P: HqcParams> TryFrom<Vec<u8>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl<P: HqcParams> TryFrom<&Vec<u8>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl<P: HqcParams> TryFrom<Box<[u8]>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_ref())
            }
        }

        impl<P: HqcParams> AsRef<[u8]> for $name<P> {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
    };
}

/// HQC encapsulation key (public key).
#[derive(Clone)]
pub struct EncapsulationKey<P: HqcParams> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) _marker: PhantomData<P>,
}

/// HQC decapsulation key (secret key).
#[derive(Clone)]
pub struct DecapsulationKey<P: HqcParams> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) ek: EncapsulationKey<P>,
    pub(crate) _marker: PhantomData<P>,
}

/// HQC ciphertext.
#[derive(Clone)]
pub struct Ciphertext<P: HqcParams> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) _marker: PhantomData<P>,
}

/// HQC shared secret.
#[derive(Clone)]
pub struct SharedSecret<P: HqcParams> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) _marker: PhantomData<P>,
}

from_bytes!(EncapsulationKey, P::PK_BYTES, InvalidPublicKeySize);
from_bytes!(Ciphertext, P::CT_BYTES, InvalidCiphertextSize);
from_bytes!(SharedSecret, P::SS_BYTES, InvalidSharedSecretSize);

// ---------------------------------------------------------------------------
// Internal constructors (crate-only)
// ---------------------------------------------------------------------------

#[cfg(any(feature = "kem", feature = "pkcs8"))]
impl<P: HqcParams> EncapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        debug_assert_eq!(bytes.len(), P::PK_BYTES);
        Self {
            bytes,
            _marker: PhantomData,
        }
    }
}

#[cfg(any(feature = "kem", feature = "pkcs8"))]
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
}

/// HQC Key Encapsulation Mechanism parameterized by security level.
///
/// Zero-sized marker type providing [`generate_key`](HqcKem::generate_key).
/// Use the type aliases [`Hqc128`](crate::Hqc128),
/// [`Hqc192`](crate::Hqc192), [`Hqc256`](crate::Hqc256).
#[derive(Debug, Clone, Copy)]
pub struct HqcKem<P: HqcParams>(PhantomData<P>);

impl<P: HqcParams> DecapsulationKey<P> {
    /// Get the encapsulation (public) key corresponding to this decapsulation key.
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
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
        Ok(Self {
            bytes: bytes.to_vec(),
            ek: EncapsulationKey::try_from(&bytes[..P::PK_BYTES])?,
            _marker: PhantomData,
        })
    }
}

basic_bytes!(DecapsulationKey, P::SK_BYTES, InvalidSecretKeySize);

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
        let ek = EncapsulationKey {
            bytes: pk.clone(),
            _marker: PhantomData,
        };
        (
            EncapsulationKey {
                bytes: pk,
                _marker: PhantomData,
            },
            DecapsulationKey {
                bytes: sk,
                ek,
                _marker: PhantomData,
            },
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
        let ek = EncapsulationKey {
            bytes: pk.clone(),
            _marker: PhantomData,
        };
        (
            EncapsulationKey {
                bytes: pk,
                _marker: PhantomData,
            },
            DecapsulationKey {
                bytes: sk,
                ek,
                _marker: PhantomData,
            },
        )
    }
}

#[cfg(feature = "ecap")]
impl<P: HqcParams> EncapsulationKey<P> {
    /// Encapsulate: produce a ciphertext and shared secret.
    pub fn encapsulate(&self, rng: &mut impl rand::CryptoRng) -> (Ciphertext<P>, SharedSecret<P>) {
        let (ss, ct) = crate::kem::encaps(&self.bytes, P::params(), rng);
        (
            Ciphertext {
                bytes: ct,
                _marker: PhantomData,
            },
            SharedSecret {
                bytes: ss,
                _marker: PhantomData,
            },
        )
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
        Ok((
            Ciphertext {
                bytes: ct,
                _marker: PhantomData,
            },
            SharedSecret {
                bytes: ss,
                _marker: PhantomData,
            },
        ))
    }
}

#[cfg(feature = "dcap")]
impl<P: HqcParams> DecapsulationKey<P> {
    /// Decapsulate: recover shared secret from ciphertext.
    pub fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedSecret<P> {
        let ss = crate::kem::decaps(&self.bytes, &ct.bytes, P::params());
        SharedSecret {
            bytes: ss,
            _marker: PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Serde (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    macro_rules! ser_impl {
        ($name:ident) => {
            impl<P: HqcParams> serde::Serialize for $name<P> {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
                }
            }
        };
    }

    macro_rules! deser_impl {
        ($name:ident, $bytes:expr) => {
            impl<'de, P: HqcParams> serde::Deserialize<'de> for $name<P> {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    let mut buf = vec![0u8; $bytes];
                    let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
                    Ok(Self {
                        bytes: buf,
                        _marker: PhantomData,
                    })
                }
            }
        };
    }

    ser_impl!(EncapsulationKey);
    deser_impl!(EncapsulationKey, P::PK_BYTES);

    ser_impl!(DecapsulationKey);

    impl<'de, P: HqcParams> serde::Deserialize<'de> for DecapsulationKey<P> {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let mut buf = vec![0u8; P::SK_BYTES];
            let _ = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
            let ek = EncapsulationKey {
                bytes: buf[..P::PK_BYTES].to_vec(),
                _marker: PhantomData,
            };
            Ok(Self {
                bytes: buf,
                ek,
                _marker: PhantomData,
            })
        }
    }

    ser_impl!(Ciphertext);
    deser_impl!(Ciphertext, P::CT_BYTES);

    ser_impl!(SharedSecret);
    deser_impl!(SharedSecret, P::SS_BYTES);
}
