//! Generic Streamlined NTRU Prime types parameterized by parameter set.

use crate::error::Error;
use crate::params::SntrupParams;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Streamlined NTRU Prime encapsulation key (public key).
#[derive(Clone)]
pub struct EncapsulationKey<P: SntrupParams> {
    bytes: Vec<u8>,
    /// Decoded public-key polynomial and Hash4(pk), cached on first encapsulation.
    ///
    /// Encapsulation re-derives both on every call otherwise — repeated work that is
    /// identical per key (~10% of the operation). Both are public values, so this
    /// needs no zeroization. Mirrors `DecapsulationKey::h_cache`.
    pk_cache: std::sync::OnceLock<(Vec<i16>, [u8; 32])>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime decapsulation key (secret key).
#[derive(Clone)]
pub struct DecapsulationKey<P: SntrupParams> {
    bytes: Vec<u8>,
    /// Decoded public-key polynomial, cached on first decapsulation.
    ///
    /// Decapsulation re-encrypts against the public key embedded in this secret
    /// key, and decoding it is ~13% of the operation — pure repeated work, since
    /// it is identical on every call. The public key is not secret, so this
    /// needs no zeroization.
    h_cache: std::sync::OnceLock<Vec<i16>>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime ciphertext.
#[derive(Clone)]
pub struct Ciphertext<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime shared secret.
#[derive(Clone)]
pub struct SharedSecret<P: SntrupParams> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// Streamlined NTRU Prime Key Encapsulation Mechanism parameterized by parameter set.
///
/// Zero-sized marker type providing [`generate_key`](SntrupKem::generate_key).
/// Use the type aliases [`Sntrup653`](crate::Sntrup653),
/// [`Sntrup761`](crate::Sntrup761), [`Sntrup857`](crate::Sntrup857),
/// [`Sntrup953`](crate::Sntrup953), [`Sntrup1013`](crate::Sntrup1013),
/// [`Sntrup1277`](crate::Sntrup1277).
#[derive(Debug, Clone, Copy)]
pub struct SntrupKem<P: SntrupParams>(PhantomData<P>);

// ---------------------------------------------------------------------------
// Internal constructors
// ---------------------------------------------------------------------------

/// Internal `from_vec` constructor for a byte-wrapper type.
macro_rules! impl_from_vec {
    ($ty:ident) => {
        impl<P: SntrupParams> $ty<P> {
            pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
                Self {
                    bytes,
                    _marker: PhantomData,
                }
            }
        }
    };
}

impl_from_vec!(Ciphertext);
impl_from_vec!(SharedSecret);

impl<P: SntrupParams> EncapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            pk_cache: std::sync::OnceLock::new(),
            _marker: PhantomData,
        }
    }

    /// The decoded public-key polynomial and Hash4(pk), computed once and reused.
    #[cfg(feature = "ecap")]
    fn cached_pk(&self) -> &(Vec<i16>, [u8; 32]) {
        self.pk_cache.get_or_init(|| {
            let params = P::params();
            let mut h = vec![0i16; params.p];
            crate::rq::encoding::rq_decode_into(&self.bytes, &mut h, params);
            let mut pk_hash = [0u8; 32];
            crate::utils::hash_prefix(&mut pk_hash, 4, &self.bytes);
            (h, pk_hash)
        })
    }
}

// ---------------------------------------------------------------------------
// DecapsulationKey: extract encapsulation key
// ---------------------------------------------------------------------------

impl<P: SntrupParams> DecapsulationKey<P> {
    pub(crate) fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            h_cache: std::sync::OnceLock::new(),
            _marker: PhantomData,
        }
    }

    /// The decoded public-key polynomial, computed once and reused.
    fn cached_h(&self) -> &[i16] {
        self.h_cache.get_or_init(|| {
            let params = P::params();
            let ses = params.small_encode_size;
            let pk = &self.bytes[2 * ses..2 * ses + params.pk_size];
            let mut h = vec![0i16; params.p];
            crate::rq::encoding::rq_decode_into(pk, &mut h, params);
            h
        })
    }

    /// Get the encapsulation (public) key embedded in this decapsulation key.
    ///
    /// SK layout: f(small_enc) || ginv(small_enc) || pk(pk_size) || rho(small_enc) || hash4(32)
    /// The public key starts at offset `2 * small_encode_size` with length `pk_size`.
    pub fn encapsulation_key(&self) -> EncapsulationKey<P> {
        let params = P::params();
        let pk_start = 2 * params.small_encode_size;
        let pk_end = pk_start + params.pk_size;
        EncapsulationKey::from_vec(self.bytes[pk_start..pk_end].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

impl<P: SntrupParams> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::EncapsulationKey", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::PK_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::DecapsulationKey", P::NAME);
        f.debug_struct(&name).finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::Ciphertext", P::NAME);
        f.debug_struct(&name)
            .field("len", &P::CT_BYTES)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: SntrupParams> core::fmt::Debug for SharedSecret<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: String = format!("{}::SharedSecret", P::NAME);
        f.debug_struct(&name).finish()
    }
}

// ---------------------------------------------------------------------------
// AsRef<[u8]>
// ---------------------------------------------------------------------------

/// `AsRef<[u8]>` byte access for a wrapper type.
macro_rules! impl_as_ref {
    ($ty:ident) => {
        impl<P: SntrupParams> AsRef<[u8]> for $ty<P> {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
    };
}

impl_as_ref!(EncapsulationKey);
impl_as_ref!(DecapsulationKey);
impl_as_ref!(Ciphertext);
impl_as_ref!(SharedSecret);

// ---------------------------------------------------------------------------
// TryFrom<&[u8]>
// ---------------------------------------------------------------------------

/// Generate the `TryFrom` family (`&[u8]`, `Vec<u8>`, `&Vec<u8>`, `Box<[u8]>`)
/// for a fixed-size wrapper type. The `&[u8]` impl is the single length-checked
/// entry point; the owned variants delegate to it.
macro_rules! impl_try_from {
    ($ty:ident, $size:ident) => {
        impl<P: SntrupParams> TryFrom<&[u8]> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() != P::$size {
                    return Err(Error::InvalidSize {
                        expected: P::$size,
                        actual: bytes.len(),
                    });
                }
                Ok(Self::from_vec(bytes.to_vec()))
            }
        }

        impl<P: SntrupParams> TryFrom<Vec<u8>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl<P: SntrupParams> TryFrom<&Vec<u8>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        impl<P: SntrupParams> TryFrom<Box<[u8]>> for $ty<P> {
            type Error = Error;
            fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_ref())
            }
        }
    };
}

impl_try_from!(EncapsulationKey, PK_BYTES);
impl_try_from!(Ciphertext, CT_BYTES);

// ---------------------------------------------------------------------------
// PartialEq / Eq (EncapsulationKey, Ciphertext — non-secret, byte equality)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: SntrupParams> Eq for EncapsulationKey<P> {}

impl<P: SntrupParams> PartialEq for Ciphertext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: SntrupParams> Eq for Ciphertext<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (DecapsulationKey)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> TryFrom<&[u8]> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::SK_BYTES {
            return Err(Error::InvalidSize {
                expected: P::SK_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self::from_vec(bytes.to_vec()))
    }
}

impl<P: SntrupParams> TryFrom<Vec<u8>> for DecapsulationKey<P> {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: SntrupParams> ConstantTimeEq for DecapsulationKey<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: SntrupParams> PartialEq for DecapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: SntrupParams> Eq for DecapsulationKey<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (SharedSecret)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> ConstantTimeEq for SharedSecret<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: SntrupParams> PartialEq for SharedSecret<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: SntrupParams> Eq for SharedSecret<P> {}

// ---------------------------------------------------------------------------
// Zeroize + Drop (secret types)
// ---------------------------------------------------------------------------

impl<P: SntrupParams> Zeroize for DecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: SntrupParams> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: SntrupParams> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: SntrupParams> Drop for SharedSecret<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// KEM operations (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
impl<P: SntrupParams> SntrupKem<P> {
    /// Generate a Streamlined NTRU Prime key pair.
    pub fn generate_key(
        rng: &mut impl rand::CryptoRng,
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::ops::keygen(P::params(), rng);
        (
            EncapsulationKey::from_vec(pk),
            DecapsulationKey::from_vec(sk),
        )
    }

    /// Generate a key pair deterministically from a 32-byte seed.
    ///
    /// The seed is expanded via ChaCha20Rng to derive the full key pair.
    /// Identical seeds always produce identical key pairs.
    ///
    /// Note: `rand_chacha` offers no zeroization support, so the RNG's internal state (which
    /// contains the seed) is dropped without being wiped when this returns. Callers with
    /// strict key-erasure requirements should treat the seed's residency in freed stack
    /// memory as a known limitation of this function.
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
        Self::generate_key(&mut rng)
    }
}

#[cfg(feature = "ecap")]
impl<P: SntrupParams> EncapsulationKey<P> {
    /// Encapsulate: produce a ciphertext and shared secret.
    pub fn encapsulate(&self, rng: &mut impl rand::CryptoRng) -> (Ciphertext<P>, SharedSecret<P>) {
        let (h, pk_hash) = self.cached_pk();
        let (ct, ss) = crate::ops::encaps(h, pk_hash, P::params(), rng);
        (Ciphertext::from_vec(ct), SharedSecret::from_vec(ss))
    }
}

#[cfg(feature = "dcap")]
impl<P: SntrupParams> DecapsulationKey<P> {
    /// Decapsulate: recover shared secret from ciphertext.
    ///
    /// Always returns a shared secret (implicit rejection / IND-CCA2).
    /// On failure, returns a pseudorandom key derived from rho,
    /// indistinguishable from a valid key to an attacker.
    pub fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedSecret<P> {
        let ss = crate::ops::decaps(&self.bytes, self.cached_h(), &ct.bytes, P::params());
        SharedSecret::from_vec(ss)
    }
}

// ---------------------------------------------------------------------------
// Serde (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;

    /// Generate `Serialize`/`Deserialize` for a byte-wrapper type. Deserialization
    /// validates that the decoded length matches the parameter set's fixed size,
    /// rejecting (rather than silently zero-padding) short or oversized input.
    macro_rules! impl_serde {
        ($ty:ident, $size:ident) => {
            impl<P: SntrupParams> serde::Serialize for $ty<P> {
                fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                    serdect::slice::serialize_hex_lower_or_bin(&self.bytes, s)
                }
            }

            impl<'de, P: SntrupParams> serde::Deserialize<'de> for $ty<P> {
                fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                    let mut buf = vec![0u8; P::$size];
                    let decoded = serdect::slice::deserialize_hex_or_bin(&mut buf, d)?;
                    if decoded.len() != P::$size {
                        return Err(serde::de::Error::invalid_length(
                            decoded.len(),
                            &concat!(
                                stringify!($ty),
                                " expects exactly P::",
                                stringify!($size),
                                " bytes"
                            ),
                        ));
                    }
                    Ok(Self::from_vec(buf))
                }
            }
        };
    }

    impl_serde!(EncapsulationKey, PK_BYTES);
    impl_serde!(DecapsulationKey, SK_BYTES);
    impl_serde!(Ciphertext, CT_BYTES);
    impl_serde!(SharedSecret, SS_BYTES);
}
