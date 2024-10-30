/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! ## Usage
//!
//! The standard safe method to use FrodoKEM is to use the [`Algorithm`]
//! enum to select the desired algorithm then encapsulate a randomly generated
//! value, and decapsulate it on the other side.
//!
//! ```
//! use frodo_kem_rs::Algorithm;
//! use rand_core::OsRng;
//!
//! let alg = Algorithm::FrodoKem640Shake;
//! let (ek, dk) = alg.generate_keypair(OsRng);
//! let (ct, enc_ss) = alg.encapsulate_with_rng(&ek, OsRng).unwrap();
//! let (dec_ss, msg) = alg.decapsulate(&dk, &ct).unwrap();
//!
//! assert_eq!(enc_ss, dec_ss);
//! ```
//! If the message to be encapsulated is known, it can be passed to the encapsulate method.
//! `encapsulate` will error if the message is not the correct size.
//!
//! ```
//! use frodo_kem_rs::Algorithm;
//! use rand_core::OsRng;
//!
//! let alg = Algorithm::FrodoKem1344Shake;
//! let (ek, dk) = alg.generate_keypair(OsRng);
//! // Top secret don't disclose
//! let aes_256_key = [3u8; 32];
//! let (ct, enc_ss) = alg.encapsulate(&ek, &aes_256_key).unwrap();
//! let (dec_ss, dec_msg) = alg.decapsulate(&dk, &ct).unwrap();
//!
//! assert_eq!(enc_ss, dec_ss);
//! assert_eq!(&aes_256_key[..], dec_msg.as_slice());
//! ```
//!
//! ## Features
//! Each algorithm can be conditionally included/excluded as needed.
//!
//! The structs used in this crate all optionally support the `serde` feature.
//!
//! ## Custom
//!
//! To create a custom implementation of FrodoKEM, use the `hazmat` feature, to enable
//! the necessary traits for creating a custom implementation. Be warned, this is not
//! recommended unless you are sure of what you are doing.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_parens,
    unused_qualifications
)]

#[cfg(not(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake"
)))]
compile_error!("no algorithm feature enabled");

mod error;
pub use error::*;

#[cfg(feature = "hazmat")]
pub mod hazmat;
#[cfg(not(feature = "hazmat"))]
mod hazmat;

use hazmat::{
    CiphertextRef, DecryptionKeyRef, EncryptionKeyRef, Frodo1344, Frodo640, Frodo976,
    FrodoKem1344Aes, FrodoKem1344Shake, FrodoKem640Aes, FrodoKem640Shake, FrodoKem976Aes,
    FrodoKem976Shake, Kem, Params,
};

use rand_core::CryptoRngCore;
use std::marker::PhantomData;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! serde_impl {
    ($name:ident, $from_method:ident) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $name {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if s.is_human_readable() {
                    use serde::ser::SerializeStruct;

                    let mut map = s.serialize_struct(stringify!($name), 2)?;
                    map.serialize_field("algorithm", &self.algorithm.to_string())?;
                    map.serialize_field("value", &hex::encode(&self.value))?;
                    map.end()
                } else {
                    let mut seq = vec![u8::from(self.algorithm)];
                    seq.extend_from_slice(self.value.as_slice());
                    s.serialize_bytes(&seq)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if d.is_human_readable() {
                    struct FieldVisitor;
                    #[derive(serde::Deserialize)]
                    #[serde(field_identifier, rename_all = "snake_case")]
                    enum Field {
                        Algorithm,
                        Value,
                    }

                    impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                        type Value = $name;

                        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            write!(f, "a struct with two fields")
                        }

                        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                        where
                            A: serde::de::MapAccess<'de>,
                        {
                            let mut algorithm = Option::<Algorithm>::None;
                            let mut value = Option::<String>::None;
                            while let Some(key) = map.next_key()? {
                                match key {
                                    Field::Algorithm => {
                                        if algorithm.is_some() {
                                            return Err(serde::de::Error::duplicate_field(
                                                "algorithm",
                                            ));
                                        }
                                        algorithm = Some(map.next_value()?);
                                    }
                                    Field::Value => {
                                        if value.is_some() {
                                            return Err(serde::de::Error::duplicate_field("value"));
                                        }
                                        value = Some(map.next_value()?);
                                    }
                                }
                            }

                            let algorithm = algorithm
                                .ok_or_else(|| serde::de::Error::missing_field("algorithm"))?;
                            let value =
                                value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                            let value = hex::decode(&value).map_err(serde::de::Error::custom)?;
                            algorithm
                                .$from_method(&value)
                                .map_err(serde::de::Error::custom)
                        }
                    }
                    const FIELDS: &[&str] = &["algorithm", "value"];
                    d.deserialize_struct("Ciphertext", FIELDS, FieldVisitor)
                } else {
                    struct BytesVisitor;

                    impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                        type Value = $name;

                        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            write!(f, "a byte sequence")
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            let algorithm =
                                Algorithm::try_from(v[0]).map_err(serde::de::Error::custom)?;

                            let value = &v[1..];
                            algorithm
                                .$from_method(value)
                                .map_err(serde::de::Error::custom)
                        }
                    }

                    d.deserialize_bytes(BytesVisitor)
                }
            }
        }
    };
}

macro_rules! ct_eq_imp {
    ($name:ident) => {
        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.algorithm.ct_eq(&other.algorithm) & ct_eq_bytes(&self.value, &other.value)
            }
        }

        impl Eq for $name {}

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other).unwrap_u8() == 1
            }
        }
    };
}

/// A FrodoKEM ciphertext key
#[derive(Debug, Clone, Default)]
pub struct Ciphertext {
    pub(crate) algorithm: Algorithm,
    pub(crate) value: Vec<u8>,
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

ct_eq_imp!(Ciphertext);

serde_impl!(Ciphertext, ciphertext_from_bytes);

impl Ciphertext {
    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Convert a slice of bytes into a [`Ciphertext`] according to the specified [`Algorithm`].
    pub fn from_bytes<B: AsRef<[u8]>>(algorithm: Algorithm, value: B) -> FrodoResult<Self> {
        algorithm.ciphertext_from_bytes(value.as_ref())
    }
}

/// A FrodoKEM public key
#[derive(Debug, Clone, Default)]
pub struct EncryptionKey {
    pub(crate) algorithm: Algorithm,
    pub(crate) value: Vec<u8>,
}

impl AsRef<[u8]> for EncryptionKey {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl From<&DecryptionKey> for EncryptionKey {
    fn from(secret_key: &DecryptionKey) -> Self {
        secret_key
            .algorithm
            .encryption_key_from_decryption_key(secret_key)
    }
}

ct_eq_imp!(EncryptionKey);

serde_impl!(EncryptionKey, encryption_key_from_bytes);

impl EncryptionKey {
    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Convert a slice of bytes into a [`EncryptionKey`] according to the specified [`Algorithm`].
    pub fn from_bytes<B: AsRef<[u8]>>(algorithm: Algorithm, value: B) -> FrodoResult<Self> {
        algorithm.encryption_key_from_bytes(value.as_ref())
    }

    /// Encapsulate a random value to generate a [`SharedSecret`] and a [`Ciphertext`].
    pub fn encapsulate_with_rng(
        &self,
        rng: impl CryptoRngCore,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        self.algorithm.encapsulate_with_rng(self, rng)
    }

    /// Encapsulate with given message to generate a [`SharedSecret`] and a [`Ciphertext`].
    ///
    /// NOTE: The message must be of the correct length for the algorithm.
    /// Also, this method is deterministic, meaning that using the same message
    /// will yield the same [`SharedSecret`] and [`Ciphertext`]
    pub fn encapsulate<B: AsRef<[u8]>>(
        &self,
        message: B,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        self.algorithm.encapsulate(self, message)
    }
}

/// A FrodoKEM secret key
#[derive(Debug, Clone, Default)]
pub struct DecryptionKey {
    pub(crate) algorithm: Algorithm,
    pub(crate) value: Vec<u8>,
}

impl AsRef<[u8]> for DecryptionKey {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

ct_eq_imp!(DecryptionKey);

serde_impl!(DecryptionKey, decryption_key_from_bytes);

impl Zeroize for DecryptionKey {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl ZeroizeOnDrop for DecryptionKey {}

impl DecryptionKey {
    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Convert a slice of bytes into a [`DecryptionKey`] according to the specified [`Algorithm`].
    pub fn from_bytes<B: AsRef<[u8]>>(algorithm: Algorithm, value: B) -> FrodoResult<Self> {
        algorithm.decryption_key_from_bytes(value.as_ref())
    }

    /// Decapsulate the [`Ciphertext`] to return the [`SharedSecret`] and
    /// message generated during encapsulation.
    pub fn decapsulate<B: AsRef<[u8]>>(
        &self,
        ciphertext: &Ciphertext,
    ) -> FrodoResult<(SharedSecret, Vec<u8>)> {
        self.algorithm.decapsulate(self, ciphertext)
    }
}

/// A FrodoKEM shared secret
#[derive(Debug, Clone, Default)]
pub struct SharedSecret {
    pub(crate) algorithm: Algorithm,
    pub(crate) value: Vec<u8>,
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

ct_eq_imp!(SharedSecret);

serde_impl!(SharedSecret, shared_secret_from_bytes);

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    /// Get the algorithm
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Convert a slice of bytes into a [`SharedSecret`] according to the specified [`Algorithm`].
    pub fn from_bytes<B: AsRef<[u8]>>(algorithm: Algorithm, value: B) -> FrodoResult<Self> {
        algorithm.shared_secret_from_bytes(value.as_ref())
    }
}

/// The supported FrodoKem algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum Algorithm {
    #[cfg(feature = "frodo640aes")]
    /// The FrodoKEM-640-AES algorithm
    FrodoKem640Aes,
    #[cfg(feature = "frodo976aes")]
    /// The FrodoKEM-976-AES algorithm
    FrodoKem976Aes,
    #[cfg(feature = "frodo1344aes")]
    /// The FrodoKEM-1344-AES algorithm
    FrodoKem1344Aes,
    #[cfg(feature = "frodo640shake")]
    /// The FrodoKEM-640-SHAKE algorithm
    FrodoKem640Shake,
    #[cfg(feature = "frodo976shake")]
    /// The FrodoKEM-976-SHAKE algorithm
    FrodoKem976Shake,
    #[cfg(feature = "frodo1344shake")]
    /// The FrodoKEM-1344-SHAKE algorithm
    FrodoKem1344Shake,
}

impl ConstantTimeEq for Algorithm {
    fn ct_eq(&self, other: &Self) -> Choice {
        match (self, other) {
            #[cfg(feature = "frodo640aes")]
            (Self::FrodoKem640Aes, Self::FrodoKem640Aes) => Choice::from(1),
            #[cfg(feature = "frodo976aes")]
            (Self::FrodoKem976Aes, Self::FrodoKem976Aes) => Choice::from(1),
            #[cfg(feature = "frodo1344aes")]
            (Self::FrodoKem1344Aes, Self::FrodoKem1344Aes) => Choice::from(1),
            #[cfg(feature = "frodo640shake")]
            (Self::FrodoKem640Shake, Self::FrodoKem640Shake) => Choice::from(1),
            #[cfg(feature = "frodo976shake")]
            (Self::FrodoKem976Shake, Self::FrodoKem976Shake) => Choice::from(1),
            #[cfg(feature = "frodo1344shake")]
            (Self::FrodoKem1344Shake, Self::FrodoKem1344Shake) => Choice::from(1),
            _ => Choice::from(0),
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::enabled_algorithms()[0]
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        static ALGORITHMS: std::sync::LazyLock<std::collections::HashMap<Algorithm, String>> =
            std::sync::LazyLock::new(|| {
                let mut set = std::collections::HashMap::new();
                #[cfg(feature = "frodo640aes")]
                set.insert(
                    Algorithm::FrodoKem640Aes,
                    FrodoKem640Aes::default().algorithm(),
                );
                #[cfg(feature = "frodo976aes")]
                set.insert(
                    Algorithm::FrodoKem976Aes,
                    FrodoKem976Aes::default().algorithm(),
                );
                #[cfg(feature = "frodo1344aes")]
                set.insert(
                    Algorithm::FrodoKem1344Aes,
                    FrodoKem1344Aes::default().algorithm(),
                );
                #[cfg(feature = "frodo640shake")]
                set.insert(
                    Algorithm::FrodoKem640Shake,
                    FrodoKem640Shake::default().algorithm(),
                );
                #[cfg(feature = "frodo976shake")]
                set.insert(
                    Algorithm::FrodoKem976Shake,
                    FrodoKem976Shake::default().algorithm(),
                );
                #[cfg(feature = "frodo1344shake")]
                set.insert(
                    Algorithm::FrodoKem1344Shake,
                    FrodoKem1344Shake::default().algorithm(),
                );

                set
            });
        let ss = &(*ALGORITHMS)[self];
        write!(f, "{}", ss)
    }
}

impl std::str::FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        static ALGORITHMS: std::sync::LazyLock<std::collections::HashMap<String, Algorithm>> =
            std::sync::LazyLock::new(|| {
                let mut set = std::collections::HashMap::new();
                #[cfg(feature = "frodo640aes")]
                set.insert(
                    FrodoKem640Aes::default().algorithm(),
                    Algorithm::FrodoKem640Aes,
                );
                #[cfg(feature = "frodo976aes")]
                set.insert(
                    FrodoKem976Aes::default().algorithm(),
                    Algorithm::FrodoKem976Aes,
                );
                #[cfg(feature = "frodo1344aes")]
                set.insert(
                    FrodoKem1344Aes::default().algorithm(),
                    Algorithm::FrodoKem1344Aes,
                );
                #[cfg(feature = "frodo640shake")]
                set.insert(
                    FrodoKem640Shake::default().algorithm(),
                    Algorithm::FrodoKem640Shake,
                );
                #[cfg(feature = "frodo976shake")]
                set.insert(
                    FrodoKem976Shake::default().algorithm(),
                    Algorithm::FrodoKem976Shake,
                );
                #[cfg(feature = "frodo1344shake")]
                set.insert(
                    FrodoKem1344Shake::default().algorithm(),
                    Algorithm::FrodoKem1344Shake,
                );

                set
            });
        (*ALGORITHMS)
            .get(s)
            .ok_or(Error::UnsupportedAlgorithm)
            .copied()
    }
}

impl From<Algorithm> for u8 {
    fn from(alg: Algorithm) -> u8 {
        match alg {
            Algorithm::FrodoKem640Aes => 1,
            Algorithm::FrodoKem976Aes => 2,
            Algorithm::FrodoKem1344Aes => 3,
            Algorithm::FrodoKem640Shake => 4,
            Algorithm::FrodoKem976Shake => 5,
            Algorithm::FrodoKem1344Shake => 6,
        }
    }
}

impl From<Algorithm> for u16 {
    fn from(alg: Algorithm) -> u16 {
        u8::from(alg) as u16
    }
}

impl From<Algorithm> for u32 {
    fn from(alg: Algorithm) -> u32 {
        u8::from(alg) as u32
    }
}

impl From<Algorithm> for u64 {
    fn from(alg: Algorithm) -> u64 {
        u8::from(alg) as u64
    }
}

#[cfg(target_pointer_width = "64")]
impl From<Algorithm> for u128 {
    fn from(alg: Algorithm) -> u128 {
        u8::from(alg) as u128
    }
}

impl From<Algorithm> for usize {
    fn from(alg: Algorithm) -> usize {
        u8::from(alg) as usize
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Algorithm::FrodoKem640Aes),
            2 => Ok(Algorithm::FrodoKem976Aes),
            3 => Ok(Algorithm::FrodoKem1344Aes),
            4 => Ok(Algorithm::FrodoKem640Shake),
            5 => Ok(Algorithm::FrodoKem976Shake),
            6 => Ok(Algorithm::FrodoKem1344Shake),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

impl TryFrom<u16> for Algorithm {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let v = u8::try_from(value).map_err(|_| Error::UnsupportedAlgorithm)?;
        v.try_into()
    }
}

impl TryFrom<u32> for Algorithm {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let v = u8::try_from(value).map_err(|_| Error::UnsupportedAlgorithm)?;
        v.try_into()
    }
}

impl TryFrom<u64> for Algorithm {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let v = u8::try_from(value).map_err(|_| Error::UnsupportedAlgorithm)?;
        v.try_into()
    }
}

#[cfg(target_pointer_width = "64")]
impl TryFrom<u128> for Algorithm {
    type Error = Error;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        let v = u8::try_from(value).map_err(|_| Error::UnsupportedAlgorithm)?;
        v.try_into()
    }
}

impl TryFrom<usize> for Algorithm {
    type Error = Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let v = u8::try_from(value).map_err(|_| Error::UnsupportedAlgorithm)?;
        v.try_into()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Algorithm {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string())
        } else {
            s.serialize_u8(u8::from(*self))
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Algorithm {
    fn deserialize<D>(d: D) -> Result<Algorithm, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse().map_err(serde::de::Error::custom)
        } else {
            let v = u8::deserialize(d)?;
            v.try_into().map_err(serde::de::Error::custom)
        }
    }
}

impl Algorithm {
    /// Get the enabled algorithms
    pub fn enabled_algorithms() -> &'static [Algorithm] {
        &[
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake,
        ]
    }

    /// Get the claimed NIST level
    pub fn claimed_nist_level(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::CLAIMED_NIST_LEVEL,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::CLAIMED_NIST_LEVEL,
        }
    }

    /// Get the length of the message
    pub fn message_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::BYTES_MU,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::BYTES_MU,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::BYTES_MU,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::BYTES_MU,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::BYTES_MU,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::BYTES_MU,
        }
    }

    /// Get the length of the public key
    pub fn encryption_key_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::PUBLIC_KEY_LENGTH,
        }
    }

    /// Get the length of the secret key
    pub fn decryption_key_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::SECRET_KEY_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::SECRET_KEY_LENGTH,
        }
    }

    /// Get the length of the shared secret
    pub fn shared_secret_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::SHARED_SECRET_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::SHARED_SECRET_LENGTH,
        }
    }

    /// Get the length of the ciphertext
    pub fn ciphertext_length(&self) -> usize {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => <Frodo640 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => <Frodo976 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => <Frodo1344 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => <Frodo640 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => <Frodo976 as Params>::CIPHERTEXT_LENGTH,
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => <Frodo1344 as Params>::CIPHERTEXT_LENGTH,
        }
    }

    /// Get the [`EncryptionKey`] from a [`DecryptionKey`]
    pub fn encryption_key_from_decryption_key(&self, secret_key: &DecryptionKey) -> EncryptionKey {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let sk =
                    DecryptionKeyRef::<FrodoKem640Aes>(secret_key.value.as_slice(), PhantomData);
                EncryptionKey {
                    algorithm: *self,
                    value: sk.public_key().to_vec(),
                }
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let sk =
                    DecryptionKeyRef::<FrodoKem976Aes>(secret_key.value.as_slice(), PhantomData);
                EncryptionKey {
                    algorithm: *self,
                    value: sk.public_key().to_vec(),
                }
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let sk =
                    DecryptionKeyRef::<FrodoKem1344Aes>(secret_key.value.as_slice(), PhantomData);
                EncryptionKey {
                    algorithm: *self,
                    value: sk.public_key().to_vec(),
                }
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let sk =
                    DecryptionKeyRef::<FrodoKem640Shake>(secret_key.value.as_slice(), PhantomData);
                EncryptionKey {
                    algorithm: *self,
                    value: sk.public_key().to_vec(),
                }
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let sk =
                    DecryptionKeyRef::<FrodoKem976Shake>(secret_key.value.as_slice(), PhantomData);
                EncryptionKey {
                    algorithm: *self,
                    value: sk.public_key().to_vec(),
                }
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let sk =
                    DecryptionKeyRef::<FrodoKem1344Shake>(secret_key.value.as_slice(), PhantomData);
                EncryptionKey {
                    algorithm: *self,
                    value: sk.public_key().to_vec(),
                }
            }
        }
    }

    /// Obtain a secret key from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn decryption_key_from_bytes(&self, buf: &[u8]) -> FrodoResult<DecryptionKey> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::DecryptionKey::<FrodoKem640Aes>::from_slice(buf).map(|s| DecryptionKey {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::DecryptionKey::<FrodoKem976Aes>::from_slice(buf).map(|s| DecryptionKey {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::DecryptionKey::<FrodoKem1344Aes>::from_slice(buf).map(|s| DecryptionKey {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => hazmat::DecryptionKey::<FrodoKem640Shake>::from_slice(buf)
                .map(|s| DecryptionKey {
                    algorithm: *self,
                    value: s.0,
                }),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => hazmat::DecryptionKey::<FrodoKem976Shake>::from_slice(buf)
                .map(|s| DecryptionKey {
                    algorithm: *self,
                    value: s.0,
                }),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => hazmat::DecryptionKey::<FrodoKem1344Shake>::from_slice(buf)
                .map(|s| DecryptionKey {
                    algorithm: *self,
                    value: s.0,
                }),
        }
    }

    /// Obtain a public key from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn encryption_key_from_bytes(&self, buf: &[u8]) -> FrodoResult<EncryptionKey> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::EncryptionKey::<FrodoKem640Aes>::from_slice(buf).map(|s| EncryptionKey {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::EncryptionKey::<FrodoKem976Aes>::from_slice(buf).map(|s| EncryptionKey {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::EncryptionKey::<FrodoKem1344Aes>::from_slice(buf).map(|s| EncryptionKey {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => hazmat::EncryptionKey::<FrodoKem640Shake>::from_slice(buf)
                .map(|s| EncryptionKey {
                    algorithm: *self,
                    value: s.0,
                }),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => hazmat::EncryptionKey::<FrodoKem976Shake>::from_slice(buf)
                .map(|s| EncryptionKey {
                    algorithm: *self,
                    value: s.0,
                }),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => hazmat::EncryptionKey::<FrodoKem1344Shake>::from_slice(buf)
                .map(|s| EncryptionKey {
                    algorithm: *self,
                    value: s.0,
                }),
        }
    }

    /// Obtain a ciphertext from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn ciphertext_from_bytes(&self, buf: &[u8]) -> FrodoResult<Ciphertext> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::Ciphertext::<FrodoKem640Aes>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::Ciphertext::<FrodoKem976Aes>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::Ciphertext::<FrodoKem1344Aes>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                hazmat::Ciphertext::<FrodoKem640Shake>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                hazmat::Ciphertext::<FrodoKem976Shake>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => hazmat::Ciphertext::<FrodoKem1344Shake>::from_slice(buf)
                .map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                }),
        }
    }

    /// Obtain a shared secret from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn shared_secret_from_bytes(&self, buf: &[u8]) -> FrodoResult<SharedSecret> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                hazmat::SharedSecret::<FrodoKem640Aes>::from_slice(buf).map(|s| SharedSecret {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                hazmat::SharedSecret::<FrodoKem976Aes>::from_slice(buf).map(|s| SharedSecret {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                hazmat::SharedSecret::<FrodoKem1344Aes>::from_slice(buf).map(|s| SharedSecret {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => hazmat::SharedSecret::<FrodoKem640Shake>::from_slice(buf)
                .map(|s| SharedSecret {
                    algorithm: *self,
                    value: s.0,
                }),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => hazmat::SharedSecret::<FrodoKem976Shake>::from_slice(buf)
                .map(|s| SharedSecret {
                    algorithm: *self,
                    value: s.0,
                }),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => hazmat::SharedSecret::<FrodoKem1344Shake>::from_slice(buf)
                .map(|s| SharedSecret {
                    algorithm: *self,
                    value: s.0,
                }),
        }
    }

    /// Generate a new keypair consisting of a [`EncryptionKey`] and a [`DecryptionKey`]
    pub fn generate_keypair(&self, rng: impl CryptoRngCore) -> (EncryptionKey, DecryptionKey) {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let (pk, sk) = FrodoKem640Aes::default().generate_keypair(rng);
                (
                    EncryptionKey {
                        algorithm: *self,
                        value: pk.0,
                    },
                    DecryptionKey {
                        algorithm: *self,
                        value: sk.0,
                    },
                )
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let (pk, sk) = FrodoKem976Aes::default().generate_keypair(rng);
                (
                    EncryptionKey {
                        algorithm: *self,
                        value: pk.0,
                    },
                    DecryptionKey {
                        algorithm: *self,
                        value: sk.0,
                    },
                )
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let (pk, sk) = FrodoKem1344Aes::default().generate_keypair(rng);
                (
                    EncryptionKey {
                        algorithm: *self,
                        value: pk.0,
                    },
                    DecryptionKey {
                        algorithm: *self,
                        value: sk.0,
                    },
                )
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let (pk, sk) = FrodoKem640Shake::default().generate_keypair(rng);
                (
                    EncryptionKey {
                        algorithm: *self,
                        value: pk.0,
                    },
                    DecryptionKey {
                        algorithm: *self,
                        value: sk.0,
                    },
                )
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let (pk, sk) = FrodoKem976Shake::default().generate_keypair(rng);
                (
                    EncryptionKey {
                        algorithm: *self,
                        value: pk.0,
                    },
                    DecryptionKey {
                        algorithm: *self,
                        value: sk.0,
                    },
                )
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let (pk, sk) = FrodoKem1344Shake::default().generate_keypair(rng);
                (
                    EncryptionKey {
                        algorithm: *self,
                        value: pk.0,
                    },
                    DecryptionKey {
                        algorithm: *self,
                        value: sk.0,
                    },
                )
            }
        }
    }

    /// Encapsulate with given message to generate a [`SharedSecret`] and a [`Ciphertext`].
    ///
    /// NOTE: The message must be of the correct length for the algorithm.
    /// Also, this method is deterministic, meaning that using the same message
    /// will yield the same [`SharedSecret`] and [`Ciphertext`]
    pub fn encapsulate<B: AsRef<[u8]>>(
        &self,
        public_key: &EncryptionKey,
        msg: B,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        let msg = msg.as_ref();
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                if <Frodo640 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (ct, ss) = FrodoKem640Aes::default().encapsulate(pk, msg);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: ct.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                ))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                if <Frodo976 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem976Aes::default().encapsulate(pk, msg);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                if <Frodo1344 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem1344Aes::default().encapsulate(pk, msg);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                if <Frodo640 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem640Shake::default().encapsulate(pk, msg);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                if <Frodo976 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem976Shake::default().encapsulate(pk, msg);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                if <Frodo1344 as Params>::BYTES_MU != msg.len() {
                    return Err(Error::InvalidMessageLength(msg.len()));
                }
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem1344Shake::default().encapsulate(pk, msg);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
        }
    }

    /// Encapsulate a random value to generate a [`SharedSecret`] and a [`Ciphertext`].
    pub fn encapsulate_with_rng(
        &self,
        public_key: &EncryptionKey,
        rng: impl CryptoRngCore,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (ct, ss) = FrodoKem640Aes::default().encapsulate_with_rng(pk, rng);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: ct.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                ))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem976Aes::default().encapsulate_with_rng(pk, rng);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem1344Aes::default().encapsulate_with_rng(pk, rng);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem640Shake::default().encapsulate_with_rng(pk, rng);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem976Shake::default().encapsulate_with_rng(pk, rng);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let pk = EncryptionKeyRef::from_slice(public_key.value.as_slice())?;
                let (pk, sk) = FrodoKem1344Shake::default().encapsulate_with_rng(pk, rng);
                Ok((
                    Ciphertext {
                        algorithm: *self,
                        value: pk.0,
                    },
                    SharedSecret {
                        algorithm: *self,
                        value: sk.0,
                    },
                ))
            }
        }
    }

    /// Decapsulate the [`Ciphertext`] to return the [`SharedSecret`] and
    /// message generated during encapsulation.
    pub fn decapsulate(
        &self,
        secret_key: &DecryptionKey,
        ciphertext: &Ciphertext,
    ) -> FrodoResult<(SharedSecret, Vec<u8>)> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
                let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
                let (ss, mu) = FrodoKem640Aes::default().decapsulate(sk, ct);
                Ok((
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                    mu,
                ))
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
                let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
                let (ss, mu) = FrodoKem976Aes::default().decapsulate(sk, ct);
                Ok((
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                    mu,
                ))
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
                let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
                let (ss, mu) = FrodoKem1344Aes::default().decapsulate(sk, ct);
                Ok((
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                    mu,
                ))
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
                let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
                let (ss, mu) = FrodoKem640Shake::default().decapsulate(sk, ct);
                Ok((
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                    mu,
                ))
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
                let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
                let (ss, mu) = FrodoKem976Shake::default().decapsulate(sk, ct);
                Ok((
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                    mu,
                ))
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
                let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
                let (ss, mu) = FrodoKem1344Shake::default().decapsulate(sk, ct);
                Ok((
                    SharedSecret {
                        algorithm: *self,
                        value: ss.0,
                    },
                    mu,
                ))
            }
        }
    }
}

fn ct_eq_bytes(lhs: &[u8], rhs: &[u8]) -> Choice {
    if lhs.len() != rhs.len() {
        return 0u8.into();
    }

    let mut eq = 0u8;
    for i in 0..lhs.len() {
        eq |= lhs[i] ^ rhs[i];
    }

    let eq = ((eq | eq.wrapping_neg()) >> 7).wrapping_add(1);
    Choice::from(eq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{RngCore, SeedableRng};
    use rstest::*;
    use safe_oqs::kem;

    #[rstest]
    #[case::aes640(Algorithm::FrodoKem640Aes, kem::Algorithm::FrodoKem640Aes)]
    #[case::aes976(Algorithm::FrodoKem976Aes, kem::Algorithm::FrodoKem976Aes)]
    #[case::aes1344(Algorithm::FrodoKem1344Aes, kem::Algorithm::FrodoKem1344Aes)]
    #[case::shake640(Algorithm::FrodoKem640Shake, kem::Algorithm::FrodoKem640Shake)]
    #[case::shake976(Algorithm::FrodoKem976Shake, kem::Algorithm::FrodoKem976Shake)]
    #[case::shake1344(Algorithm::FrodoKem1344Shake, kem::Algorithm::FrodoKem1344Shake)]
    fn works(#[case] alg: Algorithm, #[case] safe_alg: kem::Algorithm) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = alg.generate_keypair(&mut rng);
        let kem = kem::Kem::new(safe_alg).unwrap();

        let opt_pk = kem.public_key_from_bytes(&our_pk.value);
        assert!(opt_pk.is_some());
        let opt_sk = kem.secret_key_from_bytes(&our_sk.value);
        assert!(opt_sk.is_some());

        let their_pk = opt_pk.unwrap();
        let their_sk = opt_sk.unwrap();

        let mut mu = vec![0u8; alg.message_length()];
        rng.fill_bytes(&mut mu);
        let (our_ct, our_ess) = alg.encapsulate(&our_pk, &mu).unwrap();
        let (our_dss, mu_prime) = alg.decapsulate(&our_sk, &our_ct).unwrap();
        assert_eq!(our_ess.value, our_dss.value);
        assert_eq!(mu, mu_prime);

        let their_ct = kem.ciphertext_from_bytes(&our_ct.value).unwrap();
        let their_ss = kem.decapsulate(&their_sk, &their_ct).unwrap();
        assert_eq!(our_dss.value, their_ss.as_ref());

        let (their_ct, their_ess) = kem.encapsulate(&their_pk).unwrap();

        let our_ct = alg.ciphertext_from_bytes(&their_ct.as_ref()).unwrap();

        let (their_dss, _) = alg.decapsulate(&our_sk, &our_ct).unwrap();
        assert_eq!(their_ess.as_ref(), their_dss.value);
    }

    macro_rules! serde_test {
        ($name:ident, $ser:path, $de:path) => {
            #[cfg(feature = "serde")]
            #[rstest]
            #[case::aes640(Algorithm::FrodoKem640Aes)]
            #[case::aes976(Algorithm::FrodoKem976Aes)]
            #[case::aes1344(Algorithm::FrodoKem1344Aes)]
            #[case::shake640(Algorithm::FrodoKem640Shake)]
            #[case::shake976(Algorithm::FrodoKem976Shake)]
            #[case::shake1344(Algorithm::FrodoKem1344Shake)]
            fn $name(#[case] alg: Algorithm) {
                let mut rng = rand_chacha::ChaCha8Rng::from_seed([3u8; 32]);
                let (pk, sk) = alg.generate_keypair(&mut rng);
                let (ct, ss) = alg.encapsulate_with_rng(&pk, &mut rng).unwrap();

                let pk_str = $ser(&pk);
                let sk_str = $ser(&sk);
                let ct_str = $ser(&ct);
                let ss_str = $ser(&ss);

                assert!(pk_str.is_ok());
                assert!(sk_str.is_ok());
                assert!(ct_str.is_ok());
                assert!(ss_str.is_ok());

                let pk_str = pk_str.unwrap();
                let sk_str = sk_str.unwrap();
                let ct_str = ct_str.unwrap();
                let ss_str = ss_str.unwrap();

                let pk2 = $de(&pk_str);
                let sk2 = $de(&sk_str);
                let ct2 = $de(&ct_str);
                let ss2 = $de(&ss_str);

                assert!(pk2.is_ok());
                assert!(sk2.is_ok());
                assert!(ct2.is_ok());
                assert!(ss2.is_ok());

                let pk2 = pk2.unwrap();
                let sk2 = sk2.unwrap();
                let ct2 = ct2.unwrap();
                let ss2 = ss2.unwrap();

                assert_eq!(pk, pk2);
                assert_eq!(sk, sk2);
                assert_eq!(ct, ct2);
                assert_eq!(ss, ss2);
            }
        };
    }

    serde_test!(
        serialization_json,
        serde_json::to_string,
        serde_json::from_str
    );
    serde_test!(serialization_toml, toml::to_string, toml::from_str);
    serde_test!(
        serialization_yaml,
        serde_yaml::to_string,
        serde_yaml::from_str
    );
    serde_test!(
        serialization_bare,
        serde_bare::to_vec,
        serde_bare::from_slice
    );
    serde_test!(
        serialization_cbor,
        serde_cbor::to_vec,
        serde_cbor::from_slice
    );
    serde_test!(
        serialization_postcard,
        postcard::to_stdvec,
        postcard::from_bytes
    );
    serde_test!(
        serialization_bincode,
        bincode::serialize,
        bincode::deserialize
    );
}
