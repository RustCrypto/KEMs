//! ## Usage
//!
//! The standard safe method for FrodoKEM is to use [`Algorithm`],
//! `encapsulate` a randomly generated value,
//! and `decapsulate` it on the other side.
//!
//! ```
//! use frodo_kem::Algorithm;
//! use rand_core::OsRng;
//!
//! let alg = Algorithm::FrodoKem640Shake;
//! let (ek, dk) = alg.generate_keypair(OsRng);
//! let (ct, enc_ss) = alg.encapsulate_with_rng(&ek, OsRng).unwrap();
//! let (dec_ss, msg) = alg.decapsulate(&dk, &ct).unwrap();
//!
//! assert_eq!(enc_ss, dec_ss);
//! ```
//! If the `message` is known, it can be passed to the `encapsulate`.
//! `encapsulate` will error if the `message` is not the correct size. This method also requires
//! a `salt` for non-ephemeral algorithms, and the `salt` is considered public information.
//!
//! Ephemeral variants are meant to be used one-time only and thus do not require a `salt`.
//!
//! ## ☢️️ WARNING: HAZARDOUS ☢️
//! It is considered unsafe to use Ephemeral algorithms more than once.
//! For more information see [ISO Standard Annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf).
//!
//! ```
//! use frodo_kem::Algorithm;
//! use rand_core::{RngCore, OsRng};
//!
//! let alg = Algorithm::FrodoKem1344Shake;
//! let params = alg.params();
//! let (ek, dk) = alg.generate_keypair(OsRng);
//! // Key is known, generate
//! let aes_256_key = vec![3u8; params.message_length];
//! let mut salt = vec![0u8; params.salt_length];
//! OsRng.fill_bytes(&mut salt);
//! let (ct, enc_ss) = alg.encapsulate(&ek, &aes_256_key, &salt).unwrap();
//! let (dec_ss, dec_msg) = alg.decapsulate(&dk, &ct).unwrap();
//!
//! // Ephemeral method, no salt required
//! let alg = Algorithm::EphemeralFrodoKem1344Shake;
//! let (ct, enc_ss) = alg.encapsulate(&ek, &aes_256_key, &[]).unwrap();
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
//! To create a custom implementation of FrodoKEM, use the `hazmat` feature, to access
//! the necessary traits and models for creating a custom implementation.
//! Be warned, this is not recommended unless you are sure of what you are doing.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    clippy::mod_module_files
)]
#![deny(clippy::unwrap_used)]

#[cfg(not(any(
    feature = "efrodo640aes",
    feature = "frodo640aes",
    feature = "efrodo976aes",
    feature = "frodo976aes",
    feature = "efrodo1344aes",
    feature = "frodo1344aes",
    feature = "efrodo640shake",
    feature = "frodo640shake",
    feature = "efrodo976shake",
    feature = "frodo976shake",
    feature = "efrodo1344shake",
    feature = "frodo1344shake",
)))]
compile_error!("no algorithm feature enabled");

mod error;
pub use error::*;

#[cfg(feature = "hazmat")]
pub mod hazmat;
#[cfg(not(feature = "hazmat"))]
mod hazmat;

use hazmat::*;

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
    pub fn encapsulate<B: AsRef<[u8]>, S: AsRef<[u8]>>(
        &self,
        message: B,
        salt: S,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        self.algorithm.encapsulate(self, message, salt)
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
    #[cfg(feature = "efrodo640aes")]
    /// The FrodoKEM-640-AES algorithm
    EphemeralFrodoKem640Aes,
    #[cfg(feature = "efrodo976aes")]
    /// The FrodoKEM-976-AES algorithm
    EphemeralFrodoKem976Aes,
    #[cfg(feature = "efrodo1344aes")]
    /// The FrodoKEM-1344-AES algorithm
    EphemeralFrodoKem1344Aes,
    #[cfg(feature = "efrodo640shake")]
    /// The FrodoKEM-640-SHAKE algorithm
    EphemeralFrodoKem640Shake,
    #[cfg(feature = "efrodo976shake")]
    /// The FrodoKEM-976-SHAKE algorithm
    EphemeralFrodoKem976Shake,
    #[cfg(feature = "efrodo1344shake")]
    /// The FrodoKEM-1344-SHAKE algorithm
    EphemeralFrodoKem1344Shake,
}

impl ConstantTimeEq for Algorithm {
    fn ct_eq(&self, other: &Self) -> Choice {
        match (self, other) {
            #[cfg(feature = "efrodo640aes")]
            (Self::EphemeralFrodoKem640Aes, Self::EphemeralFrodoKem640Aes) => Choice::from(1),
            #[cfg(feature = "efrodo976aes")]
            (Self::EphemeralFrodoKem976Aes, Self::EphemeralFrodoKem976Aes) => Choice::from(1),
            #[cfg(feature = "efrodo1344aes")]
            (Self::EphemeralFrodoKem1344Aes, Self::EphemeralFrodoKem1344Aes) => Choice::from(1),
            #[cfg(feature = "efrodo640shake")]
            (Self::EphemeralFrodoKem640Shake, Self::EphemeralFrodoKem640Shake) => Choice::from(1),
            #[cfg(feature = "efrodo976shake")]
            (Self::EphemeralFrodoKem976Shake, Self::EphemeralFrodoKem976Shake) => Choice::from(1),
            #[cfg(feature = "efrodo1344shake")]
            (Self::EphemeralFrodoKem1344Shake, Self::EphemeralFrodoKem1344Shake) => Choice::from(1),
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
                #[cfg(feature = "efrodo640aes")]
                set.insert(
                    Algorithm::EphemeralFrodoKem640Aes,
                    EphemeralFrodoKem640Aes::default().algorithm(),
                );
                #[cfg(feature = "efrodo976aes")]
                set.insert(
                    Algorithm::EphemeralFrodoKem976Aes,
                    EphemeralFrodoKem976Aes::default().algorithm(),
                );
                #[cfg(feature = "efrodo1344aes")]
                set.insert(
                    Algorithm::EphemeralFrodoKem1344Aes,
                    EphemeralFrodoKem1344Aes::default().algorithm(),
                );
                #[cfg(feature = "efrodo640shake")]
                set.insert(
                    Algorithm::EphemeralFrodoKem640Shake,
                    EphemeralFrodoKem640Shake::default().algorithm(),
                );
                #[cfg(feature = "efrodo976shake")]
                set.insert(
                    Algorithm::EphemeralFrodoKem976Shake,
                    EphemeralFrodoKem976Shake::default().algorithm(),
                );
                #[cfg(feature = "efrodo1344shake")]
                set.insert(
                    Algorithm::EphemeralFrodoKem1344Shake,
                    EphemeralFrodoKem1344Shake::default().algorithm(),
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
                #[cfg(feature = "efrodo640aes")]
                set.insert(
                    EphemeralFrodoKem640Aes::default().algorithm(),
                    Algorithm::EphemeralFrodoKem640Aes,
                );
                #[cfg(feature = "efrodo976aes")]
                set.insert(
                    EphemeralFrodoKem976Aes::default().algorithm(),
                    Algorithm::EphemeralFrodoKem976Aes,
                );
                #[cfg(feature = "efrodo1344aes")]
                set.insert(
                    EphemeralFrodoKem1344Aes::default().algorithm(),
                    Algorithm::EphemeralFrodoKem1344Aes,
                );
                #[cfg(feature = "efrodo640shake")]
                set.insert(
                    EphemeralFrodoKem640Shake::default().algorithm(),
                    Algorithm::EphemeralFrodoKem640Shake,
                );
                #[cfg(feature = "efrodo976shake")]
                set.insert(
                    EphemeralFrodoKem976Shake::default().algorithm(),
                    Algorithm::EphemeralFrodoKem976Shake,
                );
                #[cfg(feature = "efrodo1344shake")]
                set.insert(
                    EphemeralFrodoKem1344Shake::default().algorithm(),
                    Algorithm::EphemeralFrodoKem1344Shake,
                );

                set
            });
        (*ALGORITHMS)
            .get(s)
            .copied()
            .ok_or(Error::UnsupportedAlgorithm)
    }
}

impl From<Algorithm> for u8 {
    fn from(alg: Algorithm) -> u8 {
        match alg {
            #[cfg(feature = "frodo640aes")]
            Algorithm::FrodoKem640Aes => 1,
            #[cfg(feature = "frodo976aes")]
            Algorithm::FrodoKem976Aes => 2,
            #[cfg(feature = "frodo1344aes")]
            Algorithm::FrodoKem1344Aes => 3,
            #[cfg(feature = "frodo640shake")]
            Algorithm::FrodoKem640Shake => 4,
            #[cfg(feature = "frodo976shake")]
            Algorithm::FrodoKem976Shake => 5,
            #[cfg(feature = "frodo1344shake")]
            Algorithm::FrodoKem1344Shake => 6,
            #[cfg(feature = "efrodo640aes")]
            Algorithm::EphemeralFrodoKem640Aes => 7,
            #[cfg(feature = "efrodo976aes")]
            Algorithm::EphemeralFrodoKem976Aes => 8,
            #[cfg(feature = "efrodo1344aes")]
            Algorithm::EphemeralFrodoKem1344Aes => 9,
            #[cfg(feature = "efrodo640shake")]
            Algorithm::EphemeralFrodoKem640Shake => 10,
            #[cfg(feature = "efrodo976shake")]
            Algorithm::EphemeralFrodoKem976Shake => 11,
            #[cfg(feature = "efrodo1344shake")]
            Algorithm::EphemeralFrodoKem1344Shake => 12,
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
            #[cfg(feature = "frodo640aes")]
            1 => Ok(Algorithm::FrodoKem640Aes),
            #[cfg(feature = "frodo976aes")]
            2 => Ok(Algorithm::FrodoKem976Aes),
            #[cfg(feature = "frodo1344aes")]
            3 => Ok(Algorithm::FrodoKem1344Aes),
            #[cfg(feature = "frodo640shake")]
            4 => Ok(Algorithm::FrodoKem640Shake),
            #[cfg(feature = "frodo976shake")]
            5 => Ok(Algorithm::FrodoKem976Shake),
            #[cfg(feature = "frodo1344shake")]
            6 => Ok(Algorithm::FrodoKem1344Shake),
            #[cfg(feature = "efrodo640aes")]
            7 => Ok(Algorithm::EphemeralFrodoKem640Aes),
            #[cfg(feature = "efrodo976aes")]
            8 => Ok(Algorithm::EphemeralFrodoKem976Aes),
            #[cfg(feature = "efrodo1344aes")]
            9 => Ok(Algorithm::EphemeralFrodoKem1344Aes),
            #[cfg(feature = "efrodo640shake")]
            10 => Ok(Algorithm::EphemeralFrodoKem640Shake),
            #[cfg(feature = "efrodo976shake")]
            11 => Ok(Algorithm::EphemeralFrodoKem976Shake),
            #[cfg(feature = "efrodo1344shake")]
            12 => Ok(Algorithm::EphemeralFrodoKem1344Shake),
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
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes,
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes,
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes,
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake,
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake,
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake,
        ]
    }

    /// Get the parameters for this algorithm
    pub const fn params(&self) -> AlgorithmParams {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => self.inner_params::<FrodoKem640Aes>(),
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => self.inner_params::<FrodoKem976Aes>(),
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => self.inner_params::<FrodoKem1344Aes>(),
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => self.inner_params::<FrodoKem640Shake>(),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => self.inner_params::<FrodoKem976Shake>(),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => self.inner_params::<FrodoKem1344Shake>(),
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => self.inner_params::<EphemeralFrodoKem640Aes>(),
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => self.inner_params::<EphemeralFrodoKem976Aes>(),
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => self.inner_params::<EphemeralFrodoKem1344Aes>(),
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => self.inner_params::<EphemeralFrodoKem640Shake>(),
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => self.inner_params::<EphemeralFrodoKem976Shake>(),
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => self.inner_params::<EphemeralFrodoKem1344Shake>(),
        }
    }

    const fn inner_params<B: Params>(&self) -> AlgorithmParams {
        AlgorithmParams {
            n: B::N,
            n_bar: B::N_BAR,
            log_q: B::LOG_Q,
            q: B::Q,
            extracted_bits: B::EXTRACTED_BITS,
            stripe_step: B::STRIPE_STEP,
            bytes_seed_a: B::BYTES_SEED_A,
            bytes_pk_hash: B::BYTES_PK_HASH,
            cdf_table: B::CDF_TABLE,
            claimed_nist_level: B::CLAIMED_NIST_LEVEL,
            shared_secret_length: B::SHARED_SECRET_LENGTH,
            message_length: B::BYTES_MU,
            salt_length: B::BYTES_SALT,
            encryption_key_length: B::PUBLIC_KEY_LENGTH,
            decryption_key_length: B::SECRET_KEY_LENGTH,
            ciphertext_length: B::CIPHERTEXT_LENGTH,
        }
    }

    /// Get the [`EncryptionKey`] from a [`DecryptionKey`]
    pub fn encryption_key_from_decryption_key(&self, secret_key: &DecryptionKey) -> EncryptionKey {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                self.inner_encryption_key_from_decryption_key::<FrodoKem640Aes>(secret_key)
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                self.inner_encryption_key_from_decryption_key::<FrodoKem976Aes>(secret_key)
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                self.inner_encryption_key_from_decryption_key::<FrodoKem1344Aes>(secret_key)
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                self.inner_encryption_key_from_decryption_key::<FrodoKem640Shake>(secret_key)
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                self.inner_encryption_key_from_decryption_key::<FrodoKem976Shake>(secret_key)
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                self.inner_encryption_key_from_decryption_key::<FrodoKem1344Shake>(secret_key)
            }
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_encryption_key_from_decryption_key::<EphemeralFrodoKem640Aes>(secret_key)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_encryption_key_from_decryption_key::<EphemeralFrodoKem976Aes>(secret_key)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => self
                .inner_encryption_key_from_decryption_key::<EphemeralFrodoKem1344Aes>(secret_key),
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => self
                .inner_encryption_key_from_decryption_key::<EphemeralFrodoKem640Shake>(secret_key),
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => self
                .inner_encryption_key_from_decryption_key::<EphemeralFrodoKem976Shake>(secret_key),
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => self
                .inner_encryption_key_from_decryption_key::<EphemeralFrodoKem1344Shake>(secret_key),
        }
    }

    fn inner_encryption_key_from_decryption_key<B: Params>(
        &self,
        secret_key: &DecryptionKey,
    ) -> EncryptionKey {
        let sk = DecryptionKeyRef::<B>(secret_key.value.as_slice(), PhantomData);
        EncryptionKey {
            algorithm: *self,
            value: sk.public_key().to_vec(),
        }
    }

    /// Obtain a secret key from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn decryption_key_from_bytes<B: AsRef<[u8]>>(&self, buf: B) -> FrodoResult<DecryptionKey> {
        let buf = buf.as_ref();
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => self.inner_decryption_key_from_bytes::<FrodoKem640Aes>(buf),
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => self.inner_decryption_key_from_bytes::<FrodoKem976Aes>(buf),
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => self.inner_decryption_key_from_bytes::<FrodoKem1344Aes>(buf),
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => self.inner_decryption_key_from_bytes::<FrodoKem640Shake>(buf),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => self.inner_decryption_key_from_bytes::<FrodoKem976Shake>(buf),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                self.inner_decryption_key_from_bytes::<FrodoKem1344Shake>(buf)
            }
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_decryption_key_from_bytes::<EphemeralFrodoKem640Aes>(buf)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_decryption_key_from_bytes::<EphemeralFrodoKem976Aes>(buf)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                self.inner_decryption_key_from_bytes::<EphemeralFrodoKem1344Aes>(buf)
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                self.inner_decryption_key_from_bytes::<EphemeralFrodoKem640Shake>(buf)
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                self.inner_decryption_key_from_bytes::<EphemeralFrodoKem976Shake>(buf)
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                self.inner_decryption_key_from_bytes::<EphemeralFrodoKem1344Shake>(buf)
            }
        }
    }

    fn inner_decryption_key_from_bytes<P: Params>(&self, buf: &[u8]) -> FrodoResult<DecryptionKey> {
        hazmat::DecryptionKey::<P>::from_slice(buf).map(|s| DecryptionKey {
            algorithm: *self,
            value: s.0,
        })
    }

    /// Obtain a public key from a byte slice
    ///
    /// Returns Err if the byte slice is not the correct length
    pub fn encryption_key_from_bytes<B: AsRef<[u8]>>(&self, buf: B) -> FrodoResult<EncryptionKey> {
        let buf = buf.as_ref();
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => self.inner_encryption_key_from_bytes::<FrodoKem640Aes>(buf),
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => self.inner_encryption_key_from_bytes::<FrodoKem976Aes>(buf),
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => self.inner_encryption_key_from_bytes::<FrodoKem1344Aes>(buf),
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => self.inner_encryption_key_from_bytes::<FrodoKem640Shake>(buf),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => self.inner_encryption_key_from_bytes::<FrodoKem976Shake>(buf),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                self.inner_encryption_key_from_bytes::<FrodoKem1344Shake>(buf)
            }
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_encryption_key_from_bytes::<EphemeralFrodoKem640Aes>(buf)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_encryption_key_from_bytes::<EphemeralFrodoKem976Aes>(buf)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                self.inner_encryption_key_from_bytes::<EphemeralFrodoKem1344Aes>(buf)
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                self.inner_encryption_key_from_bytes::<EphemeralFrodoKem640Shake>(buf)
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                self.inner_encryption_key_from_bytes::<EphemeralFrodoKem976Shake>(buf)
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                self.inner_encryption_key_from_bytes::<EphemeralFrodoKem1344Shake>(buf)
            }
        }
    }

    fn inner_encryption_key_from_bytes<P: Params>(&self, buf: &[u8]) -> FrodoResult<EncryptionKey> {
        hazmat::EncryptionKey::<P>::from_slice(buf).map(|s| EncryptionKey {
            algorithm: *self,
            value: s.0,
        })
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
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                hazmat::Ciphertext::<EphemeralFrodoKem640Aes>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                hazmat::Ciphertext::<EphemeralFrodoKem976Aes>::from_slice(buf).map(|s| Ciphertext {
                    algorithm: *self,
                    value: s.0,
                })
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                hazmat::Ciphertext::<EphemeralFrodoKem1344Aes>::from_slice(buf).map(|s| {
                    Ciphertext {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                hazmat::Ciphertext::<EphemeralFrodoKem640Shake>::from_slice(buf).map(|s| {
                    Ciphertext {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                hazmat::Ciphertext::<EphemeralFrodoKem976Shake>::from_slice(buf).map(|s| {
                    Ciphertext {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                hazmat::Ciphertext::<EphemeralFrodoKem1344Shake>::from_slice(buf).map(|s| {
                    Ciphertext {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
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
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                hazmat::SharedSecret::<EphemeralFrodoKem640Aes>::from_slice(buf).map(|s| {
                    SharedSecret {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                hazmat::SharedSecret::<EphemeralFrodoKem976Aes>::from_slice(buf).map(|s| {
                    SharedSecret {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                hazmat::SharedSecret::<EphemeralFrodoKem1344Aes>::from_slice(buf).map(|s| {
                    SharedSecret {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                hazmat::SharedSecret::<EphemeralFrodoKem640Shake>::from_slice(buf).map(|s| {
                    SharedSecret {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                hazmat::SharedSecret::<EphemeralFrodoKem976Shake>::from_slice(buf).map(|s| {
                    SharedSecret {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                hazmat::SharedSecret::<EphemeralFrodoKem1344Shake>::from_slice(buf).map(|s| {
                    SharedSecret {
                        algorithm: *self,
                        value: s.0,
                    }
                })
            }
        }
    }

    /// Generate a new keypair consisting of a [`EncryptionKey`] and a [`DecryptionKey`]
    pub fn generate_keypair(&self, rng: impl CryptoRngCore) -> (EncryptionKey, DecryptionKey) {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => self.inner_generate_keypair::<FrodoKem640Aes>(rng),
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => self.inner_generate_keypair::<FrodoKem976Aes>(rng),
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => self.inner_generate_keypair::<FrodoKem1344Aes>(rng),
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => self.inner_generate_keypair::<FrodoKem640Shake>(rng),
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => self.inner_generate_keypair::<FrodoKem976Shake>(rng),
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => self.inner_generate_keypair::<FrodoKem1344Shake>(rng),
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_generate_keypair::<EphemeralFrodoKem640Aes>(rng)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_generate_keypair::<EphemeralFrodoKem976Aes>(rng)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                self.inner_generate_keypair::<EphemeralFrodoKem1344Aes>(rng)
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                self.inner_generate_keypair::<EphemeralFrodoKem640Shake>(rng)
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                self.inner_generate_keypair::<EphemeralFrodoKem976Shake>(rng)
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                self.inner_generate_keypair::<EphemeralFrodoKem1344Shake>(rng)
            }
        }
    }

    fn inner_generate_keypair<K: Kem>(
        &self,
        rng: impl CryptoRngCore,
    ) -> (EncryptionKey, DecryptionKey) {
        let (pk, sk) = K::default().generate_keypair(rng);
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

    /// Encapsulate with given message to generate a [`SharedSecret`] and a [`Ciphertext`].
    ///
    /// NOTE: The message and salt must be of the correct length for the algorithm.
    /// Also, this method is deterministic, meaning that using the same message and salt
    /// will yield the same [`SharedSecret`] and [`Ciphertext`]
    pub fn encapsulate<B: AsRef<[u8]>, S: AsRef<[u8]>>(
        &self,
        public_key: &EncryptionKey,
        msg: B,
        salt: S,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        let msg = msg.as_ref();
        let salt = salt.as_ref();
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => self.inner_encapsulate::<FrodoKem640Aes>(public_key, msg, salt),
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => self.inner_encapsulate::<FrodoKem976Aes>(public_key, msg, salt),
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                self.inner_encapsulate::<FrodoKem1344Aes>(public_key, msg, salt)
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                self.inner_encapsulate::<FrodoKem640Shake>(public_key, msg, salt)
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                self.inner_encapsulate::<FrodoKem976Shake>(public_key, msg, salt)
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                self.inner_encapsulate::<FrodoKem1344Shake>(public_key, msg, salt)
            }
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_encapsulate::<EphemeralFrodoKem640Aes>(public_key, msg, salt)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_encapsulate::<EphemeralFrodoKem976Aes>(public_key, msg, salt)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                self.inner_encapsulate::<EphemeralFrodoKem1344Aes>(public_key, msg, salt)
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                self.inner_encapsulate::<EphemeralFrodoKem640Shake>(public_key, msg, salt)
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                self.inner_encapsulate::<EphemeralFrodoKem976Shake>(public_key, msg, salt)
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                self.inner_encapsulate::<EphemeralFrodoKem1344Shake>(public_key, msg, salt)
            }
        }
    }

    fn inner_encapsulate<K: Kem>(
        &self,
        encryption_key: &EncryptionKey,
        msg: &[u8],
        salt: &[u8],
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        if K::BYTES_MU != msg.len() {
            return Err(Error::InvalidMessageLength(msg.len()));
        }
        let pk = EncryptionKeyRef::from_slice(encryption_key.value.as_slice())?;
        let (ct, ss) = K::default().encapsulate(pk, msg, salt);
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

    /// Encapsulate a random value to generate a [`SharedSecret`] and a [`Ciphertext`].
    pub fn encapsulate_with_rng(
        &self,
        public_key: &EncryptionKey,
        rng: impl CryptoRngCore,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        match self {
            #[cfg(feature = "frodo640aes")]
            Self::FrodoKem640Aes => {
                self.inner_encapsulate_with_rng::<FrodoKem640Aes>(public_key, rng)
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                self.inner_encapsulate_with_rng::<FrodoKem976Aes>(public_key, rng)
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                self.inner_encapsulate_with_rng::<FrodoKem1344Aes>(public_key, rng)
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                self.inner_encapsulate_with_rng::<FrodoKem640Shake>(public_key, rng)
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                self.inner_encapsulate_with_rng::<FrodoKem976Shake>(public_key, rng)
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                self.inner_encapsulate_with_rng::<FrodoKem1344Shake>(public_key, rng)
            }
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_encapsulate_with_rng::<EphemeralFrodoKem640Aes>(public_key, rng)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_encapsulate_with_rng::<EphemeralFrodoKem976Aes>(public_key, rng)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                self.inner_encapsulate_with_rng::<EphemeralFrodoKem1344Aes>(public_key, rng)
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                self.inner_encapsulate_with_rng::<EphemeralFrodoKem640Shake>(public_key, rng)
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                self.inner_encapsulate_with_rng::<EphemeralFrodoKem976Shake>(public_key, rng)
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                self.inner_encapsulate_with_rng::<EphemeralFrodoKem1344Shake>(public_key, rng)
            }
        }
    }

    fn inner_encapsulate_with_rng<K: Kem>(
        &self,
        encryption_key: &EncryptionKey,
        rng: impl CryptoRngCore,
    ) -> FrodoResult<(Ciphertext, SharedSecret)> {
        let pk = EncryptionKeyRef::from_slice(encryption_key.value.as_slice())?;
        let (ct, ss) = K::default().encapsulate_with_rng(pk, rng);
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
                self.inner_decapsulate::<FrodoKem640Aes>(secret_key, ciphertext)
            }
            #[cfg(feature = "frodo976aes")]
            Self::FrodoKem976Aes => {
                self.inner_decapsulate::<FrodoKem976Aes>(secret_key, ciphertext)
            }
            #[cfg(feature = "frodo1344aes")]
            Self::FrodoKem1344Aes => {
                self.inner_decapsulate::<FrodoKem1344Aes>(secret_key, ciphertext)
            }
            #[cfg(feature = "frodo640shake")]
            Self::FrodoKem640Shake => {
                self.inner_decapsulate::<FrodoKem640Shake>(secret_key, ciphertext)
            }
            #[cfg(feature = "frodo976shake")]
            Self::FrodoKem976Shake => {
                self.inner_decapsulate::<FrodoKem976Shake>(secret_key, ciphertext)
            }
            #[cfg(feature = "frodo1344shake")]
            Self::FrodoKem1344Shake => {
                self.inner_decapsulate::<FrodoKem1344Shake>(secret_key, ciphertext)
            }
            #[cfg(feature = "efrodo640aes")]
            Self::EphemeralFrodoKem640Aes => {
                self.inner_decapsulate::<EphemeralFrodoKem640Aes>(secret_key, ciphertext)
            }
            #[cfg(feature = "efrodo976aes")]
            Self::EphemeralFrodoKem976Aes => {
                self.inner_decapsulate::<EphemeralFrodoKem976Aes>(secret_key, ciphertext)
            }
            #[cfg(feature = "efrodo1344aes")]
            Self::EphemeralFrodoKem1344Aes => {
                self.inner_decapsulate::<EphemeralFrodoKem1344Aes>(secret_key, ciphertext)
            }
            #[cfg(feature = "efrodo640shake")]
            Self::EphemeralFrodoKem640Shake => {
                self.inner_decapsulate::<EphemeralFrodoKem640Shake>(secret_key, ciphertext)
            }
            #[cfg(feature = "efrodo976shake")]
            Self::EphemeralFrodoKem976Shake => {
                self.inner_decapsulate::<EphemeralFrodoKem976Shake>(secret_key, ciphertext)
            }
            #[cfg(feature = "efrodo1344shake")]
            Self::EphemeralFrodoKem1344Shake => {
                self.inner_decapsulate::<EphemeralFrodoKem1344Shake>(secret_key, ciphertext)
            }
        }
    }

    fn inner_decapsulate<K: Kem>(
        &self,
        secret_key: &DecryptionKey,
        ciphertext: &Ciphertext,
    ) -> FrodoResult<(SharedSecret, Vec<u8>)> {
        let sk = DecryptionKeyRef::from_slice(secret_key.value.as_slice())?;
        let ct = CiphertextRef::from_slice(ciphertext.value.as_slice())?;
        let (ss, mu) = K::default().decapsulate(sk, ct);
        Ok((
            SharedSecret {
                algorithm: *self,
                value: ss.0,
            },
            mu,
        ))
    }
}

/// The algorithm underlying parameters
#[derive(Debug, Clone, Copy)]
pub struct AlgorithmParams {
    /// Number of elements in the ring
    pub n: usize,
    /// Number of rows in the matrix
    pub n_bar: usize,
    /// The log of the modulus
    pub log_q: usize,
    /// The modulus
    pub q: usize,
    /// The number of bits to extract when packing/unpacking
    /// encoding/decoding
    pub extracted_bits: usize,
    /// The number of steps for striping
    pub stripe_step: usize,
    /// The number of bytes in the seed for generating the matrix A
    pub bytes_seed_a: usize,
    /// The number of bytes in the public key hash
    pub bytes_pk_hash: usize,
    /// The CDF sampling table
    pub cdf_table: &'static [u16],
    /// The claimed NIST level
    pub claimed_nist_level: usize,
    /// The byte length of the shared secret
    pub shared_secret_length: usize,
    /// The byte length of an encrypted message
    pub message_length: usize,
    /// The byte length of the salt
    pub salt_length: usize,
    /// The byte length of the encryption key
    pub encryption_key_length: usize,
    /// The byte length of the decryption key
    pub decryption_key_length: usize,
    /// The byte length of the ciphertext
    pub ciphertext_length: usize,
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand_core::{RngCore, SeedableRng};
    use rstest::*;
    use safe_oqs::kem;

    #[rstest]
    #[case::aes640(Algorithm::EphemeralFrodoKem640Aes, kem::Algorithm::FrodoKem640Aes)]
    #[case::aes976(Algorithm::EphemeralFrodoKem976Aes, kem::Algorithm::FrodoKem976Aes)]
    #[case::aes1344(Algorithm::EphemeralFrodoKem1344Aes, kem::Algorithm::FrodoKem1344Aes)]
    #[case::shake640(Algorithm::EphemeralFrodoKem640Shake, kem::Algorithm::FrodoKem640Shake)]
    #[case::shake976(Algorithm::EphemeralFrodoKem976Shake, kem::Algorithm::FrodoKem976Shake)]
    #[case::shake1344(
        Algorithm::EphemeralFrodoKem1344Shake,
        kem::Algorithm::FrodoKem1344Shake
    )]
    fn ephemeral_works(#[case] alg: Algorithm, #[case] safe_alg: kem::Algorithm) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = alg.generate_keypair(&mut rng);
        let kem = kem::Kem::new(safe_alg).unwrap();

        let opt_pk = kem.public_key_from_bytes(&our_pk.value);
        assert!(opt_pk.is_some());
        let opt_sk = kem.secret_key_from_bytes(&our_sk.value);
        assert!(opt_sk.is_some());

        let their_pk = opt_pk.unwrap();
        let their_sk = opt_sk.unwrap();

        let mut mu = vec![0u8; alg.params().message_length];
        rng.fill_bytes(&mut mu);
        let (our_ct, our_ess) = alg.encapsulate(&our_pk, &mu, []).unwrap();
        let (our_dss, mu_prime) = alg.decapsulate(&our_sk, &our_ct).unwrap();
        assert_eq!(our_ess.value, our_dss.value);
        assert_eq!(mu, mu_prime);

        let their_ct = kem.ciphertext_from_bytes(&our_ct.value).unwrap();
        let their_ss = kem.decapsulate(their_sk, their_ct).unwrap();
        assert_eq!(our_dss.value, their_ss.as_ref());

        let (their_ct, their_ess) = kem.encapsulate(their_pk).unwrap();

        let our_ct = alg.ciphertext_from_bytes(their_ct.as_ref()).unwrap();

        let (their_dss, _) = alg.decapsulate(&our_sk, &our_ct).unwrap();
        assert_eq!(their_ess.as_ref(), their_dss.value);
    }

    #[rstest]
    #[case::aes640(Algorithm::FrodoKem640Aes)]
    #[case::aes976(Algorithm::FrodoKem976Aes)]
    #[case::aes1344(Algorithm::FrodoKem1344Aes)]
    #[case::shake640(Algorithm::FrodoKem640Shake)]
    #[case::shake976(Algorithm::FrodoKem976Shake)]
    #[case::shake1344(Algorithm::FrodoKem1344Shake)]
    fn works(#[case] alg: Algorithm) {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([1u8; 32]);
        let (our_pk, our_sk) = alg.generate_keypair(&mut rng);

        let mut mu = vec![0u8; alg.params().message_length];
        rng.fill_bytes(&mut mu);
        let mut salt = vec![0u8; alg.params().salt_length];
        rng.fill_bytes(&mut salt);
        let (our_ct, our_ess) = alg.encapsulate(&our_pk, &mu, &salt).unwrap();
        let (our_dss, mu_prime) = alg.decapsulate(&our_sk, &our_ct).unwrap();
        assert_eq!(our_ess.value, our_dss.value);
        assert_eq!(mu, mu_prime);
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
            #[case::aes640(Algorithm::EphemeralFrodoKem640Aes)]
            #[case::aes976(Algorithm::EphemeralFrodoKem976Aes)]
            #[case::aes1344(Algorithm::EphemeralFrodoKem1344Aes)]
            #[case::shake640(Algorithm::EphemeralFrodoKem640Shake)]
            #[case::shake976(Algorithm::EphemeralFrodoKem976Shake)]
            #[case::shake1344(Algorithm::EphemeralFrodoKem1344Shake)]
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
