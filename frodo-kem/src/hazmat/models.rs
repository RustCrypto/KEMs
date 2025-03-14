use super::{Expanded, Kem, Params, Sample};
use crate::{Error, FrodoResult};
use std::marker::PhantomData;
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! from_slice_impl {
    ($name:ident) => {
        impl<P: Params> TryFrom<&[u8]> for $name<P> {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> FrodoResult<Self> {
                Self::from_slice(bytes)
            }
        }

        impl<P: Params> TryFrom<Box<[u8]>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: Box<[u8]>) -> FrodoResult<Self> {
                Self::from_slice(bytes.as_ref())
            }
        }

        impl<P: Params> TryFrom<Vec<u8>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: Vec<u8>) -> FrodoResult<Self> {
                Self::from_slice(bytes.as_ref())
            }
        }

        impl<P: Params> TryFrom<&Vec<u8>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: &Vec<u8>) -> FrodoResult<Self> {
                Self::from_slice(bytes.as_ref())
            }
        }
    };
}

macro_rules! serde_impl {
    ($name:ident) => {
        #[cfg(feature = "serde")]
        impl<P: Params> serde::Serialize for $name<P> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serdect::slice::serialize_hex_lower_or_bin(&self.0, serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, P: Params> serde::Deserialize<'de> for $name<P> {
            fn deserialize<D>(deserializer: D) -> Result<$name<P>, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
                $name::from_slice(&bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// A FrodoKEM ciphertext
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ciphertext<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for Ciphertext<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for Ciphertext<P> {
    fn default() -> Self {
        Self(vec![0u8; P::CIPHERTEXT_LENGTH], PhantomData)
    }
}

from_slice_impl!(Ciphertext);

serde_impl!(Ciphertext);

impl<P: Params> Ciphertext<P> {
    /// Convert a slice of bytes into a ciphertext
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::CIPHERTEXT_LENGTH {
            return Err(Error::InvalidCiphertextLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }

    /// Returns a reference to the c1 component
    #[allow(dead_code)]
    pub fn c1(&self) -> &[u8] {
        &self.0[..P::LOG_Q_X_N_X_N_BAR_DIV_8]
    }

    /// Returns a mutable reference to the c1 component
    pub fn c1_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::LOG_Q_X_N_X_N_BAR_DIV_8]
    }

    /// Returns a reference to the c2 component
    #[allow(dead_code)]
    pub fn c2(&self) -> &[u8] {
        &self.0[P::LOG_Q_X_N_X_N_BAR_DIV_8..P::CIPHERTEXT_LENGTH - P::BYTES_SALT]
    }

    /// Returns a mutable reference to the c2 component
    pub fn c2_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::LOG_Q_X_N_X_N_BAR_DIV_8..P::CIPHERTEXT_LENGTH - P::BYTES_SALT]
    }

    /// Returns a reference to the salt
    #[allow(dead_code)]
    pub fn salt(&self) -> &[u8] {
        &self.0[P::CIPHERTEXT_LENGTH - P::BYTES_SALT..]
    }

    /// Returns a mutable reference to the salt
    pub fn salt_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::CIPHERTEXT_LENGTH - P::BYTES_SALT..]
    }
}

/// A FrodoKEM ciphertext reference
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CiphertextRef<'a, P: Params>(pub(crate) &'a [u8], pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for CiphertextRef<'_, P> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a, P: Params> From<&'a Ciphertext<P>> for CiphertextRef<'a, P> {
    fn from(value: &'a Ciphertext<P>) -> Self {
        Self(value.0.as_slice(), value.1)
    }
}

impl<'a, P: Params> CiphertextRef<'a, P> {
    /// Create a ciphertext reference
    #[allow(dead_code)]
    pub fn from_slice(bytes: &'a [u8]) -> FrodoResult<Self> {
        if bytes.len() != P::CIPHERTEXT_LENGTH {
            return Err(Error::InvalidCiphertextLength(bytes.len()));
        }
        Ok(Self(bytes, PhantomData))
    }

    /// Returns a reference to the c1 component
    pub fn c1(&self) -> &[u8] {
        &self.0[..P::LOG_Q_X_N_X_N_BAR_DIV_8]
    }

    /// Returns a reference to the c2 component
    pub fn c2(&self) -> &[u8] {
        &self.0[P::LOG_Q_X_N_X_N_BAR_DIV_8..P::CIPHERTEXT_LENGTH - P::BYTES_SALT]
    }

    /// Returns a reference to the salt
    pub fn salt(&self) -> &[u8] {
        &self.0[P::CIPHERTEXT_LENGTH - P::BYTES_SALT..]
    }

    /// Convert the ciphertext reference into an owned ciphertext
    #[allow(dead_code)]
    pub fn to_owned(&self) -> Ciphertext<P> {
        Ciphertext(self.0.to_vec(), PhantomData)
    }
}

/// A FrodoKEM public key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptionKey<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for EncryptionKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for EncryptionKey<P> {
    fn default() -> Self {
        Self(vec![0u8; P::PUBLIC_KEY_LENGTH], PhantomData)
    }
}

impl<P: Params> From<&DecryptionKey<P>> for EncryptionKey<P> {
    fn from(value: &DecryptionKey<P>) -> Self {
        Self(value.public_key().to_vec(), PhantomData)
    }
}

impl<'a, P: Params> From<&'a EncryptionKey<P>> for EncryptionKeyRef<'a, P> {
    fn from(value: &'a EncryptionKey<P>) -> Self {
        Self(value.0.as_slice(), value.1)
    }
}

from_slice_impl!(EncryptionKey);

serde_impl!(EncryptionKey);

impl<P: Params> EncryptionKey<P> {
    /// Convert a slice of bytes into a public key
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidPublicKeyLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }

    /// Returns a reference to the seed A
    pub fn seed_a(&self) -> &[u8] {
        &self.0[..P::BYTES_SEED_A]
    }

    /// Returns a mutable reference to the seed A
    pub fn seed_a_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::BYTES_SEED_A]
    }

    /// Returns a reference to the matrix B
    #[allow(dead_code)]
    pub fn matrix_b(&self) -> &[u8] {
        &self.0[P::BYTES_SEED_A..]
    }

    /// Returns a mutable reference to the matrix B
    pub fn matrix_b_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::BYTES_SEED_A..]
    }
}

/// A FrodoKEM public key reference
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EncryptionKeyRef<'a, P: Params>(pub(crate) &'a [u8], pub(crate) PhantomData<P>);

impl<'a, P: Params> EncryptionKeyRef<'a, P> {
    /// Create a public key reference
    pub fn from_slice(bytes: &'a [u8]) -> FrodoResult<Self> {
        if bytes.len() != P::PUBLIC_KEY_LENGTH {
            return Err(Error::InvalidPublicKeyLength(bytes.len()));
        }
        Ok(Self(bytes, PhantomData))
    }

    /// Returns a reference to the seed A
    pub fn seed_a(&self) -> &[u8] {
        &self.0[..P::BYTES_SEED_A]
    }

    /// Returns a reference to the matrix B
    pub fn matrix_b(&self) -> &[u8] {
        &self.0[P::BYTES_SEED_A..]
    }

    /// Convert the public key reference into an owned public key
    #[allow(dead_code)]
    pub fn to_owned(&self) -> EncryptionKey<P> {
        EncryptionKey(self.0.to_vec(), PhantomData)
    }
}

/// A FrodoKEM secret key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptionKey<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for DecryptionKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for DecryptionKey<P> {
    fn default() -> Self {
        Self(vec![0u8; P::SECRET_KEY_LENGTH], PhantomData)
    }
}

impl<P: Params> Zeroize for DecryptionKey<P> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<P: Params> ZeroizeOnDrop for DecryptionKey<P> {}

from_slice_impl!(DecryptionKey);

serde_impl!(DecryptionKey);

impl<P: Params> DecryptionKey<P> {
    /// Convert a slice of bytes into a secret key
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::SECRET_KEY_LENGTH {
            return Err(Error::InvalidSecretKeyLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }

    /// Returns a reference to the shared secret
    #[allow(dead_code)]
    pub fn random_s(&self) -> &[u8] {
        &self.0[..P::SHARED_SECRET_LENGTH]
    }

    /// Returns a mutable reference to the shared secret
    pub fn random_s_mut(&mut self) -> &mut [u8] {
        &mut self.0[..P::SHARED_SECRET_LENGTH]
    }

    /// Returns a reference to the public key
    pub fn public_key(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    /// Returns a mutable reference to the public key
    pub fn public_key_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    /// Returns a reference to the matrix s
    #[allow(dead_code)]
    pub fn matrix_s(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    /// Returns a mutable reference to the matrix s
    pub fn matrix_s_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    /// Returns a reference to the hash of the public key
    #[allow(dead_code)]
    pub fn hpk(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }

    /// Returns a mutable reference to the hash of the public key
    pub fn hpk_mut(&mut self) -> &mut [u8] {
        &mut self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }
}

/// A FrodoKEM secret key reference
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DecryptionKeyRef<'a, P: Params>(pub(crate) &'a [u8], pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for DecryptionKeyRef<'_, P> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a, P: Params> From<&'a DecryptionKey<P>> for DecryptionKeyRef<'a, P> {
    fn from(value: &'a DecryptionKey<P>) -> Self {
        Self(value.0.as_slice(), value.1)
    }
}

impl<'a, P: Params> DecryptionKeyRef<'a, P> {
    /// Create a secret key reference
    pub fn from_slice(bytes: &'a [u8]) -> FrodoResult<Self> {
        if bytes.len() != P::SECRET_KEY_LENGTH {
            return Err(Error::InvalidSecretKeyLength(bytes.len()));
        }
        Ok(Self(bytes, PhantomData))
    }

    /// Returns a reference to the shared secret
    #[allow(dead_code)]
    pub fn random_s(&self) -> &[u8] {
        &self.0[..P::SHARED_SECRET_LENGTH]
    }

    /// Returns a reference to the public key
    pub fn public_key(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH]
    }

    /// Returns a reference to the matrix s
    pub fn matrix_s(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH
            ..P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR]
    }

    /// Returns a reference to the hash of the public key
    pub fn hpk(&self) -> &[u8] {
        &self.0[P::SHARED_SECRET_LENGTH + P::PUBLIC_KEY_LENGTH + P::TWO_N_X_N_BAR..]
    }

    /// Convert the secret key reference into an owned secret key
    #[allow(dead_code)]
    pub fn to_owned(&self) -> DecryptionKey<P> {
        DecryptionKey(self.0.to_vec(), PhantomData)
    }
}

/// A FrodoKEM shared secret
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedSecret<P: Params>(pub(crate) Vec<u8>, pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for SharedSecret<P> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<P: Params> Default for SharedSecret<P> {
    fn default() -> Self {
        Self(vec![0u8; P::SHARED_SECRET_LENGTH], PhantomData)
    }
}

impl<P: Params> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<P: Params> ZeroizeOnDrop for SharedSecret<P> {}

from_slice_impl!(SharedSecret);

serde_impl!(SharedSecret);

impl<P: Params> SharedSecret<P> {
    /// Convert a slice of bytes into a shared secret
    pub fn from_slice(bytes: &[u8]) -> FrodoResult<Self> {
        if bytes.len() != P::SHARED_SECRET_LENGTH {
            return Err(Error::InvalidSharedSecretLength(bytes.len()));
        }
        Ok(Self(bytes.to_vec(), PhantomData))
    }
}

/// A FrodoKEM shared secret reference
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SharedSecretRef<'a, P: Params>(pub(crate) &'a [u8], pub(crate) PhantomData<P>);

impl<P: Params> AsRef<[u8]> for SharedSecretRef<'_, P> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a, P: Params> From<&'a SharedSecret<P>> for SharedSecretRef<'a, P> {
    fn from(value: &'a SharedSecret<P>) -> Self {
        Self(value.0.as_slice(), value.1)
    }
}

impl<'a, P: Params> SharedSecretRef<'a, P> {
    /// Create a shared secret reference
    #[allow(dead_code)]
    pub fn from_slice(bytes: &'a [u8]) -> FrodoResult<Self> {
        if bytes.len() != P::SHARED_SECRET_LENGTH {
            return Err(Error::InvalidSharedSecretLength(bytes.len()));
        }
        Ok(Self(bytes, PhantomData))
    }

    /// Convert the shared secret reference into an owned shared secret
    #[allow(dead_code)]
    pub fn to_owned(&self) -> SharedSecret<P> {
        SharedSecret(self.0.to_vec(), PhantomData)
    }
}

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake",
))]
/// The FrodoKEM scheme
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrodoKem<P: Params, E: Expanded, S: Sample>(pub PhantomData<(P, E, S)>);

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Params for FrodoKem<P, E, S> {
    type Shake = P::Shake;

    const BYTES_SALT: usize = P::BYTES_SALT;
    const BYTES_SEED_SE: usize = P::BYTES_SEED_SE;
    const CDF_TABLE: &'static [u16] = P::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = P::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = P::EXTRACTED_BITS;
    const LOG_Q: usize = P::LOG_Q;
    const N: usize = P::N;
    const SHARED_SECRET_LENGTH: usize = P::SHARED_SECRET_LENGTH;
}

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Expanded for FrodoKem<P, E, S> {
    const METHOD: &'static str = E::METHOD;

    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]) {
        E::expand_a(&E::default(), seed_a, a)
    }
}

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Sample for FrodoKem<P, E, S> {
    fn sample(&self, s: &mut [u16]) {
        S::sample(&S::default(), s)
    }
}

#[cfg(any(
    feature = "frodo640aes",
    feature = "frodo976aes",
    feature = "frodo1344aes",
    feature = "frodo640shake",
    feature = "frodo976shake",
    feature = "frodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Kem for FrodoKem<P, E, S> {
    const NAME: &'static str = "FrodoKEM";
}

#[cfg(any(
    feature = "efrodo640aes",
    feature = "efrodo976aes",
    feature = "efrodo1344aes",
    feature = "efrodo640shake",
    feature = "efrodo976shake",
    feature = "efrodo1344shake",
))]
/// The eFrodoKEM scheme
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EphemeralFrodoKem<P: Params, E: Expanded, S: Sample>(pub PhantomData<(P, E, S)>);

#[cfg(any(
    feature = "efrodo640aes",
    feature = "efrodo976aes",
    feature = "efrodo1344aes",
    feature = "efrodo640shake",
    feature = "efrodo976shake",
    feature = "efrodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Params for EphemeralFrodoKem<P, E, S> {
    type Shake = P::Shake;

    const BYTES_SALT: usize = P::BYTES_SALT;
    const BYTES_SEED_SE: usize = P::BYTES_SEED_SE;
    const CDF_TABLE: &'static [u16] = P::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = P::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = P::EXTRACTED_BITS;
    const LOG_Q: usize = P::LOG_Q;
    const N: usize = P::N;
    const SHARED_SECRET_LENGTH: usize = P::SHARED_SECRET_LENGTH;
}

#[cfg(any(
    feature = "efrodo640aes",
    feature = "efrodo976aes",
    feature = "efrodo1344aes",
    feature = "efrodo640shake",
    feature = "efrodo976shake",
    feature = "efrodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Expanded for EphemeralFrodoKem<P, E, S> {
    const METHOD: &'static str = E::METHOD;

    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]) {
        E::expand_a(&E::default(), seed_a, a)
    }
}

#[cfg(any(
    feature = "efrodo640aes",
    feature = "efrodo976aes",
    feature = "efrodo1344aes",
    feature = "efrodo640shake",
    feature = "efrodo976shake",
    feature = "efrodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Sample for EphemeralFrodoKem<P, E, S> {
    fn sample(&self, s: &mut [u16]) {
        S::sample(&S::default(), s)
    }
}

#[cfg(any(
    feature = "efrodo640aes",
    feature = "efrodo976aes",
    feature = "efrodo1344aes",
    feature = "efrodo640shake",
    feature = "efrodo976shake",
    feature = "efrodo1344shake",
))]
impl<P: Params, E: Expanded, S: Sample> Kem for EphemeralFrodoKem<P, E, S> {
    const NAME: &'static str = "eFrodoKEM";
}

#[cfg(any(
    feature = "efrodo640aes",
    feature = "frodo640aes",
    feature = "efrodo640shake",
    feature = "frodo640shake",
))]
struct InnerFrodo640;

#[cfg(any(
    feature = "efrodo640aes",
    feature = "frodo640aes",
    feature = "efrodo640shake",
    feature = "frodo640shake",
))]
impl InnerFrodo640 {
    const CDF_TABLE: &'static [u16] = &[
        4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766, 32767,
    ];
    const CLAIMED_NIST_LEVEL: usize = 1;
    const EXTRACTED_BITS: usize = 2;
    const LOG_Q: usize = 15;
    const N: usize = 640;
    const SHARED_SECRET_LENGTH: usize = 16;
}

#[cfg(any(feature = "frodo640aes", feature = "frodo640shake",))]
/// Frodo640 parameters
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Frodo640;

#[cfg(any(feature = "frodo640aes", feature = "frodo640shake",))]
impl Params for Frodo640 {
    type Shake = sha3::Shake128;

    const CDF_TABLE: &'static [u16] = InnerFrodo640::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = InnerFrodo640::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = InnerFrodo640::EXTRACTED_BITS;
    const LOG_Q: usize = InnerFrodo640::LOG_Q;
    const N: usize = InnerFrodo640::N;
    const SHARED_SECRET_LENGTH: usize = InnerFrodo640::SHARED_SECRET_LENGTH;
}

#[cfg(any(feature = "efrodo640aes", feature = "efrodo640shake",))]
/// Frodo640 parameters
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EphemeralFrodo640;

#[cfg(any(feature = "efrodo640aes", feature = "efrodo640shake",))]
impl Params for EphemeralFrodo640 {
    type Shake = sha3::Shake128;

    const BYTES_SALT: usize = 0;
    const BYTES_SEED_SE: usize = Self::SHARED_SECRET_LENGTH;
    const CDF_TABLE: &'static [u16] = InnerFrodo640::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = InnerFrodo640::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = InnerFrodo640::EXTRACTED_BITS;
    const LOG_Q: usize = InnerFrodo640::LOG_Q;
    const N: usize = InnerFrodo640::N;
    const SHARED_SECRET_LENGTH: usize = InnerFrodo640::SHARED_SECRET_LENGTH;
}

#[cfg(any(
    feature = "efrodo976aes",
    feature = "frodo976aes",
    feature = "efrodo976shake",
    feature = "frodo976shake",
))]
struct InnerFrodo976;

#[cfg(any(
    feature = "efrodo976aes",
    feature = "frodo976aes",
    feature = "efrodo976shake",
    feature = "frodo976shake",
))]
impl InnerFrodo976 {
    const CDF_TABLE: &'static [u16] = &[
        5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767,
    ];
    const CLAIMED_NIST_LEVEL: usize = 3;
    const EXTRACTED_BITS: usize = 3;
    const LOG_Q: usize = 16;
    const N: usize = 976;
    const SHARED_SECRET_LENGTH: usize = 24;
}

#[cfg(any(feature = "frodo976aes", feature = "frodo976shake",))]
/// Frodo976 parameters
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Frodo976;

#[cfg(any(feature = "frodo976aes", feature = "frodo976shake",))]
impl Params for Frodo976 {
    type Shake = sha3::Shake256;

    const CDF_TABLE: &'static [u16] = InnerFrodo976::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = InnerFrodo976::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = InnerFrodo976::EXTRACTED_BITS;
    const LOG_Q: usize = InnerFrodo976::LOG_Q;
    const N: usize = InnerFrodo976::N;
    const SHARED_SECRET_LENGTH: usize = InnerFrodo976::SHARED_SECRET_LENGTH;
}

#[cfg(any(feature = "efrodo976aes", feature = "efrodo976shake",))]
/// Frodo976 parameters
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EphemeralFrodo976;

#[cfg(any(feature = "efrodo976aes", feature = "efrodo976shake",))]
impl Params for EphemeralFrodo976 {
    type Shake = sha3::Shake256;

    const BYTES_SALT: usize = 0;
    const BYTES_SEED_SE: usize = InnerFrodo976::SHARED_SECRET_LENGTH;
    const CDF_TABLE: &'static [u16] = InnerFrodo976::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = InnerFrodo976::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = InnerFrodo976::EXTRACTED_BITS;
    const LOG_Q: usize = InnerFrodo976::LOG_Q;
    const N: usize = InnerFrodo976::N;
    const SHARED_SECRET_LENGTH: usize = InnerFrodo976::SHARED_SECRET_LENGTH;
}

#[cfg(any(
    feature = "efrodo1344aes",
    feature = "frodo1344aes",
    feature = "efrodo1344shake",
    feature = "frodo1344shake",
))]
struct InnerFrodo1344;

#[cfg(any(
    feature = "efrodo1344aes",
    feature = "frodo1344aes",
    feature = "efrodo1344shake",
    feature = "frodo1344shake",
))]
impl InnerFrodo1344 {
    const CDF_TABLE: &'static [u16] = &[9142, 23462, 30338, 32361, 32725, 32765, 32767];
    const CLAIMED_NIST_LEVEL: usize = 5;
    const EXTRACTED_BITS: usize = 4;
    const LOG_Q: usize = 16;
    const N: usize = 1344;
    const SHARED_SECRET_LENGTH: usize = 32;
}

#[cfg(any(feature = "frodo1344aes", feature = "frodo1344shake",))]
/// Frodo1344 parameters
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Frodo1344;

#[cfg(any(feature = "frodo1344aes", feature = "frodo1344shake",))]
impl Params for Frodo1344 {
    type Shake = sha3::Shake256;

    const CDF_TABLE: &'static [u16] = InnerFrodo1344::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = InnerFrodo1344::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = InnerFrodo1344::EXTRACTED_BITS;
    const LOG_Q: usize = InnerFrodo1344::LOG_Q;
    const N: usize = InnerFrodo1344::N;
    const SHARED_SECRET_LENGTH: usize = InnerFrodo1344::SHARED_SECRET_LENGTH;
}

#[cfg(any(feature = "efrodo1344aes", feature = "efrodo1344shake",))]
/// Frodo1344 parameters
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EphemeralFrodo1344;

#[cfg(any(feature = "efrodo1344aes", feature = "efrodo1344shake",))]
impl Params for EphemeralFrodo1344 {
    type Shake = sha3::Shake256;

    const BYTES_SALT: usize = 0;
    const BYTES_SEED_SE: usize = Self::SHARED_SECRET_LENGTH;
    const CDF_TABLE: &'static [u16] = InnerFrodo1344::CDF_TABLE;
    const CLAIMED_NIST_LEVEL: usize = InnerFrodo1344::CLAIMED_NIST_LEVEL;
    const EXTRACTED_BITS: usize = InnerFrodo1344::EXTRACTED_BITS;
    const LOG_Q: usize = InnerFrodo1344::LOG_Q;
    const N: usize = InnerFrodo1344::N;
    const SHARED_SECRET_LENGTH: usize = InnerFrodo1344::SHARED_SECRET_LENGTH;
}

#[cfg(any(
    feature = "efrodo640aes",
    feature = "frodo640aes",
    feature = "efrodo976aes",
    feature = "frodo976aes",
    feature = "efrodo1344aes",
    feature = "frodo1344aes",
))]
/// Generate matrix A (N x N) column-wise using AES-128
///
/// See Algorithm 7 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20190215.pdf)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrodoAes<P: Params>(pub(crate) PhantomData<P>);

#[cfg(all(
    not(feature = "openssl-aes"),
    any(
        feature = "efrodo640aes",
        feature = "frodo640aes",
        feature = "efrodo976aes",
        feature = "frodo976aes",
        feature = "efrodo1344aes",
        feature = "frodo1344aes",
    )
))]
impl<P: Params> Expanded for FrodoAes<P> {
    const METHOD: &'static str = "AES";

    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]) {
        use aes::{
            Aes128Enc, Block,
            cipher::{BlockEncrypt, KeyInit, KeySizeUser},
        };

        debug_assert_eq!(a.len(), P::N_X_N);
        debug_assert_eq!(seed_a.len(), P::BYTES_SEED_A);
        debug_assert_eq!(seed_a.len(), <Aes128Enc as KeySizeUser>::key_size());
        let enc = Aes128Enc::new_from_slice(seed_a).expect("a valid key size of 16 bytes");

        // Original Reference Code is much slower
        // let mut in_block = Block::default();
        // let mut out_block = Block::default();
        // for i in 0..P::N {
        //     let ii = i as u16;
        //     in_block[..2].copy_from_slice(&ii.to_le_bytes());
        //     let row = i * P::N;
        //     for j in (0..P::N).step_by(P::STRIPE_STEP) {
        //         let jj = j as u16;
        //         in_block[2..4].copy_from_slice(&jj.to_le_bytes());
        //         enc.encrypt_block_b2b(&in_block, &mut out_block);
        //
        //         for k in 0..P::STRIPE_STEP {
        //             a[row + j + k] =
        //                 u16::from_le_bytes([out_block[2 * k], out_block[2 * k + 1]]) & P::Q_MASK;
        //         }
        //     }
        // }

        // Treat `a` as blocks then overwrite in place to avoid allocation
        let blocks = unsafe {
            std::slice::from_raw_parts_mut(a.as_mut_ptr() as *mut Block, P::N_X_N / P::STRIPE_STEP)
        };
        let mut pos = 0;
        for i in 0..P::N {
            let ii = i as u16;
            let mut block = Block::default();
            block[..2].copy_from_slice(&ii.to_le_bytes());
            for j in (0..P::N).step_by(P::STRIPE_STEP) {
                let jj = j as u16;
                block[2..4].copy_from_slice(&jj.to_le_bytes());
                blocks[pos] = block;
                pos += 1;
            }
        }

        enc.encrypt_blocks(blocks);
        #[cfg(target_endian = "big")]
        {
            for i in a.iter_mut() {
                *i = i.to_be();
            }
        }
    }
}

#[cfg(all(
    feature = "openssl-aes",
    any(
        feature = "efrodo640aes",
        feature = "frodo640aes",
        feature = "efrodo976aes",
        feature = "frodo976aes",
        feature = "efrodo1344aes",
        feature = "frodo1344aes",
    )
))]
impl<P: Params> Expanded for FrodoAes<P> {
    const METHOD: &'static str = "AES";

    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]) {
        debug_assert_eq!(a.len(), P::N_X_N);
        debug_assert_eq!(seed_a.len(), P::BYTES_SEED_A);
        debug_assert_eq!(seed_a.len(), 16);

        let in_blocks =
            unsafe { std::slice::from_raw_parts_mut(a.as_mut_ptr() as *mut u8, P::N_X_N * 2) };
        let mut in_block = [0u8; 16];
        let mut pos = 0;
        for i in 0..P::N {
            let ii = i as u16;
            in_block[..2].copy_from_slice(&ii.to_le_bytes());
            for j in (0..P::N).step_by(P::STRIPE_STEP) {
                let jj = j as u16;
                in_block[2..4].copy_from_slice(&jj.to_le_bytes());
                in_blocks[pos..pos + 16].copy_from_slice(&in_block);
                pos += 16;
            }
        }
        unsafe {
            let aes_key_schedule = openssl_sys::EVP_CIPHER_CTX_new();
            if aes_key_schedule.is_null() {
                panic!("EVP_CIPHER_CTX_new failed");
            }
            if openssl_sys::EVP_EncryptInit_ex(
                aes_key_schedule,
                openssl_sys::EVP_aes_128_ecb(),
                std::ptr::null_mut(),
                seed_a.as_ptr(),
                std::ptr::null_mut(),
            ) != 1
            {
                panic!("EVP_EncryptInit_ex failed");
            }
            let mut olen = in_blocks.len() as i32;
            let ilen = in_blocks.len() as i32;
            if openssl_sys::EVP_EncryptUpdate(
                aes_key_schedule,
                in_blocks.as_mut_ptr(),
                &mut olen,
                in_blocks.as_ptr(),
                ilen,
            ) != 1
            {
                panic!("EVP_EncryptInit_ex failed");
            }
        }
        #[cfg(target_endian = "big")]
        {
            for i in a.iter_mut() {
                *i = i.to_be();
            }
        }
    }
}

#[cfg(any(
    feature = "efrodo640shake",
    feature = "frodo640shake",
    feature = "efrodo976shake",
    feature = "frodo976shake",
    feature = "efrodo1344shake",
    feature = "frodo1344shake",
))]
/// Generate matrix A (N x N) column-wise using SHAKE-128
///
/// See Algorithm 8 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20190215.pdf)
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrodoShake<P: Params>(pub PhantomData<P>);

#[cfg(all(
    not(feature = "openssl-shake"),
    any(
        feature = "efrodo640shake",
        feature = "frodo640shake",
        feature = "efrodo976shake",
        feature = "frodo976shake",
        feature = "efrodo1344shake",
        feature = "frodo1344shake",
    )
))]
impl<P: Params> Expanded for FrodoShake<P> {
    const METHOD: &'static str = "SHAKE";

    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]) {
        use sha3::{
            Shake128,
            digest::{ExtendableOutputReset, Update},
        };

        debug_assert_eq!(a.len(), P::N_X_N);
        debug_assert_eq!(seed_a.len(), P::BYTES_SEED_A);

        let mut seed_separated = vec![0u8; P::TWO_PLUS_BYTES_SEED_A];
        let mut shake = Shake128::default();

        seed_separated[2..].copy_from_slice(seed_a);

        for i in 0..P::N {
            let ii = i * P::N;

            seed_separated[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            shake.update(&seed_separated);
            let a_temp = &mut a[ii..ii + P::N];
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(a_temp.as_mut_ptr() as *mut u8, a_temp.len() * 2)
            };
            shake.finalize_xof_reset_into(bytes);
            #[cfg(target_endian = "big")]
            {
                for i in a_temp {
                    *i = i.to_be();
                }
            }
        }
    }
}

#[cfg(all(
    feature = "openssl-shake",
    any(
        feature = "efrodo640shake",
        feature = "frodo640shake",
        feature = "efrodo976shake",
        feature = "frodo976shake",
        feature = "efrodo1344shake",
        feature = "frodo1344shake",
    )
))]
impl<P: Params> Expanded for FrodoShake<P> {
    const METHOD: &'static str = "SHAKE";

    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]) {
        debug_assert_eq!(a.len(), P::N_X_N);
        debug_assert_eq!(seed_a.len(), P::BYTES_SEED_A);

        // let mut a_row = vec![0u8; P::TWO_N];
        let mut seed_separated = vec![0u8; P::TWO_PLUS_BYTES_SEED_A];

        seed_separated[2..].copy_from_slice(seed_a);

        for i in 0..P::N {
            let ii = i * P::N;

            seed_separated[0..2].copy_from_slice(&(i as u16).to_le_bytes());
            unsafe {
                let shake = openssl_sys::EVP_MD_CTX_new();
                if shake.is_null() {
                    panic!("EVP_MD_CTX_new failed");
                }
                if openssl_sys::EVP_DigestInit_ex(
                    shake,
                    openssl_sys::EVP_shake128(),
                    std::ptr::null_mut(),
                ) != 1
                {
                    panic!("EVP_DigestInit_ex failed");
                }
                if openssl_sys::EVP_DigestUpdate(
                    shake,
                    seed_separated.as_ptr() as *const _,
                    seed_separated.len(),
                ) != 1
                {
                    panic!("EVP_DigestUpdate failed");
                }
                if openssl_sys::EVP_DigestFinalXOF(
                    shake,
                    a[ii..ii + P::N].as_mut_ptr() as *mut u8,
                    P::TWO_N,
                ) != 1
                {
                    panic!("EVP_DigestFinalXOF failed");
                }
            }
        }
        #[cfg(target_endian = "big")]
        {
            for i in a.iter_mut() {
                *i = i.to_be();
            }
        }
    }
}

/// Generate sample noise using a CDF
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrodoCdfSample<P: Params>(pub PhantomData<P>);

impl<P: Params> Sample for FrodoCdfSample<P> {
    fn sample(&self, s: &mut [u16]) {
        for s_i in s.iter_mut() {
            let mut sample = 0u16;
            let prnd = *s_i >> 1; // Drop the least significant bit
            let sign = *s_i & 1; // Get the least significant bit

            for cdf in P::CDF_TABLE {
                sample = sample.wrapping_add(cdf.wrapping_sub(prnd) >> 15);
            }

            *s_i = (sign.wrapping_neg() ^ sample).wrapping_add(sign);
        }
    }
}
