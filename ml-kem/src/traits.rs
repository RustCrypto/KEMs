//! Trait definitions

use crate::{ArraySize, Seed};
use array::{Array, sizes::U64};
use kem::{InvalidKey, Kem, KeyInit, KeySizeUser};

/// An object that knows what size it is
pub trait EncodedSizeUser: Sized {
    /// The size of an encoded object
    type EncodedSize: ArraySize;

    /// Parse an object from its encoded form
    ///
    /// # Errors
    /// - If the object failed to decode successfully
    fn from_encoded_bytes(enc: &Encoded<Self>) -> Result<Self, InvalidKey>;

    /// Serialize an object to its encoded form
    fn to_encoded_bytes(&self) -> Encoded<Self>;
}

/// A byte array encoding a value the indicated size
pub type Encoded<T> = Array<u8, <T as EncodedSizeUser>::EncodedSize>;

/// Initialize a KEM from a seed.
pub trait FromSeed: Kem {
    /// Using the provided [`Seed`] value, create a KEM keypair.
    fn from_seed(seed: &Seed) -> (Self::DecapsulationKey, Self::EncapsulationKey);
}

impl<K> FromSeed for K
where
    K: Kem,
    K::DecapsulationKey: KeyInit + KeySizeUser<KeySize = U64>,
{
    fn from_seed(seed: &Seed) -> (K::DecapsulationKey, K::EncapsulationKey) {
        let dk = K::DecapsulationKey::new(seed);
        let ek = dk.as_ref().clone();
        (dk, ek)
    }
}
