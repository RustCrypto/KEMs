mod streamlined;

use crate::encoded::AsymEnc;
use hybrid_array::Array;
use sha2::{Digest, Sha512};

/// # Panics
/// This functions should never panic
#[must_use]
pub fn hash_prefix(b: u8, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([b]);
    hasher.update(data);
    let result = hasher.finalize();
    result[..32].try_into().unwrap()
}
/// # Panics
/// This functions should never panic
#[must_use]
pub fn hash_prefix_many(b: u8, data1: &[u8], data2: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([b]);
    hasher.update(data1);
    for data in data2 {
        hasher.update(data);
    }
    let result = hasher.finalize();
    result[..32].try_into().unwrap()
}

pub trait HashOps {
    ///TODO I dont like this api send the first element of y first since it
    /// is treated differently
    /// Also I don't want hashing to depend on particular choise of hash function
    /// maybe users prefer to later switch to sha3
    fn hash_session(b: u8, y: &[&[u8]]) -> [u8; 32];
    fn hash_confirm<Params: AsymEnc>(
        r: &Array<u8, Params::InputsBytes>,
        cache: &[u8; 32],
    ) -> [u8; 32];
}
