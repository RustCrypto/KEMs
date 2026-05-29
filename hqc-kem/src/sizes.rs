//! Type-level size aliases for HQC key and ciphertext sizes.
//!
//! These are provided by the `hybrid-array` crate's `extra-sizes` feature
//! (with HQC sizes added upstream).

pub use hybrid_array::sizes::{
    U2241,  // HQC-128 public key
    U4433,  // HQC-128 ciphertext
    U4514,  // HQC-192 public key
    U7237,  // HQC-256 public key
    U8978,  // HQC-192 ciphertext
    U14421, // HQC-256 ciphertext
};
