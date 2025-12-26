#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![deny(missing_docs)] // Require all public interfaces to be documented
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`

//! # Usage
//!
//! This crate implements the Module-Lattice-based Key Encapsulation Method (ML-KEM) algorithm
//! being standardized by NIST in FIPS 203.  ML-KEM is a KEM in the sense that it creates a
//! (decapsulation key, encapsulation key) pair, such that anyone can use the encapsulation key to
//! establish a shared key with the holder of the decapsulation key.  ML-KEM is the first KEM
//! algorithm standardized by NIST that is designed to be resistant to attacks using quantum
//! computers.
//!
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! // NOTE: requires the `getrandom` feature is enabled
//!
//! use ml_kem::{
//!     ml_kem_768::DecapsulationKey,
//!     kem::{Decapsulate, Encapsulate, Generate, KeyInit}
//! };
//!
//! // Generate a decapsulation/encapsulation keypair
//! let dk = DecapsulationKey::generate();
//! let ek = dk.encapsulator();
//!
//! // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
//! // secret `k_send` and the encapsulated form `ct`.
//! let (ct, k_send) = ek.encapsulate().unwrap();
//!
//! // Decapsulate the shared key and verify that it was faithfully received.
//! let k_recv = dk.decapsulate(&ct).unwrap();
//! assert_eq!(k_send, k_recv);
//! ```
//!
//! [RFC 9180]: https://www.rfc-editor.org/info/rfc9180

/// The inevitable utility module
mod util;

/// Section 2.4. Interpreting the Pseudocode
/// Section 4.2.2. Sampling algorithms
/// Section 4.3. The Number-Theoretic Transform
mod algebra;

/// Section 4.1. Crytographic Functions
mod crypto;

/// Section 4.2.1. Conversion and Compression Algorithms, Compression and decompression
mod compress;

/// Section 4.2.1. Conversion and Compression Algorithms, Encoding and decoding
mod encode;

/// Section 5. The K-PKE Component Scheme
mod pke;

/// Section 6. The ML-KEM Key-Encapsulation Mechanism
pub mod kem;

/// Section 7. Parameter Sets
mod param;

pub mod pkcs8;

/// Trait definitions
mod traits;

use core::fmt::Debug;
use hybrid_array::{
    Array,
    typenum::{U2, U3, U4, U5, U10, U11, U64},
};

pub use hybrid_array as array;

#[cfg(feature = "deterministic")]
pub use util::B32;

pub use ml_kem_512::MlKem512Params;
pub use ml_kem_768::MlKem768Params;
pub use ml_kem_1024::MlKem1024Params;
pub use param::{ArraySize, ExpandedDecapsulationKey, ParameterSet};
pub use traits::*;

/// ML-KEM seeds are decapsulation (private) keys, which are consistently 64-bytes across all
/// security levels, and are the preferred serialization for representing such keys.
pub type Seed = Array<u8, U64>;

/// ML-KEM-512 is the parameter set for security category 1, corresponding to key search on a block
/// cipher with a 128-bit key.
pub mod ml_kem_512 {
    use super::{Debug, ParameterSet, U2, U3, U4, U10, kem};

    /// `MlKem512` is the parameter set for security category 1, corresponding to key search on a
    /// block cipher with a 128-bit key.
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct MlKem512Params;

    impl ParameterSet for MlKem512Params {
        type K = U2;
        type Eta1 = U3;
        type Eta2 = U2;
        type Du = U10;
        type Dv = U4;
    }

    /// An ML-KEM-512 `DecapsulationKey` which provides the ability to generate a new key pair, and
    /// decapsulate an encapsulated shared key.
    pub type DecapsulationKey = kem::DecapsulationKey<MlKem512Params>;

    /// An ML-KEM-512 `EncapsulationKey` provides the ability to encapsulate a shared key so that it
    /// can only be decapsulated by the holder of the corresponding decapsulation key.
    pub type EncapsulationKey = kem::EncapsulationKey<MlKem512Params>;
}

/// ML-KEM-768 is the parameter set for security category 3, corresponding to key search on a block
/// cipher with a 192-bit key.
pub mod ml_kem_768 {
    use super::{Debug, ParameterSet, U2, U3, U4, U10, kem};

    /// `MlKem768` is the parameter set for security category 3, corresponding to key search on a
    /// block cipher with a 192-bit key.
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct MlKem768Params;

    impl ParameterSet for MlKem768Params {
        type K = U3;
        type Eta1 = U2;
        type Eta2 = U2;
        type Du = U10;
        type Dv = U4;
    }

    /// An ML-KEM-768 `DecapsulationKey` which provides the ability to generate a new key pair, and
    /// decapsulate an encapsulated shared key.
    pub type DecapsulationKey = kem::DecapsulationKey<MlKem768Params>;

    /// An ML-KEM-768 `EncapsulationKey` provides the ability to encapsulate a shared key so that it
    /// can only be decapsulated by the holder of the corresponding decapsulation key.
    pub type EncapsulationKey = kem::EncapsulationKey<MlKem768Params>;
}

/// ML-KEM-1024 is the parameter set for security category 5, corresponding to key search on a block
/// cipher with a 256-bit key.
pub mod ml_kem_1024 {
    use super::{Debug, ParameterSet, U2, U4, U5, U11, kem};

    /// `MlKem1024` is the parameter set for security category 5, corresponding to key search on a
    /// block cipher with a 256-bit key.
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct MlKem1024Params;

    impl ParameterSet for MlKem1024Params {
        type K = U4;
        type Eta1 = U2;
        type Eta2 = U2;
        type Du = U11;
        type Dv = U5;
    }

    /// An ML-KEM-1024 `DecapsulationKey` which provides the ability to generate a new key pair, and
    /// decapsulate an encapsulated shared key.
    pub type DecapsulationKey = kem::DecapsulationKey<MlKem1024Params>;

    /// An ML-KEM-1024 `EncapsulationKey` provides the ability to encapsulate a shared key so that
    /// it can only be decapsulated by the holder of the corresponding decapsulation key.
    pub type EncapsulationKey = kem::EncapsulationKey<MlKem1024Params>;
}

/// A shared key produced by the KEM `K`
pub type SharedKey<K> = Array<u8, <K as KemCore>::SharedKeySize>;

/// A ciphertext produced by the KEM `K`
pub type Ciphertext<K> = Array<u8, <K as KemCore>::CiphertextSize>;

/// ML-KEM with the parameter set for security category 1, corresponding to key search on a block
/// cipher with a 128-bit key.
pub type MlKem512 = kem::Kem<MlKem512Params>;

/// ML-KEM with the parameter set for security category 3, corresponding to key search on a block
/// cipher with a 192-bit key.
pub type MlKem768 = kem::Kem<MlKem768Params>;

/// ML-KEM with the parameter set for security category 5, corresponding to key search on a block
/// cipher with a 256-bit key.
pub type MlKem1024 = kem::Kem<MlKem1024Params>;

#[cfg(test)]
mod test {
    use super::*;
    use ::kem::{Decapsulate, Encapsulate};
    use rand_core::TryRngCore;

    fn round_trip_test<K>()
    where
        K: KemCore,
    {
        let mut rng = getrandom::SysRng.unwrap_err();

        let (dk, ek) = K::generate(&mut rng);

        let (ct, k_send) = ek.encapsulate_with_rng(&mut rng).unwrap();
        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn round_trip() {
        round_trip_test::<MlKem512>();
        round_trip_test::<MlKem768>();
        round_trip_test::<MlKem1024>();
    }
}
