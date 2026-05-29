//! Pure Rust implementation of HQC-KEM (NIST FIPS 207).
//!
//! HQC is a code-based Key Encapsulation Mechanism using quasi-cyclic codes
//! over the ring Z_2\[X\]/(X^n-1). Uses concatenated Reed-Solomon + Reed-Muller
//! error correction with Fujisaki-Okamoto transform for IND-CCA2 security.
//!
//! # Usage
//!
//! ```rust
//! # #[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
//! # {
//! use hqc_kem::{Hqc128, HqcKem};
//!
//! let mut rng = rand::rng();
//! let (ek, dk) = Hqc128::generate_key(&mut rng);
//! let (ct, ss1) = ek.encapsulate(&mut rng);
//! let ss2 = dk.decapsulate(&ct);
//! assert_eq!(ss1, ss2);
//! # }
//! ```
//!
//! # Security Levels
//!
//! - [`Hqc128`] / [`hqc128`]: NIST Level 1 (128-bit security)
//! - [`Hqc192`] / [`hqc192`]: NIST Level 3 (192-bit security)
//! - [`Hqc256`] / [`hqc256`]: NIST Level 5 (256-bit security)
//!
//! # Features
//!
//! - `kgen`: Key generation (default)
//! - `ecap`: Encapsulation (default)
//! - `dcap`: Decapsulation (default)
//! - `kem`: RustCrypto [`kem`](https://crates.io/crates/kem) 0.3 trait implementations
//! - `pkcs8`: PKCS#8 key encoding/decoding
//! - `pem`: PEM encoding (enables `pkcs8/pem`)
//! - `alloc`: Enables PKCS#8 encoding (requires `alloc`)
//! - `serde`: Serde serialization support

#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod code;
mod error;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod fft;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod gf256;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod kem;
#[cfg(feature = "kem")]
mod kem_impl;
mod params;
#[cfg(feature = "pkcs8")]
mod pkcs8_impl;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod pke;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod poly;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod reed_muller;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod reed_solomon;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod sampling;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod shake;
#[cfg(feature = "kem")]
mod sizes;
mod types;

pub use error::Error;
pub use params::{Hqc128Params, Hqc192Params, Hqc256Params, HqcParams};
pub use types::{Ciphertext, DecapsulationKey, EncapsulationKey, HqcKem, SharedSecret};

/// HQC-128 KEM (NIST Level 1).
pub type Hqc128 = HqcKem<Hqc128Params>;
/// HQC-192 KEM (NIST Level 3).
pub type Hqc192 = HqcKem<Hqc192Params>;
/// HQC-256 KEM (NIST Level 5).
pub type Hqc256 = HqcKem<Hqc256Params>;

/// HQC-128: NIST Level 1 security (128-bit).
pub mod hqc128 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 2241;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 2321;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 4433;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;
    /// Message size in bytes (for deterministic encapsulation).
    pub const MESSAGE_SIZE: usize = 16;
    /// Salt size in bytes (for deterministic encapsulation).
    pub const SALT_SIZE: usize = crate::params::SALT_BYTES;

    /// HQC-128 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Hqc128Params>;
    /// HQC-128 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Hqc128Params>;
    /// HQC-128 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Hqc128Params>;
    /// HQC-128 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Hqc128Params>;

    /// Generate an HQC-128 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(rng: &mut impl rand::CryptoRng) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc128::generate_key(rng)
    }

    /// Generate an HQC-128 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(seed: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc128::generate_key_deterministic(seed)
    }
}

/// HQC-192: NIST Level 3 security (192-bit).
pub mod hqc192 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 4514;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 4602;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 8978;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;
    /// Message size in bytes (for deterministic encapsulation).
    pub const MESSAGE_SIZE: usize = 24;
    /// Salt size in bytes (for deterministic encapsulation).
    pub const SALT_SIZE: usize = crate::params::SALT_BYTES;

    /// HQC-192 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Hqc192Params>;
    /// HQC-192 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Hqc192Params>;
    /// HQC-192 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Hqc192Params>;
    /// HQC-192 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Hqc192Params>;

    /// Generate an HQC-192 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(rng: &mut impl rand::CryptoRng) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc192::generate_key(rng)
    }

    /// Generate an HQC-192 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(seed: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc192::generate_key_deterministic(seed)
    }
}

/// HQC-256: NIST Level 5 security (256-bit).
pub mod hqc256 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 7237;
    /// Secret key size in bytes.
    pub const SECRET_KEY_SIZE: usize = 7333;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 14421;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;
    /// Message size in bytes (for deterministic encapsulation).
    pub const MESSAGE_SIZE: usize = 32;
    /// Salt size in bytes (for deterministic encapsulation).
    pub const SALT_SIZE: usize = crate::params::SALT_BYTES;

    /// HQC-256 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Hqc256Params>;
    /// HQC-256 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Hqc256Params>;
    /// HQC-256 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Hqc256Params>;
    /// HQC-256 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Hqc256Params>;

    /// Generate an HQC-256 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(rng: &mut impl rand::CryptoRng) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc256::generate_key(rng)
    }

    /// Generate an HQC-256 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(seed: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc256::generate_key_deterministic(seed)
    }
}
