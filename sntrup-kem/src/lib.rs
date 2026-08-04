//! Pure Rust implementation of Streamlined NTRU Prime KEM for all parameter sizes.
//!
//! Streamlined NTRU Prime is a lattice-based, quantum-resistant cryptographic
//! algorithm designed for secure key exchange. This crate supports all six
//! parameter sets: sntrup653, sntrup761, sntrup857, sntrup953, sntrup1013,
//! and sntrup1277.
//!
//! # Usage
//!
//! ```rust
//! # #[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
//! # {
//! use sntrup_kem::{Sntrup761, SntrupKem};
//!
//! let mut rng = rand::rng();
//! let (ek, dk) = Sntrup761::generate_key(&mut rng);
//! let (ct, ss1) = ek.encapsulate(&mut rng);
//! let ss2 = dk.decapsulate(&ct);
//! assert_eq!(ss1, ss2);
//! # }
//! ```
//!
//! # Security Levels
//!
//! - [`Sntrup653`] / [`sntrup653`]: NIST Level 1 (128-bit security) — research/testing only, prefer [`Sntrup761`] or higher for production
//! - [`Sntrup761`] / [`sntrup761`]: NIST Level 2 (128-bit+ security, used by OpenSSH)
//! - [`Sntrup857`] / [`sntrup857`]: NIST Level 3 (192-bit security)
//! - [`Sntrup953`] / [`sntrup953`]: NIST Level 4 (192-bit+ security)
//! - [`Sntrup1013`] / [`sntrup1013`]: NIST Level 5 (256-bit security)
//! - [`Sntrup1277`] / [`sntrup1277`]: NIST Level 5 (256-bit security, with extra margin)
//!
//! # Sizes (bytes)
//!
//! | Parameter Set | NIST Level | Public Key | Secret Key | Ciphertext | Shared Secret |
//! |---------------|------------|------------|------------|------------|---------------|
//! | sntrup653     | 1          | 994        | 1518       | 897        | 32            |
//! | sntrup761     | 2          | 1158       | 1763       | 1039       | 32            |
//! | sntrup857     | 3          | 1322       | 1999       | 1184       | 32            |
//! | sntrup953     | 4          | 1505       | 2254       | 1349       | 32            |
//! | sntrup1013    | 5          | 1623       | 2417       | 1455       | 32            |
//! | sntrup1277    | 5          | 2067       | 3059       | 1847       | 32            |
//!
//! # Features
//!
//! - `kgen`: Key generation (default)
//! - `ecap`: Encapsulation (default)
//! - `dcap`: Decapsulation (default)
//! - `serde`: Serde serialization support via `serdect`

// The `kgen`/`ecap`/`dcap` features select which KEM operations are compiled.
// Building with a subset (or none) of them leaves some shared internal helpers
// (`ct`, `r3`, `rq`, `zx`, `utils`, and their imports) without a caller — that is
// expected, not a defect. Dead-code/unused-import enforcement is therefore scoped
// to the full-feature build (default + `--all-features`); partial builds tolerate
// the uncalled helpers so the crate stays warning-clean under `-D warnings`.
#![cfg_attr(
    not(all(feature = "kgen", feature = "ecap", feature = "dcap")),
    allow(dead_code, unused_imports)
)]

mod ct;
mod error;
mod kem;
mod params;
mod r3;
mod rq;
mod types;
mod utils;
mod zx;

pub use error::Error;
pub use params::{
    Sntrup653Params, Sntrup761Params, Sntrup857Params, Sntrup953Params, Sntrup1013Params,
    Sntrup1277Params, SntrupParams,
};
pub use types::{Ciphertext, DecapsulationKey, EncapsulationKey, SharedSecret, SntrupKem};

/// sntrup653 KEM (NIST Level 1, 128-bit security).
///
/// **Not recommended for production use.** The 653 parameter set provides the
/// lowest security margin. Prefer [`Sntrup761`] or higher for production deployments.
pub type Sntrup653 = SntrupKem<Sntrup653Params>;
/// sntrup761 KEM (NIST Level 2, 128-bit+ security, used by OpenSSH).
pub type Sntrup761 = SntrupKem<Sntrup761Params>;
/// sntrup857 KEM (NIST Level 3, 192-bit security).
pub type Sntrup857 = SntrupKem<Sntrup857Params>;
/// sntrup953 KEM (NIST Level 4, 192-bit+ security).
pub type Sntrup953 = SntrupKem<Sntrup953Params>;
/// sntrup1013 KEM (NIST Level 5, 256-bit security).
pub type Sntrup1013 = SntrupKem<Sntrup1013Params>;
/// sntrup1277 KEM (NIST Level 5, 256-bit security).
pub type Sntrup1277 = SntrupKem<Sntrup1277Params>;

/// Define a per-parameter-set convenience module: size constants (sourced from
/// the `SntrupParams` impl so they cannot drift), type aliases, and free
/// `generate_key` / `generate_key_deterministic` functions.
macro_rules! sntrup_module {
    ($modname:ident, $params:ident, $kem:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $modname {
            use crate::params::SntrupParams;

            /// Public key size in bytes.
            pub const PUBLIC_KEY_SIZE: usize = crate::$params::PK_BYTES;
            /// Secret key size in bytes.
            pub const SECRET_KEY_SIZE: usize = crate::$params::SK_BYTES;
            /// Ciphertext size in bytes.
            pub const CIPHERTEXT_SIZE: usize = crate::$params::CT_BYTES;
            /// Shared secret size in bytes.
            pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;

            /// Encapsulation key for this parameter set.
            pub type EncapsulationKey = crate::EncapsulationKey<crate::$params>;
            /// Decapsulation key for this parameter set.
            pub type DecapsulationKey = crate::DecapsulationKey<crate::$params>;
            /// Ciphertext for this parameter set.
            pub type Ciphertext = crate::Ciphertext<crate::$params>;
            /// Shared secret for this parameter set.
            pub type SharedSecret = crate::SharedSecret<crate::$params>;

            /// Generate a key pair for this parameter set.
            #[cfg(feature = "kgen")]
            pub fn generate_key(
                rng: &mut impl rand::CryptoRng,
            ) -> (EncapsulationKey, DecapsulationKey) {
                crate::$kem::generate_key(rng)
            }

            /// Generate a key pair deterministically from a 32-byte seed.
            #[cfg(feature = "kgen")]
            pub fn generate_key_deterministic(
                seed: &[u8; 32],
            ) -> (EncapsulationKey, DecapsulationKey) {
                crate::$kem::generate_key_deterministic(seed)
            }
        }
    };
}

sntrup_module!(
    sntrup653,
    Sntrup653Params,
    Sntrup653,
    "sntrup653: NIST Level 1 (128-bit security), p=653, q=4621, w=288.\n\n**Not recommended for production use.** Prefer [`sntrup761`] or higher."
);
sntrup_module!(
    sntrup761,
    Sntrup761Params,
    Sntrup761,
    "sntrup761: NIST Level 2 (128-bit+ security), p=761, q=4591, w=286. Used by OpenSSH."
);
sntrup_module!(
    sntrup857,
    Sntrup857Params,
    Sntrup857,
    "sntrup857: NIST Level 3 (192-bit security), p=857, q=5167, w=322."
);
sntrup_module!(
    sntrup953,
    Sntrup953Params,
    Sntrup953,
    "sntrup953: NIST Level 4 (192-bit+ security), p=953, q=6343, w=396."
);
sntrup_module!(
    sntrup1013,
    Sntrup1013Params,
    Sntrup1013,
    "sntrup1013: NIST Level 5 (256-bit security), p=1013, q=7177, w=448."
);
sntrup_module!(
    sntrup1277,
    Sntrup1277Params,
    Sntrup1277,
    "sntrup1277: NIST Level 5 (256-bit security, extra margin), p=1277, q=7879, w=492."
);
