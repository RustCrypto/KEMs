//! ⚠️ Low-level "hazmat" FrodoKEM and eFrodoKEM functions.
//!
//! # ☢️️ WARNING: HAZARDOUS API ☢️
//!
//! This module contains the low-level API for the FrodoKEM algorithm.
//! Only use if you know what you're doing.
//!
//! This layer provides several traits for mixing and matching FrodoKEM components:
//!
//! [`Params`] for specifying the constant parameters of the FrodoKEM algorithm.
//! [`Expanded`] for specifying the expand seed A method.
//! [`Sample`] for specifying the noise sampling method.
//! [`Kem`] encompasses the entire FrodoKEM algorithm and each function can be overridden.
//!
//! There are default implementations for each of these traits that can be used to create a FrodoKEM instance.
//!
//! There are:
//! [`Frodo640`], [`Frodo976`], and [`Frodo1344`] for the FrodoKEM parameter sets.
//! [`FrodoAes`] and [`FrodoShake`] for the expand seed A methods.
//! [`FrodoCdfSample`] for the noise sampling method.
//!
//! [`FrodoKem`] is the default implementation of the FrodoKEM algorithm that combines
//! all of the above traits using generics.
//!
//! There are also type aliases for each standardized FrodoKEM algorithm:
//!
//! [`FrodoKem640Aes`], [`FrodoKem976Aes`], and [`FrodoKem1344Aes`] for the FrodoKEM-AES algorithms.
//! [`FrodoKem640Shake`], [`FrodoKem976Shake`], and [`FrodoKem1344Shake`] for the FrodoKEM-SHAKE algorithms.

#![allow(unreachable_pub, clippy::unwrap_used)]

mod models;
mod traits;

pub use models::*;
pub use traits::*;

#[cfg(feature = "frodo640aes")]
/// The FrodoKEM-640-AES algorithm
pub type FrodoKem640Aes = FrodoKem<Frodo640, FrodoAes<Frodo640>, FrodoCdfSample<Frodo640>>;

#[cfg(feature = "frodo976aes")]
/// The FrodoKEM-976-AES algorithm
pub type FrodoKem976Aes = FrodoKem<Frodo976, FrodoAes<Frodo976>, FrodoCdfSample<Frodo976>>;

#[cfg(feature = "frodo1344aes")]
/// The FrodoKEM-1344-AES algorithm
pub type FrodoKem1344Aes = FrodoKem<Frodo1344, FrodoAes<Frodo1344>, FrodoCdfSample<Frodo1344>>;

#[cfg(feature = "frodo640shake")]
/// The FrodoKEM-640-SHAKE algorithm
pub type FrodoKem640Shake = FrodoKem<Frodo640, FrodoShake<Frodo640>, FrodoCdfSample<Frodo640>>;

#[cfg(feature = "frodo976shake")]
/// The FrodoKEM-976-SHAKE algorithm
pub type FrodoKem976Shake = FrodoKem<Frodo976, FrodoShake<Frodo976>, FrodoCdfSample<Frodo976>>;

#[cfg(feature = "frodo1344shake")]
/// The FrodoKEM-1344-SHAKE algorithm
pub type FrodoKem1344Shake = FrodoKem<Frodo1344, FrodoShake<Frodo1344>, FrodoCdfSample<Frodo1344>>;

#[cfg(feature = "efrodo640aes")]
/// The eFrodoKEM-640-AES algorithm
pub type EphemeralFrodoKem640Aes = EphemeralFrodoKem<
    EphemeralFrodo640,
    FrodoAes<EphemeralFrodo640>,
    FrodoCdfSample<EphemeralFrodo640>,
>;

#[cfg(feature = "efrodo976aes")]
/// The eFrodoKEM-976-AES algorithm
pub type EphemeralFrodoKem976Aes = EphemeralFrodoKem<
    EphemeralFrodo976,
    FrodoAes<EphemeralFrodo976>,
    FrodoCdfSample<EphemeralFrodo976>,
>;

#[cfg(feature = "efrodo1344aes")]
/// The eFrodoKEM-1344-AES algorithm
pub type EphemeralFrodoKem1344Aes = EphemeralFrodoKem<
    EphemeralFrodo1344,
    FrodoAes<EphemeralFrodo1344>,
    FrodoCdfSample<EphemeralFrodo1344>,
>;

#[cfg(feature = "efrodo640shake")]
/// The eFrodoKEM-640-SHAKE algorithm
pub type EphemeralFrodoKem640Shake = EphemeralFrodoKem<
    EphemeralFrodo640,
    FrodoShake<EphemeralFrodo640>,
    FrodoCdfSample<EphemeralFrodo640>,
>;

#[cfg(feature = "efrodo976shake")]
/// The eFrodoKEM-976-SHAKE algorithm
pub type EphemeralFrodoKem976Shake = EphemeralFrodoKem<
    EphemeralFrodo976,
    FrodoShake<EphemeralFrodo976>,
    FrodoCdfSample<EphemeralFrodo976>,
>;

#[cfg(feature = "efrodo1344shake")]
/// The eFrodoKEM-1344-SHAKE algorithm
pub type EphemeralFrodoKem1344Shake = EphemeralFrodoKem<
    EphemeralFrodo1344,
    FrodoShake<EphemeralFrodo1344>,
    FrodoCdfSample<EphemeralFrodo1344>,
>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_calculations() {
        assert_eq!(EphemeralFrodoKem640Shake::N, 640);
        assert_eq!(EphemeralFrodoKem640Shake::N_BAR, 8);
        assert_eq!(EphemeralFrodoKem640Shake::LOG_Q, 15);
        assert_eq!(EphemeralFrodoKem640Shake::EXTRACTED_BITS, 2);
        assert_eq!(EphemeralFrodoKem640Shake::STRIPE_STEP, 8);
        assert_eq!(EphemeralFrodoKem640Shake::BYTES_SEED_A, 16);
        assert_eq!(EphemeralFrodoKem640Shake::BYTES_MU, 16);
        assert_eq!(EphemeralFrodoKem640Shake::BYTES_PK_HASH, 16);
        assert_eq!(
            EphemeralFrodoKem640Shake::CDF_TABLE,
            &[
                4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762, 32766,
                32767
            ]
        );
        assert_eq!(EphemeralFrodoKem640Shake::CLAIMED_NIST_LEVEL, 1);
        assert_eq!(EphemeralFrodoKem640Shake::SHARED_SECRET_LENGTH, 16);
        assert_eq!(EphemeralFrodoKem640Shake::METHOD, "SHAKE");
        assert_eq!(EphemeralFrodoKem640Shake::KEY_SEED_SIZE, 48);
        assert_eq!(EphemeralFrodoKem640Shake::TWO_N, 1280);
        assert_eq!(EphemeralFrodoKem640Shake::TWO_PLUS_BYTES_SEED_A, 18);
        assert_eq!(EphemeralFrodoKem640Shake::N_X_N, 409600);
        assert_eq!(EphemeralFrodoKem640Shake::N_X_N_BAR, 5120);
        assert_eq!(EphemeralFrodoKem640Shake::N_BAR_X_N, 5120);
        assert_eq!(EphemeralFrodoKem640Shake::N_BAR_X_N_BAR, 64);
        assert_eq!(EphemeralFrodoKem640Shake::TWO_N_X_N_BAR, 10240);
        assert_eq!(EphemeralFrodoKem640Shake::EXTRACTED_BITS_MASK, 3);
        assert_eq!(EphemeralFrodoKem640Shake::SHIFT, 13);
        assert_eq!(EphemeralFrodoKem640Shake::Q, 0x8000);
        assert_eq!(EphemeralFrodoKem640Shake::Q_MASK, 0x7FFF);
        assert_eq!(EphemeralFrodoKem640Shake::PUBLIC_KEY_LENGTH, 9616);
        assert_eq!(EphemeralFrodoKem640Shake::SECRET_KEY_LENGTH, 19888);
        assert_eq!(EphemeralFrodoKem640Shake::CIPHERTEXT_LENGTH, 9720);
    }
}
