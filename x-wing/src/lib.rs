#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

//! # Usage
//!
//! This crate implements the X-Wing Key Encapsulation Method (X-Wing-KEM) algorithm.
//! X-Wing-KEM is a KEM in the sense that it creates an (decapsulation key, encapsulation key) pair,
//! such that anyone can use the encapsulation key to establish a shared key with the holder of the
//! decapsulation key. X-Wing-KEM is a general-purpose hybrid post-quantum KEM, combining x25519 and ML-KEM-768.
//!
//! ```
//! use kem::{Decapsulate, Encapsulate};
//!
//! let mut rng = &mut rand::rngs::OsRng;
//! let (sk, pk) = x_wing::generate_key_pair(rng);
//! let (ct, ss_sender) = pk.encapsulate(rng).unwrap();
//! let ss_receiver = sk.decapsulate(&ct).unwrap();
//! assert_eq!(ss_sender, ss_receiver);
//! ```

use core::convert::Infallible;

use kem::{Decapsulate, Encapsulate};
use ml_kem::array::ArrayN;
use ml_kem::{kem, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, B32};
use rand_core::CryptoRngCore;
#[cfg(feature = "getrandom")]
use rand_core::OsRng;
use sha3::digest::core_api::XofReaderCoreWrapper;
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Sha3_256, Shake256, Shake256ReaderCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

type MlKem768DecapsulationKey = kem::DecapsulationKey<MlKem768Params>;
type MlKem768EncapsulationKey = kem::EncapsulationKey<MlKem768Params>;

const X_WING_LABEL: &[u8; 6] = br"\.//^\";

/// Size in bytes of the `EncapsulationKey`.
pub const ENCAPSULATION_KEY_SIZE: usize = 1216;
/// Size in bytes of the `DecapsulationKey`.
pub const DECAPSULATION_KEY_SIZE: usize = 32;
/// Size in bytes of the `Ciphertext`.
pub const CIPHERTEXT_SIZE: usize = 1120;

/// Shared secret key.
pub type SharedSecret = [u8; 32];

// The naming convention of variables matches the RFC.
// ss -> Shared Secret
// ct -> Cipher Text
// ek -> Ephemeral Key
// pk -> Public Key
// sk -> Secret Key
// Postfixes:
// _m -> ML-Kem related key
// _x -> x25519 related key

/// X-Wing encapsulation or public key.
#[derive(Clone, PartialEq)]
pub struct EncapsulationKey {
    pk_m: MlKem768EncapsulationKey,
    pk_x: x25519_dalek::PublicKey,
}

impl Encapsulate<Ciphertext, SharedSecret> for EncapsulationKey {
    type Error = Infallible;

    fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Ciphertext, SharedSecret), Self::Error> {
        // Swapped order of operations compared to RFC, so that usage of the rng matches the RFC
        let (ct_m, ss_m) = self.pk_m.encapsulate(rng)?;

        let ek_x: SharedSecret = generate(rng);
        let ct_x = x25519(ek_x, X25519_BASEPOINT_BYTES);
        let ss_x = x25519(ek_x, self.pk_x.to_bytes());

        let ss = combiner(&ss_m, &ss_x, &ct_x, &self.pk_x);

        #[cfg(feature = "zeroize")]
        {
            let mut ss_x = ss_x;
            ss_x.zeroize();
        }

        let ct = Ciphertext { ct_m, ct_x };
        Ok((ct, ss))
    }
}

impl EncapsulationKey {
    /// Convert the key to the following format:
    /// ML-KEM-768 public key(1184 bytes) | X25519 public key(32 bytes).
    #[must_use]
    pub fn as_bytes(&self) -> [u8; ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; ENCAPSULATION_KEY_SIZE];
        buffer[0..1184].copy_from_slice(&self.pk_m.as_bytes());
        buffer[1184..1216].copy_from_slice(self.pk_x.as_bytes());
        buffer
    }
}

impl From<&[u8; ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    fn from(value: &[u8; ENCAPSULATION_KEY_SIZE]) -> Self {
        let mut pk_m = [0; 1184];
        pk_m.copy_from_slice(&value[0..1184]);
        let pk_m = MlKem768EncapsulationKey::from_bytes(&pk_m.into());

        let mut pk_x = [0; 32];
        pk_x.copy_from_slice(&value[1184..]);
        let pk_x = x25519_dalek::PublicKey::from(pk_x);
        EncapsulationKey { pk_m, pk_x }
    }
}

/// X-Wing decapsulation key or private key.
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct DecapsulationKey {
    sk: [u8; DECAPSULATION_KEY_SIZE],
}

impl Decapsulate<Ciphertext, SharedSecret> for DecapsulationKey {
    type Error = Infallible;

    #[allow(clippy::similar_names)] // So we can use the names as in the RFC
    fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret, Self::Error> {
        let (sk_m, sk_x, _pk_m, pk_x) = self.expand_key();
        let ss_m = sk_m.decapsulate(&ct.ct_m)?;
        let ss_x = x25519(sk_x.to_bytes(), ct.ct_x);
        let ss = combiner(&ss_m, &ss_x, &ct.ct_x, &pk_x);

        #[cfg(feature = "zeroize")]
        {
            let mut ss_x = ss_x;
            ss_x.zeroize();
        }

        Ok(ss)
    }
}

impl DecapsulationKey {
    /// Generate a new `DecapsulationKey` using `OsRng`.
    #[cfg(feature = "getrandom")]
    pub fn generate_from_os_rng() -> DecapsulationKey {
        Self::generate(&mut OsRng)
    }

    /// Generate a new `DecapsulationKey` using the provided RNG.
    pub fn generate(rng: &mut impl CryptoRngCore) -> DecapsulationKey {
        let sk = generate(rng);
        DecapsulationKey { sk }
    }

    /// Provide the matching `EncapsulationKey`.
    #[must_use]
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        let (_sk_m, _sk_x, pk_m, pk_x) = self.expand_key();
        EncapsulationKey { pk_m, pk_x }
    }

    fn expand_key(
        &self,
    ) -> (
        MlKem768DecapsulationKey,
        x25519_dalek::StaticSecret,
        MlKem768EncapsulationKey,
        x25519_dalek::PublicKey,
    ) {
        use sha3::digest::Update;
        let mut shaker = Shake256::default();
        shaker.update(&self.sk);
        let mut expanded = shaker.finalize_xof();

        let d = read_from(&mut expanded).into();
        let z = read_from(&mut expanded).into();
        let (sk_m, pk_m) = MlKem768::generate_deterministic(&d, &z);

        let sk_x = read_from(&mut expanded);
        let sk_x = x25519_dalek::StaticSecret::from(sk_x);
        let pk_x = x25519_dalek::PublicKey::from(&sk_x);

        (sk_m, sk_x, pk_m, pk_x)
    }

    /// Private key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; DECAPSULATION_KEY_SIZE] {
        &self.sk
    }
}

impl From<[u8; DECAPSULATION_KEY_SIZE]> for DecapsulationKey {
    fn from(sk: [u8; DECAPSULATION_KEY_SIZE]) -> Self {
        DecapsulationKey { sk }
    }
}

/// X-Wing ciphertext.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct Ciphertext {
    ct_m: ArrayN<u8, 1088>,
    ct_x: [u8; 32],
}

impl Ciphertext {
    /// Convert the ciphertext to the following format:
    /// ML-KEM-768 ciphertext(1088 bytes) | X25519 ciphertext(32 bytes).
    #[must_use]
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        let mut buffer = [0; CIPHERTEXT_SIZE];
        buffer[0..1088].copy_from_slice(&self.ct_m);
        buffer[1088..].copy_from_slice(&self.ct_x);
        buffer
    }
}

impl From<&[u8; CIPHERTEXT_SIZE]> for Ciphertext {
    fn from(value: &[u8; CIPHERTEXT_SIZE]) -> Self {
        let mut ct_m = [0; 1088];
        ct_m.copy_from_slice(&value[0..1088]);
        let mut ct_x = [0; 32];
        ct_x.copy_from_slice(&value[1088..]);

        Ciphertext {
            ct_m: ct_m.into(),
            ct_x,
        }
    }
}

/// Generate a X-Wing key pair using `OsRng`.
#[cfg(feature = "getrandom")]
pub fn generate_key_pair_from_os_rng() -> (DecapsulationKey, EncapsulationKey) {
    generate_key_pair(&mut OsRng)
}

/// Generate a X-Wing key pair using the provided rng.
pub fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (DecapsulationKey, EncapsulationKey) {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key();
    (sk, pk)
}

fn combiner(
    ss_m: &B32,
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &x25519_dalek::PublicKey,
) -> SharedSecret {
    use sha3::Digest;

    let mut hasher = Sha3_256::new();
    hasher.update(ss_m);
    hasher.update(ss_x);
    hasher.update(ct_x);
    hasher.update(pk_x.as_bytes());
    hasher.update(X_WING_LABEL);
    hasher.finalize().into()
}

fn read_from<const N: usize>(reader: &mut XofReaderCoreWrapper<Shake256ReaderCore>) -> [u8; N] {
    let mut data = [0; N];
    reader.read(&mut data);
    data
}

fn generate<const N: usize>(rng: &mut impl CryptoRngCore) -> [u8; N] {
    let mut random = [0; N];
    rng.fill_bytes(&mut random);
    random
}

#[cfg(test)]
mod tests {
    use rand_core::{impls, CryptoRng, OsRng, RngCore};
    use serde::Deserialize;

    use super::*;

    struct SeedRng {
        seed: Vec<u8>,
    }

    impl SeedRng {
        fn new(seed: Vec<u8>) -> SeedRng {
            SeedRng { seed }
        }
    }

    impl RngCore for SeedRng {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap();
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.copy_from_slice(&self.seed[0..dest.len()]);
            self.seed.drain(0..dest.len());
            Ok(())
        }
    }

    #[derive(Deserialize)]
    struct TestVector {
        #[serde(deserialize_with = "hex::serde::deserialize")]
        seed: Vec<u8>,

        #[serde(deserialize_with = "hex::serde::deserialize")]
        eseed: Vec<u8>,

        #[serde(deserialize_with = "hex::serde::deserialize")]
        ss: [u8; 32],

        #[serde(deserialize_with = "hex::serde::deserialize")]
        sk: [u8; 32],

        #[serde(deserialize_with = "hex::serde::deserialize")]
        pk: Vec<u8>, //[u8; PUBLIC_KEY_SIZE],

        #[serde(deserialize_with = "hex::serde::deserialize")]
        ct: Vec<u8>, //[u8; 1120],
    }

    impl CryptoRng for SeedRng {}

    /// Test with test vectors from: <https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem/blob/main/spec/test-vectors.json>
    #[test]
    fn rfc_test_vectors() {
        let test_vectors =
            serde_json::from_str::<Vec<TestVector>>(include_str!("test-vectors.json")).unwrap();

        for test_vector in test_vectors {
            run_test(test_vector);
        }
    }

    fn run_test(test_vector: TestVector) {
        let mut seed = SeedRng::new(test_vector.seed);
        let (sk, pk) = generate_key_pair(&mut seed);

        assert_eq!(sk.as_bytes().to_vec(), test_vector.sk);
        assert_eq!(pk.as_bytes().to_vec(), test_vector.pk);

        let mut eseed = SeedRng::new(test_vector.eseed);
        let (ct, ss) = pk.encapsulate(&mut eseed).unwrap();

        assert_eq!(ss, test_vector.ss);
        assert_eq!(ct.as_bytes().to_vec(), test_vector.ct);

        let ss = sk.decapsulate(&ct).unwrap();
        assert_eq!(ss, test_vector.ss);
    }

    #[test]
    fn ciphertext_serialize() {
        let mut rng = OsRng;

        let ct_a = Ciphertext {
            ct_m: generate(&mut rng).into(),
            ct_x: generate(&mut rng),
        };

        let bytes = ct_a.as_bytes();

        let ct_b = Ciphertext::from(&bytes);

        assert!(ct_a == ct_b);
    }

    #[test]
    fn key_serialize() {
        let sk = DecapsulationKey::generate(&mut OsRng);
        let pk = sk.encapsulation_key();

        let sk_bytes = sk.as_bytes();
        let pk_bytes = pk.as_bytes();

        let sk_b = DecapsulationKey::from(*sk_bytes);
        let pk_b = EncapsulationKey::from(&pk_bytes.clone());

        assert!(sk == sk_b);
        assert!(pk == pk_b);
    }
}
