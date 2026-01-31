#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
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
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! // NOTE: requires the `getrandom` feature is enabled
//! use x_wing::{
//!     XWingKem,
//!     kem::{Decapsulate, Encapsulate, Kem}
//! };
//!
//! let (sk, pk) = XWingKem::generate_keypair();
//! let (ct, sk_sender) = pk.encapsulate();
//! let sk_receiver = sk.decapsulate(&ct);
//! assert_eq!(sk_sender, sk_receiver);
//! ```

pub use kem::{
    self, Decapsulate, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeyInit,
    KeySizeUser, TryKeyInit,
};

use ml_kem::{
    FromSeed, MlKem768,
    array::{
        Array, ArrayN, AsArrayRef,
        sizes::{U32, U1120, U1184, U1216},
    },
};
use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use sha3::{
    Sha3_256, Shake256, Shake256Reader,
    digest::{ExtendableOutput, XofReader},
};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

type MlKem768DecapsulationKey = ml_kem::kem::DecapsulationKey<MlKem768>;
type MlKem768EncapsulationKey = ml_kem::kem::EncapsulationKey<MlKem768>;

const X_WING_LABEL: &[u8; 6] = br"\.//^\";

/// Size in bytes of the `EncapsulationKey`.
pub const ENCAPSULATION_KEY_SIZE: usize = 1216;
/// Size in bytes of the `DecapsulationKey`.
pub const DECAPSULATION_KEY_SIZE: usize = 32;
/// Size in bytes of the `Ciphertext`.
pub const CIPHERTEXT_SIZE: usize = 1120;
/// Number of bytes necessary to encapsulate a key
pub const ENCAPSULATION_RANDOMNESS_SIZE: usize = 64;

/// Serialized ciphertext.
pub type Ciphertext = kem::Ciphertext<XWingKem>;
/// Shared secret key.
pub type SharedKey = Array<u8, U32>;

/// X-Wing Key Encapsulation Method (X-Wing-KEM).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct XWingKem;

impl Kem for XWingKem {
    type DecapsulationKey = DecapsulationKey;
    type EncapsulationKey = EncapsulationKey;
    type CiphertextSize = U1120;
    type SharedKeySize = U32;
}

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncapsulationKey {
    pk_m: MlKem768EncapsulationKey,
    pk_x: PublicKey,
}

impl EncapsulationKey {
    /// Encapsulates with the given randomness. Uses the first 32 bytes for ML-KEM and the last 32
    /// bytes for x25519. This is useful for testing against known vectors.
    ///
    /// # Warning
    /// Do NOT use this function unless you know what you're doing. If you fail to use all uniform
    /// random bytes even once, you can have catastrophic security failure.
    #[doc(hidden)]
    #[cfg_attr(not(feature = "hazmat"), doc(hidden))]
    #[expect(clippy::must_use_candidate)]
    pub fn encapsulate_deterministic(
        &self,
        randomness: &ArrayN<u8, ENCAPSULATION_RANDOMNESS_SIZE>,
    ) -> (Ciphertext, SharedKey) {
        // Split randomness into two 32-byte arrays
        let (rand_m, rand_x) = randomness.split::<U32>();

        // Encapsulate with ML-KEM first. This is infallible
        let (ct_m, ss_m) = self.pk_m.encapsulate_deterministic(&rand_m);

        let ek_x = StaticSecret::from(rand_x.0);
        // Equal to ct_x = x25519(ek_x, BASE_POINT)
        let ct_x = PublicKey::from(&ek_x);
        // Equal to ss_x = x25519(ek_x, pk_x)
        let ss_x = ek_x.diffie_hellman(&self.pk_x);

        let ss = combiner(&ss_m, &ss_x, &ct_x, &self.pk_x);
        let ct = CiphertextMessage { ct_m, ct_x };

        (ct.into(), ss)
    }
}

impl Encapsulate<XWingKem> for EncapsulationKey {
    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext, SharedKey)
    where
        R: CryptoRng + ?Sized,
    {
        #[allow(unused_mut)]
        let mut randomness = Array::generate_from_rng(rng);
        let res = self.encapsulate_deterministic(&randomness);

        #[cfg(feature = "zeroize")]
        randomness.zeroize();

        res
    }
}

impl KeySizeUser for EncapsulationKey {
    type KeySize = U1216;
}

impl KeyExport for EncapsulationKey {
    fn to_bytes(&self) -> Key<Self> {
        let mut key_bytes = Key::<Self>::default();
        let (m, x) = key_bytes.split_at_mut(1184);
        m.copy_from_slice(&self.pk_m.to_bytes());
        x.copy_from_slice(self.pk_x.as_bytes());
        key_bytes
    }
}

impl TryKeyInit for EncapsulationKey {
    fn new(key_bytes: &Key<Self>) -> Result<Self, InvalidKey> {
        let (m_bytes, x_bytes) = key_bytes.split_ref::<U1184>();

        let pk_m = MlKem768EncapsulationKey::new(m_bytes)?;
        let pk_x = PublicKey::from(x_bytes.0);

        Ok(EncapsulationKey { pk_m, pk_x })
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = InvalidKey;

    fn try_from(key_bytes: &[u8]) -> Result<Self, InvalidKey> {
        Self::new_from_slice(key_bytes)
    }
}

/// X-Wing decapsulation key or private key.
#[derive(Clone)]
pub struct DecapsulationKey {
    sk: [u8; DECAPSULATION_KEY_SIZE],
    ek: EncapsulationKey,
}

impl DecapsulationKey {
    /// Private key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; DECAPSULATION_KEY_SIZE] {
        &self.sk
    }
}

impl AsRef<EncapsulationKey> for DecapsulationKey {
    fn as_ref(&self) -> &EncapsulationKey {
        &self.ek
    }
}

impl Decapsulate<XWingKem> for DecapsulationKey {
    #[allow(clippy::similar_names)] // So we can use the names as in the RFC
    fn decapsulate(&self, ct: &Ciphertext) -> SharedKey {
        let ct = CiphertextMessage::from(ct);
        let (sk_m, sk_x, _pk_m, pk_x) = expand_key(&self.sk);

        let ss_m = sk_m.decapsulate(&ct.ct_m);

        // equal to ss_x = x25519(sk_x, ct_x)
        let ss_x = sk_x.diffie_hellman(&ct.ct_x);

        combiner(&ss_m, &ss_x, &ct.ct_x, &pk_x)
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.sk.zeroize();
    }
}

impl From<[u8; DECAPSULATION_KEY_SIZE]> for DecapsulationKey {
    fn from(sk: [u8; DECAPSULATION_KEY_SIZE]) -> Self {
        DecapsulationKey::new(sk.as_array_ref())
    }
}

impl Generate for DecapsulationKey {
    fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as TryRng>::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        <[u8; DECAPSULATION_KEY_SIZE]>::try_generate_from_rng(rng).map(Into::into)
    }
}

impl KeySizeUser for DecapsulationKey {
    type KeySize = U32;
}

impl KeyInit for DecapsulationKey {
    fn new(key: &Key<Self>) -> Self {
        let (_sk_m, _sk_x, pk_m, pk_x) = expand_key(key.as_ref());
        let ek = EncapsulationKey { pk_m, pk_x };
        Self { sk: key.0, ek }
    }
}

impl KeyExport for DecapsulationKey {
    fn to_bytes(&self) -> Key<Self> {
        self.sk.into()
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for DecapsulationKey {}

fn expand_key(
    sk: &[u8; DECAPSULATION_KEY_SIZE],
) -> (
    MlKem768DecapsulationKey,
    StaticSecret,
    MlKem768EncapsulationKey,
    PublicKey,
) {
    use sha3::digest::Update;
    let mut shaker = Shake256::default();
    shaker.update(sk);
    let mut expanded: Shake256Reader = shaker.finalize_xof();

    let seed = read_from(&mut expanded).into();
    let (sk_m, pk_m) = MlKem768::from_seed(&seed);

    let sk_x = read_from(&mut expanded);
    let sk_x = StaticSecret::from(sk_x);
    let pk_x = PublicKey::from(&sk_x);

    (sk_m, sk_x, pk_m, pk_x)
}

/// X-Wing ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct CiphertextMessage {
    ct_m: ArrayN<u8, 1088>,
    ct_x: PublicKey,
}

impl CiphertextMessage {
    /// Convert the ciphertext to the following format:
    /// ML-KEM-768 ciphertext(1088 bytes) || X25519 ciphertext(32 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Ciphertext {
        let mut buffer = Ciphertext::default();
        buffer[0..1088].copy_from_slice(&self.ct_m);
        buffer[1088..].copy_from_slice(self.ct_x.as_bytes());
        buffer
    }
}

impl From<&Ciphertext> for CiphertextMessage {
    fn from(value: &Ciphertext) -> Self {
        let mut ct_m = [0; 1088];
        ct_m.copy_from_slice(&value[0..1088]);
        let mut ct_x = [0; 32];
        ct_x.copy_from_slice(&value[1088..]);

        CiphertextMessage {
            ct_m: ct_m.into(),
            ct_x: ct_x.into(),
        }
    }
}

impl From<&CiphertextMessage> for Ciphertext {
    #[inline]
    fn from(msg: &CiphertextMessage) -> Self {
        msg.to_bytes()
    }
}

impl From<CiphertextMessage> for Ciphertext {
    #[inline]
    fn from(msg: CiphertextMessage) -> Self {
        Self::from(&msg)
    }
}

fn combiner(
    ss_m: &ArrayN<u8, 32>,
    ss_x: &x25519_dalek::SharedSecret,
    ct_x: &PublicKey,
    pk_x: &PublicKey,
) -> SharedKey {
    use sha3::Digest;

    let mut hasher = Sha3_256::new();
    hasher.update(ss_m);
    hasher.update(ss_x);
    hasher.update(ct_x);
    hasher.update(pk_x.as_bytes());
    hasher.update(X_WING_LABEL);
    hasher.finalize()
}

fn read_from<const N: usize>(reader: &mut Shake256Reader) -> [u8; N] {
    let mut data = [0; N];
    reader.read(&mut data);
    data
}

#[cfg(test)]
mod tests {
    use crate::{Kem, XWingKem};
    use core::convert::Infallible;
    use getrandom::SysRng;
    use ml_kem::array::Array;
    use rand_core::{TryCryptoRng, TryRng, UnwrapErr, utils};
    use serde::Deserialize;

    use super::*;

    pub(crate) struct SeedRng {
        pub(crate) seed: Vec<u8>,
    }

    impl SeedRng {
        fn new(seed: Vec<u8>) -> SeedRng {
            SeedRng { seed }
        }
    }

    impl TryRng for SeedRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            utils::next_word_via_fill(self)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            utils::next_word_via_fill(self)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
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

    impl TryCryptoRng for SeedRng {}

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
        let (sk, pk) = XWingKem::generate_keypair_from_rng(&mut seed);

        assert_eq!(sk.as_bytes(), &test_vector.sk);
        assert_eq!(&*pk.to_bytes(), test_vector.pk.as_slice());

        let mut eseed = SeedRng::new(test_vector.eseed);
        let (ct, ss) = pk.encapsulate_with_rng(&mut eseed);

        assert_eq!(ss, test_vector.ss);
        assert_eq!(&*ct, test_vector.ct.as_slice());

        let ss = sk.decapsulate(&ct);
        assert_eq!(ss, test_vector.ss);
    }

    #[test]
    fn ciphertext_serialize() {
        let mut rng = UnwrapErr(SysRng);

        let ct_a = CiphertextMessage {
            ct_m: Array::generate_from_rng(&mut rng),
            ct_x: <[u8; 32]>::generate_from_rng(&mut rng).into(),
        };

        let bytes = ct_a.to_bytes();
        let ct_b = CiphertextMessage::from(&bytes);

        assert!(ct_a == ct_b);
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn key_serialize() {
        let (sk, pk) = XWingKem::generate_keypair();

        let sk_bytes = sk.as_bytes();
        let pk_bytes = pk.to_bytes();

        let sk_b = DecapsulationKey::from(*sk_bytes);
        let pk_b = EncapsulationKey::new(&pk_bytes).unwrap();

        assert_eq!(sk.sk, sk_b.sk);
        assert!(pk == pk_b);
    }
}
