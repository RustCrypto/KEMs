#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]

//! # Usage
//!
//! This crate implements the Concrete Hybrid PQ/T Key Encapsulation Mechanisms (MLKEM768-P256,
//! MLKEM768-X25519 and MLKEM1024-P384) algorithm. They are KEMs in the sense that it creates an
//! (decapsulation key, encapsulation key) pair, such that anyone can use the encapsulation key to
//! establish a shared key with the holder of the decapsulation key.
//!
//! MLKEM768-P256 is a general-purpose hybrid post-quantum KEM, combining P256 and ML-KEM-768.
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! // NOTE: requires the `getrandom` feature is enabled
//! use hybrid_kem::{
//!     MlKem768P256,
//!     kem::{TryDecapsulate, Encapsulate, Kem}
//! };
//!
//! let (sk, pk) = MlKem768P256::generate_keypair();
//! let (ct, sk_sender) = pk.encapsulate();
//! let sk_receiver = sk.try_decapsulate(&ct).unwrap();
//! assert_eq!(sk_sender, sk_receiver);
//! ```
//!
//! MLKEM768-X25519 is a general-purpose hybrid post-quantum KEM, combining X25519 and ML-KEM-768.
#![cfg_attr(all(feature = "x-wing", feature = "getrandom"), doc = "```")]
#![cfg_attr(not(all(feature = "x-wing", feature = "getrandom")), doc = "```ignore")]
//! // NOTE: requires the `x-wing` and `getrandom` features are enabled
//! use hybrid_kem::{
//!     MlKem768X25519,
//!     kem::{Decapsulate, Encapsulate, Kem}
//! };
//!
//! let (sk, pk) = MlKem768X25519::generate_keypair();
//! let (ct, sk_sender) = pk.encapsulate();
//! let sk_receiver = sk.decapsulate(&ct);
//! assert_eq!(sk_sender, sk_receiver);
//! ```
//!
//! MLKEM1024-P384 is a general-purpose hybrid post-quantum KEM, combining P384 and ML-KEM-1024.
#![cfg_attr(feature = "getrandom", doc = "```")]
#![cfg_attr(not(feature = "getrandom"), doc = "```ignore")]
//! // NOTE: requires the `getrandom` feature is enabled
//! use hybrid_kem::{
//!     MlKem1024P384,
//!     kem::{TryDecapsulate, Encapsulate, Kem}
//! };
//!
//! let (sk, pk) = MlKem1024P384::generate_keypair();
//! let (ct, sk_sender) = pk.encapsulate();
//! let sk_receiver = sk.try_decapsulate(&ct).unwrap();
//! assert_eq!(sk_sender, sk_receiver);
//! ```

mod error;

pub use crate::error::{DecapsulationError, RejectionSamplingError};
use elliptic_curve::ecdh::SharedSecret;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{
    Curve, CurveArithmetic, PublicKey as GroupPublicKey, ScalarValue, SecretKey as GroupPrivateKey,
};
use kem::common::OutputSizeUser;
use kem::common::rand_core::{CryptoRng, TryCryptoRng};
pub use kem::{
    self, Ciphertext, Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey,
    Generate, InvalidKey, Kem, Key, KeyExport, KeyInit, KeySizeUser, SharedKey, TryDecapsulate,
    TryKeyInit,
};
use ml_kem::array::Array;
use ml_kem::array::sizes::{U32, U48, U128, U1153, U1249, U1665};
use ml_kem::array::typenum::Unsigned;
use ml_kem::{
    ArraySize, EncapsulationKey768 as MlKem768EncapsulationKey,
    EncapsulationKey1024 as MlKem1024EncapsulationKey, MlKem768, MlKem1024,
};
use p256::NistP256;
use p384::NistP384;
use sha3::{Digest, Sha3_256};
use shake::digest::{ExtendableOutput, XofReader};
use shake::{Shake256, Update};

#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// MLKEM768-P256 Key Encapsulation Mechanisms.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct MlKem768P256 {}
/// MLKEM768-P256 decapsulation key or private key.
pub type MlKem768P256DecapsulationKey = HybridKemDecapsulationKey<MlKem768P256>;
/// MLKEM768-P256 encapsulation key or public key.
pub type MlKem768P256EncapsulationKey = HybridKemEncapsulationKey<MlKem768P256>;

/// MLKEM768-X25519 Key Encapsulation Mechanisms.
#[cfg(feature = "x-wing")]
pub use x_wing::XWingKem as MlKem768X25519;
/// MLKEM768-X25519 decapsulation key or private key.
#[cfg(feature = "x-wing")]
pub type MlKem768X25519DecapsulationKey = x_wing::DecapsulationKey;
/// MLKEM768-X25519 encapsulation key or public key.
#[cfg(feature = "x-wing")]
pub type MlKem768X25519EncapsulationKey = x_wing::EncapsulationKey;

/// MLKEM1024-P384 Key Encapsulation Mechanisms.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct MlKem1024P384 {}
/// MLKEM1024-P384 decapsulation key or private key.
pub type MlKem1024P384DecapsulationKey = HybridKemDecapsulationKey<MlKem1024P384>;
/// MLKEM1024-P384 encapsulation key or public key.
pub type MlKem1024P384EncapsulationKey = HybridKemEncapsulationKey<MlKem1024P384>;

// Naming convention
// seed -> Random Seed
// ss   -> Shared Secret
// ct   -> Ciphertext
// ek   -> Encapsulation Key (Encapsulation Key for KEMs, Public Key for Nominal Groups)
// dk   -> Decapsulation Key (Decapsulation Key for KEMs, Secret Key for Nominal Groups)
// sk   -> Secret Key for Nominal Groups
// Postfixes:
// _PQ  -> Post-quantum
// _T   -> Traditional

/// KEM components and constant of the concrete hybrid KEM instances, as specified in Section 4 of
/// draft-irtf-cfrg-concrete-hybrid-kems-04.
pub trait HybridKemParameter
where
    <Self::GroupT as Curve>::FieldBytesSize: ModulusSize,
    <Self::GroupT as CurveArithmetic>::AffinePoint:
        FromSec1Point<Self::GroupT> + ToSec1Point<Self::GroupT>,
    <Self::KemPQ as Kem>::EncapsulationKey: EncapsulateDeterministic,
    <Self::KemPQ as Kem>::DecapsulationKey: Decapsulate + KeyInit,
{
    /// `Group_T` component
    type GroupT: Curve + CurveArithmetic + PointCompression + RandomScalar;
    /// `KEM_PQ` component
    type KemPQ: Kem;
    /// `PRG` component
    type PRG: Default + Update + ExtendableOutput;
    /// `KDF` component
    type KDF: Default + Digest;
    /// `Label` component
    const LABEL: &[u8];

    /// `Nseed` constant. The length of seed.
    type SeedSize: ArraySize;
    /// `Nek` constant. The length of encapsulation key.
    type EncapsulationKeySize: ArraySize;
    /// `Ndk` constant. The length of decapsulation key.
    type DecapsulationKeySize: ArraySize;
    /// `Nct` constant. The length of ciphertext key.
    type CiphertextSize: ArraySize;
    /// `Nss` constant. The length of shared secret key.
    type SharedSecretSize: ArraySize;

    // NOTE: The seed is directly used as the decapsulation key, so the seed length must be same as
    // the decapsulation key length. However, Rust compiler does not know it from this trait
    // definition. In this implementation, we directly use `DecapsulationKeySize` instead of
    // `SeedSize` for seed.
}

/// KEM components and constant of MLKEM768-P256, as specified in Section 4.1 of
/// draft-irtf-cfrg-concrete-hybrid-kems-04.
impl HybridKemParameter for MlKem768P256 {
    type GroupT = NistP256;
    type KemPQ = MlKem768;
    type PRG = Shake256;
    type KDF = Sha3_256;
    const LABEL: &[u8] = br"MLKEM768-P256";

    type SeedSize = U32;
    type EncapsulationKeySize = U1249;
    type DecapsulationKeySize = U32;
    type CiphertextSize = U1153;
    type SharedSecretSize = U32;
}

impl Kem for MlKem768P256 {
    type DecapsulationKey = HybridKemDecapsulationKey<Self>;
    type EncapsulationKey = HybridKemEncapsulationKey<Self>;
    type SharedKeySize = <Self as HybridKemParameter>::SharedSecretSize;
    type CiphertextSize = <Self as HybridKemParameter>::CiphertextSize;
}

/// KEM components and constant of MLKEM1024-P384, as specified in Section 4.3 of
/// draft-irtf-cfrg-concrete-hybrid-kems-04.
impl HybridKemParameter for MlKem1024P384 {
    type GroupT = NistP384;
    type KemPQ = MlKem1024;
    type PRG = Shake256;
    type KDF = Sha3_256;
    const LABEL: &[u8] = br"MLKEM1024-P384";

    type SeedSize = U32;
    type EncapsulationKeySize = U1665;
    type DecapsulationKeySize = U32;
    type CiphertextSize = U1665;
    type SharedSecretSize = U32;
}

impl Kem for MlKem1024P384 {
    type DecapsulationKey = HybridKemDecapsulationKey<Self>;
    type EncapsulationKey = HybridKemEncapsulationKey<Self>;
    type SharedKeySize = <Self as HybridKemParameter>::SharedSecretSize;
    type CiphertextSize = <Self as HybridKemParameter>::CiphertextSize;
}

/// A hybrid KEM encapsulation key whose the KEM components and constants are specified by
/// [`HybridKemParameter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridKemEncapsulationKey<H: HybridKemParameter> {
    ek_pq: <H::KemPQ as Kem>::EncapsulationKey,
    ek_t: GroupPublicKey<H::GroupT>,
}

impl<H: HybridKemParameter + Kem> HybridKemEncapsulationKey<H> {
    /// Encapsulates with the given randomness. Uses the first 32 bytes for ML-KEM and the remaining
    /// bytes for Group. This is useful for testing against known vectors.
    ///
    /// # Warning
    /// Do NOT use this function unless you know what you're doing. If you fail to use all uniform
    /// random bytes even once, you can have catastrophic security failure.
    #[doc(hidden)]
    #[cfg_attr(not(feature = "hazmat"), doc(hidden))]
    fn encapsulate_deterministic(
        &self,
        randomness_pq: &Array<
            u8,
            <<H::KemPQ as Kem>::EncapsulationKey as EncapsulateDeterministic>::SeedSize,
        >,
        randomness_t: &Array<u8, <H::GroupT as RandomScalar>::SeedSize>,
    ) -> (SharedKey<H>, Ciphertext<H>) {
        let ek_pq = &self.ek_pq;
        let ek_t = self.ek_t;

        let (ss_pq, ss_t, ct_pq, ct_t) =
            prepare_encaps_g::<H>(ek_pq, &ek_t, randomness_pq, randomness_t);

        let ss_h = c2pri_combiner::<H>(&ss_pq, &ss_t, &ct_t, &ek_t, H::LABEL);

        let mut ct_h = Array::default();
        let (ct_h_left, ct_h_right) = ct_h.split_at_mut(<H::KemPQ as Kem>::CiphertextSize::USIZE);
        ct_h_left.copy_from_slice(&ct_pq);
        ct_h_right.copy_from_slice(&ct_t.to_sec1_bytes());

        (
            Array::try_from(ss_h.as_slice())
                .expect("The length of shared secret must match the output length of KDF"),
            ct_h,
        )
    }
}

impl<H: HybridKemParameter + Kem> Encapsulate for HybridKemEncapsulationKey<H> {
    type Kem = H;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        let mut randomness_pq = Array::default();
        let mut randomness_t = Array::default();
        let _ = rng.try_fill_bytes(randomness_pq.as_mut_slice());
        let _ = rng.try_fill_bytes(randomness_t.as_mut_slice());
        let (ss, ct) = self.encapsulate_deterministic(&randomness_pq, &randomness_t);
        (ct, ss)
    }
}

impl<H: HybridKemParameter> KeyExport for HybridKemEncapsulationKey<H> {
    fn to_bytes(&self) -> Key<Self> {
        // The encapsulation key of hybrid KEM is the concatenation of the encapsulation key of
        // post-quantum component and the encapsulation key of traditional component.
        let mut bytes = Key::<Self>::default();
        let (bytes_pq, bytes_t) =
            bytes.split_at_mut(<H::KemPQ as Kem>::EncapsulationKey::key_size());
        bytes_pq.copy_from_slice(&self.ek_pq.to_bytes());
        bytes_t.copy_from_slice(&self.ek_t.to_sec1_bytes());
        bytes
    }
}

impl<H: HybridKemParameter> TryKeyInit for HybridKemEncapsulationKey<H> {
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        // The encapsulation key of hybrid KEM is the concatenation of the encapsulation key of
        // post-quantum component and the encapsulation key of traditional component.
        let (bytes_pq, bytes_t) = key.split_at(<H::KemPQ as Kem>::EncapsulationKey::key_size());
        let ek_pq = <H::KemPQ as Kem>::EncapsulationKey::new_from_slice(bytes_pq)?;
        let ek_t = GroupPublicKey::<H::GroupT>::from_sec1_bytes(bytes_t).map_err(|_| InvalidKey)?;
        Ok(HybridKemEncapsulationKey { ek_pq, ek_t })
    }
}

impl<H: HybridKemParameter> KeySizeUser for HybridKemEncapsulationKey<H> {
    type KeySize = H::EncapsulationKeySize;
}

/// A hybrid KEM decapsulation key whose the KEM components and constants are specified by
/// [`HybridKemParameter`].
#[derive(Debug)]
pub struct HybridKemDecapsulationKey<H: HybridKemParameter + Kem> {
    seed: Array<u8, H::DecapsulationKeySize>,
    ek: <H as Kem>::EncapsulationKey,
}

impl<H: HybridKemParameter + Kem> HybridKemDecapsulationKey<H> {
    /// Private key as bytes.
    pub fn as_bytes(&self) -> &Array<u8, <H as HybridKemParameter>::DecapsulationKeySize> {
        &self.seed
    }
}

impl<H: HybridKemParameter + Kem> TryDecapsulate for HybridKemDecapsulationKey<H> {
    type Error = DecapsulationError;

    fn try_decapsulate(
        &self,
        ct: &Ciphertext<Self::Kem>,
    ) -> Result<SharedKey<Self::Kem>, Self::Error> {
        let (ct_pq, ct_t) = ct.split_at(<H::KemPQ as Kem>::CiphertextSize::USIZE);
        let ct_pq = Array::slice_as_array(ct_pq).ok_or(DecapsulationError)?;
        let ct_t = GroupPublicKey::from_sec1_bytes(ct_t).map_err(|_| DecapsulationError)?;

        let (_ek_pq, ek_t, dk_pq, dk_t) = expand_decaps_key_g::<H>(&self.seed);
        let (ss_pq, ss_t) = prepare_decaps_g::<H>(ct_pq, &ct_t, &dk_pq, &dk_t);

        let ss_h = c2pri_combiner::<H>(&ss_pq, &ss_t, &ct_t, &ek_t, H::LABEL);

        Array::try_from(ss_h.as_slice()).map_err(|_| DecapsulationError)
    }
}

impl<H: HybridKemParameter + Kem> Decapsulator for HybridKemDecapsulationKey<H> {
    type Kem = H;

    fn encapsulation_key(&self) -> &EncapsulationKey<Self::Kem> {
        &self.ek
    }
}

impl<H: HybridKemParameter + Kem> Generate for HybridKemDecapsulationKey<H> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let seed = Array::try_generate_from_rng(rng)?;
        Ok(HybridKemDecapsulationKey::new(&seed))
    }
}

impl<H: HybridKemParameter + Kem> KeyExport for HybridKemDecapsulationKey<H> {
    fn to_bytes(&self) -> Key<Self> {
        self.seed.clone()
    }
}

impl<H: HybridKemParameter + Kem> KeyInit for HybridKemDecapsulationKey<H> {
    fn new(seed: &Key<Self>) -> Self {
        let (ek_pq, ek_t, _dk_pq, _dk_t) = expand_decaps_key_g::<H>(seed);

        let mut concatenated_ek = Array::default();
        let (part_pq, part_t) =
            concatenated_ek.split_at_mut(<H::KemPQ as Kem>::EncapsulationKey::key_size());
        part_pq.copy_from_slice(&ek_pq.to_bytes());
        part_t.copy_from_slice(&ek_t.to_sec1_bytes());
        HybridKemDecapsulationKey {
            seed: seed.clone(),
            ek: <H as Kem>::EncapsulationKey::new(&concatenated_ek)
                .expect("Reconstructed valid encapsulation key should remain valid"),
        }
    }
}

impl<H: HybridKemParameter + Kem> KeySizeUser for HybridKemDecapsulationKey<H> {
    type KeySize = H::DecapsulationKeySize;
}

#[cfg(feature = "zeroize")]
impl<H: HybridKemParameter + Kem> ZeroizeOnDrop for HybridKemDecapsulationKey<H> {}

/// A trait for providing common interface to encapsulate with given randomness.
pub trait EncapsulateDeterministic: Encapsulate {
    /// Length of given randomness.
    type SeedSize: ArraySize;

    /// Encapsulates with the given randomness.
    fn encapsulate_deterministic(
        &self,
        seed: &Array<u8, Self::SeedSize>,
    ) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>);
}

impl EncapsulateDeterministic for MlKem768EncapsulationKey {
    type SeedSize = U32;

    fn encapsulate_deterministic(
        &self,
        seed: &Array<u8, Self::SeedSize>,
    ) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        self.encapsulate_deterministic(seed)
    }
}

impl EncapsulateDeterministic for MlKem1024EncapsulationKey {
    type SeedSize = U32;

    fn encapsulate_deterministic(
        &self,
        seed: &Array<u8, Self::SeedSize>,
    ) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>) {
        self.encapsulate_deterministic(seed)
    }
}

/// A trait for implementing the `RandomScalar` algorithm for nominal groups, as described in
/// Section 3.1.1 of draft-irtf-cfrg-concrete-hybrid-kems-04.
pub trait RandomScalar: Curve {
    /// Length of `seed`.
    type SeedSize: ArraySize;

    /// The `RandomScalar` algorithm in Section 3.1.1 of draft-irtf-cfrg-concrete-hybrid-kems-04.
    ///
    /// # Errors
    ///
    /// Will return `Err(RejectionSamplingError)` if the rejection sampling from a seed fails. It
    /// fails with cryptographically negligible probability, as long as the input seed is uniformly
    /// random.
    fn random_scalar(
        seed: &Array<u8, Self::SeedSize>,
    ) -> Result<GroupPrivateKey<Self>, RejectionSamplingError> {
        for chunk in seed.chunks_exact(Self::FieldBytesSize::USIZE) {
            if let Some(secret_key) = Array::try_from(chunk)
                .ok()
                .and_then(|bytes| ScalarValue::from_bytes(&bytes).into_option())
                .and_then(|scalar| GroupPrivateKey::from_scalar(scalar).into_option())
            {
                return Ok(secret_key);
            }
        }
        Err(RejectionSamplingError)
    }
}

impl RandomScalar for NistP256 {
    /// `Group_T.Nseed` for P-256
    type SeedSize = U128;
}

impl RandomScalar for NistP384 {
    /// `Group_T.Nseed` for P-384
    type SeedSize = U48;
}

/// The `expandDecapsKeyG` algorithm in Section 5.1.1 of draft-irtf-cfrg-hybrid-kems-12.
#[expect(clippy::type_complexity)]
fn expand_decaps_key_g<H: HybridKemParameter>(
    seed: &Array<u8, H::DecapsulationKeySize>,
) -> (
    <H::KemPQ as Kem>::EncapsulationKey,
    GroupPublicKey<H::GroupT>,
    <H::KemPQ as Kem>::DecapsulationKey,
    GroupPrivateKey<H::GroupT>,
) {
    let mut prg = H::PRG::default();
    prg.update(seed);
    let mut seed_full = prg.finalize_xof();

    let mut seed_pq = Array::default();
    let mut seed_t = Array::default();
    seed_full.read(&mut seed_pq);
    seed_full.read(&mut seed_t);

    let dk_pq = <H::KemPQ as Kem>::DecapsulationKey::new(&seed_pq);
    let ek_pq = dk_pq.encapsulation_key().clone();

    let dk_t = H::GroupT::random_scalar(&seed_t)
        .expect("RandomScalar fails with cryptographically negligible probability");
    let ek_t = dk_t.public_key();

    (ek_pq, ek_t, dk_pq, dk_t)
}

/// The `prepareEncapsG` algorithm in Section 5.1.1 of draft-irtf-cfrg-hybrid-kems-12.
#[expect(clippy::type_complexity)]
fn prepare_encaps_g<H: HybridKemParameter>(
    ek_pq: &<H::KemPQ as Kem>::EncapsulationKey,
    ek_t: &GroupPublicKey<H::GroupT>,
    randomness_pq: &Array<
        u8,
        <<H::KemPQ as Kem>::EncapsulationKey as EncapsulateDeterministic>::SeedSize,
    >,
    randomness_t: &Array<u8, <H::GroupT as RandomScalar>::SeedSize>,
) -> (
    Array<u8, <H::KemPQ as Kem>::SharedKeySize>,
    Array<u8, <H::GroupT as Curve>::FieldBytesSize>,
    Array<u8, <H::KemPQ as Kem>::CiphertextSize>,
    GroupPublicKey<H::GroupT>,
) {
    let (ct_pq, ss_pq) = ek_pq.encapsulate_deterministic(randomness_pq);

    let secret_key_e = H::GroupT::random_scalar(randomness_t)
        .expect("RandomScalar fails with cryptographically negligible probability");

    let ct_t = secret_key_e.public_key();
    let ss_t = element_to_shared_secret::<H>(secret_key_e.diffie_hellman(ek_t));

    (ss_pq, ss_t, ct_pq, ct_t)
}

/// The `prepareDecapsG` algorithm in Section 5.1.1 of draft-irtf-cfrg-hybrid-kems-12.
#[expect(clippy::type_complexity)]
fn prepare_decaps_g<H: HybridKemParameter>(
    ct_pq: &Array<u8, <H::KemPQ as Kem>::CiphertextSize>,
    ct_t: &GroupPublicKey<H::GroupT>,
    dk_pq: &<H::KemPQ as Kem>::DecapsulationKey,
    dk_t: &GroupPrivateKey<H::GroupT>,
) -> (
    Array<u8, <H::KemPQ as Kem>::SharedKeySize>,
    Array<u8, <H::GroupT as Curve>::FieldBytesSize>,
) {
    let ss_pq = dk_pq.decapsulate(ct_pq);
    let ss_t = element_to_shared_secret::<H>(dk_t.diffie_hellman(ct_t));
    (ss_pq, ss_t)
}

/// The `C2PRICombiner` algorithm in Section 5.1.3 of draft-irtf-cfrg-hybrid-kems-12.
fn c2pri_combiner<H: HybridKemParameter>(
    ss_pq: &SharedKey<H::KemPQ>,
    ss_t: &Array<u8, <H::GroupT as Curve>::FieldBytesSize>,
    ct_t: &GroupPublicKey<H::GroupT>,
    ek_t: &GroupPublicKey<H::GroupT>,
    label: &[u8],
) -> Array<u8, <H::KDF as OutputSizeUser>::OutputSize> {
    let mut hasher = H::KDF::default();
    hasher.update(ss_pq);
    hasher.update(ss_t);
    hasher.update(ct_t.to_sec1_bytes());
    hasher.update(ek_t.to_sec1_bytes());
    hasher.update(label);
    hasher.finalize()
}

/// The `ElementToSharedSecret` algorithm in Section 4.2 of draft-irtf-cfrg-hybrid-kems-12.
fn element_to_shared_secret<H: HybridKemParameter>(
    p: SharedSecret<H::GroupT>,
) -> Array<u8, <H::GroupT as Curve>::FieldBytesSize> {
    *p.raw_secret_bytes()
}
