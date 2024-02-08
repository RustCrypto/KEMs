use core::marker::PhantomData;
use crypto_common::rand_core::CryptoRngCore;
use typenum::U32;

use crate::crypto::{rand, G, H, J};
use crate::param::{DecapsulationKeySize, EncapsulationKeySize, EncodedCiphertext, KemParams};
use crate::pke::{DecryptionKey, EncryptionKey};
use crate::util::{FastClone, FunctionalArray, B32};
use crate::{Encoded, EncodedSizeUser};

/// A shared key resulting from an ML-KEM transaction
pub(crate) type SharedKey = B32;

/// A `DecapsulationKey` provides the ability to generate a new key pair, and decapsulate an
/// encapsulated shared key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecapsulationKey<P>
where
    P: KemParams,
{
    dk_pke: DecryptionKey<P>,
    ek: EncapsulationKey<P>,
    z: B32,
}

impl<P> EncodedSizeUser for DecapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = DecapsulationKeySize<P>;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let (dk_pke, ek_pke, h, z) = P::split_dk(enc);
        let ek_pke = EncryptionKey::from_bytes(ek_pke);

        // XXX(RLB): The encoding here is redundant, since `h` can be computed from `ek_pke`.
        // Should we verify that the provided `h` value is valid?

        Self {
            dk_pke: DecryptionKey::from_bytes(dk_pke),
            ek: EncapsulationKey {
                ek_pke,
                h: h.fast_clone(),
            },
            z: z.fast_clone(),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        let dk_pke = self.dk_pke.as_bytes();
        let ek = self.ek.as_bytes();
        P::concat_dk(dk_pke, ek, self.ek.h.fast_clone(), self.z.fast_clone())
    }
}

// 0xff if x == y, 0x00 otherwise
fn constant_time_eq(x: u8, y: u8) -> u8 {
    let diff = x ^ y;
    let is_zero = !diff & diff.wrapping_sub(1);
    0u8.wrapping_sub(is_zero >> 7)
}

impl<P> crate::DecapsulationKey<SharedKey, EncodedCiphertext<P>> for DecapsulationKey<P>
where
    P: KemParams,
{
    fn decapsulate(&self, ct: &EncodedCiphertext<P>) -> SharedKey {
        let mp = self.dk_pke.decrypt(ct);
        let (Kp, rp) = G(&[&mp, &self.ek.h]);
        let Kbar = J(&[self.z.as_slice(), ct.as_ref()]);
        let cp = self.ek.ek_pke.encrypt(&mp, &rp);

        // Constant-time version of:
        //
        // if cp == *ct {
        //     Kp
        // } else {
        //     Kbar
        // }
        let equal = cp
            .zip(ct, |&x, &y| constant_time_eq(x, y))
            .fold(|x, y| x & y);
        Kp.zip(&Kbar, |x, y| (equal & x) | (!equal & y))
    }
}

impl<P> DecapsulationKey<P>
where
    P: KemParams,
{
    pub(crate) fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let d: B32 = rand(rng);
        let z: B32 = rand(rng);
        Self::generate_deterministic(&d, &z)
    }

    pub(crate) fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }

    #[must_use]
    pub(crate) fn generate_deterministic(d: &B32, z: &B32) -> Self {
        let (dk_pke, ek_pke) = DecryptionKey::generate(d);
        let ek = EncapsulationKey::new(ek_pke);
        let z = z.fast_clone();
        Self { dk_pke, ek, z }
    }
}

/// An `EncapsulationKey` provides the ability to encapsulate a shared key so that it can only be
/// decapsulated by the holder of the corresponding decapsulation key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncapsulationKey<P>
where
    P: KemParams,
{
    ek_pke: EncryptionKey<P>,
    h: B32,
}

impl<P> EncapsulationKey<P>
where
    P: KemParams,
{
    fn new(ek_pke: EncryptionKey<P>) -> Self {
        let h = H(ek_pke.as_bytes());
        Self { ek_pke, h }
    }

    fn encapsulate_deterministic_inner(&self, m: &B32) -> (SharedKey, EncodedCiphertext<P>) {
        let (K, r) = G(&[m, &self.h]);
        let c = self.ek_pke.encrypt(m, &r);
        (K, c)
    }
}

impl<P> EncodedSizeUser for EncapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = EncapsulationKeySize<P>;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        Self::new(EncryptionKey::from_bytes(enc))
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.ek_pke.as_bytes()
    }
}

impl<P> crate::EncapsulationKey<SharedKey, EncodedCiphertext<P>> for EncapsulationKey<P>
where
    P: KemParams,
{
    fn encapsulate(&self, rng: &mut impl CryptoRngCore) -> (SharedKey, EncodedCiphertext<P>) {
        let m: B32 = rand(rng);
        self.encapsulate_deterministic_inner(&m)
    }

    #[cfg(feature = "deterministic")]
    fn encapsulate_deterministic(&self, m: &B32) -> (SharedKey, EncodedCiphertext<P>) {
        self.encapsulate_deterministic_inner(m)
    }
}

/// An implementation of overall ML-KEM functionality.  Generic over parameter sets, but then ties
/// together all of the other related types and sizes.
pub struct Kem<P>
where
    P: KemParams,
{
    _phantom: PhantomData<P>,
}

impl<P> crate::KemCore for Kem<P>
where
    P: KemParams,
{
    type SharedKeySize = U32;
    type CiphertextSize = P::CiphertextSize;
    type DecapsulationKey = DecapsulationKey<P>;
    type EncapsulationKey = EncapsulationKey<P>;

    /// Generate a new (decapsulation, encapsulation) key pair
    fn generate(rng: &mut impl CryptoRngCore) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::generate(rng);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }

    #[cfg(feature = "deterministic")]
    fn generate_deterministic(
        d: &B32,
        z: &B32,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::generate_deterministic(d, z);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DecapsulationKey as _;
    use crate::EncapsulationKey as _;
    use crate::{MlKem1024Params, MlKem512Params, MlKem768Params};

    fn round_trip_test<P>()
    where
        P: KemParams,
    {
        let mut rng = rand::thread_rng();

        let dk = DecapsulationKey::<P>::generate(&mut rng);
        let ek = dk.encapsulation_key();

        let (k_send, ct) = ek.encapsulate(&mut rng);
        let k_recv = dk.decapsulate(&ct);
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn round_trip() {
        round_trip_test::<MlKem512Params>();
        round_trip_test::<MlKem768Params>();
        round_trip_test::<MlKem1024Params>();
    }

    fn codec_test<P>()
    where
        P: KemParams,
    {
        let mut rng = rand::thread_rng();
        let dk_original = DecapsulationKey::<P>::generate(&mut rng);
        let ek_original = dk_original.encapsulation_key().clone();

        let dk_encoded = dk_original.as_bytes();
        let dk_decoded = DecapsulationKey::from_bytes(&dk_encoded);
        assert_eq!(dk_original, dk_decoded);

        let ek_encoded = ek_original.as_bytes();
        let ek_decoded = EncapsulationKey::from_bytes(&ek_encoded);
        assert_eq!(ek_original, ek_decoded);
    }

    #[test]
    fn codec() {
        codec_test::<MlKem512Params>();
        codec_test::<MlKem768Params>();
        codec_test::<MlKem1024Params>();
    }
}
