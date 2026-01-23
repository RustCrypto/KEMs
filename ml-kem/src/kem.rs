//!

// Re-export traits from the `kem` crate
pub use ::kem::{Decapsulate, Encapsulate, Generate, KeyExport, KeySizeUser, TryKeyInit};

use crate::{
    Encoded, EncodedSizeUser, Error, Seed,
    crypto::{G, H, J},
    param::{
        DecapsulationKeySize, EncapsulationKeySize, EncodedCiphertext, ExpandedDecapsulationKey,
        KemParams,
    },
    pke::{DecryptionKey, EncryptionKey},
    util::B32,
};
use core::{convert::Infallible, marker::PhantomData};
use hybrid_array::typenum::{U32, U64};
use rand_core::{CryptoRng, TryCryptoRng, TryRngCore};
use subtle::{ConditionallySelectable, ConstantTimeEq};

// TODO(tarcieri): get these from `kem`
use common::{InvalidKey, Key, KeyInit};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A shared key resulting from an ML-KEM transaction
pub(crate) type SharedKey = B32;

/// A `DecapsulationKey` provides the ability to generate a new key pair, and decapsulate an
/// encapsulated shared key.
#[derive(Clone, Debug)]
pub struct DecapsulationKey<P>
where
    P: KemParams,
{
    dk_pke: DecryptionKey<P>,
    ek: EncapsulationKey<P>,
    d: Option<B32>,
    z: B32,
}

// Handwritten to omit `d` in the comparisons, so keys initialized from seeds compare equally to
// keys initialized from the expanded form
impl<P> PartialEq for DecapsulationKey<P>
where
    P: KemParams,
{
    fn eq(&self, other: &Self) -> bool {
        self.dk_pke.ct_eq(&other.dk_pke).into() && self.ek.eq(&other.ek) && self.z.eq(&other.z)
    }
}

#[cfg(feature = "zeroize")]
impl<P> Drop for DecapsulationKey<P>
where
    P: KemParams,
{
    fn drop(&mut self) {
        self.dk_pke.zeroize();
        self.z.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<P> ZeroizeOnDrop for DecapsulationKey<P> where P: KemParams {}

impl<P> From<Seed> for DecapsulationKey<P>
where
    P: KemParams,
{
    fn from(seed: Seed) -> Self {
        Self::from_seed(seed)
    }
}

impl<P> EncodedSizeUser for DecapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = DecapsulationKeySize<P>;

    fn from_encoded_bytes(expanded: &Encoded<Self>) -> Result<Self, Error> {
        #[allow(deprecated)]
        Self::from_expanded(expanded)
    }

    fn to_encoded_bytes(&self) -> Encoded<Self> {
        let dk_pke = self.dk_pke.to_bytes();
        let ek = self.ek.to_encoded_bytes();
        P::concat_dk(dk_pke, ek, self.ek.h.clone(), self.z.clone())
    }
}

impl<P> Generate for DecapsulationKey<P>
where
    P: KemParams,
{
    fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as TryRngCore>::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        Self::try_generate_from_rng(rng)
    }
}

impl<P> KeySizeUser for DecapsulationKey<P>
where
    P: KemParams,
{
    type KeySize = U64;
}

impl<P> KeyInit for DecapsulationKey<P>
where
    P: KemParams,
{
    #[inline]
    fn new(seed: &Seed) -> Self {
        Self::from_seed(*seed)
    }
}

impl<P> Decapsulate<EncodedCiphertext<P>, SharedKey> for DecapsulationKey<P>
where
    P: KemParams,
{
    type Encapsulator = EncapsulationKey<P>;
    type Error = Infallible;

    fn decapsulate(
        &self,
        encapsulated_key: &EncodedCiphertext<P>,
    ) -> Result<SharedKey, Self::Error> {
        let mp = self.dk_pke.decrypt(encapsulated_key);
        let (Kp, rp) = G(&[&mp, &self.ek.h]);
        let Kbar = J(&[self.z.as_slice(), encapsulated_key.as_ref()]);
        let cp = self.ek.ek_pke.encrypt(&mp, &rp);
        Ok(B32::conditional_select(
            &Kbar,
            &Kp,
            cp.ct_eq(encapsulated_key),
        ))
    }

    fn encapsulator(&self) -> EncapsulationKey<P> {
        self.ek.clone()
    }
}

impl<P> DecapsulationKey<P>
where
    P: KemParams,
{
    /// Create a [`DecapsulationKey`] instance from a 64-byte random seed value.
    #[inline]
    #[must_use]
    pub fn from_seed(seed: Seed) -> Self {
        let (d, z) = seed.split();
        Self::generate_deterministic(d, z)
    }

    /// Initialize a [`DecapsulationKey`] from the serialized expanded key form.
    ///
    /// Note that this form is deprecated in practice; prefer to use
    /// [`DecapsulationKey::from_seed`].
    ///
    /// # Errors
    /// - Returns [`Error`] in the event the expanded key failed validation
    #[deprecated(since = "0.3.0", note = "use `DecapsulationKey::from_seed` instead")]
    pub fn from_expanded(enc: &ExpandedDecapsulationKey<P>) -> Result<Self, Error> {
        let (dk_pke, ek_pke, h, z) = P::split_dk(enc);
        let ek_pke = EncryptionKey::from_bytes(ek_pke)?;

        // XXX(RLB): The encoding here is redundant, since `h` can be computed from `ek_pke`.
        // Should we verify that the provided `h` value is valid?

        Ok(Self {
            dk_pke: DecryptionKey::from_bytes(dk_pke),
            ek: EncapsulationKey {
                ek_pke,
                h: h.clone(),
            },
            d: None,
            z: z.clone(),
        })
    }

    /// Serialize the [`Seed`] value: 64-bytes which can be used to reconstruct the
    /// [`DecapsulationKey`].
    ///
    /// # ⚠️Warning!
    ///
    /// This value is key material. Please treat it with care.
    ///
    /// # Returns
    /// - `Some` if the [`DecapsulationKey`] was initialized using `from_seed` or `generate`.
    /// - `None` if the [`DecapsulationKey`] was initialized from the expanded form.
    #[inline]
    pub fn to_seed(&self) -> Option<Seed> {
        self.d.map(|d| d.concat(self.z))
    }

    /// Get the [`EncapsulationKey`] which corresponds to this [`DecapsulationKey`].
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }

    #[inline]
    pub(crate) fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as TryRngCore>::Error>
    where
        R: TryCryptoRng + ?Sized,
    {
        let d = B32::try_generate_from_rng(rng)?;
        let z = B32::try_generate_from_rng(rng)?;
        Ok(Self::generate_deterministic(d, z))
    }

    #[inline]
    #[must_use]
    #[allow(clippy::similar_names)] // allow dk_pke, ek_pke, following the spec
    pub(crate) fn generate_deterministic(d: B32, z: B32) -> Self {
        let (dk_pke, ek_pke) = DecryptionKey::generate(&d);
        let ek = EncapsulationKey::new(ek_pke);
        let d = Some(d);
        Self { dk_pke, ek, d, z }
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
    pub(crate) fn new(ek_pke: EncryptionKey<P>) -> Self {
        let h = H(ek_pke.to_bytes());
        Self { ek_pke, h }
    }

    fn encapsulate_deterministic_inner(&self, m: &B32) -> (EncodedCiphertext<P>, SharedKey) {
        let (K, r) = G(&[m, &self.h]);
        let c = self.ek_pke.encrypt(m, &r);
        (c, K)
    }
}

impl<P> EncodedSizeUser for EncapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = EncapsulationKeySize<P>;

    fn from_encoded_bytes(enc: &Encoded<Self>) -> Result<Self, Error> {
        Ok(Self::new(EncryptionKey::from_bytes(enc)?))
    }

    fn to_encoded_bytes(&self) -> Encoded<Self> {
        self.ek_pke.to_bytes()
    }
}

impl<P> KeySizeUser for EncapsulationKey<P>
where
    P: KemParams,
{
    type KeySize = EncapsulationKeySize<P>;
}

impl<P> TryKeyInit for EncapsulationKey<P>
where
    P: KemParams,
{
    fn new(encapsulation_key: &Key<Self>) -> Result<Self, InvalidKey> {
        EncryptionKey::from_bytes(encapsulation_key)
            .map(Self::new)
            .map_err(|_| InvalidKey)
    }
}

impl<P> KeyExport for EncapsulationKey<P>
where
    P: KemParams,
{
    fn to_bytes(&self) -> Key<Self> {
        self.ek_pke.to_bytes()
    }
}

impl<P> Encapsulate<EncodedCiphertext<P>, SharedKey> for EncapsulationKey<P>
where
    P: KemParams,
{
    type Error = Error;

    fn encapsulate_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Result<(EncodedCiphertext<P>, SharedKey), Self::Error> {
        let m = B32::try_generate_from_rng(rng).map_err(|_| Error)?;
        Ok(self.encapsulate_deterministic_inner(&m))
    }
}

#[cfg(feature = "deterministic")]
impl<P> crate::EncapsulateDeterministic<EncodedCiphertext<P>, SharedKey> for EncapsulationKey<P>
where
    P: KemParams,
{
    type Error = Infallible;

    fn encapsulate_deterministic(
        &self,
        m: &B32,
    ) -> Result<(EncodedCiphertext<P>, SharedKey), Self::Error> {
        Ok(self.encapsulate_deterministic_inner(m))
    }
}

/// An implementation of overall ML-KEM functionality.  Generic over parameter sets, but then ties
/// together all of the other related types and sizes.
#[derive(Clone)]
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
    fn generate<R: CryptoRng + ?Sized>(
        rng: &mut R,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::generate_from_rng(rng);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }

    fn from_seed(seed: Seed) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        let dk = Self::DecapsulationKey::from_seed(seed);
        let ek = dk.encapsulation_key().clone();
        (dk, ek)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MlKem512Params, MlKem768Params, MlKem1024Params};
    use ::kem::{Decapsulate, Encapsulate, Generate};
    use getrandom::SysRng;
    use rand_core::TryRngCore;

    fn round_trip_test<P>()
    where
        P: KemParams,
    {
        let mut rng = SysRng.unwrap_err();

        let dk = DecapsulationKey::<P>::generate_from_rng(&mut rng);
        let ek = dk.encapsulation_key();

        let (ct, k_send) = ek.encapsulate_with_rng(&mut rng).unwrap();
        let k_recv = dk.decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn round_trip() {
        round_trip_test::<MlKem512Params>();
        round_trip_test::<MlKem768Params>();
        round_trip_test::<MlKem1024Params>();
    }

    fn expanded_key_test<P>()
    where
        P: KemParams,
    {
        let mut rng = SysRng.unwrap_err();
        let dk_original = DecapsulationKey::<P>::generate_from_rng(&mut rng);
        let ek_original = dk_original.encapsulation_key().clone();

        let dk_encoded = dk_original.to_encoded_bytes();
        let dk_decoded = DecapsulationKey::from_encoded_bytes(&dk_encoded).unwrap();
        assert_eq!(dk_original, dk_decoded);

        let ek_encoded = ek_original.to_encoded_bytes();
        let ek_decoded = EncapsulationKey::from_encoded_bytes(&ek_encoded).unwrap();
        assert_eq!(ek_original, ek_decoded);
    }

    #[test]
    fn expanded_key() {
        expanded_key_test::<MlKem512Params>();
        expanded_key_test::<MlKem768Params>();
        expanded_key_test::<MlKem1024Params>();
    }

    fn seed_test<P>()
    where
        P: KemParams,
    {
        let mut rng = SysRng.unwrap_err();
        let mut seed = Seed::default();
        rng.try_fill_bytes(&mut seed).unwrap();

        let dk = DecapsulationKey::<P>::from_seed(seed.clone());
        let seed_encoded = dk.to_seed().unwrap();
        assert_eq!(seed, seed_encoded);
    }

    #[test]
    fn seed() {
        seed_test::<MlKem512Params>();
        seed_test::<MlKem768Params>();
        seed_test::<MlKem1024Params>();
    }
}
