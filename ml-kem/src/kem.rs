//! Key encapsulation mechanism implementation.

// Re-export traits from the `kem` crate
pub use ::kem::{
    Ciphertext, Decapsulate, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeyInit,
    KeySizeUser, TryKeyInit,
};

use crate::{
    B32, Encoded, EncodedSizeUser, Seed, SharedKey,
    crypto::{G, H, J},
    param::{DecapsulationKeySize, EncapsulationKeySize, ExpandedDecapsulationKey, KemParams},
    pke::{DecryptionKey, EncryptionKey},
};
use array::sizes::{U32, U64};
use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use sha3::Digest;
use subtle::{ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

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
        self.d.zeroize();
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

impl<P> Decapsulate<P> for DecapsulationKey<P>
where
    P: Kem<EncapsulationKey = EncapsulationKey<P>, SharedKeySize = U32> + KemParams,
{
    fn decapsulate(&self, encapsulated_key: &Ciphertext<P>) -> SharedKey {
        let mp = self.dk_pke.decrypt(encapsulated_key);
        let (Kp, rp) = G(&[&mp, &self.ek.h]);
        let Kbar = J(&[self.z.as_slice(), encapsulated_key.as_ref()]);
        let cp = self.ek.ek_pke.encrypt(&mp, &rp);
        B32::conditional_select(&Kbar, &Kp, cp.ct_eq(encapsulated_key))
    }
}

impl<P> AsRef<EncapsulationKey<P>> for DecapsulationKey<P>
where
    P: KemParams,
{
    fn as_ref(&self) -> &EncapsulationKey<P> {
        &self.ek
    }
}

impl<P> EncodedSizeUser for DecapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = DecapsulationKeySize<P>;

    fn from_encoded_bytes(expanded: &Encoded<Self>) -> Result<Self, InvalidKey> {
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
    fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as TryRng>::Error>
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
    /// - Returns [`InvalidKey`] in the event the expanded key failed validation
    #[deprecated(since = "0.3.0", note = "use `DecapsulationKey::from_seed` instead")]
    pub fn from_expanded(enc: &ExpandedDecapsulationKey<P>) -> Result<Self, InvalidKey> {
        let (dk_pke, ek_pke, h, z) = P::split_dk(enc);
        let ek_pke = EncryptionKey::from_bytes(ek_pke)?;

        let test = sha3::Sha3_256::digest(ek_pke.to_bytes());
        if test.as_slice() != h.as_slice() {
            return Err(InvalidKey);
        }

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
    /// <div class="warning">
    /// <b>Warning!</B>
    ///
    /// This value is key material. Please treat it with care.
    /// </div>
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
    pub(crate) fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as TryRng>::Error>
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
        let ek = EncapsulationKey::from_encryption_key(ek_pke);
        let d = Some(d);
        Self { dk_pke, ek, d, z }
    }
}

/// An `EncapsulationKey` provides the ability to encapsulate a shared key so that it can only be
/// decapsulated by the holder of the corresponding decapsulation key.
#[derive(Clone, Debug)]
pub struct EncapsulationKey<P>
where
    P: KemParams,
{
    ek_pke: EncryptionKey<P>,
    h: B32,
}

impl<P> EncapsulationKey<P>
where
    P: Kem<SharedKeySize = U32> + KemParams,
{
    pub(crate) fn from_encryption_key(ek_pke: EncryptionKey<P>) -> Self {
        let h = H(ek_pke.to_bytes());
        Self { ek_pke, h }
    }

    /// Encapsulates with the given randomness. This is useful for testing against known vectors.
    ///
    /// # Warning
    /// Do NOT use this function unless you know what you're doing. If you fail to use all uniform
    /// random bytes even once, you can have catastrophic security failure.
    #[cfg_attr(not(feature = "hazmat"), doc(hidden))]
    pub fn encapsulate_deterministic(&self, m: &B32) -> (Ciphertext<P>, SharedKey) {
        let (K, r) = G(&[m, &self.h]);
        let c = self.ek_pke.encrypt(m, &r);
        (c, K)
    }
}

impl<P> Encapsulate<P> for EncapsulationKey<P>
where
    P: Kem + KemParams,
{
    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<P>, SharedKey)
    where
        R: CryptoRng + ?Sized,
    {
        let m = B32::generate_from_rng(rng);
        self.encapsulate_deterministic(&m)
    }
}

impl<P> EncodedSizeUser for EncapsulationKey<P>
where
    P: KemParams,
{
    type EncodedSize = EncapsulationKeySize<P>;

    fn from_encoded_bytes(enc: &Encoded<Self>) -> Result<Self, InvalidKey> {
        Ok(Self::from_encryption_key(EncryptionKey::from_bytes(enc)?))
    }

    fn to_encoded_bytes(&self) -> Encoded<Self> {
        self.ek_pke.to_bytes()
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
            .map(Self::from_encryption_key)
            .map_err(|_| InvalidKey)
    }
}

impl<P> Eq for EncapsulationKey<P> where P: KemParams {}
impl<P> PartialEq for EncapsulationKey<P>
where
    P: KemParams,
{
    fn eq(&self, other: &Self) -> bool {
        // Handwritten to avoid derive putting `Eq` bounds on `KemParams`
        self.ek_pke == other.ek_pke && self.h == other.h
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MlKem512, MlKem768, MlKem1024};
    use ::kem::{Encapsulate, Generate, TryDecapsulate};
    use array::typenum::Unsigned;
    use getrandom::SysRng;
    use rand_core::UnwrapErr;

    fn round_trip_test<P>()
    where
        P: Kem,
    {
        let mut rng = UnwrapErr(SysRng);

        let dk = P::DecapsulationKey::generate_from_rng(&mut rng);
        let ek = dk.as_ref().clone();

        let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);
        let k_recv = dk.try_decapsulate(&ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn round_trip() {
        round_trip_test::<MlKem512>();
        round_trip_test::<MlKem768>();
        round_trip_test::<MlKem1024>();
    }

    fn expanded_key_test<P>()
    where
        P: KemParams,
    {
        let mut rng = UnwrapErr(SysRng);
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
        expanded_key_test::<MlKem512>();
        expanded_key_test::<MlKem768>();
        expanded_key_test::<MlKem1024>();
    }

    fn invalid_hash_expanded_key_test<P>()
    where
        P: KemParams,
    {
        let mut rng = UnwrapErr(SysRng);
        let dk_original = DecapsulationKey::<P>::generate_from_rng(&mut rng);

        let mut dk_encoded = dk_original.to_encoded_bytes();
        // Corrupt the hash value
        let hash_offset = P::NttVectorSize::USIZE + P::EncryptionKeySize::USIZE;
        dk_encoded[hash_offset] ^= 0xFF;

        let dk_decoded: Result<DecapsulationKey<P>, InvalidKey> =
            DecapsulationKey::from_encoded_bytes(&dk_encoded);
        assert!(dk_decoded.is_err());
    }

    #[test]
    fn invalid_hash_expanded_key() {
        invalid_hash_expanded_key_test::<MlKem512>();
        invalid_hash_expanded_key_test::<MlKem768>();
        invalid_hash_expanded_key_test::<MlKem1024>();
    }

    fn seed_test<P>()
    where
        P: KemParams,
    {
        let mut rng = UnwrapErr(SysRng);
        let mut seed = Seed::default();
        rng.try_fill_bytes(&mut seed).unwrap();

        let dk = DecapsulationKey::<P>::from_seed(seed.clone());
        let seed_encoded = dk.to_seed().unwrap();
        assert_eq!(seed, seed_encoded);
    }

    #[test]
    fn seed() {
        seed_test::<MlKem512>();
        seed_test::<MlKem768>();
        seed_test::<MlKem1024>();
    }

    fn key_inequality_test<P>()
    where
        P: KemParams,
    {
        let mut rng = UnwrapErr(SysRng);

        // Generate two different keys
        let dk1 = DecapsulationKey::<P>::generate_from_rng(&mut rng);
        let dk2 = DecapsulationKey::<P>::generate_from_rng(&mut rng);

        let ek1 = dk1.encapsulation_key();
        let ek2 = dk2.encapsulation_key();

        // Verify inequality (catches PartialEq mutation that returns true unconditionally)
        assert_ne!(dk1, dk2);
        assert_ne!(ek1, ek2);
    }

    #[test]
    fn key_inequality() {
        key_inequality_test::<MlKem512>();
        key_inequality_test::<MlKem768>();
        key_inequality_test::<MlKem1024>();
    }
}
