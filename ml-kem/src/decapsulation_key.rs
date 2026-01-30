use crate::{
    B32, EncapsulationKey, Encoded, EncodedSizeUser, ExpandedDecapsulationKey, Seed, SharedKey,
    crypto::{G, J},
    kem::{Generate, InvalidKey, Kem, KeyInit, KeySizeUser},
    param::{DecapsulationKeySize, KemParams},
    pke::{DecryptionKey, EncryptionKey},
};
use array::sizes::{U32, U64};
use kem::{Ciphertext, Decapsulate};
use rand_core::{TryCryptoRng, TryRng};
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
        let dk_pke = DecryptionKey::from_bytes(dk_pke);
        let ek_pke = EncryptionKey::from_bytes(ek_pke)?;

        let ek = EncapsulationKey::from_encryption_key(ek_pke);
        if ek.h() != *h {
            return Err(InvalidKey);
        }

        Ok(Self {
            dk_pke,
            ek,
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
        let (Kp, rp) = G(&[&mp, &self.ek.h()]);
        let Kbar = J(&[self.z.as_slice(), encapsulated_key.as_ref()]);
        let cp = self.ek.ek_pke().encrypt(&mp, &rp);
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
        P::concat_dk(dk_pke, ek, self.ek.h(), self.z.clone())
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
