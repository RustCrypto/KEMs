/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: MIT OR Apache-2.0
*/
//! Implementations of the traits from the [`kem`] crate.
//!
//! These wrap the [`crate::EncapsulationKey`] / [`crate::DecapsulationKey`] pair in the
//! fixed-size array types the `kem` traits use, so Streamlined NTRU Prime can be dropped into
//! generic code alongside other KEMs. The traits are re-exported here, so no direct dependency
//! on the `kem` crate is needed.
//!
//! # Example
//!
//! ```
//! use sntrup_kem::kem::{Decapsulate, Encapsulate, Kem, Sntrup761Params};
//! use rand::SeedableRng;
//! use rand::rngs::{StdRng, SysRng};
//!
//! // A cryptographically secure generator, seeded once from the operating system.
//! let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
//!
//! let (dk, ek) = Sntrup761Params::generate_keypair_from_rng(&mut rng);
//! let (ct, sent) = ek.encapsulate_with_rng(&mut rng);
//! let received = dk.decapsulate(&ct);
//!
//! assert_eq!(sent, received);
//! ```

use hybrid_array::{Array, ArraySize};
/// The [`kem`] crate's traits, re-exported so that callers need not depend on a
/// version-matched copy of that crate themselves.
pub use kem::{
    Ciphertext, Decapsulate, Decapsulator, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport,
    KeySizeUser, SharedKey, TryDecapsulate, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use zeroize::Zeroizing;

/// The parameter-set marker types, re-exported so callers can name them from this module.
pub use crate::{
    Sntrup653Params, Sntrup761Params, Sntrup857Params, Sntrup953Params, Sntrup1013Params,
    Sntrup1277Params,
};

fn array_from_slice<U: ArraySize>(bytes: &[u8]) -> Array<u8, U> {
    let mut array = Array::default();
    array.copy_from_slice(bytes);
    array
}

/// Compile-time sizes used by the [`kem`] trait implementations.
///
/// Generic code over these traits names key types as `EncapsulationKey<K>` and
/// `DecapsulationKey<K>`, both of which require `K` to implement this trait, so it is part
/// of the public vocabulary even though every implementation lives in this crate.
pub trait KemSizes:
    crate::SntrupParams + Copy + Clone + core::fmt::Debug + Eq + Ord + Send + Sync + 'static
{
    /// Encapsulation key size.
    type EncapsulationKeySize: ArraySize;
    /// Decapsulation key size.
    type DecapsulationKeySize: ArraySize;
    /// Ciphertext size.
    type CiphertextSize: ArraySize;
    /// Shared key size.
    type SharedKeySize: ArraySize;
}

/// A Streamlined NTRU Prime encapsulation key for use with the [`kem`] traits.
#[derive(Clone)]
pub struct EncapsulationKey<P: KemSizes>(crate::EncapsulationKey<P>);

/// A Streamlined NTRU Prime decapsulation key for use with the [`kem`] traits.
///
/// The encapsulation key is kept alongside the private key because [`Decapsulator`] exposes
/// it. Unlike some KEMs, recovering it from the private key alone is cheap here — it is a
/// slice out of the embedded public key, not a recomputation — but caching it avoids an
/// allocation on every call.
pub struct DecapsulationKey<P: KemSizes> {
    key: crate::DecapsulationKey<P>,
    encapsulation_key: EncapsulationKey<P>,
}

impl<P: KemSizes> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<P: KemSizes> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<P: KemSizes> Eq for EncapsulationKey<P> {}

impl<P: KemSizes> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &P::NAME)
            .finish_non_exhaustive()
    }
}

impl<P: KemSizes> KeySizeUser for EncapsulationKey<P> {
    type KeySize = P::EncapsulationKeySize;
}

impl<P: KemSizes> TryKeyInit for EncapsulationKey<P> {
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        crate::EncapsulationKey::<P>::try_from(key.as_slice())
            .map(Self)
            .map_err(|_| InvalidKey)
    }
}

impl<P: KemSizes> KeyExport for EncapsulationKey<P> {
    fn to_bytes(&self) -> Key<Self> {
        array_from_slice(self.0.as_ref())
    }
}

impl<P: KemSizes> KeySizeUser for DecapsulationKey<P> {
    type KeySize = P::DecapsulationKeySize;
}

impl<P: KemSizes> TryKeyInit for DecapsulationKey<P> {
    /// Import a private key. Unlike KEMs that must rerun key generation to recover the
    /// matching public key, the public key here is embedded in the private key's byte layout,
    /// so recovering it is a slice, not a recomputation.
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        let key = crate::DecapsulationKey::<P>::try_from(key.as_slice()).map_err(|_| InvalidKey)?;
        let encapsulation_key = EncapsulationKey(key.encapsulation_key());
        Ok(Self {
            key,
            encapsulation_key,
        })
    }
}

impl<P: KemSizes> KeyExport for DecapsulationKey<P> {
    fn to_bytes(&self) -> Key<Self> {
        array_from_slice(self.key.as_ref())
    }
}

impl<P: KemSizes> Generate for DecapsulationKey<P> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(seed.as_mut())?;
        let (ek, dk) = crate::SntrupKem::<P>::generate_key_deterministic(&seed);
        Ok(Self {
            key: dk,
            encapsulation_key: EncapsulationKey(ek),
        })
    }
}

impl<P> Decapsulator for DecapsulationKey<P>
where
    P: KemSizes + Kem<EncapsulationKey = EncapsulationKey<P>>,
{
    type Kem = P;

    fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.encapsulation_key
    }
}

impl<P> Decapsulate for DecapsulationKey<P>
where
    P: KemSizes + Kem<EncapsulationKey = EncapsulationKey<P>>,
{
    fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedKey<P> {
        let Ok(ct) = crate::Ciphertext::<P>::try_from(ct.as_slice()) else {
            return SharedKey::<P>::default();
        };
        array_from_slice(self.key.decapsulate(&ct).as_ref())
    }
}

impl<P> Encapsulate for EncapsulationKey<P>
where
    P: KemSizes + Kem,
{
    type Kem = P;

    fn encapsulate_with_rng<R>(&self, mut rng: &mut R) -> (Ciphertext<P>, SharedKey<P>)
    where
        R: CryptoRng + ?Sized,
    {
        // The reborrow lets an unsized `R` (permitted by this trait) satisfy the concrete
        // `impl rand::CryptoRng` bound on the underlying `encapsulate` method: `&mut R`
        // implements `CryptoRng` via rand_core's blanket impl regardless of whether `R` itself
        // is `Sized`, and a reference is always `Sized`.
        let (ct, ss) = self.0.encapsulate(&mut rng);
        (array_from_slice(ct.as_ref()), array_from_slice(ss.as_ref()))
    }
}

macro_rules! impl_kem {
    ($($params:ident, $ek:ident, $dk:ident, $ct:ident, $ss:ident;)+) => {
        $(
            impl KemSizes for $params {
                type EncapsulationKeySize = hybrid_array::sizes::$ek;
                type DecapsulationKeySize = hybrid_array::sizes::$dk;
                type CiphertextSize = hybrid_array::sizes::$ct;
                type SharedKeySize = hybrid_array::sizes::$ss;
            }

            impl Kem for $params {
                type DecapsulationKey = DecapsulationKey<Self>;
                type EncapsulationKey = EncapsulationKey<Self>;
                type SharedKeySize = hybrid_array::sizes::$ss;
                type CiphertextSize = hybrid_array::sizes::$ct;
            }
        )+
    };
}

impl_kem! {
    Sntrup653Params, U994, U1518, U897, U32;
    Sntrup761Params, U1158, U1763, U1039, U32;
    Sntrup857Params, U1322, U1999, U1184, U32;
    Sntrup953Params, U1505, U2254, U1349, U32;
    Sntrup1013Params, U1623, U2417, U1455, U32;
    Sntrup1277Params, U2067, U3059, U1847, U32;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn traits_round_trip<K>(seed: u8)
    where
        K: KemSizes
            + Kem<EncapsulationKey = EncapsulationKey<K>, DecapsulationKey = DecapsulationKey<K>>,
    {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([seed; 32]);
        let (dk, ek) = K::generate_keypair_from_rng(&mut rng);

        // The private key must not print its contents.
        assert!(!format!("{dk:?}").contains(&hex::encode(dk.key.as_ref())));

        let (ct, sent) = ek.encapsulate_with_rng(&mut rng);
        let received = dk.decapsulate(&ct);
        assert_eq!(sent, received);

        // Round tripping through the byte-array representation preserves both keys.
        let ek_bytes = ek.to_bytes();
        let imported = EncapsulationKey::<K>::new(&ek_bytes).unwrap();
        assert_eq!(imported, ek);
        assert_eq!(dk.encapsulation_key(), &ek);

        let dk_bytes = dk.to_bytes();
        let imported = DecapsulationKey::<K>::new(&dk_bytes).unwrap();
        assert_eq!(imported.decapsulate(&ct), sent);
        assert_eq!(imported.encapsulation_key(), &ek);
    }

    macro_rules! kem_trait_tests {
        ($($name:ident, $params:ident, $seed:expr;)+) => {
            $(
                #[test]
                fn $name() {
                    traits_round_trip::<$params>($seed);
                }
            )+
        };
    }

    // One per parameter set.
    kem_trait_tests! {
        round_trip_653, Sntrup653Params, 0x30;
        round_trip_761, Sntrup761Params, 0x31;
        round_trip_857, Sntrup857Params, 0x32;
        round_trip_953, Sntrup953Params, 0x33;
        round_trip_1013, Sntrup1013Params, 0x34;
        round_trip_1277, Sntrup1277Params, 0x35;
    }

    /// A ciphertext whose bytes are corrupted must not decapsulate to the original secret,
    /// and must still return *some* shared key rather than propagate an error observably —
    /// the `kem` crate's `Decapsulate` trait cannot report failure.
    #[test]
    fn corrupted_ciphertext_yields_a_different_key_without_panicking() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0x41; 32]);
        let (dk, ek) = Sntrup761Params::generate_keypair_from_rng(&mut rng);
        let (ct, sent) = ek.encapsulate_with_rng(&mut rng);

        let mut damaged = ct;
        let last = damaged.len() - 1;
        damaged[last] ^= 0xFF;
        assert_ne!(dk.decapsulate(&damaged), sent);
    }
}
