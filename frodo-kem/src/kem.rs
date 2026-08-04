//! Implementations of the traits from the [`kem`] crate.

use crate::hazmat;
use alloc::vec;
use hybrid_array::{Array, ArraySize};
use kem::{
    Ciphertext, Decapsulate, Decapsulator, Generate, InvalidKey, Key, KeyExport, KeySizeUser,
    SharedKey, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use zeroize::Zeroizing;

fn array_from_slice<U: ArraySize>(bytes: &[u8]) -> Array<u8, U> {
    let mut array = Array::default();
    array.copy_from_slice(bytes);
    array
}

#[cfg(feature = "efrodo640aes")]
pub use hazmat::EphemeralFrodoKem640Aes;
#[cfg(feature = "efrodo640shake")]
pub use hazmat::EphemeralFrodoKem640Shake;
#[cfg(feature = "efrodo976aes")]
pub use hazmat::EphemeralFrodoKem976Aes;
#[cfg(feature = "efrodo976shake")]
pub use hazmat::EphemeralFrodoKem976Shake;
#[cfg(feature = "efrodo1344aes")]
pub use hazmat::EphemeralFrodoKem1344Aes;
#[cfg(feature = "efrodo1344shake")]
pub use hazmat::EphemeralFrodoKem1344Shake;
#[cfg(feature = "frodo640aes")]
pub use hazmat::FrodoKem640Aes;
#[cfg(feature = "frodo640shake")]
pub use hazmat::FrodoKem640Shake;
#[cfg(feature = "frodo976aes")]
pub use hazmat::FrodoKem976Aes;
#[cfg(feature = "frodo976shake")]
pub use hazmat::FrodoKem976Shake;
#[cfg(feature = "frodo1344aes")]
pub use hazmat::FrodoKem1344Aes;
#[cfg(feature = "frodo1344shake")]
pub use hazmat::FrodoKem1344Shake;

/// A typed FrodoKEM encapsulation (public) key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncapsulationKey<K: KemSizes>(hazmat::EncryptionKey<K>);

/// A typed FrodoKEM decapsulation (secret) key.
pub struct DecapsulationKey<K: KemSizes> {
    key: hazmat::DecryptionKey<K>,
    encapsulation_key: EncapsulationKey<K>,
}

impl<K: KemSizes> core::fmt::Debug for DecapsulationKey<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &core::any::type_name::<K>())
            .finish_non_exhaustive()
    }
}

/// Compile-time sizes used by the [`kem`] trait implementations.
#[doc(hidden)]
pub trait KemSizes:
    hazmat::Kem + Copy + Clone + core::fmt::Debug + Eq + Ord + Send + Sync + 'static
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

impl<K: KemSizes> KeySizeUser for EncapsulationKey<K> {
    type KeySize = K::EncapsulationKeySize;
}

impl<K: KemSizes> TryKeyInit for EncapsulationKey<K> {
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        hazmat::EncryptionKey::from_slice(key)
            .map(Self)
            .map_err(|_| InvalidKey)
    }
}

impl<K: KemSizes> KeyExport for EncapsulationKey<K> {
    fn to_bytes(&self) -> Key<Self> {
        array_from_slice(self.0.as_ref())
    }
}

impl<K: KemSizes> KeySizeUser for DecapsulationKey<K> {
    type KeySize = K::DecapsulationKeySize;
}

impl<K: KemSizes> TryKeyInit for DecapsulationKey<K> {
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        let key = hazmat::DecryptionKey::from_slice(key).map_err(|_| InvalidKey)?;
        let encapsulation_key = EncapsulationKey((&key).into());
        Ok(Self {
            key,
            encapsulation_key,
        })
    }
}

impl<K: KemSizes> KeyExport for DecapsulationKey<K> {
    fn to_bytes(&self) -> Key<Self> {
        array_from_slice(self.key.as_ref())
    }
}

impl<K: KemSizes> Generate for DecapsulationKey<K> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut seed = Zeroizing::new(vec![0; K::KEY_SEED_SIZE]);
        rng.try_fill_bytes(&mut seed)?;
        let (ek, dk) = K::default().generate_keypair_from_seed(&mut seed);
        Ok(Self {
            key: dk,
            encapsulation_key: EncapsulationKey(ek),
        })
    }
}

impl<K> Decapsulator for DecapsulationKey<K>
where
    K: KemSizes + kem::Kem<EncapsulationKey = EncapsulationKey<K>>,
{
    type Kem = K;

    fn encapsulation_key(&self) -> &EncapsulationKey<K> {
        &self.encapsulation_key
    }
}

impl<K> Decapsulate for DecapsulationKey<K>
where
    K: KemSizes + kem::Kem<EncapsulationKey = EncapsulationKey<K>>,
{
    fn decapsulate(&self, ct: &Ciphertext<K>) -> SharedKey<K> {
        let ct = hazmat::CiphertextRef::from_validated_slice(ct);
        let shared_key = K::default().decapsulate_shared_secret(&self.key, ct);
        array_from_slice(shared_key.as_ref())
    }
}

impl<K> kem::Encapsulate for EncapsulationKey<K>
where
    K: KemSizes + kem::Kem,
{
    type Kem = K;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<K>, SharedKey<K>)
    where
        R: CryptoRng + ?Sized,
    {
        let (ct, shared_key) = K::default().encapsulate_with_rng(&self.0, rng);
        (
            array_from_slice(ct.as_ref()),
            array_from_slice(shared_key.as_ref()),
        )
    }
}

macro_rules! impl_kem {
    ($feature:literal, $kem:ty, $ek:ty, $dk:ty, $ct:ty, $ss:ty) => {
        #[cfg(feature = $feature)]
        impl KemSizes for $kem {
            type EncapsulationKeySize = $ek;
            type DecapsulationKeySize = $dk;
            type CiphertextSize = $ct;
            type SharedKeySize = $ss;
        }

        #[cfg(feature = $feature)]
        impl kem::Kem for $kem {
            type DecapsulationKey = DecapsulationKey<Self>;
            type EncapsulationKey = EncapsulationKey<Self>;
            type SharedKeySize = $ss;
            type CiphertextSize = $ct;
        }
    };
}

impl_kem!(
    "frodo640aes",
    FrodoKem640Aes,
    hybrid_array::sizes::U9616,
    hybrid_array::sizes::U19888,
    hybrid_array::sizes::U9752,
    hybrid_array::sizes::U16
);
impl_kem!(
    "frodo640shake",
    FrodoKem640Shake,
    hybrid_array::sizes::U9616,
    hybrid_array::sizes::U19888,
    hybrid_array::sizes::U9752,
    hybrid_array::sizes::U16
);
impl_kem!(
    "frodo976aes",
    FrodoKem976Aes,
    hybrid_array::sizes::U15632,
    hybrid_array::sizes::U31296,
    hybrid_array::sizes::U15792,
    hybrid_array::sizes::U24
);
impl_kem!(
    "frodo976shake",
    FrodoKem976Shake,
    hybrid_array::sizes::U15632,
    hybrid_array::sizes::U31296,
    hybrid_array::sizes::U15792,
    hybrid_array::sizes::U24
);
impl_kem!(
    "frodo1344aes",
    FrodoKem1344Aes,
    hybrid_array::sizes::U21520,
    hybrid_array::sizes::U43088,
    hybrid_array::sizes::U21696,
    hybrid_array::sizes::U32
);
impl_kem!(
    "frodo1344shake",
    FrodoKem1344Shake,
    hybrid_array::sizes::U21520,
    hybrid_array::sizes::U43088,
    hybrid_array::sizes::U21696,
    hybrid_array::sizes::U32
);
impl_kem!(
    "efrodo640aes",
    EphemeralFrodoKem640Aes,
    hybrid_array::sizes::U9616,
    hybrid_array::sizes::U19888,
    hybrid_array::sizes::U9720,
    hybrid_array::sizes::U16
);
impl_kem!(
    "efrodo640shake",
    EphemeralFrodoKem640Shake,
    hybrid_array::sizes::U9616,
    hybrid_array::sizes::U19888,
    hybrid_array::sizes::U9720,
    hybrid_array::sizes::U16
);
impl_kem!(
    "efrodo976aes",
    EphemeralFrodoKem976Aes,
    hybrid_array::sizes::U15632,
    hybrid_array::sizes::U31296,
    hybrid_array::sizes::U15744,
    hybrid_array::sizes::U24
);
impl_kem!(
    "efrodo976shake",
    EphemeralFrodoKem976Shake,
    hybrid_array::sizes::U15632,
    hybrid_array::sizes::U31296,
    hybrid_array::sizes::U15744,
    hybrid_array::sizes::U24
);
impl_kem!(
    "efrodo1344aes",
    EphemeralFrodoKem1344Aes,
    hybrid_array::sizes::U21520,
    hybrid_array::sizes::U43088,
    hybrid_array::sizes::U21632,
    hybrid_array::sizes::U32
);
impl_kem!(
    "efrodo1344shake",
    EphemeralFrodoKem1344Shake,
    hybrid_array::sizes::U21520,
    hybrid_array::sizes::U43088,
    hybrid_array::sizes::U21632,
    hybrid_array::sizes::U32
);

#[cfg(all(test, feature = "frodo640shake"))]
mod tests {
    use super::*;
    use kem::{Encapsulate, Kem, KeyExport, TryKeyInit};
    use rand_core::SeedableRng;

    #[test]
    fn kem_traits_round_trip() {
        type K = FrodoKem640Shake;

        let mut rng = chacha20::ChaCha8Rng::from_seed([42; 32]);
        let (dk, ek) = K::generate_keypair_from_rng(&mut rng);
        let debug = format!("{dk:?}");
        assert!(!debug.contains(&hex::encode(dk.key.as_ref())));
        let dk = DecapsulationKey::<K>::new(&dk.to_bytes()).expect("decapsulation key imports");
        let ek = EncapsulationKey::<K>::new(&ek.to_bytes()).expect("encapsulation key imports");
        let (ct, sent) = ek.encapsulate_with_rng(&mut rng);
        let received = dk.decapsulate(&ct);

        assert_eq!(sent, received);
    }

    #[cfg(feature = "efrodo640shake")]
    #[test]
    fn ephemeral_kem_traits_round_trip() {
        type K = EphemeralFrodoKem640Shake;

        let mut rng = chacha20::ChaCha8Rng::from_seed([24; 32]);
        let (dk, ek) = K::generate_keypair_from_rng(&mut rng);
        let (ct, sent) = ek.encapsulate_with_rng(&mut rng);
        let received = dk.decapsulate(&ct);

        assert_eq!(sent, received);
    }
}
