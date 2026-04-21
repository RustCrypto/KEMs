//! Implementation of the [`kem`](kem_traits) crate traits for HQC-KEM.

use crate::params::HqcParams;
use crate::sizes;
use crate::types::{DecapsulationKey, EncapsulationKey};
use hybrid_array::Array;

macro_rules! impl_hqc_kem {
    ($params:ty, $pk_size:ty, $ct_size:ty) => {
        // -- Kem on the parameter marker type --
        impl kem_traits::Kem for $params {
            type DecapsulationKey = DecapsulationKey<$params>;
            type EncapsulationKey = EncapsulationKey<$params>;
            type SharedKeySize = typenum::consts::U32;
            type CiphertextSize = $ct_size;

            fn generate_keypair_from_rng<R: rand::CryptoRng>(
                rng: &mut R,
            ) -> (
                kem_traits::DecapsulationKey<Self>,
                kem_traits::EncapsulationKey<Self>,
            ) {
                let (pk, sk) = crate::kem::keygen(<$params>::params(), rng);
                let ek = EncapsulationKey::<$params>::from_vec(pk);
                let dk = DecapsulationKey::<$params>::from_vec(sk);
                (dk, ek)
            }
        }

        // -- EncapsulationKey: KeySizeUser --
        impl kem_traits::common::KeySizeUser for EncapsulationKey<$params> {
            type KeySize = $pk_size;
        }

        // -- EncapsulationKey: TryKeyInit --
        impl kem_traits::common::TryKeyInit for EncapsulationKey<$params> {
            fn new(key: &kem_traits::Key<Self>) -> Result<Self, kem_traits::InvalidKey> {
                let bytes = key.as_slice();
                if bytes.len() != <$params>::PK_BYTES {
                    return Err(kem_traits::InvalidKey);
                }
                Ok(EncapsulationKey::<$params>::from_vec(bytes.to_vec()))
            }
        }

        // -- EncapsulationKey: KeyExport --
        impl kem_traits::common::KeyExport for EncapsulationKey<$params> {
            fn to_bytes(&self) -> kem_traits::Key<Self> {
                let mut arr = Array::<u8, $pk_size>::default();
                arr.as_mut_slice().copy_from_slice(self.as_ref());
                arr
            }
        }

        // -- EncapsulationKey: Encapsulate --
        impl kem_traits::Encapsulate for EncapsulationKey<$params> {
            type Kem = $params;

            fn encapsulate_with_rng<R>(
                &self,
                rng: &mut R,
            ) -> (
                kem_traits::Ciphertext<Self::Kem>,
                kem_traits::SharedKey<Self::Kem>,
            )
            where
                R: rand::CryptoRng + ?Sized,
            {
                let (ss_vec, ct_vec) = crate::kem::encaps(self.as_ref(), <$params>::params(), rng);

                let mut ct = Array::<u8, $ct_size>::default();
                ct.as_mut_slice().copy_from_slice(&ct_vec);

                let mut ss = Array::<u8, typenum::consts::U32>::default();
                ss.as_mut_slice().copy_from_slice(&ss_vec);

                (ct, ss)
            }
        }

        // -- DecapsulationKey: KeySizeUser (seed = 32 bytes) --
        impl kem_traits::common::KeySizeUser for DecapsulationKey<$params> {
            type KeySize = typenum::consts::U32;
        }

        // -- DecapsulationKey: KeyInit (from 32-byte seed) --
        impl kem_traits::common::KeyInit for DecapsulationKey<$params> {
            fn new(seed: &kem_traits::Key<Self>) -> Self {
                let seed_arr: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .expect("seed is exactly 32 bytes");
                let (pk, sk) = crate::kem::keygen_deterministic(&seed_arr, <$params>::params());
                let _ = pk; // pk is embedded in sk
                DecapsulationKey::<$params>::from_vec(sk)
            }
        }

        // -- DecapsulationKey: KeyExport (returns 32-byte seed) --
        impl kem_traits::common::KeyExport for DecapsulationKey<$params> {
            fn to_bytes(&self) -> kem_traits::Key<Self> {
                let sk = self.as_ref();
                let seed_start = sk.len() - crate::params::SEED_BYTES;
                let mut arr = Array::<u8, typenum::consts::U32>::default();
                arr.as_mut_slice().copy_from_slice(&sk[seed_start..]);
                arr
            }
        }

        // -- DecapsulationKey: Generate --
        impl kem_traits::common::Generate for DecapsulationKey<$params> {
            fn try_generate_from_rng<R>(rng: &mut R) -> Result<Self, <R as rand::TryRng>::Error>
            where
                R: rand::TryCryptoRng + ?Sized,
            {
                let mut seed = [0u8; 32];
                rng.try_fill_bytes(&mut seed)?;
                let seed_arr = Array::<u8, typenum::consts::U32>::from(seed);
                Ok(<Self as kem_traits::common::KeyInit>::new(&seed_arr))
            }
        }

        // -- DecapsulationKey: Decapsulator --
        impl kem_traits::Decapsulator for DecapsulationKey<$params> {
            type Kem = $params;

            fn encapsulation_key(&self) -> &kem_traits::EncapsulationKey<Self::Kem> {
                self.encapsulation_key()
            }
        }

        // -- DecapsulationKey: Decapsulate --
        impl kem_traits::Decapsulate for DecapsulationKey<$params> {
            fn decapsulate(
                &self,
                ct: &kem_traits::Ciphertext<Self::Kem>,
            ) -> kem_traits::SharedKey<Self::Kem> {
                let ss_vec = crate::kem::decaps(self.as_ref(), ct.as_slice(), <$params>::params());
                let mut ss = Array::<u8, typenum::consts::U32>::default();
                ss.as_mut_slice().copy_from_slice(&ss_vec);
                ss
            }
        }
    };
}

impl_hqc_kem!(crate::params::Hqc128Params, sizes::U2241, sizes::U4433);
impl_hqc_kem!(crate::params::Hqc192Params, sizes::U4514, sizes::U8978);
impl_hqc_kem!(crate::params::Hqc256Params, sizes::U7237, sizes::U14421);

#[cfg(test)]
mod tests {
    use super::*;
    use kem_traits::common::{Generate, KeyExport, KeyInit};
    use kem_traits::{Decapsulate, Encapsulate, Kem};

    macro_rules! kem_roundtrip_test {
        ($name:ident, $params:ty) => {
            #[test]
            fn $name() {
                // Generate via kem trait
                let mut rng = rand::rng();
                let (dk, ek) = <$params>::generate_keypair_from_rng(&mut rng);

                // Encapsulate
                let (ct, ss1) = ek.encapsulate_with_rng(&mut rng);

                // Decapsulate (use UFCS to call trait method, not inherent)
                let ss2 = <_ as Decapsulate>::decapsulate(&dk, &ct);
                assert_eq!(ss1, ss2);

                // Verify Decapsulator returns the right EK
                let ek_ref = kem_traits::Decapsulator::encapsulation_key(&dk);
                assert_eq!(&ek, ek_ref);
            }
        };
    }

    kem_roundtrip_test!(kem_roundtrip_128, crate::params::Hqc128Params);
    kem_roundtrip_test!(kem_roundtrip_192, crate::params::Hqc192Params);
    kem_roundtrip_test!(kem_roundtrip_256, crate::params::Hqc256Params);

    macro_rules! from_seed_test {
        ($name:ident, $params:ty) => {
            #[test]
            fn $name() {
                // Generate DK, export seed, re-import, verify deterministic
                let dk = DecapsulationKey::<$params>::generate_from_rng(&mut rand::rng());
                let seed = dk.to_bytes();
                let dk2 = DecapsulationKey::<$params>::new(&seed);

                // Both should produce the same EK
                let ek1 = kem_traits::Decapsulator::encapsulation_key(&dk);
                let ek2 = kem_traits::Decapsulator::encapsulation_key(&dk2);
                assert_eq!(ek1, ek2);

                // Both should produce the same shared secret
                let mut rng = rand::rng();
                let (ct, ss1) = ek1.encapsulate_with_rng(&mut rng);
                let ss2 = <_ as Decapsulate>::decapsulate(&dk2, &ct);
                assert_eq!(ss1, ss2);
            }
        };
    }

    from_seed_test!(from_seed_128, crate::params::Hqc128Params);
    from_seed_test!(from_seed_192, crate::params::Hqc192Params);
    from_seed_test!(from_seed_256, crate::params::Hqc256Params);
}
