//! Hybrid KEM Known Answer Tests (KATs)

use core::convert::Infallible;
use hybrid_kem::{Encapsulate, Kem, KeyExport, MlKem768P256, MlKem1024P384, TryDecapsulate};
use rand_core::{TryCryptoRng, TryRng, utils};
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVector {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    seed: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    randomness: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    encapsulation_key: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    decapsulation_key: [u8; 32],

    #[serde(deserialize_with = "hex::serde::deserialize")]
    #[expect(unused)]
    decapsulation_key_pq: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    #[expect(unused)]
    decapsulation_key_t: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    ciphertext: Vec<u8>,

    #[serde(deserialize_with = "hex::serde::deserialize")]
    shared_secret: [u8; 32],
}

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

impl TryCryptoRng for SeedRng {}

/// Test with test vectors from: <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html#name-mlkem768-p256-2>
#[test]
fn mlkem768_p256_test_vectors() {
    let test_vectors =
        serde_json::from_str::<Vec<TestVector>>(include_str!("mlkem768-p256.json")).unwrap();

    for test_vector in test_vectors {
        run_test::<MlKem768P256>(test_vector);
    }
}

/// Test with test vectors from: <https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html#name-mlkem1024-p384-2>
#[test]
fn mlkem1024_p384_test_vectors() {
    let test_vectors =
        serde_json::from_str::<Vec<TestVector>>(include_str!("mlkem1024-p384.json")).unwrap();

    for test_vector in test_vectors {
        run_test::<MlKem1024P384>(test_vector);
    }
}

fn run_test<T>(test_vector: TestVector)
where
    T: Kem,
    <T as Kem>::DecapsulationKey: KeyExport,
{
    let mut seed = SeedRng::new(test_vector.seed);
    let (decapsulation_key, encapsulation_key) = T::generate_keypair_from_rng(&mut seed);

    assert_eq!(
        &*decapsulation_key.to_bytes(),
        test_vector.decapsulation_key
    );
    assert_eq!(
        &*encapsulation_key.to_bytes(),
        test_vector.encapsulation_key
    );

    let mut randomness = SeedRng::new(test_vector.randomness);
    let (ciphertext, shared_secret) = encapsulation_key.encapsulate_with_rng(&mut randomness);

    assert_eq!(&*shared_secret, test_vector.shared_secret);
    assert_eq!(&*ciphertext, test_vector.ciphertext);

    let shared_secret = decapsulation_key
        .try_decapsulate(&ciphertext)
        .expect("Decapsulation error");
    assert_eq!(&*shared_secret, test_vector.shared_secret);
}
