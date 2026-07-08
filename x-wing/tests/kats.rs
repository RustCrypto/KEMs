//! X-Wing Known Answer Tests (KATs): test vectors

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng, utils};
use serde::Deserialize;
use x_wing::{Decapsulate, Encapsulate, Kem, KeyExport, XWingKem};

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
