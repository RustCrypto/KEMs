#![cfg(feature = "deterministic")]

use ml_kem::*;

use hybrid_array::Array;
use std::{fs::read_to_string, path::PathBuf};

#[test]
fn acvp_key_gen() {
    // Load the JSON test file
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/key-gen.json");
    let tv_json = read_to_string(p.as_path()).unwrap();

    // Parse the test vectors
    let tv: acvp::TestVectorFile = serde_json::from_str(&tv_json).unwrap();

    // Verify the test vectors
    for tg in tv.test_groups {
        for tc in tg.tests {
            match tg.parameter_set {
                acvp::ParameterSet::MlKem512 => verify::<MlKem512>(&tc),
                acvp::ParameterSet::MlKem768 => verify::<MlKem768>(&tc),
                acvp::ParameterSet::MlKem1024 => verify::<MlKem1024>(&tc),
            }
        }
    }
}

fn verify<K: KemCore>(tc: &acvp::TestCase) {
    // Import test data into the relevant array structures
    let d = Array::try_from(tc.d.as_slice()).unwrap();
    let z = Array::try_from(tc.z.as_slice()).unwrap();
    let dk_bytes = Encoded::<K::DecapsulationKey>::try_from(tc.dk.as_slice()).unwrap();
    let ek_bytes = Encoded::<K::EncapsulationKey>::try_from(tc.ek.as_slice()).unwrap();

    let (dk, ek) = K::generate_deterministic(&d, &z);

    // Verify correctness via serialization
    assert_eq!(dk.as_bytes().as_slice(), tc.dk.as_slice());
    assert_eq!(ek.as_bytes().as_slice(), tc.ek.as_slice());

    // Verify correctness via deserialization
    assert_eq!(dk, K::DecapsulationKey::from_bytes(&dk_bytes));
    assert_eq!(ek, K::EncapsulationKey::from_bytes(&ek_bytes));
}

mod acvp {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct TestVectorFile {
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<TestGroup>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        pub tests: Vec<TestCase>,
    }

    #[derive(Deserialize, Serialize)]
    pub enum ParameterSet {
        #[serde(rename = "ML-KEM-512")]
        MlKem512,

        #[serde(rename = "ML-KEM-768")]
        MlKem768,

        #[serde(rename = "ML-KEM-1024")]
        MlKem1024,
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(with = "hex::serde")]
        pub z: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub d: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub ek: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub dk: Vec<u8>,
    }
}
