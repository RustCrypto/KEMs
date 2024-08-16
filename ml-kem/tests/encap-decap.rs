#![cfg(feature = "deterministic")]

use ml_kem::*;

use ::kem::Decapsulate;
use hybrid_array::Array;
use std::{fs::read_to_string, path::PathBuf};

#[test]
fn acvp_encap_decap() {
    // Load the JSON test file
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/encap-decap.json");
    let tv_json = read_to_string(p.as_path()).unwrap();

    // Parse the test vectors
    let tv: acvp::TestVectorFile = serde_json::from_str(&tv_json).unwrap();

    // Verify the test vectors
    for tg in tv.test_groups {
        match tg {
            acvp::TestGroup::Encapsulation(tg) => verify_encap_group(&tg),
            acvp::TestGroup::Decapsulation(tg) => verify_decap_group(&tg),
        }
    }
}

fn verify_encap_group(tg: &acvp::EncapTestGroup) {
    for tc in tg.tests.iter() {
        match tg.parameter_set {
            acvp::ParameterSet::MlKem512 => verify_encap::<MlKem512>(tc),
            acvp::ParameterSet::MlKem768 => verify_encap::<MlKem768>(tc),
            acvp::ParameterSet::MlKem1024 => verify_encap::<MlKem1024>(tc),
        }
    }
}

fn verify_encap<K: KemCore>(tc: &acvp::EncapTestCase) {
    let m = Array::try_from(tc.m.as_slice()).unwrap();
    let ek_bytes = Encoded::<K::EncapsulationKey>::try_from(tc.ek.as_slice()).unwrap();
    let ek = K::EncapsulationKey::from_bytes(&ek_bytes);

    let (c, k) = ek.encapsulate_deterministic(&m).unwrap();

    assert_eq!(k.as_slice(), tc.k.as_slice());
    assert_eq!(c.as_slice(), tc.c.as_slice());
}

fn verify_decap_group(tg: &acvp::DecapTestGroup) {
    for tc in tg.tests.iter() {
        match tg.parameter_set {
            acvp::ParameterSet::MlKem512 => verify_decap::<MlKem512>(tc, &tg.dk),
            acvp::ParameterSet::MlKem768 => verify_decap::<MlKem768>(tc, &tg.dk),
            acvp::ParameterSet::MlKem1024 => verify_decap::<MlKem1024>(tc, &tg.dk),
        }
    }
}

fn verify_decap<K: KemCore>(tc: &acvp::DecapTestCase, dk_slice: &[u8]) {
    let dk_bytes = Encoded::<K::DecapsulationKey>::try_from(dk_slice).unwrap();
    let dk = K::DecapsulationKey::from_bytes(&dk_bytes);

    let c = Ciphertext::<K>::try_from(tc.c.as_slice()).unwrap();
    let k = dk.decapsulate(&c).unwrap();
    assert_eq!(k.as_slice(), tc.k.as_slice());
}

mod acvp {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct TestVectorFile {
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<TestGroup>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(tag = "function")]
    pub enum TestGroup {
        #[serde(rename = "encapsulation")]
        Encapsulation(EncapTestGroup),

        #[serde(rename = "decapsulation")]
        Decapsulation(DecapTestGroup),
    }

    #[derive(Deserialize, Serialize)]
    pub struct EncapTestGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        pub tests: Vec<EncapTestCase>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct DecapTestGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        #[serde(with = "hex::serde")]
        pub dk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub ek: Vec<u8>,

        pub tests: Vec<DecapTestCase>,
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
    pub struct EncapTestCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(with = "hex::serde")]
        pub ek: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub dk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub c: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub k: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub m: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct DecapTestCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        #[serde(with = "hex::serde")]
        pub c: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub k: Vec<u8>,
    }
}
