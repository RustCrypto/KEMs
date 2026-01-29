//! Test against the Wycheproof test vectors.

use ml_kem::{
    EncodedSizeUser, KemCore, MlKem512, MlKem768, MlKem1024,
    kem::{KeyExport, TryKeyInit},
};
use serde::Deserialize;
use std::fs::File;

#[derive(Deserialize, Debug)]
struct TestFile {
    algorithm: String,
    schema: String,
    #[serde(rename(deserialize = "testGroups"))]
    groups: Vec<TestGroup>,
}

#[derive(Deserialize, Debug)]
struct TestGroup {
    #[allow(dead_code)]
    #[serde(rename(deserialize = "type"))]
    type_: String,
    #[serde(default, rename(deserialize = "parameterSet"))]
    parameter_set: String,
    source: Source,
    tests: Vec<Test>,
}

#[derive(Deserialize, Debug)]
struct Source {
    name: String,
    version: String,
}

#[derive(Deserialize, Debug)]
struct Test {
    #[serde(rename(deserialize = "tcId"))]
    id: usize,
    comment: Option<String>,
    seed: Option<String>,
    #[serde(default, with = "hex::serde")]
    ek: Vec<u8>,
    dk: Option<String>,
    #[cfg(feature = "hazmat")]
    m: Option<String>,
    #[cfg(feature = "hazmat")]
    c: Option<String>,
    #[cfg(feature = "hazmat")]
    #[serde(default, rename(deserialize = "K"))]
    k: Option<String>,
    result: ExpectedResult,
}

#[derive(Copy, Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

macro_rules! load_json_file {
    ($json_file:expr) => {{
        let path = format!("../thirdparty/wycheproof/testvectors_v1/{}", $json_file);
        let data_file = File::open(&path)
            .expect("failed to open data file (try running `git submodule update --init`)");

        println!("Loading file: {path}");

        let tests: TestFile = serde_json::from_reader(data_file).expect("invalid test JSON");
        println!("{} ({})", tests.algorithm, tests.schema);
        tests
    }};
}

fn decode_optional_hex(opt: &Option<String>, field: &str) -> Vec<u8> {
    match opt {
        Some(h) => {
            hex::decode(h).unwrap_or_else(|e| panic!("invalid hex for field '{field}': {e}"))
        }
        None => panic!("missing field: {field}"),
    }
}

macro_rules! mlkem_keygen_seed_test {
    ($name:ident, $json_file:expr, $kem:ident) => {
        #[test]
        fn $name() {
            let tests = load_json_file!($json_file);

            for group in tests.groups {
                println!(
                    "Parameter set: {} ({} v{})\n",
                    &group.parameter_set, &group.source.name, &group.source.version
                );

                for test in &group.tests {
                    println!(
                        "Test #{}: {} ({:?})",
                        test.id,
                        test.comment.as_ref().unwrap(),
                        &test.result
                    );
                    let test_seed = decode_optional_hex(&test.seed, "seed");
                    let test_dk = decode_optional_hex(&test.dk, "dk");

                    let (dk, ek) = $kem::from_seed(test_seed.as_slice().try_into().unwrap());
                    assert_eq!(test_dk.as_slice(), dk.to_encoded_bytes().as_slice());
                    assert_eq!(test.ek.as_slice(), ek.to_bytes().as_slice());
                }
            }
        }
    };
}

macro_rules! mlkem_encaps_test {
    ($name:ident, $json_file:expr, $kem_module:ident) => {
        #[test]
        fn $name() {
            let tests = load_json_file!($json_file);

            for group in tests.groups {
                println!(
                    "Parameter set: {} ({} v{})\n",
                    &group.parameter_set, &group.source.name, &group.source.version
                );

                for test in &group.tests {
                    println!("Test #{} ({:?})", test.id, &test.result);

                    use ml_kem::$kem_module::EncapsulationKey;
                    let ek_result = EncapsulationKey::new_from_slice(&test.ek);

                    #[cfg_attr(not(feature = "hazmat"), allow(unused_variables))]
                    let ek = match test.result {
                        ExpectedResult::Valid => ek_result.expect("should be valid"),
                        ExpectedResult::Invalid => {
                            assert!(ek_result.is_err());
                            continue;
                        }
                        other => todo!("{:?}", other),
                    };

                    #[cfg(feature = "hazmat")]
                    {
                        let test_m = decode_optional_hex(&test.m, "m");
                        let test_m = test_m.as_slice().try_into().unwrap();
                        let (c, k) = ek.encapsulate_deterministic(test_m);

                        let test_c = decode_optional_hex(&test.c, "c");
                        let test_k = decode_optional_hex(&test.k, "K");
                        assert_eq!(test_c.as_slice(), c.as_slice());
                        assert_eq!(test_k.as_slice(), k.as_slice());
                    }
                }
            }
        }
    };
}

mlkem_keygen_seed_test!(
    mlkem_512_keygen_seed_test,
    "mlkem_512_keygen_seed_test.json",
    MlKem512
);
mlkem_keygen_seed_test!(
    mlkem_768_keygen_seed_test,
    "mlkem_768_keygen_seed_test.json",
    MlKem768
);
mlkem_keygen_seed_test!(
    mlkem_1024_keygen_seed_test,
    "mlkem_1024_keygen_seed_test.json",
    MlKem1024
);

mlkem_encaps_test!(
    mlkem_512_encaps_test,
    "mlkem_512_encaps_test.json",
    ml_kem_512
);
mlkem_encaps_test!(
    mlkem_768_encaps_test,
    "mlkem_768_encaps_test.json",
    ml_kem_768
);
mlkem_encaps_test!(
    mlkem_1024_encaps_test,
    "mlkem_1024_encaps_test.json",
    ml_kem_1024
);
