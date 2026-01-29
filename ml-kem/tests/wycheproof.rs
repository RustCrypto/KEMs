//! Test against the Wycheproof test vectors.

use ml_kem::{EncodedSizeUser, KemCore, MlKem512, MlKem768, MlKem1024, kem::KeyExport};
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
    comment: String,
    #[serde(with = "hex::serde")]
    seed: Vec<u8>,
    #[serde(default, with = "hex::serde")]
    ek: Vec<u8>,
    #[serde(with = "hex::serde")]
    dk: Vec<u8>,
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
                    println!("Test #{}: {} ({:?})", test.id, &test.comment, &test.result);

                    let (dk, ek) = $kem::from_seed(test.seed.as_slice().try_into().unwrap());
                    assert_eq!(test.dk.as_slice(), dk.to_encoded_bytes().as_slice());
                    assert_eq!(test.ek.as_slice(), ek.to_bytes().as_slice());
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
