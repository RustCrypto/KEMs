//! Tests for the FrodoKEM and FrodoKEM-640 schemes
use rstest::*;
use std::path::PathBuf;

mod rng;
mod rsp_reader;

use rng::*;
use rsp_reader::*;

#[rstest]
#[case::aes640("./tests/frodoKAT/PQCkemKAT_19888.rsp")]
#[case::shake640("./tests/frodoKAT/PQCkemKAT_19888_shake.rsp")]
#[case::aes976("./tests/frodoKAT/PQCkemKAT_31296.rsp")]
#[case::shake976("./tests/frodoKAT/PQCkemKAT_31296_shake.rsp")]
#[case::aes1344("./tests/frodoKAT/PQCkemKAT_43088.rsp")]
#[case::shake1344("./tests/frodoKAT/PQCkemKAT_43088_shake.rsp")]
#[case::ephemeral_aes640("./tests/efrodoKAT/PQCkemKAT_19888.rsp")]
#[case::ephemeral_shake640("./tests/efrodoKAT/PQCkemKAT_19888_shake.rsp")]
#[case::ephemeral_aes976("./tests/efrodoKAT/PQCkemKAT_31296.rsp")]
#[case::ephemeral_shake976("./tests/efrodoKAT/PQCkemKAT_31296_shake.rsp")]
#[case::ephemeral_aes1344("./tests/efrodoKAT/PQCkemKAT_43088.rsp")]
#[case::ephemeral_shake1344("./tests/efrodoKAT/PQCkemKAT_43088_shake.rsp")]
fn test_vector(#[case] path: &str) {
    let path = PathBuf::from(path);
    let rsp_reader = RspReader::new(path);
    let mut rng = AesCtrDrbg::default();

    for rsp_data in rsp_reader {
        println!("{} Test {}", rsp_data.scheme, rsp_data.count + 1);
        rng.reseed(&rsp_data.seed);
        let (pk, sk) = rsp_data.scheme.generate_keypair(&mut rng);
        assert_eq!(pk, rsp_data.pk);
        assert_eq!(sk, rsp_data.sk);

        let (ct, ess) = rsp_data.scheme.encapsulate_with_rng(&pk, &mut rng).unwrap();
        assert_eq!(ct, rsp_data.ct);
        assert_eq!(ess, rsp_data.ss);

        let (dss, _) = rsp_data.scheme.decapsulate(&sk, &ct).unwrap();
        assert_eq!(dss, rsp_data.ss);
    }
}

/// Run all tests serially
#[ignore]
#[test]
fn test_vectors() {
    use std::fs::read_dir;

    let kat_dir = read_dir("./tests/efrodoKAT").unwrap();
    let mut rng = AesCtrDrbg::default();

    for path in kat_dir {
        let path = path.unwrap();
        if path.path().extension().unwrap() != "rsp" {
            continue;
        }
        let rsp_reader = RspReader::new(path.path());

        for rsp_data in rsp_reader {
            println!("{} Test {}", rsp_data.scheme, rsp_data.count + 1);
            rng.reseed(&rsp_data.seed);
            let (pk, sk) = rsp_data.scheme.generate_keypair(&mut rng);
            assert_eq!(pk, rsp_data.pk);
            assert_eq!(sk, rsp_data.sk);

            let (ct, ess) = rsp_data.scheme.encapsulate_with_rng(&pk, &mut rng).unwrap();
            assert_eq!(ct, rsp_data.ct);
            assert_eq!(ess, rsp_data.ss);

            let (dss, _) = rsp_data.scheme.decapsulate(&sk, &ct).unwrap();
            assert_eq!(dss, rsp_data.ss);
        }
    }
}
