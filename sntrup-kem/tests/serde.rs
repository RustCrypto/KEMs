#![allow(missing_docs)]
#![cfg(feature = "serde")]

use sntrup_kem::*;

macro_rules! serde_json_test {
    ($name:ident, $kem:ty, $params:ty, $pk_size:expr, $ct_size:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn json_roundtrip_encapsulation_key() {
                let mut rng = rand::rng();
                let (ek, _dk) = <$kem>::generate_key(&mut rng);
                let json = serde_json::to_string(&ek).expect("serialize EK");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
                assert!(parsed.is_string(), "EK should serialize as hex string");
                assert_eq!(
                    parsed.as_str().expect("str").len(),
                    $pk_size * 2,
                    "hex length mismatch"
                );
                let ek2: EncapsulationKey<$params> =
                    serde_json::from_str(&json).expect("deserialize EK");
                assert_eq!(ek, ek2);
            }

            #[test]
            fn json_roundtrip_decapsulation_key() {
                let mut rng = rand::rng();
                let (_ek, dk) = <$kem>::generate_key(&mut rng);
                let json = serde_json::to_string(&dk).expect("serialize DK");
                let dk2: DecapsulationKey<$params> =
                    serde_json::from_str(&json).expect("deserialize DK");
                assert!(dk == dk2, "DK must match after JSON roundtrip");
            }

            #[test]
            fn json_roundtrip_ciphertext() {
                let mut rng = rand::rng();
                let (ek, _dk) = <$kem>::generate_key(&mut rng);
                let (ct, _ss) = ek.encapsulate(&mut rng);
                let json = serde_json::to_string(&ct).expect("serialize CT");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
                assert!(parsed.is_string(), "CT should serialize as hex string");
                assert_eq!(
                    parsed.as_str().expect("str").len(),
                    $ct_size * 2,
                    "hex length mismatch"
                );
                let ct2: Ciphertext<$params> = serde_json::from_str(&json).expect("deserialize CT");
                assert_eq!(ct, ct2);
            }

            #[test]
            fn json_roundtrip_shared_secret() {
                let mut rng = rand::rng();
                let (ek, _dk) = <$kem>::generate_key(&mut rng);
                let (_ct, ss) = ek.encapsulate(&mut rng);
                let json = serde_json::to_string(&ss).expect("serialize SS");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
                assert!(parsed.is_string(), "SS should serialize as hex string");
                assert_eq!(
                    parsed.as_str().expect("str").len(),
                    64,
                    "hex length mismatch"
                );
                let ss2: SharedSecret<$params> =
                    serde_json::from_str(&json).expect("deserialize SS");
                assert!(ss == ss2, "SS must match after JSON roundtrip");
            }

            #[test]
            fn json_full_kem_roundtrip() {
                let mut rng = rand::rng();
                let (ek, dk) = <$kem>::generate_key(&mut rng);
                let (ct, ss_encap) = ek.encapsulate(&mut rng);

                let dk_json = serde_json::to_string(&dk).expect("serialize DK");
                let ct_json = serde_json::to_string(&ct).expect("serialize CT");

                let dk2: DecapsulationKey<$params> =
                    serde_json::from_str(&dk_json).expect("deserialize DK");
                let ct2: Ciphertext<$params> =
                    serde_json::from_str(&ct_json).expect("deserialize CT");

                let ss_decap = dk2.decapsulate(&ct2);
                assert!(ss_encap == ss_decap, "KEM roundtrip through JSON must work");
            }
        }
    };
}

mod reject_malformed_input {
    use super::*;

    /// Inputs shorter than the expected size must be rejected, not zero-padded.
    #[test]
    fn short_input_rejected() {
        let json = "\"deadbeef\""; // 4 bytes — far shorter than any expected size
        assert!(
            serde_json::from_str::<EncapsulationKey<Sntrup761Params>>(json).is_err(),
            "short EncapsulationKey input must be rejected, not zero-padded"
        );
        assert!(
            serde_json::from_str::<DecapsulationKey<Sntrup761Params>>(json).is_err(),
            "short DecapsulationKey input must be rejected, not zero-padded"
        );
        assert!(
            serde_json::from_str::<Ciphertext<Sntrup761Params>>(json).is_err(),
            "short Ciphertext input must be rejected, not zero-padded"
        );
        assert!(
            serde_json::from_str::<SharedSecret<Sntrup761Params>>(json).is_err(),
            "short SharedSecret input must be rejected, not zero-padded"
        );
    }

    /// Empty input must be rejected for all four types.
    #[test]
    fn empty_input_rejected() {
        let json = "\"\"";
        assert!(serde_json::from_str::<EncapsulationKey<Sntrup761Params>>(json).is_err());
        assert!(serde_json::from_str::<DecapsulationKey<Sntrup761Params>>(json).is_err());
        assert!(serde_json::from_str::<Ciphertext<Sntrup761Params>>(json).is_err());
        assert!(serde_json::from_str::<SharedSecret<Sntrup761Params>>(json).is_err());
    }
}

serde_json_test!(serde_653, Sntrup653, Sntrup653Params, 994, 897);
serde_json_test!(serde_761, Sntrup761, Sntrup761Params, 1158, 1039);
serde_json_test!(serde_857, Sntrup857, Sntrup857Params, 1322, 1184);
serde_json_test!(serde_953, Sntrup953, Sntrup953Params, 1505, 1349);
serde_json_test!(serde_1013, Sntrup1013, Sntrup1013Params, 1623, 1455);
serde_json_test!(serde_1277, Sntrup1277, Sntrup1277Params, 2067, 1847);
