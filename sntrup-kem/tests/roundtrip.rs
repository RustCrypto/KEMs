#![allow(missing_docs)]
#![cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]

use sntrup_kem::*;

macro_rules! roundtrip_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, ss1) = ek.encapsulate(&mut rng);
            let ss2 = dk.decapsulate(&ct);
            assert_eq!(ss1, ss2);
        }
    };
}

roundtrip_test!(roundtrip_653, Sntrup653);
roundtrip_test!(roundtrip_761, Sntrup761);
roundtrip_test!(roundtrip_857, Sntrup857);
roundtrip_test!(roundtrip_953, Sntrup953);
roundtrip_test!(roundtrip_1013, Sntrup1013);
roundtrip_test!(roundtrip_1277, Sntrup1277);
