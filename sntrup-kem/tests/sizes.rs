#![allow(missing_docs)]
#![cfg(all(feature = "kgen", feature = "ecap"))]

use sntrup_kem::*;

macro_rules! size_test {
    ($name:ident, $kem:ty, $pk:expr, $sk:expr, $ct:expr) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            assert_eq!(ek.as_ref().len(), $pk, "PK size mismatch");
            assert_eq!(dk.as_ref().len(), $sk, "SK size mismatch");

            let (ct, ss) = ek.encapsulate(&mut rng);
            assert_eq!(ct.as_ref().len(), $ct, "CT size mismatch");
            assert_eq!(ss.as_ref().len(), 32, "SS size mismatch");
        }
    };
}

size_test!(sizes_653, Sntrup653, 994, 1518, 897);
size_test!(sizes_761, Sntrup761, 1158, 1763, 1039);
size_test!(sizes_857, Sntrup857, 1322, 1999, 1184);
size_test!(sizes_953, Sntrup953, 1505, 2254, 1349);
size_test!(sizes_1013, Sntrup1013, 1623, 2417, 1455);
size_test!(sizes_1277, Sntrup1277, 2067, 3059, 1847);
