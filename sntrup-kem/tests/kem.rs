#![allow(missing_docs)]

use sntrup_kem::*;

// ---------------------------------------------------------------------------
// Implicit rejection: corrupted CT still returns a key, but a different one
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! implicit_rejection_test {
    ($name:ident, $kem:ty, $ct_size:expr) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, ss_encap) = ek.encapsulate(&mut rng);

            // Corrupt the ciphertext
            let mut ct_bytes = ct.as_ref().to_vec();
            ct_bytes[0] ^= 0xFF;
            ct_bytes[100] ^= 0x42;
            let ct_bad = Ciphertext::try_from(ct_bytes.as_slice()).expect("CT size");

            let ss_decap = dk.decapsulate(&ct_bad);
            assert!(
                ss_encap != ss_decap,
                "corrupted CT must produce different key"
            );

            // Deterministic: same corrupted CT + SK always produces same key
            let ss_decap2 = dk.decapsulate(&ct_bad);
            assert!(
                ss_decap == ss_decap2,
                "repeated decap must be deterministic"
            );
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_653, Sntrup653, 897);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_761, Sntrup761, 1039);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_857, Sntrup857, 1184);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_953, Sntrup953, 1349);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_1013, Sntrup1013, 1455);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
implicit_rejection_test!(implicit_rejection_1277, Sntrup1277, 1847);

// ---------------------------------------------------------------------------
// Wrong secret key gives different shared secret
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! wrong_sk_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek1, _dk1) = <$kem>::generate_key(&mut rng);
            let (_ek2, dk2) = <$kem>::generate_key(&mut rng);
            let (ct, ss_encap) = ek1.encapsulate(&mut rng);
            let ss_decap = dk2.decapsulate(&ct);
            assert!(ss_encap != ss_decap, "wrong SK must produce different key");
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_653, Sntrup653);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_761, Sntrup761);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_857, Sntrup857);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_953, Sntrup953);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_1013, Sntrup1013);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
wrong_sk_test!(wrong_sk_1277, Sntrup1277);

// ---------------------------------------------------------------------------
// Constant-time decapsulate always returns SS_BYTES
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! constant_time_test {
    ($name:ident, $kem:ty, $ct_size:expr) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, _ss) = ek.encapsulate(&mut rng);
            let result = dk.decapsulate(&ct);
            assert_eq!(result.as_ref().len(), 32);

            // Even with garbage ciphertext
            let garbage = vec![0xABu8; $ct_size];
            let garbage_ct = Ciphertext::try_from(garbage.as_slice()).expect("CT size");
            let result2 = dk.decapsulate(&garbage_ct);
            assert_eq!(result2.as_ref().len(), 32);
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
constant_time_test!(constant_time_653, Sntrup653, 897);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
constant_time_test!(constant_time_761, Sntrup761, 1039);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
constant_time_test!(constant_time_857, Sntrup857, 1184);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
constant_time_test!(constant_time_953, Sntrup953, 1349);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
constant_time_test!(constant_time_1013, Sntrup1013, 1455);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
constant_time_test!(constant_time_1277, Sntrup1277, 1847);

// ---------------------------------------------------------------------------
// Deterministic keygen from seed
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
macro_rules! deterministic_keygen_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let seed = [0xABu8; 32];
            let (ek1, dk1) = <$kem>::generate_key_deterministic(&seed);
            let (ek2, dk2) = <$kem>::generate_key_deterministic(&seed);
            assert_eq!(ek1, ek2, "same seed must produce same EK");
            assert!(dk1 == dk2, "same seed must produce same DK");

            // Different seed produces different key
            let (ek3, _dk3) = <$kem>::generate_key_deterministic(&[0xCDu8; 32]);
            assert_ne!(ek1, ek3, "different seed must produce different EK");
        }
    };
}

#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_653, Sntrup653);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_761, Sntrup761);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_857, Sntrup857);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_953, Sntrup953);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_1013, Sntrup1013);
#[cfg(feature = "kgen")]
deterministic_keygen_test!(deterministic_keygen_1277, Sntrup1277);

// ---------------------------------------------------------------------------
// Extract encapsulation key from decapsulation key
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! ek_from_dk_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let ek_extracted = dk.encapsulation_key();
            assert_eq!(ek, ek_extracted, "extracted EK must match original");

            // Encapsulating with the extracted key should produce a valid shared secret
            let (ct, ss_encap) = ek_extracted.encapsulate(&mut rng);
            let ss_decap = dk.decapsulate(&ct);
            assert!(ss_encap == ss_decap, "shared secrets must match");
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_653, Sntrup653);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_761, Sntrup761);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_857, Sntrup857);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_953, Sntrup953);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_1013, Sntrup1013);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
ek_from_dk_test!(ek_from_dk_1277, Sntrup1277);

// ---------------------------------------------------------------------------
// TryFrom with wrong sizes
// ---------------------------------------------------------------------------

macro_rules! try_from_invalid_size_test {
    ($name:ident, $ek:ty, $dk:ty, $ct:ty) => {
        #[test]
        fn $name() {
            let short = vec![0u8; 16];
            assert!(<$ek>::try_from(short.as_slice()).is_err());
            assert!(<$dk>::try_from(short.as_slice()).is_err());
            assert!(<$ct>::try_from(short.as_slice()).is_err());
        }
    };
}

try_from_invalid_size_test!(
    try_from_invalid_653,
    sntrup653::EncapsulationKey,
    sntrup653::DecapsulationKey,
    sntrup653::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_761,
    sntrup761::EncapsulationKey,
    sntrup761::DecapsulationKey,
    sntrup761::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_857,
    sntrup857::EncapsulationKey,
    sntrup857::DecapsulationKey,
    sntrup857::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_953,
    sntrup953::EncapsulationKey,
    sntrup953::DecapsulationKey,
    sntrup953::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_1013,
    sntrup1013::EncapsulationKey,
    sntrup1013::DecapsulationKey,
    sntrup1013::Ciphertext
);
try_from_invalid_size_test!(
    try_from_invalid_1277,
    sntrup1277::EncapsulationKey,
    sntrup1277::DecapsulationKey,
    sntrup1277::Ciphertext
);

// ---------------------------------------------------------------------------
// TryFrom / AsRef roundtrip
// ---------------------------------------------------------------------------

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
macro_rules! bytes_roundtrip_test {
    ($name:ident, $kem:ty) => {
        #[test]
        fn $name() {
            let mut rng = rand::rng();
            let (ek, dk) = <$kem>::generate_key(&mut rng);
            let (ct, ss) = ek.encapsulate(&mut rng);

            // EK roundtrip
            let ek2 = EncapsulationKey::try_from(ek.as_ref()).expect("EK roundtrip");
            assert_eq!(ek, ek2);

            // DK roundtrip
            let dk2 = DecapsulationKey::try_from(dk.as_ref()).expect("DK roundtrip");
            assert!(dk == dk2, "DK must match");

            // CT roundtrip
            let ct2 = Ciphertext::try_from(ct.as_ref()).expect("CT roundtrip");
            assert_eq!(ct, ct2);

            // Full KEM roundtrip through bytes
            let ss_decap = dk2.decapsulate(&ct2);
            assert!(ss == ss_decap, "KEM roundtrip through bytes must work");
        }
    };
}

#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_653, Sntrup653);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_761, Sntrup761);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_857, Sntrup857);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_953, Sntrup953);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_1013, Sntrup1013);
#[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
bytes_roundtrip_test!(bytes_roundtrip_1277, Sntrup1277);
