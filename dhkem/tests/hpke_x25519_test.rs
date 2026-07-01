//! HPKE X25519 tests.

#![cfg(feature = "x25519")]
#![allow(clippy::unwrap_used, reason = "tests")]

use dhkem::{HPKE_DHKEM_X25519_HKDF_SHA256_KEM_ID, X25519DecapsulationKey};
use hex_literal::hex;
use kem::{Decapsulate, Key, KeyInit};
use sha2::Sha256;

type Expander = dhkem::Expander<Sha256>;

fn extract_and_expand(shared_secret: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let expander = Expander::new_labeled_hpke_with_kem_id(
        HPKE_DHKEM_X25519_HKDF_SHA256_KEM_ID,
        b"",
        b"eae_prk",
        shared_secret,
    )
    .unwrap();
    expander
        .expand_labeled_hpke_with_kem_id(
            HPKE_DHKEM_X25519_HKDF_SHA256_KEM_ID,
            b"shared_secret",
            kem_context,
            &mut out,
        )
        .unwrap();

    out
}

#[test]
// RFC 9180 appendix A.7.1
fn test_dhkem_x25519_hkdf_sha256_export_only() {
    let recipient_secret = Key::<X25519DecapsulationKey>::from(hex!(
        "33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848"
    ));
    let recipient_public = hex!("194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664");
    let encapsulated = hex!("e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918");
    let expected_shared_secret =
        hex!("e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66");

    let skr = X25519DecapsulationKey::new(&recipient_secret);
    let raw_shared_secret = skr.decapsulate(&encapsulated.into());
    let kem_context = [encapsulated.as_slice(), recipient_public.as_slice()].concat();

    let shared_secret = extract_and_expand(&raw_shared_secret, &kem_context);
    assert_eq!(shared_secret, expected_shared_secret);
}
