#![cfg(feature = "p256")]

use dhkem::{DhKem, NistP256Kem};
use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

/// Constant RNG for testing purposes only.
struct ConstantRng<'a>(pub &'a [u8]);

impl RngCore for ConstantRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let (head, tail) = self.0.split_at(4);
        self.0 = tail;
        u32::from_be_bytes(head.try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        let (head, tail) = self.0.split_at(8);
        self.0 = tail;
        u64::from_be_bytes(head.try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let (hd, tl) = self.0.split_at(dest.len());
        dest.copy_from_slice(hd);
        self.0 = tl;
    }
}

// this is only ever ok for testing
impl CryptoRng for ConstantRng<'_> {}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let labeled_ikm = [b"HPKE-v1".as_slice(), b"KEM\x00\x10".as_slice(), label, ikm].concat();
    Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm).0.to_vec()
}

fn labeled_expand(prk: &[u8], label: &[u8], info: &[u8], l: u16) -> Vec<u8> {
    let labeled_info = [
        &l.to_be_bytes(),
        b"HPKE-v1".as_slice(),
        b"KEM\x00\x10".as_slice(),
        label,
        info,
    ]
    .concat();
    let mut out = vec![0; l as usize];
    Hkdf::<Sha256>::from_prk(prk)
        .unwrap()
        .expand(&labeled_info, &mut out)
        .expect("ok");
    out
}

fn extract_and_expand(dh: <NistP256Kem as DhKem>::SharedSecret, kem_context: &[u8]) -> Vec<u8> {
    let eae_prk = labeled_extract(b"", b"eae_prk", dh.raw_secret_bytes());
    labeled_expand(&eae_prk, b"shared_secret", kem_context, 32)
}

#[test]
// section A.3.1 https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3.1
fn test_dhkem_p256_hkdf_sha256() {
    let pke_hex = hex!(
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32\
                  5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
    );
    let pkr_hex = hex!(
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70\
                  6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
    );
    let shared_secret_hex =
        hex!("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");

    let (skr, pkr) = NistP256Kem::random_keypair(&mut ConstantRng(&hex!(
        "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"
    )));
    assert_eq!(pkr.to_encoded_point(false).as_bytes(), &pkr_hex);

    let (pke, ss1) = pkr
        .encapsulate(&mut ConstantRng(&hex!(
            "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"
        )))
        .expect("never fails");
    assert_eq!(pke.to_encoded_point(false).as_bytes(), &pke_hex);

    let ss2 = skr.decapsulate(&pke).expect("never fails");

    assert_eq!(ss1.raw_secret_bytes(), ss2.raw_secret_bytes());

    let kem_context = [pke_hex, pkr_hex].concat();
    let shared_secret = extract_and_expand(ss1, &kem_context);

    assert_eq!(&shared_secret, &shared_secret_hex);
}
