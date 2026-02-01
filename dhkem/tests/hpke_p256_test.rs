//! HPKE tests (P-256 only)

#![cfg(feature = "p256")]
#![allow(clippy::unwrap_in_result, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]

use core::convert::Infallible;
use dhkem::NistP256DecapsulationKey;
use hex_literal::hex;
use kem::{Encapsulate, KeyExport, TryDecapsulate, TryKeyInit};
use rand_core::{TryCryptoRng, TryRng};
use sha2::Sha256;

type Expander = dhkem::Expander<Sha256>;

/// Constant RNG for testing purposes only.
struct ConstantRng<'a>(pub &'a [u8]);

impl TryRng for ConstantRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let (head, tail) = self.0.split_at(4);
        self.0 = tail;
        Ok(u32::from_be_bytes(head.try_into().unwrap()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let (head, tail) = self.0.split_at(8);
        self.0 = tail;
        Ok(u64::from_be_bytes(head.try_into().unwrap()))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        let (hd, tl) = self.0.split_at(dest.len());
        dest.copy_from_slice(hd);
        self.0 = tl;
        Ok(())
    }
}

// this is only ever ok for testing
impl TryCryptoRng for ConstantRng<'_> {}

fn extract_and_expand(shared_secret: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let expander = Expander::new_labeled_hpke(b"", b"eae_prk", shared_secret).unwrap();
    expander
        .expand_labeled_hpke(b"shared_secret", kem_context, &mut out)
        .unwrap();

    out
}

#[test]
// section A.3.1 https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3.1
fn test_dhkem_p256_hkdf_sha256() {
    let example_key = hex!("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    let example_pke = hex!(
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32\
         5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
    );
    let example_pkr = hex!(
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70\
         6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
    );
    let example_shared_secret =
        hex!("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");

    let skr = NistP256DecapsulationKey::new(&example_key.into()).unwrap();
    let pkr = skr.as_ref();
    assert_eq!(&pkr.to_bytes(), &example_pkr);

    let (pke, ss1) = pkr.encapsulate_with_rng(&mut ConstantRng(&hex!(
        "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb"
    )));
    assert_eq!(&pke, &example_pke);

    let ss2 = skr.try_decapsulate(&pke).unwrap();

    assert_eq!(ss1, ss2);

    let kem_context = [example_pke, example_pkr].concat();
    let shared_secret = extract_and_expand(&ss1, &kem_context);

    assert_eq!(&shared_secret, &example_shared_secret);
}
