//! HPKE tests (X25519)
//
//! Test vectors from RFC 9180 Appendix A.

#![cfg(feature = "x25519")]
#![allow(clippy::unwrap_in_result, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]

use hex_literal::hex;
use kem::{Decapsulate, KeyInit};
use sha2::Sha256;

type Expander = dhkem::Expander<Sha256>;

fn extract_and_expand(shared_secret: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let expander = Expander::new_labeled_hpke(b"", b"eae_prk", shared_secret).unwrap();
    expander
        .expand_labeled_hpke(b"shared_secret", kem_context, &mut out)
        .unwrap();
    out
}

#[test]
fn test_a_1_1_base() {
    // RFC 9180 A.1.1 (Base) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1.1
    let skrm = hex!("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let pkrm = hex!("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    let enc = hex!("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    let expected = hex!("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh = dk.decapsulate(&enc.into());
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_1_2_psk() {
    // RFC 9180 A.1.2 (Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1.2
    let skrm = hex!("c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd");
    let pkrm = hex!("9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366");
    let enc = hex!("0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
    let expected = hex!("727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh = dk.decapsulate(&enc.into());
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_1_3_auth() {
    // RFC 9180 A.1.3 (Auth) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1.3
    let skrm = hex!("fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e");
    let pkrm = hex!("1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e");
    let enc = hex!("23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    let expected = hex!("2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7");
    let pksm = hex!("8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh1 = dk.decapsulate(&enc.into());
    let dh2 = dk.decapsulate(&pksm.into());
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_1_4_auth_psk() {
    // RFC 9180 A.1.4 (Auth Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.1.4
    let skrm = hex!("cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423");
    let pkrm = hex!("1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976");
    let enc = hex!("820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    let expected = hex!("f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577");
    let pksm = hex!("2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh1 = dk.decapsulate(&enc.into());
    let dh2 = dk.decapsulate(&pksm.into());
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_2_1_base() {
    // RFC 9180 A.2.1 (Base) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2.1
    let skrm = hex!("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    let pkrm = hex!("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    let enc = hex!("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    let expected = hex!("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh = dk.decapsulate(&enc.into());
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_2_2_psk() {
    // RFC 9180 A.2.2 (Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2.2
    let skrm = hex!("77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879");
    let pkrm = hex!("13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062");
    let enc = hex!("2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04");
    let expected = hex!("4be079c5e77779d0215b3f689595d59e3e9b0455d55662d1f3666ec606e50ea7");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh = dk.decapsulate(&enc.into());
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_2_3_auth() {
    // RFC 9180 A.2.3 (Auth) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2.3
    let skrm = hex!("3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82");
    let pkrm = hex!("1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44");
    let enc = hex!("f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e");
    let expected = hex!("d2d67828c8bc9fa661cf15a31b3ebf1febe0cafef7abfaaca580aaf6d471e3eb");
    let pksm = hex!("f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh1 = dk.decapsulate(&enc.into());
    let dh2 = dk.decapsulate(&pksm.into());
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_2_4_auth_psk() {
    // RFC 9180 A.2.4 (Auth Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.2.4
    let skrm = hex!("7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c");
    let pkrm = hex!("a5099431c35c491ec62ca91df1525d6349cb8aa170c51f9581f8627be6334851");
    let enc = hex!("656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02");
    let expected = hex!("86a6c0ed17714f11d2951747e660857a5fd7616c933ef03207808b7a7123fe67");
    let pksm = hex!("3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh1 = dk.decapsulate(&enc.into());
    let dh2 = dk.decapsulate(&pksm.into());
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_7_1_base() {
    // RFC 9180 A.7.1 (Base) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.7.1
    let skrm = hex!("33d196c830a12f9ac65d6e565a590d80f04ee9b19c83c87f2c170d972a812848");
    let pkrm = hex!("194141ca6c3c3beb4792cd97ba0ea1faff09d98435012345766ee33aae2d7664");
    let enc = hex!("e5e8f9bfff6c2f29791fc351d2c25ce1299aa5eaca78a757c0b4fb4bcd830918");
    let expected = hex!("e81716ce8f73141d4f25ee9098efc968c91e5b8ce52ffff59d64039e82918b66");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh = dk.decapsulate(&enc.into());
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_7_2_psk() {
    // RFC 9180 A.7.2 (Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.7.2
    let skrm = hex!("98f304d4ecb312689690b113973c61ffe0aa7c13f2fbe365e48f3ed09e5a6a0c");
    let pkrm = hex!("d53af36ea5f58f8868bb4a1333ed4cc47e7a63b0040eb54c77b9c8ec456da824");
    let enc = hex!("d3805a97cbcd5f08babd21221d3e6b362a700572d14f9bbeb94ec078d051ae3d");
    let expected = hex!("024573db58c887decb4c57b6ed39f2c9a09c85600a8a0ecb11cac24c6aaec195");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh = dk.decapsulate(&enc.into());
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_7_3_auth() {
    // RFC 9180 A.7.3 (Auth) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.7.3
    let skrm = hex!("ed88cda0e91ca5da64b6ad7fc34a10f096fa92f0b9ceff9d2c55124304ed8b4a");
    let pkrm = hex!("ffd7ac24694cb17939d95feb7c4c6539bb31621deb9b96d715a64abdd9d14b10");
    let enc = hex!("5ac1671a55c5c3875a8afe74664aa8bc68830be9ded0c5f633cd96400e8b5c05");
    let expected = hex!("e204156fd17fd65b132d53a0558cd67b7c0d7095ee494b00f47d686eb78f8fb3");
    let pksm = hex!("89eb1feae431159a5250c5186f72a15962c8d0debd20a8389d8b6e4996e14306");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh1 = dk.decapsulate(&enc.into());
    let dh2 = dk.decapsulate(&pksm.into());
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_7_4_auth_psk() {
    // RFC 9180 A.7.4 (Auth Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.7.4
    let skrm = hex!("c4962a7f97d773a47bdf40db4b01dc6a56797c9e0deaab45f4ea3aa9b1d72904");
    let pkrm = hex!("f47cd9d6993d2e2234eb122b425accfb486ee80f89607b087094e9f413253c2d");
    let enc = hex!("81cbf4bd7eee97dd0b600252a1c964ea186846252abb340be47087cc78f3d87c");
    let expected = hex!("d69246bcd767e579b1eec80956d7e7dfbd2902dad920556f0de69bd54054a2d1");
    let pksm = hex!("29a5bf3867a6128bbdf8e070abe7fe70ca5e07b629eba5819af73810ee20112f");

    let dk = dhkem::X25519DecapsulationKey::new(&skrm.into());
    let dh1 = dk.decapsulate(&enc.into());
    let dh2 = dk.decapsulate(&pksm.into());
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}
