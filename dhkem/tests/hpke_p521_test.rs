//! HPKE tests (P-521)
//
//! Test vectors from RFC 9180 Appendix A.

#![cfg(feature = "p521")]
#![allow(clippy::unwrap_in_result, reason = "tests")]
#![allow(clippy::unwrap_used, reason = "tests")]

use hex_literal::hex;
use kem::{TryDecapsulate, TryKeyInit};
use sha2::Sha512;

type Expander = dhkem::Expander<Sha512>;

fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let expander = Expander::new_labeled_hpke(b"", b"eae_prk", dh).unwrap();
    expander
        .expand_labeled_hpke(b"shared_secret", kem_context, &mut out)
        .unwrap();
    out
}

#[test]
fn test_a_6_1_base() {
    // RFC 9180 A.6.1 (Base)
    let skrm = hex!(
        "01462680369ae375e4b3791070a7458ed527842f6a98a79ff5e0d4cbde83c271\
         96a3916956655523a6a2556a7af62c5cadabe2ef9da3760bb21e005202f7b246\
         2847"
    );
    let enc = hex!(
        "040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab890\
         0aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f27\
         31ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de1205\
         1f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5\
         739d2f29b0"
    );
    let pkrm = hex!(
        "0401b45498c1714e2dce167d3caf162e45e0642afc7ed435df7902ccae0e84ba\
         0f7d373f646b7738bbbdca11ed91bdeae3cdcba3301f2457be452f271fa68375\
         80e661012af49583a62e48d44bed350c7118c0d8dc861c238c72a2bda17f6470\
         4f464b57338e7f40b60959480c0e58e6559b190d81663ed816e523b6b6a418f6\
         6d2451ec64"
    );
    let expected = hex!(
        "776ab421302f6eff7d7cb5cb1adaea0cd50872c71c2d63c30c4f1d5e43653336\
         fef33b103c67e7a98add2d3b66e2fda95b5b2a667aa9dac7e59cc1d46d30e818"
    );

    let dk = dhkem::NistP521DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_6_2_psk() {
    // RFC 9180 A.6.2 (Psk)
    let skrm = hex!(
        "011bafd9c7a52e3e71afbdab0d2f31b03d998a0dc875dd7555c63560e142bde2\
         64428de03379863b4ec6138f813fa009927dc5d15f62314c56d4e7ff2b485753\
         eb72"
    );
    let enc = hex!(
        "040085eff0835cc84351f32471d32aa453cdc1f6418eaaecf1c2824210eb1d48\
         d0768b368110fab21407c324b8bb4bec63f042cfa4d0868d19b760eb4beba1bf\
         f793b30036d2c614d55730bd2a40c718f9466faf4d5f8170d22b6df98dfe0c06\
         7d02b349ae4a142e0c03418f0a1479ff78a3db07ae2c2e89e5840f712c174ba2\
         118e90fdcb"
    );
    let pkrm = hex!(
        "04006917e049a2be7e1482759fb067ddb94e9c4f7f5976f655088dec45246614\
         ff924ed3b385fc2986c0ecc39d14f907bf837d7306aada59dd5889086125ecd0\
         38ead400603394b5d81f89ebfd556a898cc1d6a027e143d199d3db845cb91c52\
         89fb26c5ff80832935b0e8dd08d37c6185a6f77683347e472d1edb6daa6bd765\
         2fea628fae"
    );
    let expected = hex!(
        "0d52de997fdaa4797720e8b1bebd3df3d03c4cf38cc8c1398168d36c3fc76264\
         28c9c254dd3f9274450909c64a5b3acbe45e2d850a2fd69ac0605fe5c8a057a5"
    );

    let dk = dhkem::NistP521DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_6_3_auth() {
    // RFC 9180 A.6.3 (Auth)
    let skrm = hex!(
        "013ef326940998544a899e15e1726548ff43bbdb23a8587aa3bef9d1b857338d\
         87287df5667037b519d6a14661e9503cfc95a154d93566d8c84e95ce93ad0529\
         3a0b"
    );
    let enc = hex!(
        "04017de12ede7f72cb101dab36a111265c97b3654816dcd6183f809d4b3d111f\
         e759497f8aefdc5dbb40d3e6d21db15bdc60f15f2a420761bcaeef73b891c2b1\
         17e9cf01e29320b799bbc86afdc5ea97d941ea1c5bd5ebeeac7a784b3bab5247\
         46f3e640ec26ee1bd91255f9330d974f845084637ee0e6fe9f505c5b87c86a4e\
         1a6c3096dd"
    );
    let pkrm = hex!(
        "04007d419b8834e7513d0e7cc66424a136ec5e11395ab353da324e3586673ee7\
         3d53ab34f30a0b42a92d054d0db321b80f6217e655e304f72793767c4231785c\
         4a4a6e008f31b93b7a4f2b8cd12e5fe5a0523dc71353c66cbdad51c86b9e0bdf\
         cd9a45698f2dab1809ab1b0f88f54227232c858accc44d9a8d41775ac0263415\
         64a2d749f4"
    );
    let expected = hex!(
        "26648fa2a2deb0bfc56349a590fd4cb7108a51797b634694fc02061e8d91b357\
         6ac736a68bf848fe2a58dfb1956d266e68209a4d631e513badf8f4dcfc00f30a"
    );
    let pksm = hex!(
        "04015cc3636632ea9a3879e43240beae5d15a44fba819282fac26a19c989fafd\
         d0f330b8521dff7dc393101b018c1e65b07be9f5fc9a28a1f450d6a541ee0d76\
         221133001e8f0f6a05ab79f9b9bb9ccce142a453d59c5abebb5674839d935a3c\
         a1a3fbc328539a60b3bc3c05fed22838584a726b9c176796cad0169ba4093332\
         cbd2dc3a9f"
    );

    let dk = dhkem::NistP521DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_6_4_auth_psk() {
    // RFC 9180 A.6.4 (Auth Psk)
    let skrm = hex!(
        "0053c0bc8c1db4e9e5c3e3158bfdd7fc716aef12db13c8515adf821dd692ba3c\
         a53041029128ee19c8556e345c4bcb840bb7fd789f97fe10f17f0e2c6c252807\
         2843"
    );
    let enc = hex!(
        "04000a5096a6e6e002c83517b494bfc2e36bfb8632fae8068362852b70d0ff71\
         e560b15aff96741ecffb63d8ac3090c3769679009ac59a99a1feb4713c5f090f\
         c0dbed01ad73c45d29d369e36744e9ed37d12f80700c16d816485655169a5dd6\
         6e4ddf27f2acffe0f56f7f77ea2b473b4bf0518b975d9527009a3d14e5a4957e\
         3e8a9074f8"
    );
    let pkrm = hex!(
        "0401655b5d3b7cfafaba30851d25edc44c6dd17d99410efbed8591303b4dbeea\
         8cb1045d5255f9a60384c3bbd4a3386ae6e6fab341dc1f8db0eed5f0ab1aaac6\
         d7838e00dadf8a1c2c64b48f89c633721e88369e54104b31368f26e35d04a442\
         b0b428510fb23caada686add16492f333b0f7ba74c391d779b788df2c38d7a7f\
         4778009d91"
    );
    let expected = hex!(
        "9e1d5f62cb38229f57f68948a0fbc1264499910cce50ec62cb24188c5b0a9886\
         8f3c1cfa8c5baa97b3f24db3cdd30df6e04eae83dc4347be8a981066c3b5b945"
    );
    let pksm = hex!(
        "040013761e97007293d57de70962876b4926f69a52680b4714bee1d4236aa96c\
         19b840c57e80b14e91258f0a350e3f7ba59f3f091633aede4c7ec4fa8918323a\
         a45d5901076dec8eeb22899fda9ab9e1960003ff0535f53c02c40f2ae4cdc607\
         0a3870b85b4bdd0bb77f1f889e7ee51f465a308f08c666ad3407f75dc046b2ff\
         5a24dbe2ed"
    );

    let dk = dhkem::NistP521DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}
