//! HPKE tests (P-256)
//
//! Test vectors from RFC 9180 Appendix A.

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

#[test]
fn test_a_3_1_base() {
    // RFC 9180 A.3.1 (Base) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3.1
    let skrm = hex!("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    let enc = hex!(
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325a\
         c98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18\
         c4"
    );
    let pkrm = hex!(
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a\
         826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72e\
         a0"
    );
    let expected = hex!("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_3_2_psk() {
    // RFC 9180 A.3.2 (Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3.2
    let skrm = hex!("438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661");
    let enc = hex!(
        "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4\
         d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b\
         5f"
    );
    let pkrm = hex!(
        "040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446\
         ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ff\
         d1"
    );
    let expected = hex!("2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b");

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_3_3_auth() {
    // RFC 9180 A.3.3 (Auth) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3.3
    let skrm = hex!("d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e");
    let enc = hex!(
        "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e1\
         5b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d534\
         54"
    );
    let pkrm = hex!(
        "04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b018\
         36835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a7\
         8d"
    );
    let expected = hex!("d4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f");
    let pksm = hex!(
        "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10e\
         ef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f\
         73"
    );

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_3_4_auth_psk() {
    // RFC 9180 A.3.4 (Auth Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.3.4
    let skrm = hex!("bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394");
    let enc = hex!(
        "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131\
         357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a845114\
         01"
    );
    let pkrm = hex!(
        "04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f\
         725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1\
         b3"
    );
    let expected = hex!("d4c27698391db126f1612d9e91a767f10b9b19aa17e1695549203f0df7d9aebe");
    let pksm = hex!(
        "049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d048\
         0069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af\
         9e"
    );

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_4_1_base() {
    // RFC 9180 A.4.1 (Base) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.4.1
    let skrm = hex!("3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38");
    let enc = hex!(
        "0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15\
         565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a4725\
         80"
    );
    let pkrm = hex!(
        "04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818\
         a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610e\
         dd"
    );
    let expected = hex!("02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd");

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_4_2_psk() {
    // RFC 9180 A.4.2 (Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.4.2
    let skrm = hex!("bc6f0b5e22429e5ff47d5969003f3cae0f4fec50e23602e880038364f33b8522");
    let enc = hex!(
        "04a307934180ad5287f95525fe5bc6244285d7273c15e061f0f2efb211c35057\
         f3079f6e0abae200992610b25f48b63aacfcb669106ddee8aa023feed3019013\
         71"
    );
    let pkrm = hex!(
        "043f5266fba0742db649e1043102b8a5afd114465156719cea90373229aabdd8\
         4d7f45dabfc1f55664b888a7e86d594853a6cccdc9b189b57839cbbe3b90b558\
         73"
    );
    let expected = hex!("2912aacc6eaebd71ff715ea50f6ef3a6637856b2a4c58ea61e0c3fc159e3bc16");

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_4_3_auth() {
    // RFC 9180 A.4.3 (Auth) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.4.3
    let skrm = hex!("1ea4484be482bf25fdb2ed39e6a02ed9156b3e57dfb18dff82e4a048de990236");
    let enc = hex!(
        "04fec59fa9f76f5d0f6c1660bb179cb314ed97953c53a60ab38f8e6ace60fd59\
         178084d0dd66e0f79172992d4ddb2e91172ce24949bcebfff158dcc417f2c6e9\
         c6"
    );
    let pkrm = hex!(
        "04378bad519aab406e04d0e5608bcca809c02d6afd2272d4dd03e9357bd0eee8\
         adf84c8deba3155c9cf9506d1d4c8bfefe3cf033a75716cc3cc07295100ec962\
         76"
    );
    let expected = hex!("1ed49f6d7ada333d171cd63861a1cb700a1ec4236755a9cd5f9f8f67a2f8e7b3");
    let pksm = hex!(
        "0404d3c1f9fca22eb4a6d326125f0814c35593b1da8ea0d11a640730b215a259\
         b9b98a34ad17e21617d19fe1d4fa39a4828bfdb306b729ec51c543caca3b2d95\
         29"
    );

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_4_4_auth_psk() {
    // RFC 9180 A.4.4 (Auth Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.4.4
    let skrm = hex!("00510a70fde67af487c093234fc4215c1cdec09579c4b30cc8e48cb530414d0e");
    let enc = hex!(
        "04801740f4b1b35823f7fb2930eac2efc8c4893f34ba111c0bb976e3c7d5dc0a\
         ef5a7ef0bf4057949a140285f774f1efc53b3860936b92279a11b68395d898d1\
         38"
    );
    let pkrm = hex!(
        "04a4ca7af2fc2cce48edbf2f1700983e927743a4e85bb5035ad562043e25d9a1\
         11cbf6f7385fac55edc5c9d2ca6ed351a5643de95c36748e11dbec98730f4d43\
         e9"
    );
    let expected = hex!("02bee8be0dda755846115db45071c0cf59c25722e015bde1c124de849c0fea52");
    let pksm = hex!(
        "04b59a4157a9720eb749c95f842a5e3e8acdccbe834426d405509ac3191e23f2\
         165b5bb1f07a6240dd567703ae75e13182ee0f69fc102145cdb5abf681ff126d\
         60"
    );

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_5_1_base() {
    // RFC 9180 A.5.1 (Base) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.5.1
    let skrm = hex!("a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b");
    let enc = hex!(
        "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824f\
         c1559eac6fb9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e3812\
         91"
    );
    let pkrm = hex!(
        "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40\
         bad9bb726f68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a0\
         06"
    );
    let expected = hex!("806520f82ef0b03c823b7fc524b6b55a088f566b9751b89551c170f4113bd850");

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_5_2_psk() {
    // RFC 9180 A.5.2 (Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.5.2
    let skrm = hex!("12ecde2c8bc2d5d7ed2219c71f27e3943d92b344174436af833337c557c300b3");
    let enc = hex!(
        "04f336578b72ad7932fe867cc4d2d44a718a318037a0ec271163699cee653fa8\
         05c1fec955e562663e0c2061bb96a87d78892bff0cc0bad7906c2d998ebe1a72\
         46"
    );
    let pkrm = hex!(
        "041eb8f4f20ab72661af369ff3231a733672fa26f385ffb959fd1bae46bfda43\
         ad55e2d573b880831381d9367417f554ce5b2134fbba5235b44db465feffc618\
         9e"
    );
    let expected = hex!("ac4f260dce4db6bf45435d9c92c0e11cfdd93743bd3075949975974cc2b3d79e");

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let kem_context = [enc.as_slice(), pkrm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh1, &kem_context), expected);
}

#[test]
fn test_a_5_3_auth() {
    // RFC 9180 A.5.3 (Auth) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.5.3
    let skrm = hex!("3cb2c125b8c5a81d165a333048f5dcae29a2ab2072625adad66dbb0f48689af9");
    let enc = hex!(
        "040d5176aedba55bc41709261e9195c5146bb62d783031280775f32e507d79b5\
         cbc5748b6be6359760c73cfe10ca19521af704ca6d91ff32fc0739527b9385d4\
         15"
    );
    let pkrm = hex!(
        "0444f6ee41818d9fe0f8265bffd016b7e2dd3964d610d0f7514244a60dbb7a11\
         ece876bb110a97a2ac6a9542d7344bf7d2bd59345e3e75e497f7416cf38d2962\
         33"
    );
    let expected = hex!("1a45aa4792f4b166bfee7eeab0096c1a6e497480e2261b2a59aad12f2768d469");
    let pksm = hex!(
        "04265529a04d4f46ab6fa3af4943774a9f1127821656a75a35fade898a9a1b01\
         4f64d874e88cddb24c1c3d79004d3a587db67670ca357ff4fba7e8b56ec013b9\
         8b"
    );

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}

#[test]
fn test_a_5_4_auth_psk() {
    // RFC 9180 A.5.4 (Auth Psk) https://datatracker.ietf.org/doc/html/rfc9180#appendix-A.5.4
    let skrm = hex!("c29fc577b7e74d525c0043f1c27540a1248e4f2c8d297298e99010a92e94865c");
    let enc = hex!(
        "043539917ee26f8ae0aa5f784a387981b13de33124a3cde88b94672030183110\
         f331400115855808244ff0c5b6ca6104483ac95724481d41bdcd9f15b430ad16\
         f6"
    );
    let pkrm = hex!(
        "04d383fd920c42d018b9d57fd73a01f1eee480008923f67d35169478e55d2e88\
         17068daf62a06b10e0aad4a9e429fa7f904481be96b79a9c231a33e956c20b81\
         b6"
    );
    let expected = hex!("87584311791036a3019bc36803cdd42e9a8931a98b13c88835f2f8a9036a4fd6");
    let pksm = hex!(
        "0492cf8c9b144b742fe5a63d9a181a19d416f3ec8705f24308ad316564823c34\
         4e018bd7c03a33c926bb271b28ef5bf28c0ca00abff249fee5ef7f33315ff34f\
         db"
    );

    let dk = NistP256DecapsulationKey::new(&skrm.into()).unwrap();
    let dh1 = dk.try_decapsulate(&enc.into()).unwrap();
    let dh2 = dk.try_decapsulate(&pksm.into()).unwrap();
    let dh = [&dh1[..], &dh2[..]].concat();
    let kem_context = [enc.as_slice(), pkrm.as_slice(), pksm.as_slice()].concat();
    assert_eq!(extract_and_expand(&dh, &kem_context), expected);
}
