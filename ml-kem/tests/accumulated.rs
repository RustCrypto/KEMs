//! Accumulated test vectors, following the C2SP CCTV procedure:
//! <https://github.com/C2SP/CCTV/tree/main/ML-KEM>
//!
//! One SHAKE-128 stream supplies the inputs and a second one hashes all outputs. CCTV's published
//! hashes target the FIPS 203 draft (`G(d)` instead of `G(d || k)`), so these values are for final
//! FIPS 203, computed with libcrux-ml-kem 0.0.11.
//!
//! Longer runs are ignored by default: `cargo test --release --test accumulated -- --ignored`

#![allow(clippy::unwrap_used, missing_docs)]

use hex_literal::hex;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{
    B32, Seed,
    kem::{Decapsulate, KeyExport, KeyInit},
};
use shake::{ExtendableOutput, Shake128, Update, XofReader};

macro_rules! accumulated_test {
    ($name:ident, $module:ident, $count:expr, $expected:expr $(, $ignore:literal)?) => {
        #[test]
        $(#[ignore = $ignore])?
        #[allow(deprecated)]
        fn $name() {
            let mut rng = Shake128::default().finalize_xof();
            let mut accumulator = Shake128::default();

            for _ in 0..$count {
                // `d || z`
                let mut seed = Seed::default();
                rng.read(&mut seed);
                let dk = ml_kem::$module::DecapsulationKey::new(&seed);
                let ek = dk.encapsulation_key();
                accumulator.update(&ek.to_bytes());
                accumulator.update(&dk.to_expanded_bytes());

                let mut m = B32::default();
                rng.read(&mut m);
                let (ct, k) = ek.encapsulate_deterministic(&m);
                assert_eq!(dk.decapsulate(&ct), k);
                accumulator.update(&ct);
                accumulator.update(&k);

                let mut random_ct = ml_kem::$module::Ciphertext::default();
                rng.read(&mut random_ct);
                accumulator.update(&dk.decapsulate(&random_ct));
            }

            let mut digest = [0u8; 32];
            accumulator.finalize_xof().read(&mut digest);
            assert_eq!(digest, $expected);
        }
    };
}

accumulated_test!(
    accumulated_512_100,
    ml_kem_512,
    100,
    hex!("449120c6e320ef3e9fbfa2316e5f2d2e1e6dd37d8ff5d086d5d2db7d42aff0a1")
);
accumulated_test!(
    accumulated_768_100,
    ml_kem_768,
    100,
    hex!("8d65b902f28edc683cebee2872962fd165a4d197c9e24ec74caa4470270df0b7")
);
accumulated_test!(
    accumulated_1024_100,
    ml_kem_1024,
    100,
    hex!("c3ffe9ebecfa479c142656cbfbc6417efa05b77e994fe538eef4daed166363df")
);
accumulated_test!(
    accumulated_512_10k,
    ml_kem_512,
    10_000,
    hex!("705dcffc87f4e67e35a09dcaa31772e86f3341bd3ccf1e78a5fef99ae6a35a13"),
    "long-running"
);
accumulated_test!(
    accumulated_768_10k,
    ml_kem_768,
    10_000,
    hex!("f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1"),
    "long-running"
);
accumulated_test!(
    accumulated_1024_10k,
    ml_kem_1024,
    10_000,
    hex!("e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5"),
    "long-running"
);
accumulated_test!(
    accumulated_512_1m,
    ml_kem_512,
    1_000_000,
    hex!("21dd330d4355f2ae2876b9fa2b9de62ecaf76aca1d598de8db2b467d36e36a6a"),
    "long-running"
);
accumulated_test!(
    accumulated_768_1m,
    ml_kem_768,
    1_000_000,
    hex!("3b108396a277f2952ff3243a985c9709bcb95788c39b7b36a2c4e19d1a41e51e"),
    "long-running"
);
accumulated_test!(
    accumulated_1024_1m,
    ml_kem_1024,
    1_000_000,
    hex!("6377c4f0ecfdb32e63f7b58227960828784fe0b3e0e5e5e9f77be300f003512a"),
    "long-running"
);
