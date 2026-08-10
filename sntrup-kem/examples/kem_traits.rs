/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: MIT OR Apache-2.0
*/
//! Streamlined NTRU Prime through the [`kem`](https://docs.rs/kem) crate traits, in code that
//! is generic over the parameter set and would work just as well over any other KEM.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --example kem_traits --features kem
//! ```

use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};
use rand_core::CryptoRng;
use sntrup_kem::kem::{
    Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey, Generate, Kem,
    KemSizes, KeyExport, Sntrup653Params, Sntrup761Params, Sntrup1277Params, TryKeyInit,
};

/// Establish a shared secret and hand back the sizes involved.
///
/// Nothing here names Streamlined NTRU Prime: the same function compiles against any KEM
/// whose key types implement the `kem` traits.
fn round_trip<K>(mut rng: impl CryptoRng) -> (usize, usize)
where
    K: KemSizes
        + Kem<EncapsulationKey = EncapsulationKey<K>, DecapsulationKey = DecapsulationKey<K>>,
{
    let (dk, ek) = K::generate_keypair_from_rng(&mut rng);
    let (ct, sent) = ek.encapsulate_with_rng(&mut rng);
    let received = dk.decapsulate(&ct);
    assert_eq!(sent, received);
    (ct.len(), received.len())
}

fn main() {
    // A cryptographically secure generator, seeded once from the operating system.
    let mut rng = StdRng::try_from_rng(&mut SysRng).expect("the OS RNG is available");

    for (name, (ct, ss)) in [
        ("Sntrup653Params", round_trip::<Sntrup653Params>(&mut rng)),
        ("Sntrup761Params", round_trip::<Sntrup761Params>(&mut rng)),
        ("Sntrup1277Params", round_trip::<Sntrup1277Params>(&mut rng)),
    ] {
        println!("{name}: ciphertext {ct} bytes, shared secret {ss} bytes");
    }

    // Exporting or importing a key moves the whole key by value. Streamlined NTRU Prime keys
    // are small (at most a few kilobytes), so unlike KEMs with megabyte-scale keys this needs
    // no special thread-stack handling.
    let dk = DecapsulationKey::<Sntrup761Params>::generate_from_rng(&mut rng);
    let ek = dk.encapsulation_key();
    let exported = ek.to_bytes();
    let imported =
        EncapsulationKey::<Sntrup761Params>::new(&exported).expect("exported key round-trips");
    assert_eq!(&imported, dk.encapsulation_key());
    println!(
        "Sntrup761Params: exported and reimported {} bytes",
        exported.len()
    );
}
