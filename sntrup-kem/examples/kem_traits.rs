//! Streamlined NTRU Prime through the [`kem`](https://docs.rs/kem) crate traits.

use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};
use rand_core::CryptoRng;
use sntrup_kem::kem::{
    Decapsulate, DecapsulationKey, Decapsulator, Encapsulate, EncapsulationKey, Generate, Kem,
    KemSizes, KeyExport, Sntrup653Params, Sntrup761Params, Sntrup1277Params, TryKeyInit,
};

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
    let Ok(mut rng) = StdRng::try_from_rng(&mut SysRng) else {
        return;
    };

    for (ct, ss) in [
        round_trip::<Sntrup653Params>(&mut rng),
        round_trip::<Sntrup761Params>(&mut rng),
        round_trip::<Sntrup1277Params>(&mut rng),
    ] {
        assert!(ct > 0);
        assert_eq!(ss, 32);
    }

    let dk = DecapsulationKey::<Sntrup761Params>::generate_from_rng(&mut rng);
    let exported = dk.encapsulation_key().to_bytes();
    let Ok(imported) = EncapsulationKey::<Sntrup761Params>::new(&exported) else {
        return;
    };
    assert_eq!(&imported, dk.encapsulation_key());
}
