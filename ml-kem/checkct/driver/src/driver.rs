use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use ml_kem::{B32, EncapsulationKey, MlKem512};

#[checkct]
pub fn encapsulate_deterministic() {
    // The generated BINSEC script references both RNG hooks unconditionally.
    black_box(PublicRng.next_u32());
    let ek = EncapsulationKey::<MlKem512>::new(&[0u8; 800].into()).unwrap();
    let mut m = B32::default();
    PrivateRng.fill_bytes(&mut m);
    black_box(ek.encapsulate_deterministic(&m));
}
