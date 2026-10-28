use crate::rng::{PrivateRng, PublicRng};
use checkct_macros::checkct;
use core::hint::black_box;
use ml_kem::{B32, EncapsulationKey};

macro_rules! check_encapsulation {
    ($name:ident, $kem:ident, $key_len:expr) => {
        #[checkct]
        pub fn $name() {
            // The generated BINSEC script references both RNG hooks.
            black_box(PublicRng.next_u32());

            // One accepted public key per parameter set. Keeping rho concrete
            // avoids symbolic SHAKE/rejection sampling during public-key expansion.
            let ek = EncapsulationKey::<ml_kem::$kem>::new(&[0u8; $key_len].into()).unwrap();
            let mut m = B32::default();
            PrivateRng.fill_bytes(&mut m);
            black_box(ek.encapsulate_deterministic(&m));
        }
    };
}

check_encapsulation!(encapsulate_deterministic, MlKem512, 800);
check_encapsulation!(encapsulate_768, MlKem768, 1184);
check_encapsulation!(encapsulate_1024, MlKem1024, 1568);

module_lattice::define_field!(KyberField, u16, u32, u64, 3329);
module_lattice::define_field!(DilithiumField, u32, u64, u128, 8_380_417);

#[checkct]
pub fn small_reduce_u16() {
    use module_lattice::Field;
    black_box(PublicRng.next_u32());
    black_box(KyberField::small_reduce(PrivateRng.next_u32() as u16));
}

#[checkct]
pub fn small_reduce_u32() {
    use module_lattice::Field;
    black_box(PublicRng.next_u32());
    black_box(DilithiumField::small_reduce(PrivateRng.next_u32()));
}
