use hybrid_array::typenum::Unsigned;
use rand_core::CryptoRngCore;

use crate::{
    algebra::{f3::Small, r3::R3, rq::Rq},
    params::NtruCommon,
};

///  (h,f,ginv) = `key_gen()`
pub fn key_gen<Params: NtruCommon>(
    rng: &mut impl CryptoRngCore,
) -> (Rq<Params>, R3<Params>, R3<Params>) {
    let mut g = R3::default();
    let mut ginv = R3::default();
    loop {
        g.small_random_buffer(rng);
        if g.recip_buffer(&mut ginv) == 0 {
            break;
        };
    }
    let f = R3::short_random(rng);
    let (finv, status) = Rq::recip3(&f);
    debug_assert_eq!(status, 0);
    let h = finv.mult_r3(&g);
    (h, f, ginv)
}

pub fn encrypt<Params: NtruCommon>(r: &R3<Params>, h: &Rq<Params>) -> Rq<Params> {
    let hr = h.mult_r3(r);
    hr.round()
}

pub fn decrypt<Params: NtruCommon>(
    c: &Rq<Params>,
    f: &R3<Params>,
    ginv: &R3<Params>,
) -> R3<Params> {
    let cf = c.mult_r3(f);
    let cf3 = cf.mult3();
    let e: R3<Params> = cf3.into();
    let ev = e.mult(ginv);
    let mask = ev.weight_w_mask() as i8;
    let mut r = R3::<Params>::default();
    for i in 0..Params::W as usize {
        r.0[i] = Small::new_i8(((*ev.0[i] ^ 1) & !mask) ^ 1);
    }
    for i in Params::W as usize..Params::P::USIZE {
        r.0[i] = Small::new_i8(*ev.0[i] & !mask);
    }
    r
}
