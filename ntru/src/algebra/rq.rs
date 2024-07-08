use super::{f3::Small, fq::Fq, r3::R3};
use crate::{
    const_time::{i16_negative_mask, i16_nonzero_mask},
    params::NtruCommon,
};
use hybrid_array::{typenum::Unsigned, Array};

pub struct Rq<Params: NtruCommon>(pub Array<Fq<Params>, Params::P>);

impl<Params: NtruCommon> Default for Rq<Params> {
    fn default() -> Self {
        Self(Array::default())
    }
}

impl<Params: NtruCommon> Rq<Params> {
    /// calculates self * other in the ring Rq
    /// # Panics
    /// This functions should never panic
    #[must_use]
    pub fn mult_r3(&self, other: &R3<Params>) -> Self {
        let p = Params::P::USIZE;
        let mut fg = Array::<Fq<Params>, Params::PPM1>::default();
        //TODO maybe map?
        for i in 0..p {
            let mut result = Fq::<Params>::default();
            for j in 0..=i {
                result = Fq::freeze(*result as i32 + *self.0[j] as i32 * *other.0[i - j] as i32);
            }
            fg[i] = result;
        }
        //TODO maybe map? for perfomance
        for i in p..p + p - 1 {
            let mut result = Fq::<Params>::default();
            for j in i - p + 1..p {
                result = Fq::freeze(*result as i32 + *self.0[j] as i32 * *other.0[i - j] as i32);
            }
            fg[i] = result;
        }
        for i in (p..=p + p - 2).rev() {
            fg[i - p] = Fq::freeze(*fg[i - p] as i32 + *fg[i] as i32);
            fg[i - p + 1] = Fq::freeze(*fg[i - p + 1] as i32 + *fg[i] as i32);
        }
        Self(Array::try_from(&fg[..p]).unwrap())
    }
    /// returns 3*self in Rq
    #[must_use]
    pub fn mult3(&self) -> Self {
        let mut res = Array::<Fq<Params>, Params::P>::default();
        for i in 0..Params::P::USIZE {
            res[i] = Fq::freeze(*self.0[i] as i32 * 3);
        }
        Rq(res)
    }
    /// Returns Tuple of `1/3*data_in` and 0 if recip succeeded or tuple of garbage filled Fq and -1 if recip failed;
    pub fn recip3(data_in: &R3<Params>) -> (Self, i32) {
        let mut f = Array::<Fq<Params>, Params::P1>::default();
        let mut g = Array::<Fq<Params>, Params::P1>::default();
        let mut v = Array::<Fq<Params>, Params::P1>::default();
        let mut r = Array::<Fq<Params>, Params::P1>::default();
        r[0] = Fq::recip(Fq::new_i8(3));
        f[0] = Fq::new_i8(1);
        f[Params::P::USIZE - 1] = Fq::new_i8(-1);
        f[Params::P::USIZE] = Fq::new_i8(-1);
        for i in 0..Params::P::USIZE {
            g[Params::P::USIZE - 1 - i] = Fq::new_i8(*data_in.0[i]);
        }
        let mut delta = 1;
        for _ in 0..Params::PPM1::USIZE {
            for i in (1..=Params::P::USIZE).rev() {
                v[i] = v[i - 1];
            }
            v[0] = Fq::new_i8(0);
            let swap = i16_negative_mask(-delta as i16) & i16_nonzero_mask(*g[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            for i in 0..Params::P1::USIZE {
                let t = swap & (*f[i] ^ *g[i]) as i32;
                f[i] = Fq::new_i32(*f[i] as i32 ^ t);
                g[i] = Fq::new_i32(*g[i] as i32 ^ t);
                let t = swap & (*v[i] ^ *r[i]) as i32;
                v[i] = Fq::new_i32(*v[i] as i32 ^ t);
                r[i] = Fq::new_i32(*r[i] as i32 ^ t);
            }
            let f0 = *f[0] as i32;
            let g0 = *g[0] as i32;
            //TODO merge the two loops?
            for i in 0..Params::P1::USIZE {
                g[i] = Fq::freeze(f0 * *g[i] as i32 - g0 * *f[i] as i32);
            }
            for i in 0..Params::P1::USIZE {
                r[i] = Fq::freeze(f0 * *r[i] as i32 - g0 * *v[i] as i32);
            }
            for i in 0..Params::P::USIZE {
                g[i] = g[i + 1];
            }
            g[Params::P::USIZE] = Fq::new_i8(0);
        }
        let scale = *Fq::<Params>::recip(f[0]) as i32;
        let mut out = Array::<Fq<_>, Params::P>::default();
        for i in 0..Params::P::USIZE {
            out[i] = Fq::freeze(scale * *v[Params::P::USIZE - 1 - i] as i32);
        }
        (Rq(out), i16_nonzero_mask(delta as i16))
    }
    /// rounded polynomials mod q
    #[must_use]
    pub fn round(&self) -> Self {
        let mut out = Array::<Fq<_>, Params::P>::default();
        for i in 0..Params::P::USIZE {
            out[i] = Fq::new_i16(*self.0[i] - *Small::freeze(*self.0[i]) as i16);
        }
        Rq(out)
    }
}
