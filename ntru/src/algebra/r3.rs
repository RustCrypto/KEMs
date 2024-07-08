use super::{f3::Small, rq::Rq};
use crate::{
    const_time::{crypto_sort_u32, i16_negative_mask, i16_nonzero_mask},
    params::NtruCommon,
};
use hybrid_array::{typenum::Unsigned, Array};
use rand_core::CryptoRngCore;

pub struct R3<Params: NtruCommon>(pub Array<Small, Params::P>);

impl<Params: NtruCommon> Default for R3<Params> {
    fn default() -> Self {
        Self(Array::default())
    }
}

impl<Params: NtruCommon> R3<Params> {
    pub fn weight_w_mask(&self) -> i32 {
        let mut weight = 0i16;
        for s in &self.0 {
            weight += (**s & 1) as i16;
        }
        i16_nonzero_mask(weight - Params::W)
    }
    /// returns self * other in `R3`
    /// # Panics
    ///  this function should naver panic
    #[must_use]
    pub fn mult(&self, other: &Self) -> Self {
        let p = Params::P::to_usize();
        let mut fg = Array::<Small, Params::PPM1>::default();
        //TODO maybe map?
        for i in 0..p {
            let mut result = Small::default();
            for j in 0..=i {
                result = Small::freeze(*result as i16 + *self.0[j] as i16 * *other.0[i - j] as i16);
            }
            fg[i] = result;
        }
        //TODO maybe map?
        for i in p..p + p - 1 {
            let mut result = Small::default();
            for j in i - p + 1..p {
                result = Small::freeze(*result as i16 + *self.0[j] as i16 * *other.0[i - j] as i16);
            }
            fg[i] = result;
        }
        for i in (p..=p + p - 2).rev() {
            fg[i - p] = Small::freeze(*fg[i - p] as i16 + *fg[i] as i16);
            fg[i - p + 1] = Small::freeze(*fg[i - p + 1] as i16 + *fg[i] as i16);
        }
        Self(Array::try_from(&fg[..p]).unwrap())
    }

    /// Returns Tuple of recip and 0 if recip succeeded or tuple of garbage filled R3 and -1 if recip failed;
    pub fn recip(&self) -> (Self, i32) {
        let mut out = R3::default();
        let ret = self.recip_buffer(&mut out);
        (out, ret)
    }
    /// Fills `out` with of recip and returns 0 if recip succeeded or Fills `out` with
    /// garbage and returns -1 if recip failed
    pub fn recip_buffer(&self, out: &mut Self) -> i32 {
        let mut f = Array::<Small, Params::P1>::default();
        let mut g = Array::<Small, Params::P1>::default();
        let mut v = Array::<Small, Params::P1>::default();
        let mut r = Array::<Small, Params::P1>::default();
        r[0] = Small::ONE;
        f[0] = Small::ONE;
        f[Params::P::USIZE - 1] = Small::MONE;
        f[Params::P::USIZE] = Small::MONE;
        for i in 0..Params::P::USIZE {
            g[Params::P::USIZE - 1 - i] = self.0[i];
        }
        let mut delta = 1;
        for _ in 0..Params::PPM1::USIZE {
            for i in (1..=Params::P::USIZE).rev() {
                v[i] = v[i - 1];
            }
            v[0] = Small::ZERO;
            let sign = -*g[0] as i16 * *f[0] as i16;
            let swap = i16_negative_mask(-delta as i16) & i16_nonzero_mask(*g[0] as i16);
            delta ^= swap & (delta ^ -delta);
            delta += 1;
            for i in 0..Params::P1::USIZE {
                let t = swap & (*f[i] ^ *g[i]) as i32;
                f[i] = Small::new_i32(*f[i] as i32 ^ t);
                g[i] = Small::new_i32(*g[i] as i32 ^ t);
                let t = swap & (*v[i] ^ *r[i]) as i32;
                v[i] = Small::new_i32(*v[i] as i32 ^ t);
                r[i] = Small::new_i32(*r[i] as i32 ^ t);
            }
            //TODO merge the two loops?
            for i in 0..Params::P1::USIZE {
                g[i] = Small::freeze(*g[i] as i16 + sign * *f[i] as i16);
            }
            for i in 0..Params::P1::USIZE {
                r[i] = Small::freeze(*r[i] as i16 + sign * *v[i] as i16);
            }
            for i in 0..Params::P::USIZE {
                g[i] = g[i + 1];
            }
            g[Params::P::USIZE] = Small::ZERO;
        }
        let sign = *f[0];
        for i in 0..Params::P::USIZE {
            out.0[i] = Small::new_i8(sign * *v[Params::P::USIZE - 1 - i]);
        }
        i16_nonzero_mask(delta as i16)
    }
    /// sorting to generate short polynomial
    pub fn short_from_list(data_in: &Array<u32, Params::P>) -> Self {
        let mut l = Array::<u32, Params::P>::default();
        for i in 0..Params::W as usize {
            l[i] = data_in[i] & (-2i32 as u32);
        }
        for i in Params::W as usize..Params::P::USIZE {
            l[i] = (data_in[i] & (-3i32 as u32)) | 1;
        }
        crypto_sort_u32(&mut l);
        let mut out = Array::<Small, Params::P>::default();
        for i in 0..Params::P::USIZE {
            out[i] = Small::new_i32((l[i] & 3) as i32 - 1);
        }
        R3(out)
    }

    pub fn short_random(rng: &mut impl CryptoRngCore) -> Self {
        let mut l = Array::<u32, Params::P>::default();
        l.iter_mut().for_each(|x: &mut u32| *x = rng.next_u32());
        Self::short_from_list(&l)
    }
    pub fn small_random(rng: &mut impl CryptoRngCore) -> Self {
        let mut ret = R3::default();
        ret.small_random_buffer(rng);
        ret
    }
    pub fn small_random_buffer(&mut self, rng: &mut impl CryptoRngCore) {
        self.0.iter_mut().for_each(|x: &mut Small| {
            *x = Small::new_i32((((rng.next_u32() & 0x3fffffff) * 3) >> 30) as i32 - 1);
        });
    }
}

impl<P: NtruCommon> From<Rq<P>> for R3<P> {
    fn from(value: Rq<P>) -> Self {
        Self(value.0.iter().map(|fq| Into::<Small>::into(*fq)).collect())
    }
}
