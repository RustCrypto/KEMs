//! arithmetic mod q

use crate::{
    const_time::i32_mod_u14,
    params::{NtruCommon, NtruLRPrime},
};
use core::marker::PhantomData;
use core::ops::Deref;

/// always represented as `-F::Q12...F::Q12`
#[derive(Copy, Clone)]
pub struct Inner<Params> {
    inner: i16,
    marker: PhantomData<Params>,
}

impl<P> Default for Inner<P> {
    fn default() -> Self {
        Self {
            inner: 0,
            marker: PhantomData,
        }
    }
}
/// we need this type for the following reason, there is an expressivity
/// problem, that is `FqInner<T>` implements only `Clone` and `Copy` if
/// `T: Clone + Copy`. In this case, we do not require `T:  Clone + Copy`
/// So to bypass this we can:
/// A- manually implment Clone + Copy
/// B - Add Clone+Copy  a trait bounds for T
/// C - This trick which is saying that we use static reference to T which is always Clone + Copy
/// D - Use third party crates like derivatives.
pub type Fq<Params> = Inner<&'static Params>;

/// the benefit is from outside, anyone can access the inner value as number,
/// but no one can modify it without refreezing
impl<Params> Deref for Fq<Params> {
    type Target = i16;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
// TODO should we have `T: Clone + Copy` or should we specify
// trait bounds for the derive (either by manual
// implementation or via derivative)
impl<Params: NtruCommon> Fq<Params> {
    const Q12: u16 = ((Params::Q - 1) / 2);
    pub(super) fn new_i32(n: i32) -> Self {
        debug_assert!(n < Self::Q12 as i32);
        debug_assert!(n > -(Self::Q12 as i32));
        Fq {
            inner: n as i16,
            marker: PhantomData,
        }
    }
    pub(super) fn new_i16(n: i16) -> Self {
        debug_assert!(n < Self::Q12 as i16);
        debug_assert!(n > -(Self::Q12 as i16));
        Fq {
            inner: n,
            marker: PhantomData,
        }
    }

    pub(super) fn new_i8(n: i8) -> Self {
        let n = n as i16;
        debug_assert!(n < Self::Q12 as i16);
        debug_assert!(n > -(Self::Q12 as i16));
        Fq {
            inner: n,
            marker: PhantomData,
        }
    }

    /// x must not be close to top int32
    #[must_use]
    pub const fn freeze(x: i32) -> Self {
        debug_assert!(x <= i32::MAX - Self::Q12 as i32);
        Fq {
            inner: i32_mod_u14(x + Self::Q12 as i32, Params::Q).wrapping_sub(Self::Q12) as i16,
            marker: PhantomData,
        }
    }
    /// caclucates the multiplicative inverse of a1
    /// a1 must not be zero
    #[must_use]
    pub const fn recip(a1: Self) -> Self {
        debug_assert!(a1.inner != 0);
        let mut i = 1;
        let mut ai = a1;
        while i < Params::Q - 2 {
            // we have to use `a1.0` instead of deref to maintian
            // the const status of the function
            ai = Fq::freeze(a1.inner as i32 * ai.inner as i32);
            i += 1;
        }
        ai
    }
}

///TODO tests for both funtions
impl<Params: NtruLRPrime + NtruCommon> Fq<Params> {
    #[must_use]
    pub const fn top(self) -> i8 {
        ((Params::TAU1 * (self.inner + Params::TAU0) as i32 + 16384) >> 15) as i8
    }
    #[must_use]
    pub const fn right(t: i8) -> Self {
        Fq::freeze(Params::TAU3 * t as i32 - Params::TAU2)
    }
}

#[cfg(test)]
mod test {
    use super::Fq;
    use crate::params::*;
    use rayon::prelude::*;
    use std::io::{stdout, Write};

    fn naive_freeze(x: i32, q: u16) -> i16 {
        let res = (x % (q as i32)) as i16;
        if res > ((q as i16 - 1) / 2) {
            return res - q as i16;
        }
        if res < -((q as i16 - 1) / 2) {
            return res + q as i16;
        }
        res
    }
    #[test]
    #[ignore = "Expected to take ~ 1 hour to finish on single core"]
    fn test_fq_freezer() {
        // if i is close to i32::Max we overflow and crash
        // we also need to chunk things a bit
        (i32::MIN..i32::MAX - S1277::Q as i32)
            .into_par_iter()
            .chunks(0xffffff)
            .for_each(|chunk| {
                print!(".");
                stdout().flush().unwrap();
                for i in chunk {
                    // all viable Q values from section 3.4 of NTRU NIST submission
                    assert_eq!(*Fq::<S653>::freeze(i), naive_freeze(i, S653::Q));
                    assert_eq!(*Fq::<S761>::freeze(i), naive_freeze(i, S761::Q));
                    assert_eq!(*Fq::<S857>::freeze(i), naive_freeze(i, S857::Q));
                    assert_eq!(*Fq::<S953>::freeze(i), naive_freeze(i, S953::Q));
                    assert_eq!(*Fq::<S1013>::freeze(i), naive_freeze(i, S1013::Q));
                    assert_eq!(*Fq::<S1277>::freeze(i), naive_freeze(i, S1277::Q));
                }
            })
    }
    #[test]
    fn test_f_s653_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Fq::<S653>::Q12 as i32)..0).chain(1..Fq::<S653>::Q12 as i32) {
            assert_eq!(
                *Fq::<S653>::freeze(i * *Fq::<S653>::recip(Fq::<S653>::freeze(i)) as i32),
                1
            )
        }
    }
    #[test]
    fn test_f_s761_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Fq::<S761>::Q12 as i32)..0).chain(1..Fq::<S761>::Q12 as i32) {
            assert_eq!(
                *Fq::<S761>::freeze(i * *Fq::<S761>::recip(Fq::<S761>::freeze(i)) as i32),
                1
            )
        }
    }
    #[test]
    fn test_f_s857_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Fq::<S857>::Q12 as i32)..0).chain(1..Fq::<S857>::Q12 as i32) {
            assert_eq!(
                *Fq::<S857>::freeze(i * *Fq::<S857>::recip(Fq::<S857>::freeze(i)) as i32),
                1
            )
        }
    }
    #[test]
    fn test_f_s953_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Fq::<S953>::Q12 as i32)..0).chain(1..Fq::<S953>::Q12 as i32) {
            assert_eq!(
                *Fq::<S953>::freeze(i * *Fq::<S953>::recip(Fq::<S953>::freeze(i)) as i32),
                1
            )
        }
    }
    #[test]
    fn test_f_s1013_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Fq::<S1013>::Q12 as i32)..0).chain(1..Fq::<S1013>::Q12 as i32) {
            assert_eq!(
                *Fq::<S1013>::freeze(i * *Fq::<S1013>::recip(Fq::<S1013>::freeze(i)) as i32),
                1
            )
        }
    }
    #[test]
    fn test_f_s1277_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Fq::<S1277>::Q12 as i32)..0).chain(1..Fq::<S1277>::Q12 as i32) {
            assert_eq!(
                *Fq::<S1277>::freeze(i * *Fq::<S1277>::recip(Fq::<S1277>::freeze(i)) as i32),
                1
            )
        }
    }
}
