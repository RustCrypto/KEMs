//! arithmetic mod q

use crate::{
    const_time::i32_mod_u14,
    params::{NtruCommon, NtruLPrime},
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

impl<Params: NtruCommon> Fq<Params> {
    pub(super) fn new_i32(n: i32) -> Self {
        debug_assert!(n <= Params::Q12 as i32);
        debug_assert!(n >= -(Params::Q12 as i32));
        Fq {
            inner: n as i16,
            marker: PhantomData,
        }
    }
    #[must_use]
    pub fn new_i16(n: i16) -> Self {
        debug_assert!(n <= Params::Q12 as i16);
        debug_assert!(n >= -(Params::Q12 as i16));
        Fq {
            inner: n,
            marker: PhantomData,
        }
    }

    pub(super) fn new_i8(n: i8) -> Self {
        let n = n as i16;
        debug_assert!(n <= Params::Q12 as i16);
        debug_assert!(n >= -(Params::Q12 as i16));
        Fq {
            inner: n,
            marker: PhantomData,
        }
    }

    /// x must not be close to top int32
    #[must_use]
    pub const fn freeze(x: i32) -> Self {
        debug_assert!(x <= i32::MAX - Params::Q12 as i32);
        Fq {
            inner: i32_mod_u14(x + Params::Q12 as i32, Params::Q).wrapping_sub(Params::Q12) as i16,
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
impl<Params: NtruLPrime> Fq<Params> {
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
    use hybrid_array::sizes::{U1013, U1277, U653, U761, U857, U953};
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
        (i32::MIN..i32::MAX - Streamlined::<U1277>::Q as i32)
            .into_par_iter()
            .chunks(0xffffff)
            .for_each(|chunk| {
                print!(".");
                stdout().flush().unwrap();
                for i in chunk {
                    // all viable Q values from section 3.4 of NTRU NIST submission
                    assert_eq!(
                        *Fq::<Streamlined::<U653>>::freeze(i),
                        naive_freeze(i, Streamlined::<U653>::Q)
                    );
                    assert_eq!(
                        *Fq::<Streamlined::<U761>>::freeze(i),
                        naive_freeze(i, Streamlined::<U761>::Q)
                    );
                    assert_eq!(
                        *Fq::<Streamlined::<U857>>::freeze(i),
                        naive_freeze(i, Streamlined::<U857>::Q)
                    );
                    assert_eq!(
                        *Fq::<Streamlined::<U953>>::freeze(i),
                        naive_freeze(i, Streamlined::<U953>::Q)
                    );
                    assert_eq!(
                        *Fq::<Streamlined::<U1013>>::freeze(i),
                        naive_freeze(i, Streamlined::<U1013>::Q)
                    );
                    assert_eq!(
                        *Fq::<Streamlined::<U1277>>::freeze(i),
                        naive_freeze(i, Streamlined::<U1277>::Q)
                    );
                }
            });
    }
    #[test]
    fn test_f_s653_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Streamlined::<U653>::Q12 as i32)..0).chain(1..=Streamlined::<U653>::Q12 as i32)
        {
            assert_eq!(
                *Fq::<Streamlined::<U653>>::freeze(
                    i * *Fq::<Streamlined::<U653>>::recip(Fq::<Streamlined::<U653>>::freeze(i))
                        as i32
                ),
                1
            );
        }
    }
    #[test]
    fn test_f_s761_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Streamlined::<U761>::Q12 as i32)..0).chain(1..=Streamlined::<U761>::Q12 as i32)
        {
            assert_eq!(
                *Fq::<Streamlined::<U761>>::freeze(
                    i * *Fq::<Streamlined::<U761>>::recip(Fq::<Streamlined::<U761>>::freeze(i))
                        as i32
                ),
                1
            );
        }
    }
    #[test]
    fn test_f_s857_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Streamlined::<U857>::Q12 as i32)..0).chain(1..=Streamlined::<U857>::Q12 as i32)
        {
            assert_eq!(
                *Fq::<Streamlined::<U857>>::freeze(
                    i * *Fq::<Streamlined::<U857>>::recip(Fq::<Streamlined::<U857>>::freeze(i))
                        as i32
                ),
                1
            );
        }
    }
    #[test]
    fn test_f_s953_recip() {
        // note that zero has no recip, so we skip zero
        for i in (-(Streamlined::<U953>::Q12 as i32)..0).chain(1..=Streamlined::<U953>::Q12 as i32)
        {
            assert_eq!(
                *Fq::<Streamlined::<U953>>::freeze(
                    i * *Fq::<Streamlined::<U953>>::recip(Fq::<Streamlined::<U953>>::freeze(i))
                        as i32
                ),
                1
            );
        }
    }
    #[test]
    fn test_f_s1013_recip() {
        // note that zero has no recip, so we skip zero
        for i in
            (-(Streamlined::<U1013>::Q12 as i32)..0).chain(1..=Streamlined::<U1013>::Q12 as i32)
        {
            assert_eq!(
                *Fq::<Streamlined::<U1013>>::freeze(
                    i * *Fq::<Streamlined::<U1013>>::recip(Fq::<Streamlined::<U1013>>::freeze(i))
                        as i32
                ),
                1
            );
        }
    }
    #[test]
    fn test_f_s1277_recip() {
        // note that zero has no recip, so we skip zero
        for i in
            (-(Streamlined::<U1277>::Q12 as i32)..0).chain(1..=Streamlined::<U1277>::Q12 as i32)
        {
            assert_eq!(
                *Fq::<Streamlined::<U1277>>::freeze(
                    i * *Fq::<Streamlined::<U1277>>::recip(Fq::<Streamlined::<U1277>>::freeze(i))
                        as i32
                ),
                1
            );
        }
    }
}
