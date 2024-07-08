//! arithmetic mod 3

use super::fq::Fq;
use crate::const_time::i32_mod_u14;
use core::ops::Deref;

/// always represented as -1,0,1
#[derive(Eq, PartialEq, Debug, Copy, Clone, Default)]
pub struct Small(i8);

impl Small {
    pub const ZERO: Small = Small(0);
    pub const ONE: Small = Small(1);
    pub const MONE: Small = Small(-1);

    pub(super) fn new_i32(n: i32) -> Self {
        debug_assert!(n < 2);
        debug_assert!(n > -2);
        Small(n as i8)
    }
    #[must_use]
    pub fn new_i8(n: i8) -> Self {
        debug_assert!(n < 2);
        debug_assert!(n > -2);
        Small(n)
    }

    #[must_use]
    pub const fn freeze(x: i16) -> Self {
        Small((i32_mod_u14((x as i32) + 1, 3).wrapping_sub(1)) as i8)
    }
}

/// the benefit is from outside, anyone can access the inner value as number,
/// but no one can modify it without refreezing
impl Deref for Small {
    type Target = i8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Q> From<Fq<Q>> for Small {
    fn from(value: Fq<Q>) -> Self {
        Small::freeze(*value)
    }
}

#[cfg(test)]
mod test {
    use super::Small;
    fn naive_freeze(x: i16) -> i8 {
        // returns values in the set [-2, 2]
        let res = (x % 3) as i8;
        if res > 1 {
            return res - 3;
        }
        if res < -1 {
            return res + 3;
        }
        res
    }
    #[test]
    fn test_freeze() {
        for i in i16::MIN..i16::MAX {
            assert_eq!(*Small::freeze(i), naive_freeze(i));
        }
    }
}
