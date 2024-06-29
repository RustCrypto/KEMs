/// return -1 if x!=0; else return 0
#[must_use]
pub const fn i16_nonzero_mask(x: i16) -> i32 {
    let u: u16 = x as u16;
    let mut v: u32 = u as u32;
    v = (!v).wrapping_add(1); // in reference code they did v = -v;
    v >>= 31;
    ((!v).wrapping_add(1)) as i32
}

/// return -1 if x<0; otherwise return 0
#[must_use]
pub const fn i16_negative_mask(x: i16) -> i32 {
    let mut u: u16 = x as u16;
    u >>= 15;
    -(u as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i16_nonzero_mask_exhaust() {
        assert_eq!(i16_nonzero_mask(0), 0);
        for i in 1..i16::MAX {
            assert_eq!(i16_nonzero_mask(i), -1);
        }
        for i in i16::MIN..-1 {
            assert_eq!(i16_nonzero_mask(i), -1);
        }
    }
    #[test]
    fn test_i16_negative_mask() {
        for i in 0..i16::MAX {
            assert_eq!(i16_negative_mask(i), 0);
        }
        for i in i16::MIN..-1 {
            assert_eq!(i16_negative_mask(i), -1);
        }
    }
}
