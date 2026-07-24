//! Small branchless helpers shared by the R3 and Rq reciprocal loops.
//!
//! Both extended-GCD reciprocals (`r3::reciprocal`, `rq::reciprocal3`) drive the
//! same constant-time control flow, so these primitives live in one place.

/// Branchless conditional swap: returns `(y, x)` when `mask == -1`, `(x, y)` when `mask == 0`.
#[inline(always)]
pub(crate) fn swap_int(x: isize, y: isize, mask: isize) -> (isize, isize) {
    let t = mask & (x ^ y);
    (x ^ t, y ^ t)
}

/// Branchless sign test: returns `-1` (all ones) when `x < y`, else `0`.
#[inline(always)]
pub(crate) fn smaller_mask(x: isize, y: isize) -> isize {
    (x - y) >> 31
}
