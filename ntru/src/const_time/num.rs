//! best effort constant time divide

/// this function is optimized out at release mode
const fn debug_checks(m: u32, v: u32, x: u32) {
    debug_assert!(m > 0);
    debug_assert!(m < 16384);
    debug_assert!(v * m <= u32::pow(2, 31));
    debug_assert!(u32::pow(2, 31) < v * m + m);
    let x = x as u64;
    let m = m as u64;
    let v = v as u64;
    debug_assert!(x * v * m <= u64::pow(2, 31) * x);
    debug_assert!(u64::pow(2, 31) * x <= x * v * (m) + x * (m - 1));
}

/// constant time division
/// this function returns quotient and remainder
/// this function is problemetic according to original implmentation:
///     CPU division instruction typically takes time depending on x.
///     This software is designed to take time independent of x.
///     Time still varies depending on m; user must ensure that m is constant.
///     Time also varies on CPUs where multiplication is variable-time.
///     There could be more CPU issues.
///     There could also be compiler issues.
#[must_use]
pub const fn u32_divmod_u14(mut x: u32, m: u16) -> (u32, u16) {
    let m = m as u32;
    let mut v = 0x8000_0000_u32;
    v /= m;
    // the following asserts must be guaranteed by th caller of divmod
    debug_checks(m, v, x);
    let mut q = 0;
    let mut qpart = (((x as u64) * (v as u64)) >> 31) as u32;
    x -= qpart * m;
    q += qpart;
    debug_assert!(x < 49146);

    qpart = (((x as u64) * (v as u64)) >> 31) as u32;
    x -= qpart * m;
    q += qpart;

    x = x.wrapping_sub(m);
    q += 1;
    let mask = (!(x >> 31)).wrapping_add(1);
    x = x.wrapping_add(mask & m);
    q = q.wrapping_add(mask);
    debug_assert!(x <= m);
    (q, x as u16)
}

#[must_use]
pub const fn u32_div_u14(x: u32, m: u16) -> u32 {
    u32_divmod_u14(x, m).0
}

#[must_use]
pub const fn u32_mod_u14(x: u32, m: u16) -> u16 {
    u32_divmod_u14(x, m).1
}

#[must_use]
pub const fn i32_divmod_u14(x: i32, m: u16) -> (i32, u16) {
    let (mut uq, mut ur) = u32_divmod_u14(0x8000_0000_u32.wrapping_add(x as u32), m);
    let (uq2, ur2) = u32_divmod_u14(0x8000_0000, m);
    ur = ur.wrapping_sub(ur2);
    uq = uq.wrapping_sub(uq2);
    let mask = (!((ur >> 15) as u32)).wrapping_add(1);
    ur = ur.wrapping_add(mask as u16 & m);
    uq = uq.wrapping_add(mask);
    (uq as i32, ur)
}

#[must_use]
pub const fn i32_div_u14(x: i32, m: u16) -> i32 {
    i32_divmod_u14(x, m).0
}

#[must_use]
pub const fn i32_mod_u14(x: i32, m: u16) -> u16 {
    i32_divmod_u14(x, m).1
}
