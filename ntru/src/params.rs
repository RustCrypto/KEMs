//! The parameters for NTRU prime as described in section 3.4
//! SX is parameters for Streamlined NTRU Prime with `p = x`.
//! Lx is parameters for `NTRULPRime` with `p = x`;

use hybrid_array::{
    sizes::{U1277, U1278, U1305, U1521, U1713, U1905, U2025, U2552},
    typenum::{U1013, U1014, U653, U654, U761, U762, U857, U858, U953, U954},
    ArraySize,
};

pub trait NtruCommon: 'static {
    type P: ArraySize;
    /// P + 1
    type P1: ArraySize;
    /// P + P - 1
    type PPM1: ArraySize;
    const Q: u16;
    const W: i16;
}

pub trait NtruLRPrime {
    const DELTA: u16;
    const TAU0: i16;
    const TAU1: i32;
    const TAU2: i32;
    const TAU3: i32;
}

macro_rules! impl_ntru_common {
    ($ty:ident, $p: ident, $p1: ident, $ppm1: ident, $q: literal, $w: literal ) => {
        impl NtruCommon for $ty {
            type P = $p;
            type P1 = $p1;
            type PPM1 = $ppm1;
            const Q: u16 = $q;
            const W: i16 = $w;
        }
    };
}

macro_rules! impl_ntru_lrprime {
    ($ty:ident, $delta: literal, $tau0: literal, $tau1: literal, $tau2: literal, $tau3: literal ) => {
        impl NtruLRPrime for $ty {
            const DELTA: u16 = $delta;
            const TAU0: i16 = $tau0;
            const TAU1: i32 = $tau1;
            const TAU2: i32 = $tau2;
            const TAU3: i32 = $tau3;
        }
    };
}

pub struct S653;
pub struct S761;
pub struct S857;
pub struct S953;
pub struct S1013;
pub struct S1277;
pub struct L653;
pub struct L761;
pub struct L857;
pub struct L953;
pub struct L1013;
pub struct L1277;

impl_ntru_common!(S653, U653, U654, U1305, 4621, 288);
impl_ntru_common!(S761, U761, U762, U1521, 4591, 286);
impl_ntru_common!(S857, U857, U858, U1713, 5167, 322);
impl_ntru_common!(S953, U953, U954, U1905, 6343, 396);
impl_ntru_common!(S1013, U1013, U1014, U2025, 7177, 448);
impl_ntru_common!(S1277, U1277, U1278, U2552, 7879, 429);
impl_ntru_common!(L653, U653, U654, U1305, 4621, 252);
impl_ntru_common!(L761, U761, U762, U1521, 4591, 250);
impl_ntru_common!(L857, U857, U858, U1713, 5167, 281);
impl_ntru_common!(L953, U953, U954, U1905, 6343, 345);
impl_ntru_common!(L1013, U1013, U1014, U2025, 7177, 392);
impl_ntru_common!(L1277, U1277, U1278, U2552, 7879, 429);
impl_ntru_lrprime!(L653, 289, 2175, 113, 2031, 290);
impl_ntru_lrprime!(L761, 292, 2156, 114, 2007, 287);
impl_ntru_lrprime!(L857, 329, 2433, 101, 2265, 324);
impl_ntru_lrprime!(L953, 404, 2997, 82, 2798, 400);
impl_ntru_lrprime!(L1013, 450, 3367, 73, 3143, 449);
impl_ntru_lrprime!(L1277, 502, 3724, 66, 3469, 469);
