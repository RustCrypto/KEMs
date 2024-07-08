//! The parameters for NTRU prime as described in section 3.4
use core::marker::PhantomData;

use hybrid_array::{
    sizes::{
        U1, U1007, U1013, U1152, U1158, U1277, U1317, U1322, U1423, U1505, U1623, U1815, U2, U2067,
        U256, U3, U32, U4, U653, U761, U8, U857, U865, U953, U994,
    },
    ArraySize,
};
pub type I = U256;
pub type TopBytes = <I as core::ops::Div<U2>>::Output;
pub type SeedBytes = U32;

pub trait NtruCommonCore: 'static {
    type RoundedBytes: ArraySize;
    const Q: u16;
    const W: i16;
}

pub trait NtruCommon: NtruCommonCore + 'static {
    type P: ArraySize;
    /// P + 1
    type P1: ArraySize;
    /// P + P - 1
    type PPM1: ArraySize;
    type SmallBytes: ArraySize;
    /// (Q - 1) / 2
    const Q12: u16;
    type CipherTextBytes: ArraySize;
    type SecretKeyBytes: ArraySize;
    type PublicKeyBytes: ArraySize;
    type InputsBytes: ArraySize;
}

pub trait NtruLPrime: NtruCommon {
    const TAU0: i16;
    const TAU1: i32;
    const TAU2: i32;
    const TAU3: i32;
}

pub trait StreamlinedNtru: NtruCommon {
    type RqBytes: ArraySize;
}
macro_rules! impl_ntru_common_core {
    ($ty:ty, $r: ty, $q: literal, $w: literal) => {
        impl NtruCommonCore for $ty {
            type RoundedBytes = $r;
            const Q: u16 = $q;
            const W: i16 = $w;
        }
    };
}

macro_rules! impl_ntru_lprime {
    ($P:ty, $tau0: literal, $tau1: literal, $tau2: literal, $tau3: literal ) => {
        impl NtruLPrime for Lpr<$P> {
            const TAU0: i16 = $tau0;
            const TAU1: i32 = $tau1;
            const TAU2: i32 = $tau2;
            const TAU3: i32 = $tau3;
        }
        impl NtruCommon for Lpr<$P> {
            type P = $P;
            /// `P + 1`
            type P1 = <$P as core::ops::Add<U1>>::Output;
            /// `P + P - 1`
            type PPM1 = <<$P as core::ops::Add<$P>>::Output as core::ops::Sub<U1>>::Output;
            type SmallBytes = <<$P as core::ops::Add<U3>>::Output as core::ops::Div<U4>>::Output;
            type InputsBytes = <I as core::ops::Div<U8>>::Output;
            type PublicKeyBytes =
                <SeedBytes as core::ops::Add<<Lpr<$P> as NtruCommonCore>::RoundedBytes>>::Output;
            type CipherTextBytes =
                <<Lpr<$P> as NtruCommonCore>::RoundedBytes as core::ops::Add<TopBytes>>::Output;
            type SecretKeyBytes = Self::SmallBytes;
            const Q12: u16 = (<Streamlined<$P>>::Q - 1) / 2;
        }
    };
}

macro_rules! impl_streamlined_ntru {
    ($P:ty, $rq: ty) => {
        impl StreamlinedNtru for Streamlined<$P> {
            type RqBytes = $rq;
        }
        impl NtruCommon for Streamlined<$P> {
            type P = $P;
            /// `P + 1`
            type P1 = <$P as core::ops::Add<U1>>::Output;
            /// `P + P - 1`
            type PPM1 = <<$P as core::ops::Add<$P>>::Output as core::ops::Sub<U1>>::Output;
            /// `(P + 3) / 4`
            type SmallBytes = <<$P as core::ops::Add<U3>>::Output as core::ops::Div<U4>>::Output;
            type InputsBytes = Self::SmallBytes;
            type PublicKeyBytes = <Streamlined<$P> as StreamlinedNtru>::RqBytes;
            type CipherTextBytes = <Streamlined<$P> as NtruCommonCore>::RoundedBytes;
            // `SmallBytes * 2`
            type SecretKeyBytes = <Self::SmallBytes as core::ops::Mul<U2>>::Output;
            const Q12: u16 = (<Streamlined<$P>>::Q - 1) / 2;
        }
    };
}

pub struct Streamlined<P: ArraySize>(PhantomData<P>);
pub struct Lpr<P: ArraySize>(PhantomData<P>);

impl_ntru_common_core!(Streamlined<U653>, U865, 4621, 288);
impl_ntru_common_core!(Streamlined<U761>, U1007, 4591, 286);
impl_ntru_common_core!(Streamlined<U857>, U1152, 5167, 322);
impl_ntru_common_core!(Streamlined<U953>, U1317, 6343, 396);
impl_ntru_common_core!(Streamlined<U1013>, U1423, 7177, 448);
impl_ntru_common_core!(Streamlined<U1277>, U1815, 7879, 492);
impl_ntru_common_core!(Lpr<U653>, U865, 4621, 252);
impl_ntru_common_core!(Lpr<U761>, U1007, 4591, 250);
impl_ntru_common_core!(Lpr<U857>, U1152, 5167, 281);
impl_ntru_common_core!(Lpr<U953>, U1317, 6343, 345);
impl_ntru_common_core!(Lpr<U1013>, U1423, 7177, 392);
impl_ntru_common_core!(Lpr<U1277>, U1815, 7879, 429);

impl_streamlined_ntru!(U653, U994);
impl_streamlined_ntru!(U761, U1158);
impl_streamlined_ntru!(U857, U1322);
impl_streamlined_ntru!(U953, U1505);
impl_streamlined_ntru!(U1013, U1623);
impl_streamlined_ntru!(U1277, U2067);

impl_ntru_lprime!(U653, 2175, 113, 2031, 290);
impl_ntru_lprime!(U761, 2156, 114, 2007, 287);
impl_ntru_lprime!(U857, 2433, 101, 2265, 324);
impl_ntru_lprime!(U953, 2997, 82, 2798, 400);
impl_ntru_lprime!(U1013, 3367, 73, 3143, 449);
impl_ntru_lprime!(U1277, 3724, 66, 3469, 469);
