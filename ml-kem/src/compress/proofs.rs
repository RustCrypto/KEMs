//! Scalar FIPS 203 compression and decompression, with symbolic inputs.

#![allow(
    clippy::integer_division_remainder_used,
    reason = "mathematical specifications"
)]

use super::{Compress, CompressionFactor, Elem};
use array::typenum::{U1, U4, U5, U6, U10, U11, U12};

const Q: u32 = 3329;

fn compression<D: CompressionFactor>() {
    let x: u16 = kani::any();
    kani::assume(u32::from(x) < Q);
    let mut actual = Elem::new(x);
    actual.compress::<D>();
    let scale = 1u32 << D::USIZE;
    // Integer division implements nearest rounding, with ties rounded up.
    let expected = ((u32::from(x) * scale + Q / 2) / Q) % scale;
    assert!(u32::from(actual.0) < scale);
    assert_eq!(u32::from(actual.0), expected);
}

fn decompression<D: CompressionFactor>() {
    let x: u16 = kani::any();
    let scale = 1u32 << D::USIZE;
    kani::assume(u32::from(x) < scale);
    let mut actual = Elem::new(x);
    actual.decompress::<D>();
    let expected = (u32::from(x) * Q + scale / 2) / scale;
    assert!(u32::from(actual.0) < Q);
    assert_eq!(u32::from(actual.0), expected);
}

macro_rules! proofs {
    ($($compress:ident, $decompress:ident: $d:ty);+ $(;)?) => {$ (
        #[kani::proof]
        fn $compress() { compression::<$d>(); }

        #[kani::proof]
        fn $decompress() { decompression::<$d>(); }
    )+};
}

// All widths exercised by the existing scalar compression tests. The KEM
// itself uses 1, 4, 5, 10, and 11; 6 and 12 are additional primitive coverage.
proofs! {
    compress_1, decompress_1: U1;
    compress_4, decompress_4: U4;
    compress_5, decompress_5: U5;
    compress_6, decompress_6: U6;
    compress_10, decompress_10: U10;
    compress_11, decompress_11: U11;
    compress_12, decompress_12: U12;
}
