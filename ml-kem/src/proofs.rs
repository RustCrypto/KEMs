//! Bit-level specifications for ML-KEM's use of module-lattice encoding.

#![allow(
    clippy::integer_division_remainder_used,
    reason = "mathematical specifications"
)]

use crate::algebra::{BaseField, Elem};
use array::{
    Array,
    typenum::{U1, U4, U5, U6, U10, U11, U12},
};
use module_lattice::{EncodedPolynomial, EncodingSize, byte_decode, byte_encode};

fn encode<D: EncodingSize>() {
    let input = Array::from_fn(|_| {
        let x: u16 = kani::any();
        // ByteEncode_12 accepts canonical field elements; smaller widths
        // encode compressed coefficients or CBD sampling values.
        let limit = if D::USIZE == 12 {
            3329
        } else {
            1u16 << D::USIZE
        };
        kani::assume(x < limit);
        Elem::new(x)
    });
    let bytes = byte_encode::<BaseField, D>(&input);
    // One arbitrary output bit establishes the bit ordering for every bit.
    let bit: usize = kani::any();
    kani::assume(bit < 256 * D::USIZE);
    let expected = (input[bit / D::USIZE].0 >> (bit % D::USIZE)) & 1;
    assert_eq!(u16::from((bytes[bit / 8] >> (bit % 8)) & 1), expected);
}

fn decode<D: EncodingSize>() {
    let bytes: EncodedPolynomial<D> = Array::from_fn(|_| kani::any());
    let vals = byte_decode::<BaseField, D>(&bytes);
    let index: usize = kani::any();
    kani::assume(index < 256);
    let mut expected = 0u16;
    for j in 0..D::USIZE {
        let bit = index * D::USIZE + j;
        expected |= u16::from((bytes[bit / 8] >> (bit % 8)) & 1) << j;
    }
    if D::USIZE == 12 {
        // Arbitrary byte strings include noncanonical values 3329..4095.
        // ByteDecode reduces these; public-key validation is a separate step.
        expected %= 3329;
    }
    assert_eq!(vals[index].0, expected);
}

macro_rules! proofs {
    ($($encode:ident, $decode:ident: $d:ty);+ $(;)?) => {$ (
        #[kani::proof]
        #[kani::unwind(513)]
        fn $encode() { encode::<$d>(); }

        #[kani::proof]
        #[kani::unwind(513)]
        fn $decode() { decode::<$d>(); }
    )+};
}

proofs! {
    encode_1, decode_1: U1;
    encode_4, decode_4: U4;
    encode_5, decode_5: U5;
    encode_6, decode_6: U6;
    encode_10, decode_10: U10;
    encode_11, decode_11: U11;
    encode_12, decode_12: U12;
}
