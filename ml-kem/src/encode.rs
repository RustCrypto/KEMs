use hybrid_array::{
    Array,
    typenum::{U256, Unsigned},
};

use crate::algebra::{
    FieldElement, Integer, NttPolynomial, NttVector, Polynomial, PolynomialVector,
};
use crate::param::{ArraySize, EncodedPolynomial, EncodingSize, VectorEncodingSize};
use crate::util::Truncate;

type DecodedValue = Array<FieldElement, U256>;

// Algorithm 4 ByteEncode_d(F)
//
// Note: This algorithm performs compression as well as encoding.
fn byte_encode<D: EncodingSize>(vals: &DecodedValue) -> EncodedPolynomial<D> {
    let val_step = D::ValueStep::USIZE;
    let byte_step = D::ByteStep::USIZE;

    let mut bytes = EncodedPolynomial::<D>::default();

    let vc = vals.chunks(val_step);
    let bc = bytes.chunks_mut(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut x = 0u128;
        for (j, vj) in v.iter().enumerate() {
            x |= u128::from(vj.0) << (D::USIZE * j);
        }

        let xb = x.to_le_bytes();
        b.copy_from_slice(&xb[..byte_step]);
    }

    bytes
}

// Algorithm 5 ByteDecode_d(F)
//
// Note: This function performs decompression as well as decoding.
fn byte_decode<D: EncodingSize>(bytes: &EncodedPolynomial<D>) -> DecodedValue {
    let val_step = D::ValueStep::USIZE;
    let byte_step = D::ByteStep::USIZE;
    let mask = (1 << D::USIZE) - 1;

    let mut vals = DecodedValue::default();

    let vc = vals.chunks_mut(val_step);
    let bc = bytes.chunks(byte_step);
    for (v, b) in vc.zip(bc) {
        let mut xb = [0u8; 16];
        xb[..byte_step].copy_from_slice(b);

        let x = u128::from_le_bytes(xb);
        for (j, vj) in v.iter_mut().enumerate() {
            let val: Integer = (x >> (D::USIZE * j)).truncate();
            vj.0 = val & mask;

            if D::USIZE == 12 {
                vj.0 %= FieldElement::Q;
            }
        }
    }

    vals
}

pub trait Encode<D: EncodingSize> {
    type EncodedSize: ArraySize;
    fn encode(&self) -> Array<u8, Self::EncodedSize>;
    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self;
}

impl<D: EncodingSize> Encode<D> for Polynomial {
    type EncodedSize = D::EncodedPolynomialSize;

    fn encode(&self) -> Array<u8, Self::EncodedSize> {
        byte_encode::<D>(&self.0)
    }

    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
        Self(byte_decode::<D>(enc))
    }
}

impl<D, K> Encode<D> for PolynomialVector<K>
where
    K: ArraySize,
    D: VectorEncodingSize<K>,
{
    type EncodedSize = D::EncodedPolynomialVectorSize;

    fn encode(&self) -> Array<u8, Self::EncodedSize> {
        let polys = self.0.iter().map(|x| Encode::<D>::encode(x)).collect();
        <D as VectorEncodingSize<K>>::flatten(polys)
    }

    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
        let unfold = <D as VectorEncodingSize<K>>::unflatten(enc);
        Self(
            unfold
                .iter()
                .map(|&x| <Polynomial as Encode<D>>::decode(x))
                .collect(),
        )
    }
}

impl<D: EncodingSize> Encode<D> for NttPolynomial {
    type EncodedSize = D::EncodedPolynomialSize;

    fn encode(&self) -> Array<u8, Self::EncodedSize> {
        byte_encode::<D>(&self.0)
    }

    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
        Self(byte_decode::<D>(enc))
    }
}

impl<D, K> Encode<D> for NttVector<K>
where
    D: VectorEncodingSize<K>,
    K: ArraySize,
{
    type EncodedSize = D::EncodedPolynomialVectorSize;

    fn encode(&self) -> Array<u8, Self::EncodedSize> {
        let polys = self.0.iter().map(|x| Encode::<D>::encode(x)).collect();
        <D as VectorEncodingSize<K>>::flatten(polys)
    }

    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
        let unfold = <D as VectorEncodingSize<K>>::unflatten(enc);
        Self(
            unfold
                .iter()
                .map(|&x| <NttPolynomial as Encode<D>>::decode(x))
                .collect(),
        )
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use core::fmt::Debug;
    use core::ops::Rem;
    use hybrid_array::typenum::{
        U1, U2, U3, U4, U5, U6, U8, U10, U11, U12, marker_traits::Zero, operator_aliases::Mod,
    };
    use rand::Rng;

    use crate::param::EncodedPolynomialVector;

    // A helper trait to construct larger arrays by repeating smaller ones
    trait Repeat<T: Clone, D: ArraySize> {
        fn repeat(&self) -> Array<T, D>;
    }

    impl<T, N, D> Repeat<T, D> for Array<T, N>
    where
        N: ArraySize,
        T: Clone,
        D: ArraySize + Rem<N>,
        Mod<D, N>: Zero,
    {
        #[allow(clippy::integer_division_remainder_used)]
        fn repeat(&self) -> Array<T, D> {
            Array::from_fn(|i| self[i % N::USIZE].clone())
        }
    }

    #[allow(clippy::integer_division_remainder_used)]
    fn byte_codec_test<D>(decoded: &DecodedValue, encoded: &EncodedPolynomial<D>)
    where
        D: EncodingSize,
    {
        // Test known answer
        let actual_encoded = byte_encode::<D>(decoded);
        assert_eq!(&actual_encoded, encoded);

        let actual_decoded = byte_decode::<D>(encoded);
        assert_eq!(&actual_decoded, decoded);

        // Test random decode/encode and encode/decode round trips
        let mut rng = rand::rng();
        let mut decoded: Array<Integer, U256> = Array::default();
        rng.fill(decoded.as_mut_slice());
        let m = match D::USIZE {
            12 => FieldElement::Q,
            d => (1 as Integer) << d,
        };
        let decoded = decoded.iter().map(|x| FieldElement(x % m)).collect();

        let actual_encoded = byte_encode::<D>(&decoded);
        let actual_decoded = byte_decode::<D>(&actual_encoded);
        assert_eq!(actual_decoded, decoded);

        let actual_reencoded = byte_encode::<D>(&decoded);
        assert_eq!(actual_reencoded, actual_encoded);
    }

    #[test]
    fn byte_codec() {
        // The 1-bit can only represent decoded values equal to 0 or 1.
        let decoded: DecodedValue = Array::<_, U2>([FieldElement(0), FieldElement(1)]).repeat();
        let encoded: EncodedPolynomial<U1> = Array([0xaa; 32]);
        byte_codec_test::<U1>(&decoded, &encoded);

        // For other codec widths, we use a standard sequence
        let decoded: DecodedValue = Array::<_, U8>([
            FieldElement(0),
            FieldElement(1),
            FieldElement(2),
            FieldElement(3),
            FieldElement(4),
            FieldElement(5),
            FieldElement(6),
            FieldElement(7),
        ])
        .repeat();

        let encoded: EncodedPolynomial<U4> = Array::<_, U4>([0x10, 0x32, 0x54, 0x76]).repeat();
        byte_codec_test::<U4>(&decoded, &encoded);

        let encoded: EncodedPolynomial<U5> =
            Array::<_, U5>([0x20, 0x88, 0x41, 0x8a, 0x39]).repeat();
        byte_codec_test::<U5>(&decoded, &encoded);

        let encoded: EncodedPolynomial<U6> =
            Array::<_, U6>([0x40, 0x20, 0x0c, 0x44, 0x61, 0x1c]).repeat();
        byte_codec_test::<U6>(&decoded, &encoded);

        let encoded: EncodedPolynomial<U10> =
            Array::<_, U10>([0x00, 0x04, 0x20, 0xc0, 0x00, 0x04, 0x14, 0x60, 0xc0, 0x01]).repeat();
        byte_codec_test::<U10>(&decoded, &encoded);

        let encoded: EncodedPolynomial<U11> = Array::<_, U11>([
            0x00, 0x08, 0x80, 0x00, 0x06, 0x40, 0x80, 0x02, 0x18, 0xe0, 0x00,
        ])
        .repeat();
        byte_codec_test::<U11>(&decoded, &encoded);

        let encoded: EncodedPolynomial<U12> = Array::<_, U12>([
            0x00, 0x10, 0x00, 0x02, 0x30, 0x00, 0x04, 0x50, 0x00, 0x06, 0x70, 0x00,
        ])
        .repeat();
        byte_codec_test::<U12>(&decoded, &encoded);
    }

    #[allow(clippy::integer_division_remainder_used)]
    #[test]
    fn byte_codec_12_mod() {
        // DecodeBytes_12 is required to reduce mod q
        let encoded: EncodedPolynomial<U12> = Array([0xff; 384]);
        let decoded: DecodedValue = Array([FieldElement(0xfff % FieldElement::Q); 256]);

        let actual_decoded = byte_decode::<U12>(&encoded);
        assert_eq!(actual_decoded, decoded);
    }

    fn vector_codec_known_answer_test<D, T>(decoded: &T, encoded: &Array<u8, T::EncodedSize>)
    where
        D: EncodingSize,
        T: Encode<D> + PartialEq + Debug,
    {
        let actual_encoded = decoded.encode();
        assert_eq!(&actual_encoded, encoded);

        let actual_decoded: T = Encode::decode(encoded);
        assert_eq!(&actual_decoded, decoded);
    }

    #[test]
    fn vector_codec() {
        let poly = Polynomial(
            Array::<_, U8>([
                FieldElement(0),
                FieldElement(1),
                FieldElement(2),
                FieldElement(3),
                FieldElement(4),
                FieldElement(5),
                FieldElement(6),
                FieldElement(7),
            ])
            .repeat(),
        );

        // The required vector sizes are 2, 3, and 4.
        let decoded: PolynomialVector<U2> = PolynomialVector(Array([poly, poly]));
        let encoded: EncodedPolynomialVector<U5, U2> =
            Array::<_, U5>([0x20, 0x88, 0x41, 0x8a, 0x39]).repeat();
        vector_codec_known_answer_test::<U5, PolynomialVector<U2>>(&decoded, &encoded);

        let decoded: PolynomialVector<U3> = PolynomialVector(Array([poly, poly, poly]));
        let encoded: EncodedPolynomialVector<U5, U3> =
            Array::<_, U5>([0x20, 0x88, 0x41, 0x8a, 0x39]).repeat();
        vector_codec_known_answer_test::<U5, PolynomialVector<U3>>(&decoded, &encoded);

        let decoded: PolynomialVector<U4> = PolynomialVector(Array([poly, poly, poly, poly]));
        let encoded: EncodedPolynomialVector<U5, U4> =
            Array::<_, U5>([0x20, 0x88, 0x41, 0x8a, 0x39]).repeat();
        vector_codec_known_answer_test::<U5, PolynomialVector<U4>>(&decoded, &encoded);
    }
}
