use crate::algebra::{BaseField, Elem, Int, Polynomial, Vector};
use module_lattice::{
    ArraySize, EncodingSize, Field, FixedWidthInt, FixedWidthPolynomial, FixedWidthVector,
    Truncate,
};

// A convenience trait to allow us to associate some constants with a typenum
pub(crate) trait CompressionFactor: EncodingSize {
    const POW2_HALF: u32;
    const MASK: Int;
    const DIV_SHIFT: usize;
    const DIV_MUL: u64;
}

impl<T> CompressionFactor for T
where
    T: EncodingSize,
{
    const POW2_HALF: u32 = 1 << (T::USIZE - 1);
    const MASK: Int = (1 << T::USIZE) - 1;
    const DIV_SHIFT: usize = 34;
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const DIV_MUL: u64 = (1 << T::DIV_SHIFT) / BaseField::QLL;
}

/// Compress a prime-field representation into its `Z_{2^D}` fixed-width form.
pub(crate) trait Compress<D: CompressionFactor> {
    type Output;
    fn compress(self) -> Self::Output;
}

/// Decompress a `Z_{2^D}` fixed-width representation back into the prime field.
pub(crate) trait Decompress<D: CompressionFactor> {
    type Output;
    fn decompress(self) -> Self::Output;
}

impl<D: CompressionFactor> Compress<D> for Elem {
    type Output = FixedWidthInt<BaseField, D>;

    // Equation 4.5: Compress_d(x) = round((2^d / q) x)
    //
    // Here and in decompression, we leverage the following facts:
    //
    //   round(a / b) = floor((a + b/2) / b)
    //   a / q ~= (a * x) >> s where x >> s ~= 1/q
    fn compress(self) -> FixedWidthInt<BaseField, D> {
        const Q_HALF: u64 = (BaseField::QLL + 1) >> 1;
        let x = u64::from(self.0);
        let y = (((x << D::USIZE) + Q_HALF) * D::DIV_MUL) >> D::DIV_SHIFT;
        FixedWidthInt::new(u16::truncate(y) & D::MASK)
    }
}

impl<D: CompressionFactor> Decompress<D> for FixedWidthInt<BaseField, D> {
    type Output = Elem;

    // Equation 4.6: Decompress_d(x) = round((q / 2^d) x)
    fn decompress(self) -> Elem {
        let x = u32::from(self.value());
        let y = ((x * BaseField::QL) + D::POW2_HALF) >> D::USIZE;
        Elem::new(Truncate::truncate(y))
    }
}

impl<D: CompressionFactor> Compress<D> for Polynomial {
    type Output = FixedWidthPolynomial<BaseField, D>;

    fn compress(self) -> FixedWidthPolynomial<BaseField, D> {
        FixedWidthPolynomial::new(self.0.into_iter().map(Compress::<D>::compress).collect())
    }
}

impl<D: CompressionFactor> Decompress<D> for FixedWidthPolynomial<BaseField, D> {
    type Output = Polynomial;

    fn decompress(self) -> Polynomial {
        Polynomial::new(self.0.into_iter().map(Decompress::<D>::decompress).collect())
    }
}

impl<K: ArraySize, D: CompressionFactor> Compress<D> for Vector<K> {
    type Output = FixedWidthVector<BaseField, K, D>;

    fn compress(self) -> FixedWidthVector<BaseField, K, D> {
        FixedWidthVector::new(self.0.into_iter().map(Compress::<D>::compress).collect())
    }
}

impl<K: ArraySize, D: CompressionFactor> Decompress<D> for FixedWidthVector<BaseField, K, D> {
    type Output = Vector<K>;

    fn decompress(self) -> Vector<K> {
        Vector::new(self.0.into_iter().map(Decompress::<D>::decompress).collect())
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, reason = "tests")]
#[allow(clippy::integer_division_remainder_used, reason = "tests")]
pub(crate) mod tests {
    use super::*;
    use array::typenum::{U1, U4, U5, U6, U10, U11, U12};
    use num_rational::Ratio;

    fn rational_compress<D: CompressionFactor>(input: u16) -> u16 {
        let fraction = Ratio::new(u32::from(input) * (1 << D::USIZE), BaseField::QL);
        (fraction.round().to_integer() as u16) & D::MASK
    }

    fn rational_decompress<D: CompressionFactor>(input: u16) -> u16 {
        let fraction = Ratio::new(u32::from(input) * BaseField::QL, 1 << D::USIZE);
        fraction.round().to_integer() as u16
    }

    // Verify against inequality 4.7
    fn compression_decompression_inequality<D: CompressionFactor>() {
        const QI32: i32 = BaseField::Q as i32;
        let error_threshold = i32::from(Ratio::new(BaseField::Q, 1 << D::USIZE).to_integer());

        for x in 0..BaseField::Q {
            let compressed = Compress::<D>::compress(Elem::new(x));
            let decompressed = Decompress::<D>::decompress(compressed);

            let mut error = i32::from(decompressed.0) - i32::from(x) + QI32;
            if error > (QI32 - 1) / 2 {
                error -= QI32;
            }

            assert!(
                error.abs() <= error_threshold,
                "Inequality failed for x = {x}: error = {}, error_threshold = {error_threshold}, D = {:?}",
                error.abs(),
                D::USIZE
            );
        }
    }

    fn decompression_compression_equality<D: CompressionFactor>() {
        for x in 0..(1 << D::USIZE) {
            let decompressed = Decompress::<D>::decompress(FixedWidthInt::<BaseField, D>::new(x));
            let recompressed = Compress::<D>::compress(decompressed);

            assert_eq!(recompressed.value(), x, "failed for x: {}, D: {}", x, D::USIZE);
        }
    }

    fn decompress_KAT<D: CompressionFactor>() {
        for y in 0..(1 << D::USIZE) {
            let x_expected = rational_decompress::<D>(y);
            let x_actual = Decompress::<D>::decompress(FixedWidthInt::<BaseField, D>::new(y));

            assert_eq!(x_expected, x_actual.0);
        }
    }

    fn compress_KAT<D: CompressionFactor>() {
        for x in 0..BaseField::Q {
            let y_expected = rational_compress::<D>(x);
            let y_actual = Compress::<D>::compress(Elem::new(x));

            assert_eq!(y_expected, y_actual.value(), "for x: {}, D: {}", x, D::USIZE);
        }
    }

    fn compress_decompress_properties<D: CompressionFactor>() {
        compression_decompression_inequality::<D>();
        decompression_compression_equality::<D>();
    }

    fn compress_decompress_KATs<D: CompressionFactor>() {
        decompress_KAT::<D>();
        compress_KAT::<D>();
    }

    #[test]
    fn decompress_compress() {
        compress_decompress_properties::<U1>();
        compress_decompress_properties::<U4>();
        compress_decompress_properties::<U5>();
        compress_decompress_properties::<U6>();
        compress_decompress_properties::<U10>();
        compress_decompress_properties::<U11>();
        // preservation under decompression first only holds for d < 12
        compression_decompression_inequality::<U12>();

        compress_decompress_KATs::<U1>();
        compress_decompress_KATs::<U4>();
        compress_decompress_KATs::<U5>();
        compress_decompress_KATs::<U6>();
        compress_decompress_KATs::<U10>();
        compress_decompress_KATs::<U11>();
        compress_decompress_KATs::<U12>();
    }
}
