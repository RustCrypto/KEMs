use crate::algebra::{FieldElement, Integer, Polynomial, PolynomialVector};
use crate::param::{ArraySize, EncodingSize};
use crate::util::Truncate;

// A convenience trait to allow us to associate some constants with a typenum
pub trait CompressionFactor: EncodingSize {
    const POW2_HALF: u32;
    const MASK: Integer;
    const DIV_SHIFT: usize;
    const DIV_MUL: u64;
}

impl<T> CompressionFactor for T
where
    T: EncodingSize,
{
    const POW2_HALF: u32 = 1 << (T::USIZE - 1);
    const MASK: Integer = ((1 as Integer) << T::USIZE) - 1;
    const DIV_SHIFT: usize = 34;
    #[allow(clippy::integer_division_remainder_used)]
    const DIV_MUL: u64 = (1 << T::DIV_SHIFT) / FieldElement::Q64;
}

// Traits for objects that allow compression / decompression
pub trait Compress {
    fn compress<D: CompressionFactor>(&mut self) -> &Self;
    fn decompress<D: CompressionFactor>(&mut self) -> &Self;
}

impl Compress for FieldElement {
    // Equation 4.5: Compress_d(x) = round((2^d / q) x)
    //
    // Here and in decompression, we leverage the following facts:
    //
    //   round(a / b) = floor((a + b/2) / b)
    //   a / q ~= (a * x) >> s where x >> s ~= 1/q
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        const Q_HALF: u64 = (FieldElement::Q64 + 1) >> 1;
        let x = u64::from(self.0);
        let y = ((((x << D::USIZE) + Q_HALF) * D::DIV_MUL) >> D::DIV_SHIFT).truncate();
        self.0 = y.truncate() & D::MASK;
        self
    }

    // Equation 4.6: Decompress_d(x) = round((q / 2^d) x)
    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        let x = u32::from(self.0);
        let y = ((x * FieldElement::Q32) + D::POW2_HALF) >> D::USIZE;
        self.0 = y.truncate();
        self
    }
}
impl Compress for Polynomial {
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.compress::<D>();
        }

        self
    }

    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.decompress::<D>();
        }

        self
    }
}

impl<K: ArraySize> Compress for PolynomialVector<K> {
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.compress::<D>();
        }

        self
    }

    fn decompress<D: CompressionFactor>(&mut self) -> &Self {
        for x in &mut self.0 {
            x.decompress::<D>();
        }

        self
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use hybrid_array::typenum::{U1, U4, U5, U6, U10, U11, U12};
    use num_rational::Ratio;

    #[allow(clippy::cast_possible_truncation)]
    fn rational_compress<D: CompressionFactor>(input: u16) -> u16 {
        let fraction = Ratio::new(u32::from(input) * (1 << D::USIZE), FieldElement::Q32);
        (fraction.round().to_integer() as u16) & D::MASK
    }

    #[allow(clippy::cast_possible_truncation)]
    fn rational_decompress<D: CompressionFactor>(input: u16) -> u16 {
        let fraction = Ratio::new(u32::from(input) * FieldElement::Q32, 1 << D::USIZE);
        fraction.round().to_integer() as u16
    }

    // Verify against inequality 4.7
    #[allow(clippy::integer_division_remainder_used)]
    fn compression_decompression_inequality<D: CompressionFactor>() {
        const QI32: i32 = FieldElement::Q as i32;
        let error_threshold = i32::from(Ratio::new(FieldElement::Q, 1 << D::USIZE).to_integer());

        for x in 0..FieldElement::Q {
            let mut y = FieldElement(x);
            y.compress::<D>();
            y.decompress::<D>();

            let mut error = i32::from(y.0) - i32::from(x) + QI32;
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
            let mut y = FieldElement(x);
            y.decompress::<D>();
            y.compress::<D>();

            assert_eq!(y.0, x, "failed for x: {}, D: {}", x, D::USIZE);
        }
    }

    fn decompress_KAT<D: CompressionFactor>() {
        for y in 0..(1 << D::USIZE) {
            let x_expected = rational_decompress::<D>(y);
            let mut x_actual = FieldElement(y);
            x_actual.decompress::<D>();

            assert_eq!(x_expected, x_actual.0);
        }
    }

    fn compress_KAT<D: CompressionFactor>() {
        for x in 0..FieldElement::Q {
            let y_expected = rational_compress::<D>(x);
            let mut y_actual = FieldElement(x);
            y_actual.compress::<D>();

            assert_eq!(y_expected, y_actual.0, "for x: {}, D: {}", x, D::USIZE);
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
