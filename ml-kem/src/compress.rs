use crate::algebra::{FieldElement, Integer, Polynomial, PolynomialVector};
use crate::param::{ArraySize, EncodingSize};
use crate::util::Truncate;

// A convenience trait to allow us to associate some constants with a typenum
pub trait CompressionFactor: EncodingSize {
    const POW2_HALF: u32;
    const MASK: Integer;
    const DIV_SHIFT: u32;
    const DIV_MUL: u64;
}

impl<T> CompressionFactor for T
where
    T: EncodingSize,
{
    const POW2_HALF: u32 = 1 << (T::USIZE - 1);
    const MASK: Integer = ((1 as Integer) << T::USIZE) - 1;
    const DIV_SHIFT: u32 = 28 + (T::U32 >> 3) * 4;
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
        const Q_HALF: u64 = (FieldElement::Q64 - 1) >> 1;
        let x = u64::from(self.0);
        let y = ((((x << D::USIZE) + Q_HALF) * D::DIV_MUL) >> D::DIV_SHIFT).truncate();
        self.0 = y.truncate() & D::MASK;
        self
    }

    // Equation 4.6: Decomporess_d(x) = round((q / 2^d) x)
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
    use hybrid_array::typenum::{U1, U10, U11, U12, U4, U5, U6};

    // Verify against inequality 4.7
    #[allow(clippy::integer_division_remainder_used)]
    fn compression_decompression_inequality<D: CompressionFactor>() {
        let half_q: i32 = i32::from(FieldElement::Q) / 2;
        let error_threshold = ((f64::from(FieldElement::Q)) / f64::from(1 << (D::U32 + 1))).round() as i32;
        for x in 0..FieldElement::Q {
            let mut y = FieldElement(x);

            y.compress::<D>();
            y.decompress::<D>();

            let mut error = (i32::from(y.0) - i32::from(x)) % half_q;
            if error < - half_q {
                error += half_q;
            }

            assert!(
                error <= error_threshold,
                "Inequality failed for x = {x}: error = {error}, error_threshold = {error_threshold}, D = {:?}",
                D::USIZE
            );
        }
    }

    #[test]
    fn compress_decompress() {
        compression_decompression_inequality::<U1>();
        compression_decompression_inequality::<U4>();
        compression_decompression_inequality::<U5>();
        compression_decompression_inequality::<U6>();
        compression_decompression_inequality::<U10>();
        compression_decompression_inequality::<U11>();
        compression_decompression_inequality::<U12>();
    }
}
