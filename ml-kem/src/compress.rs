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
    //   a / q ~= (a * x) >> s where x / (2^s) ~= 1/q
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
    fn compression_decompression_inequality<D: CompressionFactor>() {
        for x in 0..FieldElement::Q {
            let mut y = FieldElement(x);

            y.compress::<D>();
            y.decompress::<D>();

            let lhs = (i32::from(y.0) - i32::from(x)) % (i32::from(FieldElement::Q));
            let rhs = ((FieldElement::Q32 + (1 << (D::U32 + 1)) - 1) / (1 << (D::U32 + 1))) as i32;

            assert!(
                lhs <= rhs,
                "Inequality failed for x = {x}: lhs = {lhs}, rhs = {rhs}"
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
