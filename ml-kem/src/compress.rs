use crate::algebra::{FieldElement, Integer, Polynomial, PolynomialVector};
use crate::param::{ArrayLength, EncodingSize};
use crate::util::Truncate;

// A convenience trait to allow us to associate some constants with a typenum
pub trait CompressionFactor: EncodingSize {
    const POW2_HALF: u32;
    const MASK: Integer;
}

impl<T> CompressionFactor for T
where
    T: EncodingSize,
{
    const POW2_HALF: u32 = 1 << (T::USIZE - 1);
    const MASK: Integer = ((1 as Integer) << T::USIZE) - 1;
}

// Traits for objects that allow compression / decompression
pub trait Compress {
    fn compress<D: CompressionFactor>(&mut self) -> &Self;
    fn decompress<D: CompressionFactor>(&mut self) -> &Self;
}

impl Compress for FieldElement {
    // Equation 4.5: Compress_d(x) = round((2^d / q) x)
    //
    // Here and in decompression, we leverage the following fact:
    //
    //   round(a / b) = floor((a + b/2) / b)
    fn compress<D: CompressionFactor>(&mut self) -> &Self {
        const Q_HALF: u32 = (FieldElement::Q32 - 1) / 2;
        let x = u32::from(self.0);
        let y = ((x << D::USIZE) + Q_HALF) / FieldElement::Q32;
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

impl<K: ArrayLength> Compress for PolynomialVector<K> {
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
    use typenum::consts::*;

    // Verify that the integer compression routine produces the same results as rounding with
    // floats.
    fn compression_known_answer_test<D: CompressionFactor>() {
        let fq: f64 = FieldElement::Q as f64;
        let f2d: f64 = 2.0_f64.powi(D::I32);

        for x in 0..FieldElement::Q {
            let fx = x as f64;
            let mut x = FieldElement(x);

            // Verify equivalence of compression
            x.compress::<D>();
            let fcx = ((f2d / fq * fx).round() as Integer) % (1 << D::USIZE);
            assert_eq!(x.0, fcx);

            // Verify equivalence of decompression
            x.decompress::<D>();
            let fdx = (fq / f2d * (fcx as f64)).round() as Integer;
            assert_eq!(x.0, fdx);
        }
    }

    #[test]
    fn compress_decompress() {
        compression_known_answer_test::<U1>();
        compression_known_answer_test::<U4>();
        compression_known_answer_test::<U5>();
        compression_known_answer_test::<U6>();
        compression_known_answer_test::<U10>();
        compression_known_answer_test::<U11>();
        compression_known_answer_test::<U12>();
    }
}
