use crate::algebra::{Elem, Field, Polynomial, Vector};
use crate::encoding::{ArraySize, Encode, EncodingSize, VectorEncodingSize};
use array::{Array, typenum::U256};
use core::marker::PhantomData;

/// A value of width `D` bits, stored in `F::Int` for compatibility with the
/// rest of the lattice algebra plumbing.
///
/// Despite carrying an `F: Field` parameter, a [`FixedWidthInt`] is *not* a
/// member of `F`; it is an element of `Z_{2^D}`.  The type exists so that
/// compressed values (i.e., the codomain of `Compress_d` in FIPS 203) can be
/// distinguished from field elements at the type level.
///
/// Multiplication is intentionally not provided: `Z_{2^D}` is not a prime
/// field and the Barrett-reduced [`Mul`] on [`Elem`] would be wrong here.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FixedWidthInt<F: Field, D: EncodingSize> {
    val: F::Int,
    _phantom: PhantomData<D>,
}

impl<F: Field, D: EncodingSize> FixedWidthInt<F, D> {
    /// Create a new fixed-width value.  The caller is responsible for
    /// ensuring `val < 2^D`; the type does not enforce this.
    pub const fn new(val: F::Int) -> Self {
        Self {
            val,
            _phantom: PhantomData,
        }
    }

    /// Access the underlying integer.
    pub fn value(&self) -> F::Int {
        self.val
    }
}

impl<F: Field, D: EncodingSize> From<Elem<F>> for FixedWidthInt<F, D> {
    fn from(elem: Elem<F>) -> Self {
        Self::new(elem.0)
    }
}

impl<F: Field, D: EncodingSize> From<FixedWidthInt<F, D>> for Elem<F> {
    fn from(fwi: FixedWidthInt<F, D>) -> Self {
        Elem(fwi.val)
    }
}

/// A polynomial whose coefficients are [`FixedWidthInt<F, D>`] values.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FixedWidthPolynomial<F: Field, D: EncodingSize>(
    pub Array<FixedWidthInt<F, D>, U256>,
);

impl<F: Field, D: EncodingSize> FixedWidthPolynomial<F, D> {
    /// Create a new polynomial.
    pub const fn new(coeffs: Array<FixedWidthInt<F, D>, U256>) -> Self {
        Self(coeffs)
    }
}

impl<F: Field, D: EncodingSize> From<Polynomial<F>> for FixedWidthPolynomial<F, D> {
    fn from(poly: Polynomial<F>) -> Self {
        Self(poly.0.iter().map(|&elem| elem.into()).collect())
    }
}

impl<F: Field, D: EncodingSize> From<FixedWidthPolynomial<F, D>> for Polynomial<F> {
    fn from(poly: FixedWidthPolynomial<F, D>) -> Self {
        Polynomial::new(poly.0.iter().map(|&fwi| fwi.into()).collect())
    }
}

impl<F: Field, D: EncodingSize> Encode<D> for FixedWidthPolynomial<F, D>
where
    Polynomial<F>: Encode<D>,
{
    type EncodedSize = <Polynomial<F> as Encode<D>>::EncodedSize;

    fn encode(&self) -> Array<u8, Self::EncodedSize> {
        Encode::<D>::encode(&Polynomial::<F>::from(*self))
    }

    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
        <Polynomial<F> as Encode<D>>::decode(enc).into()
    }
}

/// A vector of [`FixedWidthPolynomial<F, D>`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FixedWidthVector<F: Field, K: ArraySize, D: EncodingSize>(
    pub Array<FixedWidthPolynomial<F, D>, K>,
);

impl<F: Field, K: ArraySize, D: EncodingSize> FixedWidthVector<F, K, D> {
    /// Create a new vector.
    pub const fn new(polys: Array<FixedWidthPolynomial<F, D>, K>) -> Self {
        Self(polys)
    }
}

impl<F: Field, K: ArraySize, D: EncodingSize> From<Vector<F, K>>
    for FixedWidthVector<F, K, D>
{
    fn from(vec: Vector<F, K>) -> Self {
        Self(vec.0.into_iter().map(FixedWidthPolynomial::from).collect())
    }
}

impl<F: Field, K: ArraySize, D: EncodingSize> From<FixedWidthVector<F, K, D>>
    for Vector<F, K>
{
    fn from(vec: FixedWidthVector<F, K, D>) -> Self {
        Vector::new(vec.0.into_iter().map(Polynomial::from).collect())
    }
}

impl<F, K, D> Encode<D> for FixedWidthVector<F, K, D>
where
    F: Field,
    K: ArraySize,
    D: VectorEncodingSize<K>,
    Vector<F, K>: Encode<D>,
{
    type EncodedSize = <Vector<F, K> as Encode<D>>::EncodedSize;

    fn encode(&self) -> Array<u8, Self::EncodedSize> {
        Encode::<D>::encode(&Vector::<F, K>::from(self.clone()))
    }

    fn decode(enc: &Array<u8, Self::EncodedSize>) -> Self {
        <Vector<F, K> as Encode<D>>::decode(enc).into()
    }
}
