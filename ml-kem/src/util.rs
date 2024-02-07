use core::mem::ManuallyDrop;
use core::ops::{Div, Mul, Rem};
use core::ptr;
use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use typenum::{
    operator_aliases::{Prod, Quot},
    Unsigned, U0, U32,
};

/// A 32-byte array, defined here for brevity because it is used several times
pub type B32 = GenericArray<u8, U32>;

/// Benchmarking shows that `GenericArray::clone` does not optimize as well as this alternative
/// implementation.  (Obviously, we can't re-implement Clone, so we have a new name.)
pub trait FastClone {
    fn fast_clone(&self) -> Self;
}

impl<T, N> FastClone for GenericArray<T, N>
where
    T: Copy + Default,
    N: ArrayLength,
{
    fn fast_clone(&self) -> Self {
        self.map(Clone::clone)
    }
}

/// Benchmarking shows that the `FunctionalSequence` versions of `zip`, `fold`, and `map` do not
/// optimize as well as these alternative implementations.
pub trait FunctionalArray<T, N>
where
    N: ArrayLength,
{
    fn map<U, F>(&self, f: F) -> GenericArray<U, N>
    where
        U: Default,
        F: Fn(&T) -> U;

    fn zip<U, F>(&self, b: &Self, f: F) -> GenericArray<U, N>
    where
        U: Default,
        F: Fn(&T, &T) -> U;

    fn fold<F>(&self, f: F) -> T
    where
        T: Clone,
        F: Fn(&T, &T) -> T;
}

impl<T, N> FunctionalArray<T, N> for GenericArray<T, N>
where
    N: ArrayLength,
{
    fn map<U, F>(&self, f: F) -> GenericArray<U, N>
    where
        U: Default,
        F: Fn(&T) -> U,
    {
        GenericArray::generate(|i| f(&self[i]))
    }

    fn zip<U, F>(&self, other: &Self, f: F) -> GenericArray<U, N>
    where
        U: Default,
        F: Fn(&T, &T) -> U,
    {
        GenericArray::generate(|i| f(&self[i], &other[i]))
    }

    fn fold<F>(&self, f: F) -> T
    where
        T: Clone,
        F: Fn(&T, &T) -> T,
    {
        let mut out = self[0].clone();
        for i in 1..N::USIZE {
            out = f(&out, &self[i]);
        }
        out
    }
}

/// Safely truncate an unsigned integer value to shorter representation
pub trait Truncate<T> {
    fn truncate(self) -> T;
}

macro_rules! define_truncate {
    ($from:ident, $to:ident) => {
        impl Truncate<$to> for $from {
            fn truncate(self) -> $to {
                // This line is marked unsafe because the `unwrap_unchecked` call is UB when its
                // `self` argument is `Err`.  It never will be, because we explicitly zeroize the
                // high-order bits before converting.  We could have used `unwrap()`, but chose to
                // avoid the possibility of panic.
                unsafe { (self & $from::from($to::MAX)).try_into().unwrap_unchecked() }
            }
        }
    };
}

define_truncate!(u32, u16);
define_truncate!(u64, u32);
define_truncate!(usize, u8);
define_truncate!(u128, u16);
define_truncate!(u128, u8);

/// Defines a sequence of sequences that can be merged into a bigger overall seequence
pub trait Flatten<T, M: ArrayLength> {
    type OutputSize: ArrayLength;

    fn flatten(self) -> GenericArray<T, Self::OutputSize>;
}

impl<T, N, M> Flatten<T, Prod<M, N>> for GenericArray<GenericArray<T, M>, N>
where
    N: ArrayLength,
    M: ArrayLength + Mul<N>,
    Prod<M, N>: ArrayLength,
{
    type OutputSize = Prod<M, N>;

    // This is the reverse transmute between [T; K*N] and [[T; K], M], which is guaranteed to be
    // safe by the Rust memory layout of these types.
    fn flatten(self) -> GenericArray<T, Self::OutputSize> {
        let whole = ManuallyDrop::new(self);
        unsafe { ptr::read(whole.as_ptr().cast()) }
    }
}

/// Defines a sequence that can be split into a sequence of smaller sequences of uniform size
pub trait Unflatten<M>
where
    M: ArrayLength,
{
    type Part;

    fn unflatten(self) -> GenericArray<Self::Part, M>;
}

impl<T, N, M> Unflatten<M> for GenericArray<T, N>
where
    T: Default,
    N: ArrayLength + Div<M> + Rem<M, Output = U0>,
    M: ArrayLength,
    Quot<N, M>: ArrayLength,
{
    type Part = GenericArray<T, Quot<N, M>>;

    // This requires some unsafeness, but it is the same as what is done in GenericArray::split.
    // Basically, this is doing transmute between [T; K*N] and [[T; K], M], which is guaranteed to
    // be safe by the Rust memory layout of these types.
    fn unflatten(self) -> GenericArray<Self::Part, M> {
        let part_size = Quot::<N, M>::USIZE;
        let whole = ManuallyDrop::new(self);
        GenericArray::generate(|i| unsafe { ptr::read(whole.as_ptr().add(i * part_size).cast()) })
    }
}

impl<'a, T, N, M> Unflatten<M> for &'a GenericArray<T, N>
where
    T: Default,
    N: ArrayLength + Div<M> + Rem<M, Output = U0>,
    M: ArrayLength,
    Quot<N, M>: ArrayLength,
{
    type Part = &'a GenericArray<T, Quot<N, M>>;

    // This requires some unsafeness, but it is the same as what is done in GenericArray::split.
    // Basically, this is doing transmute between [T; K*N] and [[T; K], M], which is guaranteed to
    // be safe by the Rust memory layout of these types.
    fn unflatten(self) -> GenericArray<Self::Part, M> {
        let part_size = Quot::<N, M>::USIZE;
        let mut ptr: *const T = self.as_ptr();
        GenericArray::generate(|_i| unsafe {
            let part = &*(ptr.cast());
            ptr = ptr.add(part_size);
            part
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use generic_array::arr;
    use typenum::consts::*;

    #[test]
    fn flatten() {
        let flat: GenericArray<u8, _> = arr![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let unflat2: GenericArray<GenericArray<u8, _>, _> =
            arr![arr![1, 2], arr![3, 4], arr![5, 6], arr![7, 8], arr![9, 10]];
        let unflat5: GenericArray<GenericArray<u8, _>, _> =
            arr![arr![1, 2, 3, 4, 5], arr![6, 7, 8, 9, 10]];

        // Flatten
        let actual = unflat2.flatten();
        assert_eq!(flat, actual);

        let actual = unflat5.flatten();
        assert_eq!(flat, actual);

        // Unflatten
        let actual: GenericArray<GenericArray<u8, U2>, U5> = flat.unflatten();
        assert_eq!(unflat2, actual);

        let actual: GenericArray<GenericArray<u8, U5>, U2> = flat.unflatten();
        assert_eq!(unflat5, actual);

        // Unflatten on references
        let actual: GenericArray<&GenericArray<u8, U2>, U5> = (&flat).unflatten();
        for (i, part) in actual.iter().enumerate() {
            assert_eq!(&unflat2[i], *part);
        }

        let actual: GenericArray<&GenericArray<u8, U5>, U2> = (&flat).unflatten();
        for (i, part) in actual.iter().enumerate() {
            assert_eq!(&unflat5[i], *part);
        }
    }
}
