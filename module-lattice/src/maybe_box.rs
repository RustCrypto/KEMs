use array::{Array, ArraySize};
use core::{
    iter::FromIterator,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

/// Fixed-length storage which uses the heap when `alloc` is available.
///
/// Unlike passing a completed fixed-size array to [`MaybeBox::new`], collecting
/// elements into this type constructs the allocation incrementally and never
/// materializes the complete array on the caller's stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayStorage<T, N: ArraySize> {
    #[cfg(not(feature = "alloc"))]
    inner: Array<T, N>,
    #[cfg(feature = "alloc")]
    inner: alloc::boxed::Box<[T]>,
    size: PhantomData<N>,
}

impl<T, N: ArraySize> From<Array<T, N>> for ArrayStorage<T, N> {
    fn from(inner: Array<T, N>) -> Self {
        #[cfg(not(feature = "alloc"))]
        {
            Self {
                inner,
                size: PhantomData,
            }
        }
        #[cfg(feature = "alloc")]
        {
            Self {
                inner: inner.into_iter().collect(),
                size: PhantomData,
            }
        }
    }
}

impl<T, N: ArraySize> FromIterator<T> for ArrayStorage<T, N> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        #[cfg(not(feature = "alloc"))]
        let inner = iter.into_iter().collect();
        #[cfg(feature = "alloc")]
        let inner = {
            let inner: alloc::boxed::Box<[T]> = iter.into_iter().collect();
            assert_eq!(inner.len(), N::USIZE, "incorrect fixed storage length");
            inner
        };
        Self {
            inner,
            size: PhantomData,
        }
    }
}

impl<T: Default, N: ArraySize> Default for ArrayStorage<T, N> {
    fn default() -> Self {
        core::iter::repeat_with(T::default).take(N::USIZE).collect()
    }
}

impl<T, N: ArraySize> Deref for ArrayStorage<T, N> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, N: ArraySize> DerefMut for ArrayStorage<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a, T, N: ArraySize> IntoIterator for &'a ArrayStorage<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, N: ArraySize> IntoIterator for &'a mut ArrayStorage<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

#[cfg(feature = "zeroize")]
impl<T: zeroize::Zeroize, N: ArraySize> zeroize::Zeroize for ArrayStorage<T, N> {
    fn zeroize(&mut self) {
        for element in self.iter_mut() {
            element.zeroize();
        }
    }
}

/// `Box`-like type providing opportunistic heap allocation when the `alloc` feature is available
/// that falls back to stack allocation when it's unavailable.
#[derive(Clone, Debug, PartialEq)]
pub struct MaybeBox<T> {
    #[cfg(not(feature = "alloc"))]
    inner: T,
    #[cfg(feature = "alloc")]
    inner: alloc::boxed::Box<T>,
}

impl<T> MaybeBox<T> {
    /// Create a new `MaybeBox`, using `Box` if `alloc` is available.
    #[inline]
    pub fn new(inner: T) -> Self {
        #[cfg(not(feature = "alloc"))]
        {
            Self { inner }
        }
        #[cfg(feature = "alloc")]
        Self {
            inner: alloc::boxed::Box::new(inner),
        }
    }

    /// Move the contents out of a [`MaybeBox`].
    ///
    /// This emulates the compiler magic that allows moving out of a box with `*my_box`.
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> T {
        #[cfg(not(feature = "alloc"))]
        {
            self.inner
        }
        #[cfg(feature = "alloc")]
        {
            *self.inner
        }
    }
}

impl<T> Deref for MaybeBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for MaybeBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
