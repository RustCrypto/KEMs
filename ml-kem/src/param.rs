//! This module encapsulates all of the compile-time logic related to parameter-set dependent sizes
//! of objects.  `ParameterSet` captures the parameters in the form described by the ML-KEM
//! specification.  `EncodingSize`, `VectorEncodingSize`, and `CbdSamplingSize` are "upstream" of
//! `ParameterSet`; they provide basic logic about the size of encoded objects.  `PkeParams` and
//! `KemParams` are "downstream" of `ParameterSet`; they define derived parameters relevant to
//! K-PKE and ML-KEM.
//!
//! While the primary purpose of these traits is to describe the sizes of objects, in order to
//! avoid leakage of complicated trait bounds, they also need to provide any logic that needs to
//! know any details about object sizes.  For example, `VectorEncodingSize::flatten` needs to know
//! that the size of an encoded vector is `K` times the size of an encoded polynomial.

use core::fmt::Debug;
use core::ops::{Add, Div, Mul, Rem, Sub};
use generic_array::{
    sequence::{Concat, Split},
    GenericArray, IntoArrayLength,
};
use typenum::{
    consts::{U0, U12, U16, U2, U3, U32, U384, U4, U6, U64, U8},
    operator_aliases::{Gcf, Prod, Quot, Sum},
    type_operators::Gcd,
    Const,
};

use crate::algebra::{FieldElement, NttVector};
use crate::encode::Encode;
use crate::util::{Flatten, Unflatten, B32};

/// An array length with other useful properties
pub trait ArrayLength: generic_array::ArrayLength + PartialEq + Debug {}

impl<T> ArrayLength for T where T: generic_array::ArrayLength + PartialEq + Debug {}

/// An integer that can be used as a length for encoded values.
pub trait EncodingSize: ArrayLength {
    type EncodedPolynomialSize: ArrayLength;
    type ValueStep: ArrayLength;
    type ByteStep: ArrayLength;
}

type EncodingUnit<D> = Quot<Prod<D, U8>, Gcf<D, U8>>;

pub type EncodedPolynomialSize<D> = <D as EncodingSize>::EncodedPolynomialSize;
pub type EncodedPolynomial<D> = GenericArray<u8, EncodedPolynomialSize<D>>;

impl<D> EncodingSize for D
where
    D: ArrayLength + Mul<U8> + Gcd<U8> + Mul<U32>,
    Prod<D, U32>: ArrayLength,
    Prod<D, U8>: Div<Gcf<D, U8>>,
    EncodingUnit<D>: Div<D> + Div<U8>,
    Quot<EncodingUnit<D>, D>: ArrayLength,
    Quot<EncodingUnit<D>, U8>: ArrayLength,
{
    type EncodedPolynomialSize = Prod<D, U32>;
    type ValueStep = Quot<EncodingUnit<D>, D>;
    type ByteStep = Quot<EncodingUnit<D>, U8>;
}

/// An integer that can describe encoded vectors.
pub trait VectorEncodingSize<K>: EncodingSize
where
    K: ArrayLength,
{
    type EncodedPolynomialVectorSize: ArrayLength;

    fn flatten(polys: GenericArray<EncodedPolynomial<Self>, K>)
        -> EncodedPolynomialVector<Self, K>;
    fn unflatten(
        vec: &EncodedPolynomialVector<Self, K>,
    ) -> GenericArray<&EncodedPolynomial<Self>, K>;
}

pub type EncodedPolynomialVectorSize<D, K> =
    <D as VectorEncodingSize<K>>::EncodedPolynomialVectorSize;
pub type EncodedPolynomialVector<D, K> = GenericArray<u8, EncodedPolynomialVectorSize<D, K>>;

impl<D, K> VectorEncodingSize<K> for D
where
    D: EncodingSize,
    K: ArrayLength,
    D::EncodedPolynomialSize: Mul<K>,
    Prod<D::EncodedPolynomialSize, K>:
        ArrayLength + Div<K, Output = D::EncodedPolynomialSize> + Rem<K, Output = U0>,
{
    type EncodedPolynomialVectorSize = Prod<D::EncodedPolynomialSize, K>;

    fn flatten(
        polys: GenericArray<EncodedPolynomial<Self>, K>,
    ) -> EncodedPolynomialVector<Self, K> {
        polys.flatten()
    }

    fn unflatten(
        vec: &EncodedPolynomialVector<Self, K>,
    ) -> GenericArray<&EncodedPolynomial<Self>, K> {
        vec.unflatten()
    }
}

/// An integer that describes a bit length to be used in CBD sampling
pub trait CbdSamplingSize: ArrayLength {
    type SampleSize: EncodingSize;
    type OnesSize: ArrayLength;
    const ONES: GenericArray<FieldElement, Self::OnesSize>;
}

// To speed up CBD sampling, we pre-compute all the bit-manipulations:
//
// * Splitting a sampled integer into two parts
// * Counting the ones in each part
// * Taking the difference between the two counts mod q
//
// We have to allow the use of `as` here because we can't use our nice Truncate trait, because
// const functions don't support traits.
#[allow(clippy::cast_possible_truncation)]
const fn ones_array<const B: usize, const N: usize, U>() -> GenericArray<FieldElement, U>
where
    U: ArrayLength,
    Const<N>: IntoArrayLength<ArrayLength = U>,
{
    let max = 1 << B;
    let mut out = [FieldElement(0); N];
    let mut x = 0usize;
    while x < max {
        let mut y = 0usize;
        while y < max {
            let x_ones = x.count_ones() as u16;
            let y_ones = y.count_ones() as u16;
            let i = x + (y << B);
            out[i] = FieldElement((x_ones + FieldElement::Q - y_ones) % FieldElement::Q);

            y += 1;
        }
        x += 1;
    }
    GenericArray::from_array(out)
}

impl CbdSamplingSize for U2 {
    type SampleSize = U4;
    type OnesSize = U16;
    const ONES: GenericArray<FieldElement, U16> = ones_array::<2, 16, U16>();
}

impl CbdSamplingSize for U3 {
    type SampleSize = U6;
    type OnesSize = U64;
    const ONES: GenericArray<FieldElement, U64> = ones_array::<3, 64, U64>();
}

/// A `ParameterSet` captures the parameters that describe a particular instance of ML-KEM.  There
/// are three variants, corresponding to three different security levels.
pub trait ParameterSet: Default + Clone + Debug + PartialEq {
    /// The dimensionality of vectors and arrays
    type K: ArrayLength;

    /// The bit width of the centered binary distribution used when sampling random polynomials in
    /// key generation and encryption.
    type Eta1: CbdSamplingSize;

    /// The bit width of the centered binary distribution used when sampling error vectors during
    /// encryption.
    type Eta2: CbdSamplingSize;

    /// The bit width of encoded integers in the `u` vector in a ciphertext
    type Du: VectorEncodingSize<Self::K>;

    /// The bit width of encoded integers in the `v` polynomial in a ciphertext
    type Dv: EncodingSize;
}

type EncodedUSize<P> = EncodedPolynomialVectorSize<<P as ParameterSet>::Du, <P as ParameterSet>::K>;
type EncodedVSize<P> = EncodedPolynomialSize<<P as ParameterSet>::Dv>;

type EncodedU<P> = GenericArray<u8, EncodedUSize<P>>;
type EncodedV<P> = GenericArray<u8, EncodedVSize<P>>;

/// Derived parameter relevant to K-PKE
pub trait PkeParams: ParameterSet {
    type NttVectorSize: ArrayLength;
    type EncryptionKeySize: ArrayLength;
    type CiphertextSize: ArrayLength;

    fn encode_u12(p: &NttVector<Self::K>) -> EncodedNttVector<Self>;
    fn decode_u12(v: &EncodedNttVector<Self>) -> NttVector<Self::K>;

    fn concat_ct(u: EncodedU<Self>, v: EncodedV<Self>) -> EncodedCiphertext<Self>;
    fn split_ct(ct: &EncodedCiphertext<Self>) -> (&EncodedU<Self>, &EncodedV<Self>);

    fn concat_ek(t_hat: EncodedNttVector<Self>, rho: B32) -> EncodedEncryptionKey<Self>;
    fn split_ek(ek: &EncodedEncryptionKey<Self>) -> (&EncodedNttVector<Self>, &B32);
}

pub type EncodedNttVector<P> = GenericArray<u8, <P as PkeParams>::NttVectorSize>;
pub type EncodedDecryptionKey<P> = GenericArray<u8, <P as PkeParams>::NttVectorSize>;
pub type EncodedEncryptionKey<P> = GenericArray<u8, <P as PkeParams>::EncryptionKeySize>;
pub type EncodedCiphertext<P> = GenericArray<u8, <P as PkeParams>::CiphertextSize>;

impl<P> PkeParams for P
where
    P: ParameterSet,
    U384: Mul<P::K>,
    Prod<U384, P::K>: ArrayLength + Add<U32> + Div<P::K, Output = U384> + Rem<P::K, Output = U0>,
    EncodedUSize<P>: Add<EncodedVSize<P>>,
    Sum<EncodedUSize<P>, EncodedVSize<P>>:
        ArrayLength + Sub<EncodedUSize<P>, Output = EncodedVSize<P>>,
    EncodedPolynomialVectorSize<U12, P::K>: Add<U32>,
    Sum<EncodedPolynomialVectorSize<U12, P::K>, U32>:
        ArrayLength + Sub<EncodedPolynomialVectorSize<U12, P::K>, Output = U32>,
{
    type NttVectorSize = EncodedPolynomialVectorSize<U12, P::K>;
    type EncryptionKeySize = Sum<Self::NttVectorSize, U32>;
    type CiphertextSize = Sum<EncodedUSize<P>, EncodedVSize<P>>;

    fn encode_u12(p: &NttVector<Self::K>) -> EncodedNttVector<Self> {
        Encode::<U12>::encode(p)
    }

    fn decode_u12(v: &EncodedNttVector<Self>) -> NttVector<Self::K> {
        Encode::<U12>::decode(v)
    }

    fn concat_ct(u: EncodedU<Self>, v: EncodedV<Self>) -> EncodedCiphertext<Self> {
        u.concat(v)
    }

    fn split_ct(ct: &EncodedCiphertext<Self>) -> (&EncodedU<Self>, &EncodedV<Self>) {
        ct.split()
    }

    fn concat_ek(t_hat: EncodedNttVector<Self>, rho: B32) -> EncodedEncryptionKey<Self> {
        t_hat.concat(rho)
    }

    fn split_ek(ek: &EncodedEncryptionKey<Self>) -> (&EncodedNttVector<Self>, &B32) {
        ek.split()
    }
}

/// Derived parameters relevant to ML-KEM
pub trait KemParams: PkeParams {
    type DecapsulationKeySize: ArrayLength;

    fn concat_dk(
        dk: EncodedDecryptionKey<Self>,
        ek: EncodedEncryptionKey<Self>,
        h: B32,
        z: B32,
    ) -> EncodedDecapsulationKey<Self>;

    fn split_dk(
        enc: &EncodedDecapsulationKey<Self>,
    ) -> (
        &EncodedDecryptionKey<Self>,
        &EncodedEncryptionKey<Self>,
        &B32,
        &B32,
    );
}

pub type DecapsulationKeySize<P> = <P as KemParams>::DecapsulationKeySize;
pub type EncapsulationKeySize<P> = <P as PkeParams>::EncryptionKeySize;

pub type EncodedDecapsulationKey<P> = GenericArray<u8, <P as KemParams>::DecapsulationKeySize>;

impl<P> KemParams for P
where
    P: PkeParams,
    P::NttVectorSize: Add<P::EncryptionKeySize>,
    Sum<P::NttVectorSize, P::EncryptionKeySize>:
        ArrayLength + Add<U32> + Sub<P::NttVectorSize, Output = P::EncryptionKeySize>,
    Sum<Sum<P::NttVectorSize, P::EncryptionKeySize>, U32>:
        ArrayLength + Add<U32> + Sub<Sum<P::NttVectorSize, P::EncryptionKeySize>, Output = U32>,
    Sum<Sum<Sum<P::NttVectorSize, P::EncryptionKeySize>, U32>, U32>:
        ArrayLength + Sub<Sum<Sum<P::NttVectorSize, P::EncryptionKeySize>, U32>, Output = U32>,
{
    type DecapsulationKeySize = Sum<Sum<Sum<P::NttVectorSize, P::EncryptionKeySize>, U32>, U32>;

    fn concat_dk(
        dk: EncodedDecryptionKey<Self>,
        ek: EncodedEncryptionKey<Self>,
        h: B32,
        z: B32,
    ) -> EncodedDecapsulationKey<Self> {
        dk.concat(ek).concat(h).concat(z)
    }

    fn split_dk(
        enc: &EncodedDecapsulationKey<Self>,
    ) -> (
        &EncodedDecryptionKey<Self>,
        &EncodedEncryptionKey<Self>,
        &B32,
        &B32,
    ) {
        // We parse from right to left to make it easier to write the trait bounds above
        let (enc, z) = enc.split();
        let (enc, h) = enc.split();
        let (dk_pke, ek_pke) = enc.split();
        (dk_pke, ek_pke, h, z)
    }
}
