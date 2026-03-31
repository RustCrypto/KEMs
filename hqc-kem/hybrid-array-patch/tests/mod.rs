#![allow(missing_docs, clippy::cast_possible_truncation, clippy::unwrap_used)]

use core::mem::MaybeUninit;
use hybrid_array::{Array, ArrayN};
use typenum::{U0, U2, U3, U4, U5, U6, U7};

const EXAMPLE_SLICE: &[u8] = &[1, 2, 3, 4, 5, 6];

/// Ensure `ArrayN` works as expected.
const _FOO: ArrayN<u8, 4> = Array([1, 2, 3, 4]);

#[test]
fn tryfrom_slice_for_clonable_array() {
    assert!(Array::<u8, U0>::try_from(EXAMPLE_SLICE).is_err());
    assert!(Array::<u8, U3>::try_from(EXAMPLE_SLICE).is_err());

    let array_ref = Array::<u8, U6>::try_from(EXAMPLE_SLICE).expect("slice contains 6 bytes");
    assert_eq!(&*array_ref, EXAMPLE_SLICE);

    assert!(Array::<u8, U7>::try_from(EXAMPLE_SLICE).is_err());
}

#[test]
fn tryfrom_slice_for_array_ref() {
    assert!(<&Array<u8, U0>>::try_from(EXAMPLE_SLICE).is_err());
    assert!(<&Array::<u8, U3>>::try_from(EXAMPLE_SLICE).is_err());

    let array_ref = <&Array<u8, U6>>::try_from(EXAMPLE_SLICE).expect("slice contains 6 bytes");
    assert_eq!(array_ref.as_slice(), EXAMPLE_SLICE);

    assert!(<&Array::<u8, U7>>::try_from(EXAMPLE_SLICE).is_err());
}

#[test]
fn slice_as_array() {
    type A = Array<u8, U2>;
    assert_eq!(A::slice_as_array(&[]), None);
    assert_eq!(A::slice_as_array(&[1]), None);
    assert_eq!(A::slice_as_array(&[1, 2]), Some(&Array([1, 2])));
    assert_eq!(A::slice_as_array(&[1, 2, 3]), None);
}

#[test]
fn slice_as_mut_array() {
    type A = Array<u8, U2>;
    assert_eq!(A::slice_as_mut_array(&mut []), None);
    assert_eq!(A::slice_as_mut_array(&mut [1]), None);
    assert_eq!(A::slice_as_mut_array(&mut [1, 2]), Some(&mut Array([1, 2])));
    assert_eq!(A::slice_as_mut_array(&mut [1, 2, 3]), None);
}

#[test]
fn concat() {
    let prefix = Array::<u8, U2>::try_from(&EXAMPLE_SLICE[..2]).unwrap();
    let suffix = Array::<u8, U4>::try_from(&EXAMPLE_SLICE[2..]).unwrap();

    let array = prefix.concat(suffix);
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);
}

#[test]
fn split() {
    let array = Array::<u8, U6>::try_from(EXAMPLE_SLICE).unwrap();
    let (prefix, suffix) = array.split::<U2>();

    assert_eq!(prefix.as_slice(), &EXAMPLE_SLICE[..2]);
    assert_eq!(suffix.as_slice(), &EXAMPLE_SLICE[2..]);
}

#[test]
fn split_ref() {
    let array = Array::<u8, U6>::try_from(EXAMPLE_SLICE).unwrap();
    let (prefix, suffix) = array.split_ref::<U3>();

    assert_eq!(prefix.as_slice(), &EXAMPLE_SLICE[..3]);
    assert_eq!(suffix.as_slice(), &EXAMPLE_SLICE[3..]);
}

#[test]
fn split_ref_mut() {
    let array = &mut Array::<u8, U6>::try_from(EXAMPLE_SLICE).unwrap();
    let (prefix, suffix) = array.split_ref_mut::<U4>();

    assert_eq!(prefix.as_slice(), &EXAMPLE_SLICE[..4]);
    assert_eq!(suffix.as_slice(), &EXAMPLE_SLICE[4..]);
}

#[test]
fn from_ref() {
    let n = 42u64;
    let array = Array::from_ref(&n);
    assert_eq!(array[0], n);
}

#[test]
fn from_mut() {
    let mut n = 42u64;
    let array = Array::from_mut(&mut n);
    array[0] = 43;
    assert_eq!(n, 43);
}

#[test]
fn from_fn() {
    let array = Array::<u8, U6>::from_fn(|n| (n + 1) as u8);
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);
}

#[test]
fn try_from_fn() {
    let array = Array::<u8, U6>::try_from_fn::<()>(|n| Ok((n + 1) as u8)).unwrap();
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);

    let err = Array::<u8, U6>::try_from_fn::<&'static str>(|_| Err("err"))
        .err()
        .unwrap();

    assert_eq!(err, "err");
}

#[test]
fn from_iterator_correct_size() {
    let array: Array<u8, U6> = EXAMPLE_SLICE.iter().copied().collect();
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);
}

#[test]
#[should_panic]
fn from_iterator_too_short() {
    let _array: Array<u8, U7> = EXAMPLE_SLICE.iter().copied().collect();
}

#[test]
#[should_panic]
fn from_iterator_too_long() {
    let _array: Array<u8, U5> = EXAMPLE_SLICE.iter().copied().collect();
}

#[test]
fn try_from_iterator_correct_size() {
    let array = Array::<u8, U6>::try_from_iter(EXAMPLE_SLICE.iter().copied()).unwrap();
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);
}

#[test]
fn try_from_iterator_too_short() {
    let result = Array::<u8, U7>::try_from_iter(EXAMPLE_SLICE.iter().copied());
    assert!(result.is_err());
}

#[test]
fn try_from_iterator_too_long() {
    let result = Array::<u8, U5>::try_from_iter(EXAMPLE_SLICE.iter().copied());
    assert!(result.is_err());
}

#[test]
fn maybe_uninit() {
    let mut uninit_array = Array::<MaybeUninit<u8>, U6>::uninit();

    for i in 0..6 {
        uninit_array[i].write(EXAMPLE_SLICE[i]);
    }

    let array = unsafe { uninit_array.assume_init() };
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);
}

#[test]
fn map() {
    let base = Array::<u8, U4>::from([1, 2, 3, 4]);
    let expected = Array::<u16, U4>::from([2, 3, 4, 5]);
    assert_eq!(base.map(|item| u16::from(item) + 1), expected);
}

#[test]
#[allow(deprecated)]
fn clone_from_slice() {
    let array = Array::<u8, U6>::clone_from_slice(EXAMPLE_SLICE);
    assert_eq!(array.as_slice(), EXAMPLE_SLICE);
}

#[test]
fn slice_as_flattened() {
    let slice: &mut [Array<u8, U4>] = &mut [Array([1, 2, 3, 4]), Array([5, 6, 7, 8])];
    assert_eq!(
        Array::slice_as_flattened_mut(slice),
        &mut [1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(Array::slice_as_flattened(slice), &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
#[cfg(feature = "zerocopy")]
#[allow(unused)]
fn zerocopy_traits() {
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
    struct Check<T: IntoBytes + FromBytes + Unaligned + Immutable + KnownLayout>(T);
    let ok: Check<Array<u8, U5>> = Check(Array([1, 2, 3, 4, 5]));
    // let not_unaligned:  Check::<Array<u16, U5>> = Check(Array([1, 2, 3, 4, 5]));
}
