//! Regression tests for heap-backed lattice matrix construction.

#![cfg(feature = "alloc")]

use array::{
    Array,
    typenum::{U8, U64},
};
use module_lattice::{Elem, NttMatrix, NttVector, define_field};

define_field!(TestField, u32, u64, u128, 8_380_417);

#[test]
fn matrix_construction_fits_small_stack() {
    let worker = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            // 512 KiB of coefficients, allocated one 8 KiB row at a time.
            let matrix = NttMatrix::<TestField, U64, U8>::new(Array::from_fn(|i| {
                let mut row = NttVector::<TestField, U8>::default();
                row.0[7].0[255] = Elem::new(u32::try_from(i).expect("row index fits u32"));
                row
            }));
            assert_eq!(matrix.0.len(), 64);
            assert_eq!(matrix.0[63].0.len(), 8);
            assert_eq!(matrix.0[63].0[7].0[255], Elem::new(63));
            core::hint::black_box(matrix);
        })
        .expect("create small-stack worker");

    assert!(worker.join().is_ok(), "small-stack worker panicked");
}
