//! Regression tests for heap-backed fixed-length storage.

#![cfg(feature = "alloc")]

use array::typenum::U64;
use module_lattice::ArrayStorage;

#[test]
fn array_storage_constructs_incrementally_on_a_small_stack() {
    const STACK_SIZE: usize = 128 * 1024;
    const ELEMENT_SIZE: usize = 4 * 1024;

    let worker = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(|| {
            let storage: ArrayStorage<[u8; ELEMENT_SIZE], U64> =
                (0..64).map(|value| [value; ELEMENT_SIZE]).collect();
            assert_eq!(storage.len(), 64);
            assert_eq!(storage[63][ELEMENT_SIZE - 1], 63);
        })
        .expect("create small-stack worker");

    assert!(worker.join().is_ok(), "small-stack worker panicked");
}
