//! Tests for the `algebra` module.

use module_lattice::algebra::Field;

// Field used by ML-KEM.
module_lattice::define_field!(KyberField, u16, u32, u64, 3329);

// Field used by ML-DSA.
module_lattice::define_field!(DilithiumField, u32, u64, u128, 8_380_417);

#[test]
fn small_reduce() {
    assert_eq!(KyberField::small_reduce(3328), 3328);
    assert_eq!(KyberField::small_reduce(3329), 0);

    assert_eq!(DilithiumField::small_reduce(8_380_416), 8_380_416);
    assert_eq!(DilithiumField::small_reduce(8_380_417), 0);
}
