//! Tests for the `encode` module.

use hybrid_array::typenum::{U1, U4, U10, U12};
use module_lattice::algebra::{Elem, NttPolynomial, NttVector, Polynomial, Vector};
use module_lattice::encode::{Encode, byte_decode, byte_encode};

// Field used by ML-KEM.
module_lattice::define_field!(KyberField, u16, u32, u64, 3329);

// ========================================
// byte_encode / byte_decode round-trip tests
// ========================================

#[test]
fn byte_encode_decode_d1_roundtrip() {
    // D=1: Single bit encoding
    let vals: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i % 2) as u16));

    let encoded = byte_encode::<KyberField, U1>(&vals.into());
    let decoded = byte_decode::<KyberField, U1>(&encoded);

    for (i, (dec, val)) in decoded.iter().zip(vals.iter()).enumerate() {
        assert_eq!(dec.0, val.0, "Mismatch at index {i}");
    }
}

#[test]
fn byte_encode_decode_d4_roundtrip() {
    // D=4: 4-bit encoding
    let vals: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i % 16) as u16));

    let encoded = byte_encode::<KyberField, U4>(&vals.into());
    let decoded = byte_decode::<KyberField, U4>(&encoded);

    for (i, (dec, val)) in decoded.iter().zip(vals.iter()).enumerate() {
        assert_eq!(dec.0, val.0, "Mismatch at index {i}");
    }
}

#[test]
fn byte_encode_decode_d10_roundtrip() {
    // D=10: 10-bit encoding
    let vals: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i % 1024) as u16));

    let encoded = byte_encode::<KyberField, U10>(&vals.into());
    let decoded = byte_decode::<KyberField, U10>(&encoded);

    for (i, (dec, val)) in decoded.iter().zip(vals.iter()).enumerate() {
        assert_eq!(dec.0, val.0, "Mismatch at index {i}");
    }
}

#[test]
fn byte_encode_decode_d12_roundtrip() {
    // D=12: 12-bit encoding (special case with modular reduction)
    // Values up to q-1 (3328)
    let vals: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 13) as u16 % 3329));

    let encoded = byte_encode::<KyberField, U12>(&vals.into());
    let decoded = byte_decode::<KyberField, U12>(&encoded);

    for (i, (dec, val)) in decoded.iter().zip(vals.iter()).enumerate() {
        assert_eq!(dec.0, val.0, "Mismatch at index {i}");
    }
}

#[test]
fn byte_encode_decode_d12_modular_reduction() {
    // Test that D=12 properly reduces values >= Q
    // Fill with values near and above Q
    let vals: [Elem<KyberField>; 256] =
        core::array::from_fn(|i| Elem::new(3329 + (i as u16) % 100));

    let encoded = byte_encode::<KyberField, U12>(&vals.into());
    let decoded = byte_decode::<KyberField, U12>(&encoded);

    // After decode, values should be reduced mod Q
    for (i, dec) in decoded.iter().enumerate() {
        assert!(dec.0 < 3329, "Value at {i} not reduced: {}", dec.0);
    }
}

#[test]
fn byte_encode_zero_values() {
    let vals = [Elem::<KyberField>::new(0); 256];

    let encoded = byte_encode::<KyberField, U4>(&vals.into());
    let decoded = byte_decode::<KyberField, U4>(&encoded);

    for dec in &decoded {
        assert_eq!(dec.0, 0);
    }
}

#[test]
fn byte_encode_max_values() {
    // D=4: max value is 15
    let vals = [Elem::<KyberField>::new(15); 256];

    let encoded = byte_encode::<KyberField, U4>(&vals.into());
    let decoded = byte_decode::<KyberField, U4>(&encoded);

    for dec in &decoded {
        assert_eq!(dec.0, 15);
    }
}

// ========================================
// Polynomial encoding tests
// ========================================

#[test]
fn polynomial_encode_decode_roundtrip() {
    let coeffs: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 7) as u16 % 16));
    let p = Polynomial::<KyberField>::new(coeffs.into());

    let encoded = <Polynomial<KyberField> as Encode<U4>>::encode(&p);
    let decoded = <Polynomial<KyberField> as Encode<U4>>::decode(&encoded);

    assert_eq!(p, decoded);
}

#[test]
fn polynomial_encode_decode_d12() {
    let coeffs: [Elem<KyberField>; 256] =
        core::array::from_fn(|i| Elem::new((i * 13) as u16 % 3329));
    let p = Polynomial::<KyberField>::new(coeffs.into());

    let encoded = <Polynomial<KyberField> as Encode<U12>>::encode(&p);
    let decoded = <Polynomial<KyberField> as Encode<U12>>::decode(&encoded);

    assert_eq!(p, decoded);
}

// ========================================
// Vector encoding tests
// ========================================

#[test]
fn vector_encode_decode_roundtrip() {
    use hybrid_array::typenum::U2;

    let coeffs1: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 3) as u16 % 16));
    let coeffs2: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 5) as u16 % 16));

    let p1 = Polynomial::<KyberField>::new(coeffs1.into());
    let p2 = Polynomial::<KyberField>::new(coeffs2.into());
    let v: Vector<KyberField, U2> = Vector::new([p1, p2].into());

    let encoded = <Vector<KyberField, U2> as Encode<U4>>::encode(&v);
    let decoded = <Vector<KyberField, U2> as Encode<U4>>::decode(&encoded);

    assert_eq!(v, decoded);
}

// ========================================
// NttPolynomial encoding tests
// ========================================

#[test]
fn ntt_polynomial_encode_decode_roundtrip() {
    let coeffs: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 7) as u16 % 16));
    let p = NttPolynomial::<KyberField>::new(coeffs.into());

    let encoded = <NttPolynomial<KyberField> as Encode<U4>>::encode(&p);
    let decoded = <NttPolynomial<KyberField> as Encode<U4>>::decode(&encoded);

    assert_eq!(p, decoded);
}

#[test]
fn ntt_polynomial_encode_decode_d12() {
    let coeffs: [Elem<KyberField>; 256] =
        core::array::from_fn(|i| Elem::new((i * 13) as u16 % 3329));
    let p = NttPolynomial::<KyberField>::new(coeffs.into());

    let encoded = <NttPolynomial<KyberField> as Encode<U12>>::encode(&p);
    let decoded = <NttPolynomial<KyberField> as Encode<U12>>::decode(&encoded);

    assert_eq!(p, decoded);
}

// ========================================
// NttVector encoding tests
// ========================================

#[test]
fn ntt_vector_encode_decode_roundtrip() {
    use hybrid_array::typenum::U2;

    let coeffs1: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 3) as u16 % 16));
    let coeffs2: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new((i * 5) as u16 % 16));

    let p1 = NttPolynomial::<KyberField>::new(coeffs1.into());
    let p2 = NttPolynomial::<KyberField>::new(coeffs2.into());
    let v: NttVector<KyberField, U2> = NttVector::new([p1, p2].into());

    let encoded = <NttVector<KyberField, U2> as Encode<U4>>::encode(&v);
    let decoded = <NttVector<KyberField, U2> as Encode<U4>>::decode(&encoded);

    assert_eq!(v, decoded);
}

// ========================================
// Encoding size verification
// ========================================

#[test]
fn encoded_polynomial_size_d4() {
    // D=4 means 4 bits per coefficient, 256 coefficients = 1024 bits = 128 bytes
    let coeffs = [Elem::<KyberField>::new(0); 256];
    let p = Polynomial::<KyberField>::new(coeffs.into());

    let encoded = <Polynomial<KyberField> as Encode<U4>>::encode(&p);
    assert_eq!(encoded.len(), 128);
}

#[test]
fn encoded_polynomial_size_d12() {
    // D=12 means 12 bits per coefficient, 256 coefficients = 3072 bits = 384 bytes
    let coeffs = [Elem::<KyberField>::new(0); 256];
    let p = Polynomial::<KyberField>::new(coeffs.into());

    let encoded = <Polynomial<KyberField> as Encode<U12>>::encode(&p);
    assert_eq!(encoded.len(), 384);
}

#[test]
fn encoded_vector_size() {
    use hybrid_array::typenum::U3;

    // D=4, K=3: 128 bytes per polynomial * 3 = 384 bytes
    let coeffs = [Elem::<KyberField>::new(0); 256];
    let p = Polynomial::<KyberField>::new(coeffs.into());
    let v: Vector<KyberField, U3> = Vector::new([p, p, p].into());

    let encoded = <Vector<KyberField, U3> as Encode<U4>>::encode(&v);
    assert_eq!(encoded.len(), 384);
}

// ========================================
// Edge cases and boundary tests
// ========================================

#[test]
fn byte_encode_alternating_bits() {
    // Test alternating patterns to catch bit manipulation issues
    let vals: [Elem<KyberField>; 256] =
        core::array::from_fn(|i| Elem::new(if i % 2 == 0 { 0b0101 } else { 0b1010 }));

    let encoded = byte_encode::<KyberField, U4>(&vals.into());
    let decoded = byte_decode::<KyberField, U4>(&encoded);

    for (i, (dec, val)) in decoded.iter().zip(vals.iter()).enumerate() {
        assert_eq!(dec.0, val.0, "Mismatch at index {i}");
    }
}

#[test]
fn byte_encode_sequential_values() {
    // Sequential values to catch ordering issues
    let vals: [Elem<KyberField>; 256] = core::array::from_fn(|i| Elem::new(i as u16 % 16));

    let encoded = byte_encode::<KyberField, U4>(&vals.into());
    let decoded = byte_decode::<KyberField, U4>(&encoded);

    for (i, (dec, val)) in decoded.iter().zip(vals.iter()).enumerate() {
        assert_eq!(dec.0, val.0, "Mismatch at index {i}");
    }
}
