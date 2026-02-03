#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
//#![deny(missing_docs)] // TODO: Require all public interfaces to be documented
#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`

/// Linear algebra with degree-256 polynomials over a prime-order field, vectors of such
/// polynomials, and NTT polynomials / vectors
pub mod algebra;

/// Packing of polynomials into coefficients with a specified number of bits.
pub mod encoding;

/// Utility functions such as truncating integers, flattening arrays of arrays, and unflattening
/// arrays into arrays of arrays.
pub mod truncate;
