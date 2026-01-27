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

// XXX(RLB) There are no unit tests in this crate right now, because the algebra and encode/decode
// routines all require a field, and the concrete field definitions are down in the dependent
// modules.  Maybe we should pull the field definitions up into this module so that we can verify
// that everything works.  That might also let us make private some of the tools used to build
// things up.

/// Linear algebra with degree-256 polynomials over a prime-order field, vectors of such
/// polynomials, and NTT polynomials / vectors
pub mod algebra;

/// Packing of polynomials into coefficients with a specified number of bits.
pub mod encode;

/// Utility functions such as truncating integers, flattening arrays of arrays, and unflattening
/// arrays into arrays of arrays.
pub mod util;
