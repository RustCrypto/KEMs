# [RustCrypto] eFrodo-KEM

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/RustCrypto/KEMs/actions/workflows/frodo-kem/badge.svg)

A pure rust implementation of [eFrodoKEM Learning with Errors Key Encapsulation](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf) and ISO [spec](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).

It's submission was included in NIST's PQ Round 3 competition.

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.81** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## Details

This code implements

- eFrodoKEM-640 with AES and SHAKE.
- eFrodoKEM-976 with AES and SHAKE.
- eFrodoKEM-1344 with AES and SHAKE.

## Future work

- Speed up AES implementation.

## License

Licensed under

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[RustCrypto]: https://github.com/rustcrypto
[crate-image]: https://img.shields.io/crates/v/frodo-kem-rs.svg
[crate-link]: https://crates.io/crates/frodo-kem-rs
[docs-image]: https://docs.rs/frodo-kem-rs/badge.svg
[docs-link]: https://docs.rs/frodo-kem-rs/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/frodo-kem-rs.svg
