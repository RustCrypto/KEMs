# [RustCrypto]: ML-KEM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Module-Lattice-Based Key-Encapsulation Mechanism Standard
(formerly known as Kyber) as described in the [FIPS 203 Initial Public Draft].

[Documentation][docs-link]

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

This crate requires **Rust 1.74** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/ml-kem
[crate-link]: https://crates.io/crates/ml-kem
[docs-image]: https://docs.rs/ml-kem/badge.svg
[docs-link]: https://docs.rs/ml-kem/
[build-image]: https://github.com/RustCrypto/KEMs/actions/workflows/ml-kem.yml/badge.svg
[build-link]: https://github.com/RustCrypto/KEMs/actions/workflows/ml-kem.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.74+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/406484-KEMs

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[FIPS 203 Initial Public Draft]: https://csrc.nist.gov/pubs/fips/203/ipd
