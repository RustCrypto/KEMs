# [RustCrypto]: Diffie-Hellman-Based KEM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the Diffie-Hellman-Based Key-Encapsulation Mechanism
as described in the [RFC9180 § 4.1].

[Documentation][docs-link]

## About

Key Encapsulation Mechanisms (KEMs) provide a common API for establishing a
symmetric key using public-key cryptography.

This crate implements a KEM-based API for elliptic curve Diffie-Hellman as
specified for Hybrid Public Key Encryption (HPKE) which is described in
[RFC9180].

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

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

[crate-image]: https://img.shields.io/crates/v/dhkem?logo=rust
[crate-link]: https://crates.io/crates/dhkem
[docs-image]: https://docs.rs/dhkem/badge.svg
[docs-link]: https://docs.rs/dhkem/
[build-image]: https://github.com/RustCrypto/KEMs/actions/workflows/dhkem.yml/badge.svg
[build-link]: https://github.com/RustCrypto/KEMs/actions/workflows/dhkem.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.74+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/406484-KEMs

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC9180]: https://datatracker.ietf.org/doc/html/rfc9180
[RFC9180 § 4.1]: https://datatracker.ietf.org/doc/html/rfc9180#name-dh-based-kem-dhkem
