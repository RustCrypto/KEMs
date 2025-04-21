# [RustCrypto]: X-Wing KEM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of X-Wing, a general-purpose post-quantum/traditional
hybrid key encapsulation mechanism (PQ/T KEM) built on X25519 and ML-KEM-768.
Built on the [ml-kem] and [x25519-dalek] crates.

Current implementation matches the [draft RFC][RFC-DRAFT] version 06.

The original paper: [X-Wing The Hybrid KEM You’ve Been Looking For][X-WING-PAPER]

[Documentation][docs-link]

## About

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

[crate-image]: https://img.shields.io/crates/v/x-wing?logo=rust
[crate-link]: https://crates.io/crates/x-wing
[docs-image]: https://docs.rs/x-wing/badge.svg
[docs-link]: https://docs.rs/x-wing/
[build-image]: https://github.com/RustCrypto/KEMs/actions/workflows/x-wing.yml/badge.svg
[build-link]: https://github.com/RustCrypto/KEMs/actions/workflows/x-wing.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/406484-KEMs

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[RFC-DRAFT]: https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem
[X-WING-PAPER]: https://eprint.iacr.org/2024/039.pdf
[x25519-dalek]: https://crates.io/crates/x25519-dalek
[ml-kem]: https://crates.io/crates/ml-kem
