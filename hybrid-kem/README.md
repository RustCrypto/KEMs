# [RustCrypto]: Hybrid KEM

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of MLKEM768-P256, MLKEM768-X25519 and MLKEM1024-P384, which are
general-purpose post-quantum/traditional hybrid key encapsulation mechanism (PQ/T KEM) built on
P256, P384 and X25519 as traditional components, with ML-KEM-768 and ML-KEM-1024 as post-quantum
components. Built on the [ml-kem], [p256], [p384], [x25519-dalek] and [x-wing] crates.

Current implementation matches the [draft-irtf-cfrg-hybrid-kems] version 12 and [draft-irtf-cfrg-concrete-hybrid-kems] version 04.

[Documentation][docs-link]

## Features

The following features are provided by this crate:
* `x-wing` — Enables re-exporting MLKEM768-X25519 implementation from the [x-wing] crate
* `getrandom` — Enables `generate_key_pair` (generate without an explicit RNG)
* `zeroize` — Enables memory zeroing for all cryptographic secrets
* `hazmat` — Enables `EncapsulationKey::encapsulate_deterministic`. Useful for testing purposes.
  Do NOT enable unless you know what you are doing.

The **default** features are `["x-wing"]`.

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version (MSRV) Policy

MSRV increases are not considered breaking changes and can happen in patch
releases.

The crate MSRV accounts for all supported targets and crate feature
combinations, excluding explicitly unstable features.

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

[crate-image]: https://img.shields.io/crates/v/hybrid-kem?logo=rust
[crate-link]: https://crates.io/crates/hybrid-kem
[docs-image]: https://docs.rs/hybrid-kem/badge.svg
[docs-link]: https://docs.rs/hybrid-kem/
[build-image]: https://github.com/RustCrypto/KEMs/actions/workflows/hybrid-kem.yml/badge.svg
[build-link]: https://github.com/RustCrypto/KEMs/actions/workflows/hybrid-kem.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/406484-KEMs

[//]: # (links)

[RustCrypto]: https://github.com/rustcrypto
[draft-irtf-cfrg-hybrid-kems]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems
[draft-irtf-cfrg-concrete-hybrid-kems]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems
[p256]: https://crates.io/crates/p256
[p384]: https://crates.io/crates/p384
[x25519-dalek]: https://crates.io/crates/x25519-dalek
[ml-kem]: https://crates.io/crates/ml-kem
[x-wing]: https://crates.io/crates/x-wing
