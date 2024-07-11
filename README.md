# [RustCrypto]: Key Encapsulation Mechanisms (KEMs) [![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link]

Collection of [Key Encapsulation Mechanisms] (KEMs) written in pure Rust.

# About

KEMs are public-key algorithms designed to secure symmetric key material for transmission, and are 
commonly used in transport encryption protocols (e.g. [TLS]) and hybrid cryptosystems (e.g. [HPKE]).

## Crates

| Name     | crates.io                                                                                   | Docs                                                                         | Description        |
|----------|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|--------------------|
| `dhkem`  | [![crates.io](https://img.shields.io/crates/v/dhkem.svg)](https://crates.io/crates/dhkem)   | [![Documentation](https://docs.rs/dhkem/badge.svg)](https://docs.rs/dhkem)   | Diffie-Hellman KEM |
| `ml-kem` | [![crates.io](https://img.shields.io/crates/v/ml-kem.svg)](https://crates.io/crates/ml-kem) | [![Documentation](https://docs.rs/ml-kem/badge.svg)](https://docs.rs/ml-kem) | Module Lattice KEM |

## License

All crates licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/406484-KEMs
[deps-image]: https://deps.rs/repo/github/RustCrypto/KEMs/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/KEMs

[//]: # "links"
[RustCrypto]: https://github.com/RustCrypto/
[Key Encapsulation Mechanisms]: https://en.wikipedia.org/wiki/Key_encapsulation_mechanism
[TLS]: https://en.wikipedia.org/wiki/Transport_Layer_Security
[HPKE]: https://datatracker.ietf.org/doc/rfc9180/
