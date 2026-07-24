# [RustCrypto] Frodo-KEM

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Build](https://github.com/RustCrypto/KEMs/actions/workflows/frodo-kem.yml/badge.svg)
![Apache2/MIT licensed][license-image]
![MSRV][msrv-image]

A pure Rust implementation of FrodoKEM and eFrodoKEM as specified in
[ISO/IEC 18033-2:2006/Amd 2:2026][iso-standard].

FrodoKEM was an alternate candidate in round 3 of the NIST Post-Quantum
Cryptography Standardization Project and is now standardized by ISO.

## ISO conformance

This crate implements the `Frodo.KeyGen`, `Frodo.Encaps`, and `Frodo.Decaps`
mathematical functions from Clause 14 of ISO/IEC 18033-2:2006/Amd 2:2026 for
all twelve parameter sets listed below.

Algorithmic conformance is checked against all 1,200 known-answer tests from
the FrodoKEM team's [official reference implementation][reference-kats]:
100 cases for each standard and ephemeral AES and SHAKE parameter set. The
tests verify deterministic key generation, encapsulation, and decapsulation
outputs. Additional tests exercise implicit rejection of modified ciphertexts,
parameter sizes, and serialization.

Based on a clause-by-clause implementation review and the complete official
KAT suite, this crate conforms to the FrodoKEM algorithms and parameter sets
specified by Clause 14 of ISO/IEC 18033-2:2006/Amd 2:2026.

This conformance assessment has not been independently verified by a third
party. The crate has not received ISO certification, an accredited
conformance assessment, or an independent security audit. See the detailed
[conformance review](CONFORMANCE.md) for the evidence and limitations behind
the claim.

## ⚠️ Security Warning

This crate has been tested against the test vectors provided by the FrodoKEM
team and for interoperability with Open Quantum Safe's
[liboqs](https://github.com/open-quantum-safe/liboqs).

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

## Details

This crate provides the following FrodoKEM algorithms:

- [x] FrodoKEM-640-AES ✅
- [x] FrodoKEM-976-AES ✅
- [x] FrodoKEM-1344-AES ✅
- [x] FrodoKEM-640-SHAKE ✅
- [x] FrodoKEM-976-SHAKE ✅
- [x] FrodoKEM-1344-SHAKE ✅
- [x] eFrodoKEM-640-AES ✅
- [x] eFrodoKEM-976-AES ✅
- [x] eFrodoKEM-1344-AES ✅
- [x] eFrodoKEM-640-SHAKE ✅
- [x] eFrodoKEM-976-SHAKE ✅
- [x] eFrodoKEM-1344-SHAKE ✅

eFrodoKEM is intended only for applications that guarantee a small number of
ciphertexts per public key (for example, at most 2<sup>8</sup>). Prefer standard
FrodoKEM unless that usage restriction is enforced by the application.

When in doubt use the FrodoKEM algorithm variants.

## Expanding matrix A

### NOTE on AES

To speed up AES, there are a few options available:

- `RUSTFLAGS="--cfg aes_armv8" cargo build --release` ensures that the ARMv8 AES instructions are used if available.
- `frodo-kem = { version = "0.3", features = ["openssl"] }` uses the `openssl` crate for AES.

By default, the `aes` feature auto-detects the best AES implementation for your platform
for x86 and x86\_64,
but not on ARMv8 where it defaults to the software implementation as of this writing.
To enable the ARMv8 AES instructions, the `aes_armv8` feature is enabled in the `.cargo/config` file in this crate.

Enabling openssl and aesni provides the fastest Aes algorithms.  

openssl tends to be faster than the aes rust crate implementation by about 10-15% on Armv8.

### NOTE on SHAKE
Shake auto detects the best implementation for your platform or like AES you can enable `openssl` for it also.

On Armv8, the rust shake implementation is faster than the openssl implementation by about 22-25%.

## Serialization

This crate has been tested against the following `serde` compatible formats:

- [x] serde_bare
- [x] postcard
- [x] serde_cbor
- [x] serde_json
- [x] serde_yaml
- [x] toml

## Minimum Supported Rust Version (MSRV) Policy

MSRV increases are not considered breaking changes and can happen in patch
releases.

The crate MSRV accounts for all supported targets and crate feature
combinations, excluding explicitly unstable features.

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
[crate-image]: https://img.shields.io/crates/v/frodo-kem.svg?logo=rust
[crate-link]: https://crates.io/crates/frodo-kem
[docs-image]: https://docs.rs/frodo-kem/badge.svg
[docs-link]: https://docs.rs/frodo-kem/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[iso-standard]: https://www.iso.org/standard/86890.html
[reference-kats]: https://github.com/microsoft/PQCrypto-LWEKE/tree/7a4e7219d06305e16aef734213001cd8fefbcc14
