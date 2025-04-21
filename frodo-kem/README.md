# [RustCrypto] Frodo-KEM

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Build](https://github.com/RustCrypto/KEMs/actions/workflows/frodo-kem.yml/badge.svg)
![Apache2/MIT licensed][license-image]
![MSRV][msrv-image]

A pure rust implementation of 
- [FrodoKEM Learning with Errors Key Encapsulation](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
- [ISO Standard](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf)
- [ISO Standard Annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf)

It's submission was included in NIST's PQ Round 3 competition, and is now being standardized at ISO.

## ⚠️ Security Warning

This crate has been tested against the test vectors provided by the FrodoKEM team
and been rigorously tested for correctness, performance, and security. It has 
also been tested against opensafequatum's [liboqs](https://github.com/open-quantum-safe/liboqs) library to compatibility and correctness.

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

eFrodoKEM is a variant of FrodoKEM that is meant to be used one-time only. Using more than once
is considered a security risk.

When in doubt use the FrodoKEM algorithm variants.

## Expanding matrix A

### NOTE on AES

To speed up AES, there are a few options available:

- `RUSTFLAGS="--cfg aes_armv8" cargo build --release` ensures that the ARMv8 AES instructions are used if available.
- `frodo-kem = { version = "0.3", features = ["openssl"] }` uses the `openssl` crate for AES.

By default, the `aes` feature auto-detects the best AES implementation for your platform
for x86 and x86_64,
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
- [x] bincode
- [x] postcard
- [x] serde_cbor
- [x] serde_json
- [x] serde_yaml
- [x] toml

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
[msrv-image]: https://img.shields.io/badge/rustc-1.82+-blue.svg
