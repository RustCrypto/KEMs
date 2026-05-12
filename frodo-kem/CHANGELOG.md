# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 (2026-04-28)
### Added
- Preliminary `no_std` support ([#238])

### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#118])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Bump `hybrid-array` dependency to v0.4 ([#129])
- Bump `serdect` dependency to v0.4 ([#130])
- Bump `getrandom` dependency to v0.4 ([#245])
- Bump `rand_core` dependency to v0.10 ([#245])
- Bump `sha3` dependency to v0.11 ([#282])
- Bump `aes` to v0.9 ([#294])
- Bump `getrandom` to v0.4 ([#294])
- Bump `chacha20` to v0.10 ([#294])
- Bump `toml` to v1 ([#294])
  
### Removed
- `safe-oqs` equivalence tests ([#166])

### Fixed
- Return error instead of panicking on empty `serde` input ([#259])
- OpenSSL EVP contexts memory leak ([#260])

[#118]: https://github.com/RustCrypto/KEMs/pull/118
[#129]: https://github.com/RustCrypto/KEMs/pull/129
[#130]: https://github.com/RustCrypto/KEMs/pull/130
[#166]: https://github.com/RustCrypto/KEMs/pull/166
[#238]: https://github.com/RustCrypto/KEMs/pull/238
[#245]: https://github.com/RustCrypto/KEMs/pull/245
[#259]: https://github.com/RustCrypto/KEMs/pull/259
[#260]: https://github.com/RustCrypto/KEMs/pull/260
[#282]: https://github.com/RustCrypto/KEMs/pull/282
[#294]: https://github.com/RustCrypto/KEMs/pull/294

## 0.0.1 (2025-01-19)
- Initial release
