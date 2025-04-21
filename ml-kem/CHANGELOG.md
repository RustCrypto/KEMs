# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.0 (UNRELEASED)
### Changed
- Edition changed to 2024 and MSRV bumped to 1.85 ([#118])
- Relax MSRV policy and allow MSRV bumps in patch releases

[#118]: https://github.com/RustCrypto/KEMs/pull/118

## 0.2.1 (2024-08-17)
### Added
- `zeroize` feature ([#51])

[#51]: https://github.com/RustCrypto/KEMs/pull/51

## 0.2.0 (2024-08-16)
### Added
- `DecapsulationKey::encapsulation_key` ([#48])
- Re-export `kem::{Decapsulate, Encapsulate}` under `kem` module ([#49])
- Re-exports `hybrid-array` as `array` ([#49])

### Changed
- Update to FIPS 203 final ([#47])

[#47]: https://github.com/RustCrypto/KEMs/pull/47
[#48]: https://github.com/RustCrypto/KEMs/pull/48
[#49]: https://github.com/RustCrypto/KEMs/pull/49

## 0.1.1 (2024-06-04)
### Security
- Fix potential "Kyberslash" attack ([#18])

[#18]: https://github.com/RustCrypto/KEMs/pull/18

## 0.1.0 (2024-04-12)
- Initial release
