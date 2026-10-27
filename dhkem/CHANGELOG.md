# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.1 (2026-10-25)
### Changed
- Bump `ctutils` to v0.4.5; MSRV 1.87 ([#405])

### Fixed
- Ensure serialized X25519 private keys are clamped ([#402])

[#402]: https://github.com/RustCrypto/KEMs/pull/402
[#405]: https://github.com/RustCrypto/KEMs/pull/405

## 0.1.0 (2026-07-11) [YANKED]

NOTE: this release was yanked because it incorrectly serialized X25519 keys

Initial release.
