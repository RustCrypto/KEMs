# sntrup-kem
[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/RustCrypto/KEMs/actions/workflows/sntrup-kem.yml/badge.svg)
![MSRV][msrv-image]

A pure-Rust implementation of [Streamlined NTRU Prime](https://ntruprime.cr.yp.to/) for all parameter sizes.

NTRU Prime is a lattice-based cryptosystem aiming to improve the security of lattice schemes at minimal cost. It is thought to be resistant to quantum computing advances, in particular Shor's algorithm. It made it to NIST final round but was not selected for finalization.

Please read the [warnings](#warnings) before use.

The algorithm was authored by Daniel J. Bernstein, Chitchanok Chuengsatiansup, Tanja Lange & Christine van Vredendaal. This implementation is aligned with the [PQClean reference](https://github.com/PQClean/PQClean/tree/master/crypto_kem) and verified against the [IETF draft](https://datatracker.ietf.org/doc/draft-josefsson-ntruprime-streamlined/) KAT vectors.

## Parameter Sets

| Parameter Set | NIST Level | P    | Q    | W   | Public Key | Secret Key | Ciphertext | Shared Secret |
|---------------|:----------:|-----:|-----:|----:|-----------:|-----------:|-----------:|--------------:|
| sntrup653     | 1          |  653 | 4621 | 288 |        994 |       1518 |        897 |            32 |
| sntrup761     | 2          |  761 | 4591 | 286 |       1158 |       1763 |       1039 |            32 |
| sntrup857     | 3          |  857 | 5167 | 322 |       1322 |       1999 |       1184 |            32 |
| sntrup953     | 4          |  953 | 6343 | 396 |       1505 |       2254 |       1349 |            32 |
| sntrup1013    | 5          | 1013 | 7177 | 448 |       1623 |       2417 |       1455 |            32 |
| sntrup1277    | 5          | 1277 | 7879 | 492 |       2067 |       3059 |       1847 |            32 |

All key and ciphertext sizes are in bytes. Sizes are fixed per parameter set using a canonical encoding enforced by the code.

> **Note:** sntrup653 (NIST Level 1) is recommended for research and testing only. Prefer sntrup761 or higher for production use.

## Features

- Pure Rust, `no_std`-compatible, dependency-minimal
- All six parameter sizes: sntrup653, sntrup761, sntrup857, sntrup953, sntrup1013, sntrup1277
- IND-CCA2 secure with implicit rejection
- Constant-time operations throughout (branchless sort, constant-time comparison and selection)
- SIMD acceleration (AVX2 on x86_64, NEON on aarch64) with automatic detection
- Optional `serde` support via the `serde` feature
- Deterministic key generation from a 32-byte seed

### Feature Flags

The KEM API is split into three default features so downstream crates can pull in only what they need:

| Feature | Default | Description |
|---------|:-------:|-------------|
| `kgen`  | **yes** | Key generation: `SntrupKem::generate_key`, `SntrupKem::generate_key_deterministic` |
| `ecap`  | **yes** | Encapsulation: `EncapsulationKey::encapsulate` |
| `dcap`  | **yes** | Decapsulation: `DecapsulationKey::decapsulate` |
| `force-scalar` | no | Disable SIMD (AVX2/NEON) and use pure-Rust scalar code |
| `serde` | no | Enables `Serialize`/`Deserialize` for all key and ciphertext types (via `serdect` for constant-time hex encoding) |
| `js`    | no | Enables WebAssembly support for `wasm32-unknown-unknown` by configuring `getrandom` to use JavaScript's `crypto.getRandomValues()` |

To use only a subset of the KEM API, disable defaults and pick the features you need:

```toml
[dependencies]
# Decapsulation only (e.g. a receiver that never generates keys or encapsulates)
sntrup-kem = { version = "0.1", default-features = false, features = ["dcap"] }
```

## Usage

### Key generation

```rust
use sntrup_kem::{Sntrup761, SntrupKem};

let mut rng = rand::rng();
let (encapsulation_key, decapsulation_key) = Sntrup761::generate_key(&mut rng);
```

All six parameter sets are available as type aliases:

```rust
use sntrup_kem::{Sntrup653, Sntrup761, Sntrup857, Sntrup953, Sntrup1013, Sntrup1277, SntrupKem};

let mut rng = rand::rng();
let (ek_653, dk_653) = Sntrup653::generate_key(&mut rng);
let (ek_761, dk_761) = Sntrup761::generate_key(&mut rng);
let (ek_857, dk_857) = Sntrup857::generate_key(&mut rng);
let (ek_953, dk_953) = Sntrup953::generate_key(&mut rng);
let (ek_1013, dk_1013) = Sntrup1013::generate_key(&mut rng);
let (ek_1277, dk_1277) = Sntrup1277::generate_key(&mut rng);
```

Or use the convenience modules with parameter-specific types:

```rust
let mut rng = rand::rng();
let (ek, dk) = sntrup_kem::sntrup761::generate_key(&mut rng);
```

### Encapsulation

The sender uses the encapsulation (public) key to produce a ciphertext and shared secret:

```rust
use sntrup_kem::{Sntrup761, SntrupKem};

let mut rng = rand::rng();
let (encapsulation_key, decapsulation_key) = Sntrup761::generate_key(&mut rng);

// Sender side
let (ciphertext, shared_secret_sender) = encapsulation_key.encapsulate(&mut rng);
```

### Decapsulation

The receiver uses the decapsulation (secret) key and the ciphertext to recover the shared secret:

```rust
use sntrup_kem::{Sntrup761, SntrupKem};

let mut rng = rand::rng();
let (encapsulation_key, decapsulation_key) = Sntrup761::generate_key(&mut rng);
let (ciphertext, shared_secret_sender) = encapsulation_key.encapsulate(&mut rng);

// Receiver side — implicit rejection: always returns a key
let shared_secret_receiver = decapsulation_key.decapsulate(&ciphertext);

assert_eq!(shared_secret_sender, shared_secret_receiver);
```

### Deterministic key generation

Derive the same keypair from a 32-byte seed:

```rust
use sntrup_kem::{Sntrup761, SntrupKem};

let seed = [0x42u8; 32]; // must come from a cryptographically secure source
let (ek1, dk1) = Sntrup761::generate_key_deterministic(&seed);
let (ek2, dk2) = Sntrup761::generate_key_deterministic(&seed);
assert_eq!(ek1, ek2);
assert_eq!(dk1, dk2);
```

### Serialization with serde

Enable the `serde` feature:

```toml
sntrup-kem = { version = "0.1", features = ["serde"] }
```

Keys and ciphertexts serialize to hex in human-readable formats (JSON) and raw bytes in binary formats (postcard, bincode):

```rust,ignore
use sntrup_kem::{Sntrup761, SntrupKem, EncapsulationKey, Sntrup761Params};

let mut rng = rand::rng();
let (ek, dk) = Sntrup761::generate_key(&mut rng);
let json = serde_json::to_string(&ek).unwrap();
let ek2: EncapsulationKey<Sntrup761Params> = serde_json::from_str(&json).unwrap();
assert_eq!(ek, ek2);
```

### Byte conversions

All types support `AsRef<[u8]>` and `TryFrom<&[u8]>`:

```rust
use sntrup_kem::{Sntrup761, SntrupKem, EncapsulationKey, Sntrup761Params};

let mut rng = rand::rng();
let (ek, dk) = Sntrup761::generate_key(&mut rng);

// Serialize to bytes
let ek_bytes: &[u8] = ek.as_ref();

// Deserialize from bytes (validates size)
let ek2 = EncapsulationKey::<Sntrup761Params>::try_from(ek_bytes).unwrap();
assert_eq!(ek, ek2);
```

## WebAssembly

To compile for `wasm32-unknown-unknown`, enable the `js` feature so that `getrandom` uses JavaScript's `crypto.getRandomValues()` for randomness:

```toml
[dependencies]
sntrup-kem = { version = "0.1", features = ["js"] }
```

Install the target and build:

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --features js
```

For `wasm32-wasi` (or `wasm32-wasip1`), the `js` feature is **not** needed since WASI provides its own random source.

## Security Properties

- **IND-CCA2 security** via implicit rejection: decapsulation always returns a shared key. On failure, a pseudorandom key is derived from secret randomness (`rho`), making it indistinguishable from a valid key to an attacker.
- **Hash domain separation**: all hashes use prefix bytes (following the NTRU Prime specification).
- **Constant-time operations**: branchless sorting (djbsort), constant-time weight checks, constant-time ciphertext comparison, and constant-time selection in decapsulation.
- **Zeroization**: secret key material is zeroized on drop.

## Warnings

#### Implementation

This implementation has not undergone any security auditing and while care has been taken no guarantees can be made for either correctness or the constant time running of the underlying functions. **Please use at your own risk.**

#### Algorithm

Streamlined NTRU Prime was first published in 2016. The algorithm still requires careful security review. Please see [here](https://ntruprime.cr.yp.to/warnings.html) for further warnings from the authors regarding NTRU Prime and lattice-based encryption schemes.

# License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/sntrup-kem.svg
[crate-link]: https://crates.io/crates/sntrup-kem
[docs-image]: https://docs.rs/sntrup-kem/badge.svg
[docs-link]: https://docs.rs/sntrup-kem/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/sntrup-kem.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
