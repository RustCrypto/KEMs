# hqc-kem

Pure Rust implementation of **HQC-KEM** (Hamming Quasi-Cyclic Key Encapsulation Mechanism), a post-quantum KEM based on quasi-cyclic codes over the ring Z_2[X]/(X^n-1).

HQC uses concatenated Reed-Solomon + Reed-Muller error correction with the Fujisaki-Okamoto transform for IND-CCA2 security. It's currently selected as the backup approved KEM to ML-KEM.

[![Crates.io](https://img.shields.io/crates/v/hqc-kem.svg)](https://crates.io/crates/hqc-kem)
[![Documentation](https://docs.rs/hqc-kem/badge.svg)](https://docs.rs/hqc-kem)
[![License](https://img.shields.io/crates/l/hqc-kem.svg)](https://github.com/mikelodder7/hqc-kem)

## References

- [NIST FIPS 207 (HQC)](https://csrc.nist.gov/pubs/fips/207/ipd) - HQC Initial Public Draft
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) - NIST PQC project page
- [HQC Official Site](https://pqc-hqc.org/) - Reference implementations, specifications, and KAT vectors
- [HQC v5.0.0 Specification](https://pqc-hqc.org/doc/hqc-spec-2025-02-10.pdf) - Full specification document

## Security Levels

| Level | Type Alias | NIST Category | Public Key | Secret Key | Ciphertext | Shared Secret |
|-------|-----------|---------------|------------|------------|------------|---------------|
| HQC-128 | `Hqc128` | Level 1 (128-bit) | 2,241 B | 2,321 B | 4,433 B | 32 B |
| HQC-192 | `Hqc192` | Level 3 (192-bit) | 4,514 B | 4,602 B | 8,978 B | 32 B |
| HQC-256 | `Hqc256` | Level 5 (256-bit) | 7,237 B | 7,333 B | 14,421 B | 32 B |

### Key Generation

```rust
use hqc_kem::{Hqc256, HqcKem};

let mut rng = rand::rng();
let (ek, dk) = Hqc256::generate_key(&mut rng);

// Access raw bytes
let pk_bytes: &[u8] = ek.as_ref();
let sk_bytes: &[u8] = dk.as_ref();
```

### Encapsulation

```rust
use hqc_kem::{Hqc256, HqcKem};

let mut rng = rand::rng();
let (ek, dk) = Hqc256::generate_key(&mut rng);

// Sender encapsulates with the public key
let (ct, shared_secret) = ek.encapsulate(&mut rng);

let ct_bytes: &[u8] = ct.as_ref();
let ss_bytes: &[u8] = shared_secret.as_ref();
```

### Decapsulation

```rust
use hqc_kem::{Hqc256, HqcKem};

let mut rng = rand::rng();
let (ek, dk) = Hqc256::generate_key(&mut rng);
let (ct, ss_sender) = ek.encapsulate(&mut rng);

// Receiver decapsulates with the secret key
let ss_receiver = dk.decapsulate(&ct);

assert_eq!(ss_sender, ss_receiver);
```

### Serialization / Deserialization

All types implement `AsRef<[u8]>` and `TryFrom<&[u8]>` for raw byte conversion:

```rust
use hqc_kem::{Hqc128, HqcKem, EncapsulationKey, Hqc128Params};

let mut rng = rand::rng();
let (ek, dk) = Hqc128::generate_key(&mut rng);

// Serialize to bytes
let pk_bytes: Vec<u8> = ek.as_ref().to_vec();

// Deserialize from bytes
let ek_restored: EncapsulationKey<Hqc128Params> = pk_bytes.as_slice().try_into()
    .expect("invalid public key length");
```

With the `serde` feature enabled, all types implement `Serialize` and `Deserialize`:

```toml
[dependencies]
hqc-kem = { version = "0.1", features = ["serde"] }
```

```rust,ignore
use hqc_kem::{Hqc128, HqcKem};

let mut rng = rand::rng();
let (ek, _dk) = Hqc128::generate_key(&mut rng);

// Serialize to JSON (hex-encoded)
let json = serde_json::to_string(&ek).unwrap();

// Deserialize from JSON
let ek_restored: hqc_kem::EncapsulationKey<hqc_kem::Hqc128Params> =
    serde_json::from_str(&json).unwrap();
```

### Deterministic Key Generation

Generate identical key pairs from a 32-byte seed:

```rust
use hqc_kem::{Hqc128, HqcKem};

let seed = [0x42u8; 32];
let (ek, dk) = Hqc128::generate_key_deterministic(&seed);

// Same seed always produces the same key pair
let (ek2, dk2) = Hqc128::generate_key_deterministic(&seed);
assert_eq!(ek.as_ref(), ek2.as_ref());
```

### Deterministic Encapsulation

Produce identical ciphertext and shared secret from a message and salt:

```rust
use hqc_kem::{Hqc128, HqcKem, hqc128};

let mut rng = rand::rng();
let (ek, dk) = Hqc128::generate_key(&mut rng);

// Message size depends on security level (16/24/32 bytes)
let m = [0xABu8; hqc128::MESSAGE_SIZE];
let salt = [0xCDu8; hqc128::SALT_SIZE];

let (ct, ss) = ek.encapsulate_deterministic(&m, &salt).unwrap();

// Same inputs always produce the same output
let (ct2, ss2) = ek.encapsulate_deterministic(&m, &salt).unwrap();
assert_eq!(ct.as_ref(), ct2.as_ref());
assert_eq!(ss, ss2);

// Decapsulation works as usual
let ss3 = dk.decapsulate(&ct);
assert_eq!(ss, ss3);
```

Message sizes per security level:

| Level | `MESSAGE_SIZE` | `SALT_SIZE` |
|-------|---------------|-------------|
| HQC-128 | 16 bytes | 16 bytes |
| HQC-192 | 24 bytes | 16 bytes |
| HQC-256 | 32 bytes | 16 bytes |

### Module-Style API

For a more concise import style, use the security-level modules directly:

```rust
use hqc_kem::hqc128;

let mut rng = rand::rng();
let (ek, dk) = hqc128::generate_key(&mut rng);
let (ct, ss1) = ek.encapsulate(&mut rng);
let ss2 = dk.decapsulate(&ct);
assert_eq!(ss1, ss2);
```

### Generic Code

Write code that works across all security levels:

```rust,ignore
use hqc_kem::{HqcKem, HqcParams, EncapsulationKey, DecapsulationKey};

fn roundtrip<P: HqcParams>(rng: &mut impl rand::CryptoRng) {
    let (ek, dk) = HqcKem::<P>::generate_key(rng);
    let (ct, ss1) = ek.encapsulate(rng);
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss1, ss2);
}
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `kgen` | Yes | Key generation (`HqcKem::generate_key`) |
| `ecap` | Yes | Encapsulation (`EncapsulationKey::encapsulate`) |
| `dcap` | Yes | Decapsulation (`DecapsulationKey::decapsulate`) |
| `serde` | No | Serde `Serialize`/`Deserialize` for all types |

## Security

- Constant-time operations for side-channel resistance (via `subtle` crate)
- Secret key material is zeroized on drop (via `zeroize` crate)
- Shared secrets use constant-time equality comparison
- IND-CCA2 security via Fujisaki-Okamoto transform with implicit rejection

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](http://opensource.org/licenses/MIT)

at your option.
