# ISO/IEC 18033-2 FrodoKEM conformance review

This document records the implementation review against Clause 14 of
ISO/IEC 18033-2:2006/Amd 2:2026. It is an engineering conformance review, not
an ISO certification or an independent security audit.

## Conformance criteria

Clause 14.2 requires a conforming implementation to identify `Frodo.KeyGen`,
`Frodo.Encaps`, or `Frodo.Decaps`, identify a parameter set listed by the
standard, and compute the corresponding mathematical function exactly.

This crate maps those functions as follows:

| ISO function | Rust implementation |
| --- | --- |
| `Frodo.KeyGen` | `hazmat::Kem::generate_keypair_from_seed` |
| `Frodo.Encaps` | `hazmat::Kem::encapsulate` |
| `Frodo.Decaps` | `hazmat::Kem::decapsulate` |

The randomized wrappers obtain the exact amount of randomness required by the
selected parameter set before calling these deterministic functions.

## Parameter sets

The implementation covers the AES128 and SHAKE128 matrix-generation options
for each standard and ephemeral parameter set:

- FrodoKEM-640, FrodoKEM-976, and FrodoKEM-1344
- eFrodoKEM-640, eFrodoKEM-976, and eFrodoKEM-1344

The implementation uses the specified dimensions, modulus, encoding width,
CDF tables, SHAKE variant, key sizes, ciphertext sizes, shared-secret sizes,
salt sizes, and `seedSE` sizes. Standard FrodoKEM uses a salt and a `seedSE`
twice the security parameter. Ephemeral FrodoKEM uses no salt and a `seedSE`
equal to the security parameter.

## Algorithm review

- Key generation parses randomness as `s || seedSE || z`, derives `seedA`,
  samples `S` and `E`, computes and packs `B`, hashes the public key, and emits
  the specified public and secret key encodings.
- Encapsulation hashes `pk || mu || salt` as specified, uses the `0x96` domain
  separator, samples all three error matrices, computes and packs `B'` and
  `C`, appends the salt, and derives the shared secret from the complete
  ciphertext and `k`.
- Decapsulation unpacks the ciphertext, recovers `mu'`, recomputes the
  ciphertext, compares both matrix components in constant time, and selects
  between `k'` and the fallback secret `s` without a secret-dependent branch.
- CDF sampling scans the complete table for every coefficient without a
  secret-dependent branch.
- Dynamic API boundaries reject keys and ciphertexts tagged for another
  parameter set and reject invalid message, salt, key, and ciphertext lengths.
- Secret keys, shared secrets, intermediate sampling material, recovered
  messages, and fallback key material are zeroized where owned by the
  implementation.

## Known-answer tests

The repository contains all 1,200 KAT cases from the FrodoKEM team's official
reference implementation at commit
`7a4e7219d06305e16aef734213001cd8fefbcc14`:

- 600 standard FrodoKEM cases;
- 600 ephemeral FrodoKEM cases;
- 100 cases for every AES and SHAKE parameter set.

Each case checks the generated public key, secret key, ciphertext, encapsulated
shared secret, and decapsulated shared secret. The test harness also requires
exactly 100 records in every vector file, preventing silently truncated vector
sets from passing.

Additional tests cover parameter sizes, modified-ciphertext implicit
rejection, deterministic fallback output, and serialization.

## Review limitations

- No claim of ISO certification or third-party validation is made.
- Constant-time properties are established by source review and use of
  constant-time primitives; they have not been independently verified on
  every compiler, target, or microarchitecture.
- Resistance to physical side channels such as power or electromagnetic
  analysis is outside the scope of this software review.
- Applications selecting eFrodoKEM must enforce its per-public-key ciphertext
  limit. The crate cannot enforce that protocol-level lifecycle requirement.
