# Primitive verification

The Kani harnesses in this crate check the production ML-KEM arithmetic and
its use of `module-lattice`. They are compile only and add no runtime dependency
or public API.

## Library use and release builds

Kani is a development and CI tool. Applications that depend on `ml-kem` do not
need to install, run, or link Kani. Normal debug and release builds exclude the
proof harnesses through `#[cfg(kani)]`, so those harnesses add no runtime checks,
binary size, or execution overhead. Build and use the library normally, including
with `cargo build --release`.

The CI proof job runs a separate Kani verification build. It checks a model of
the production Rust implementation against the assertions in each harness,
using symbolic inputs. A successful proof covers all inputs admitted by the
harness's assumptions and checked loop bounds, rather than a sample of test
cases.

This is not verification of the optimized release binary. The proofs rely on
the compiler preserving the verified behavior and do not establish that release
machine code executes in constant time. See [Scope and assumptions](#scope-and-assumptions)
for the remaining limits of these primitive proofs.

## Running the proofs

Install the pinned verifier (requires Rust installed through rustup):

```sh
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup
```

If `cargo-binstall` is already installed, the launcher can be installed without
compilation instead:

```sh
cargo binstall --no-confirm --disable-strategies compile --version 0.67.0 kani-verifier
cargo kani setup
```

This uses a prebuilt launcher (available from cargo-bins/QuickInstall). Kani's
setup command separately downloads the official compiler/solver bundle and
installs its required Rust toolchain. The binary-only command fails if no
compatible launcher is available; the `cargo install` command above remains
the source-build alternative.

From the workspace root, run:

```sh
cargo kani -p ml-kem --lib --no-default-features
```

Individual harnesses can be selected with `--harness`, for example:

```sh
cargo kani -p ml-kem --lib --no-default-features --harness algebra::proofs::small_reduce
```

The `kani` job in `.github/workflows/ml-kem.yml` installs the same pinned
version and runs every harness, with two concurrent solver processes. It runs
on pull requests affecting this crate, `module-lattice`, the workspace manifests,
or that workflow, and on pushes to `master`. Proof failures fail the job; its
30-minute timeout also fails rather than treating unfinished proofs as passed.

CI uses `cargo-binstall` for the launcher and caches both the Kani bundle and
its required nightly Rust toolchain. Setup runs only on an exact cache miss.
The installation is saved before proof execution, so a failing proof does not
force the next CI run to download the toolchain again.
The cache key includes the Ubuntu release, architecture, Kani version, and
toolchain version. When upgrading Kani, update `KANI_TOOLCHAIN` to match the
new bundle's `rust-toolchain-version` as well. Proofs always rerun; proof results
are not cached or skipped. Installation caching does not reduce solver time.

Keep Kani's default safety checks and unwinding assertions enabled. A timeout,
unsupported operation, or failed unwinding assertion is not a successful proof.
The encoding harnesses specify an unwind bound of 513 to accommodate fixed-size
array initialization (at most 384 bytes) and loops over 256 coefficients.

## Target and ABI coverage

The CI Kani job is configured for `x86_64-unknown-linux-gnu` on Ubuntu 24.04,
with 64-bit pointers and `usize`, little-endian byte order, and
`--no-default-features`. A successful run establishes the harness properties
for that modeled target and feature configuration. It is not a proof for every
architecture, operating system, or ABI, nor a validation of machine-level
calling conventions or FFI boundaries.

The verified primitives use fixed-width coefficient arithmetic and explicit
little-endian serialization. These choices support portability, but do not
automatically extend the proofs to 32-bit targets, big-endian targets, or other
environments such as Windows/MSVC, Linux/musl, or Apple platforms. Pointer width,
`usize` arithmetic, type layout, target-specific dependencies, and conditional
compilation can change the modeled program. An ARM64 run would add coverage for
that target, but would not by itself cover 32-bit or big-endian behavior.

The existing `powerpc-unknown-linux-gnu` release tests provide complementary
32-bit, big-endian coverage. The `thumbv7em-none-eabi` and
`wasm32-unknown-unknown` jobs check that the crate builds for those targets.
These tests and build checks are not Kani proofs for those targets.

One ABI is sufficient for the current CI verification baseline because the
properties under examination concern shared Rust arithmetic and encoding
primitives: fixed-width integer calculations, coefficient bounds, bit packing,
and bounded array indices. These primitives do not select different arithmetic
implementations by OS or ABI, call foreign functions, or depend on a particular
struct layout. Their specifications describe values and indices rather than
register assignments or calling conventions. Repeating the suite on another
64-bit, little-endian ABI would therefore largely repeat the same checks while
increasing CI cost.

This is a scope and coverage decision, not a claim that a proof on one ABI
formally establishes correctness on every other ABI. The target-dependent
limits above remain, with cross-platform tests providing additional empirical
coverage.

Revisit formal coverage when
adding target-specific implementations, SIMD, assembly, unsafe code, FFI, or
features that change code reached by the harnesses. Constant-time assurance
requires separate checks of compiled binaries for the relevant architectures
and compiler configurations; expanding the Kani matrix alone does not provide
that assurance.

## Properties and input domains

The modulus in the specifications is independently fixed to FIPS 203's `q = 3329`.
The harnesses call the actual `BaseField` implementation generated by
`module_lattice::define_field!`; they do not substitute a copy of its arithmetic.
Reference formulas use wider integers and ordinary division/remainder, which
are acceptable in proof specifications even when inappropriate for production
secret-dependent computation.

| Harnesses | Input domain | Properties |
| --- | --- | --- |
| `algebra::proofs::small_reduce` | `0 <= x < 2q` | Result is `x mod q` and below `q` |
| `algebra::proofs::barrett_reduce` | `0 <= x <= 2(q-1)^2` | Result is `x mod q` and below `q` |
| `algebra::proofs::{add,subtract,negate,multiply}` | Each coefficient is below `q` | Exact field operation and canonical result |
| `algebra::proofs::{forward_butterfly,inverse_butterfly}` | Coefficients and twiddle below `q` | Both scalar outputs match the butterfly equations and are canonical |
| `algebra::proofs::{layer_*,inverse_layer_*}` | 256 independent coefficients below `q`; each of the seven production layer sizes and starting twiddle indices | Array/table accesses and arithmetic are safe, outputs are canonical, and twiddle index advances as expected |
| `algebra::proofs::base_case` | Four coefficients below `q`; `0 <= i < 128` | Multiplication modulo `X^2 - GAMMA[i]` and canonical outputs |
| `compress::proofs::compress_*` | `0 <= x < q` | FIPS 203 compression formula and `d`-bit output |
| `compress::proofs::decompress_*` | `0 <= x < 2^d` | FIPS 203 decompression formula and canonical output |
| `proofs::encode_*` | Each coefficient below `2^d`, or below `q` for `d=12` | Every output bit matches little-endian coefficient packing |
| `proofs::decode_*` | Arbitrary bytes of the required length | Every output coefficient matches bit unpacking, reduced modulo `q` for `d=12` |

Compression and encoding cover widths 1, 4, 5, 6, 10, 11, and 12. Compression
at widths 6 and 12 is extra primitive coverage matching the existing tests;
the KEM uses compression widths 1, 4, 5, 10, and 11. Encoding at width 6 also
covers CBD sampling input. These primitives are shared by all three ML-KEM
parameter sets.

Encoding inputs contain independently symbolic elements. The output bit or
coefficient selected for comparison is also symbolic, so a successful proof
establishes the specified property at every position, not just one fixed index.
The full production encoding/decoding loops still execute under verification.

## Scope and assumptions

These are proofs of isolated primitives under explicit preconditions, not a
proof of the complete KEM. In particular, `Elem::new` does not enforce a range;
establishing that every caller satisfies these preconditions is separate work.
The Barrett input range covers products of canonical coefficients and the sums
of two products used in `base_case_multiply`. It is not a claim about arbitrary
`u32` inputs or other instantiations of the field macro, such as ML-DSA.

The butterfly proofs cover scalar arithmetic; layer proofs cover bounds and
index safety. They do not establish twiddle ordering, inverse scaling, or
correctness of the complete transform. Base-case
multiplication is specified relative to the existing `GAMMA` table; these proofs
do not independently establish that the table matches FIPS 203.

Also outside this scope: sampling, key validation, PKE/KEM composition, implicit
rejection, SHA3/SHAKE, secret erasure, allocation failure, and constant-time
execution. In particular, the CBD lookup in `sample_poly_cbd` is unchanged.

Kani checks the reachable Rust operations for panics, arithmetic overflow, and
the memory-safety properties supported by its model. Intentional truncation
and wrapping operations are allowed by Rust; the functional assertions check
their consequences within the stated domains. The proofs use no function
stubs and do not disable safety checks.

Assurance depends on Kani's Rust model and translation, CBMC and its solver,
the specifications and assumptions in each harness, and the compiler and
hardware used to run the resulting library. Source-level proofs do not prove
properties of emitted machine code. Existing unit, ACVP, and Wycheproof tests
remain complementary checks.
