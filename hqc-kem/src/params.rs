//! HQC parameter definitions for all security levels.

/// Seed size in bytes.
#[cfg(any(
    feature = "kgen",
    feature = "ecap",
    feature = "dcap",
    feature = "pkcs8",
    feature = "kem"
))]
pub(crate) const SEED_BYTES: usize = 32;
/// Salt size in bytes.
pub(crate) const SALT_BYTES: usize = 16;
/// Shared secret size in bytes.
pub(crate) const SS_BYTES: usize = 32;
/// GF(2^M) parameter M.
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
pub(crate) const PARAM_M: usize = 8;

/// Internal runtime parameter set.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct HqcParameters {
    /// Ring dimension.
    pub n: usize,
    /// RS code length.
    pub n1: usize,
    /// RM code length.
    pub n2: usize,
    /// Concatenated code length n1*n2.
    pub n1n2: usize,
    /// Message length in bytes.
    pub k: usize,
    /// RS error-correction capability.
    pub delta: usize,
    /// Secret key Hamming weight.
    pub w: usize,
    /// Error vector Hamming weight.
    pub w_e: usize,
    /// Random vector Hamming weight.
    pub w_r: usize,
    /// FFT parameter: 2^fft >= delta+1.
    pub fft: usize,
    /// Byte size of n-bit vector: ceil(n/8).
    pub n_bytes: usize,
    /// Byte size of n1n2-bit vector: ceil(n1n2/8).
    pub n1n2_bytes: usize,
    /// u64 array size for n-bit vector: ceil(n/64).
    pub vec_n_size_64: usize,
    /// u64 array size for n1n2-bit vector: ceil(n1n2/64).
    pub vec_n1n2_size_64: usize,
    /// Public key size in bytes: SEED_BYTES + n_bytes.
    pub pk_bytes: usize,
    /// Secret key size in bytes: pk_bytes + SEED_BYTES + k + SEED_BYTES.
    pub sk_bytes: usize,
    /// Ciphertext size in bytes: n_bytes + n1n2_bytes + SALT_BYTES.
    pub ct_bytes: usize,
    /// Reduction mask for top u64 word.
    pub red_mask: u64,
    /// Barrett reciprocal for constant-time modular reduction: floor(2^32 / n).
    pub barrett_recip: u32,
    /// RS generator polynomial coefficients (ascending degree, monic).
    pub rs_poly: &'static [u8],
}

/// RS generator polynomial for HQC-128 (degree 30, delta=15).
static RS_POLY_128: [u8; 31] = [
    89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103, 173, 67, 118,
    105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
];

/// RS generator polynomial for HQC-192 (degree 32, delta=16).
static RS_POLY_192: [u8; 33] = [
    45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158, 119, 13, 158, 1,
    238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
];

/// RS generator polynomial for HQC-256 (degree 58, delta=29).
static RS_POLY_256: [u8; 59] = [
    49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101, 32, 215, 159, 71, 201,
    115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243, 180, 219, 152, 239, 99, 141, 4, 246, 191,
    144, 8, 232, 47, 27, 141, 178, 130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
];

/// HQC-128 parameters.
pub(crate) const HQC_128: HqcParameters = HqcParameters {
    n: 17669,
    n1: 46,
    n2: 384,
    n1n2: 17664,
    k: 16,
    delta: 15,
    w: 66,
    w_e: 75,
    w_r: 75,
    fft: 4,
    n_bytes: 2209,
    n1n2_bytes: 2208,
    vec_n_size_64: 277,
    vec_n1n2_size_64: 276,
    pk_bytes: 2241,
    sk_bytes: 2321,
    ct_bytes: 4433,
    red_mask: 0x1f,
    barrett_recip: 243079, // floor(2^32 / 17669)
    rs_poly: &RS_POLY_128,
};

/// HQC-192 parameters.
pub(crate) const HQC_192: HqcParameters = HqcParameters {
    n: 35851,
    n1: 56,
    n2: 640,
    n1n2: 35840,
    k: 24,
    delta: 16,
    w: 100,
    w_e: 114,
    w_r: 114,
    fft: 5,
    n_bytes: 4482,
    n1n2_bytes: 4480,
    vec_n_size_64: 561,
    vec_n1n2_size_64: 560,
    pk_bytes: 4514,
    sk_bytes: 4602,
    ct_bytes: 8978,
    red_mask: 0x7ff,
    barrett_recip: 119800, // floor(2^32 / 35851)
    rs_poly: &RS_POLY_192,
};

/// HQC-256 parameters.
pub(crate) const HQC_256: HqcParameters = HqcParameters {
    n: 57637,
    n1: 90,
    n2: 640,
    n1n2: 57600,
    k: 32,
    delta: 29,
    w: 131,
    w_e: 149,
    w_r: 149,
    fft: 5,
    n_bytes: 7205,
    n1n2_bytes: 7200,
    vec_n_size_64: 901,
    vec_n1n2_size_64: 900,
    pk_bytes: 7237,
    sk_bytes: 7333,
    ct_bytes: 14421,
    red_mask: (1u64 << 37) - 1,
    barrett_recip: 74517, // floor(2^32 / 57637)
    rs_poly: &RS_POLY_256,
};

// Maximum sizes for stack-allocated arrays.
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
pub(crate) const MAX_N1: usize = 90;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
pub(crate) const MAX_DELTA: usize = 29;
/// Maximum fixed-vector Hamming weight across all levels (w_e/w_r of HQC-256).
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
pub(crate) const MAX_W: usize = 149;

/// Fixed-size buffer abstraction over `[T; N]` arrays.
///
/// Lets generic code allocate exact per-level stack buffers through the
/// associated types on [`HqcParams`] without heap allocation or unstable
/// `generic_const_exprs`.
#[doc(hidden)]
pub trait Buffer<T: Copy + Default>: AsRef<[T]> + AsMut<[T]> + Clone {
    /// A zero-initialized buffer.
    fn zeroed() -> Self;
}

impl<T: Copy + Default, const N: usize> Buffer<T> for [T; N] {
    fn zeroed() -> Self {
        [T::default(); N]
    }
}

mod sealed {
    /// Sealed trait preventing external implementations of [`HqcParams`](super::HqcParams).
    pub trait Sealed {}
}

/// Trait defining an HQC parameter set.
///
/// Sealed — cannot be implemented outside this crate. Use one of the provided
/// marker types: [`Hqc128Params`], [`Hqc192Params`], [`Hqc256Params`].
pub trait HqcParams: sealed::Sealed + 'static {
    /// Human-readable name (e.g. `"hqc128"`).
    const NAME: &'static str;
    /// Public key size in bytes.
    const PK_BYTES: usize;
    /// Secret key size in bytes.
    const SK_BYTES: usize;
    /// Ciphertext size in bytes.
    const CT_BYTES: usize;
    /// Shared secret size in bytes (always 32).
    const SS_BYTES: usize = SS_BYTES;

    /// n-bit vector as u64 words: `[u64; ceil(n/64)]`.
    #[doc(hidden)]
    type VecN: Buffer<u64>;
    /// n1n2-bit vector as u64 words: `[u64; ceil(n1n2/64)]`.
    #[doc(hidden)]
    type VecN1N2: Buffer<u64>;
    /// Full Karatsuba product: `[u64; 2*ceil(n/64)]`.
    #[doc(hidden)]
    type ProdBuf: Buffer<u64>;
    /// n-bit vector as bytes: `[u8; ceil(n/8)]`.
    #[doc(hidden)]
    type NBytesBuf: Buffer<u8>;
    /// Message buffer: `[u8; k]`.
    #[doc(hidden)]
    type KBuf: Buffer<u8>;
    /// Public key bytes: `[u8; PK_BYTES]`.
    #[doc(hidden)]
    type PkBuf: Buffer<u8>;
    /// Secret key bytes: `[u8; SK_BYTES]`.
    #[doc(hidden)]
    type SkBuf: Buffer<u8>;
    /// Ciphertext bytes: `[u8; CT_BYTES]`.
    #[doc(hidden)]
    type CtBuf: Buffer<u8>;
    /// PKE ciphertext bytes (u || v, no salt): `[u8; n_bytes + n1n2_bytes]`.
    #[doc(hidden)]
    type CPkeBuf: Buffer<u8>;

    /// Runtime parameter struct for internal operations.
    #[doc(hidden)]
    fn params() -> &'static HqcParameters;
}

/// HQC-128 parameter marker (NIST Level 1, 128-bit security).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hqc128Params;

impl sealed::Sealed for Hqc128Params {}

impl HqcParams for Hqc128Params {
    const NAME: &'static str = "hqc128";
    const PK_BYTES: usize = 2241;
    const SK_BYTES: usize = 2321;
    const CT_BYTES: usize = 4433;
    type VecN = [u64; 277];
    type VecN1N2 = [u64; 276];
    type ProdBuf = [u64; 554];
    type NBytesBuf = [u8; 2209];
    type KBuf = [u8; 16];
    type PkBuf = [u8; 2241];
    type SkBuf = [u8; 2321];
    type CtBuf = [u8; 4433];
    type CPkeBuf = [u8; 4417];
    fn params() -> &'static HqcParameters {
        &HQC_128
    }
}

/// HQC-192 parameter marker (NIST Level 3, 192-bit security).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hqc192Params;

impl sealed::Sealed for Hqc192Params {}

impl HqcParams for Hqc192Params {
    const NAME: &'static str = "hqc192";
    const PK_BYTES: usize = 4514;
    const SK_BYTES: usize = 4602;
    const CT_BYTES: usize = 8978;
    type VecN = [u64; 561];
    type VecN1N2 = [u64; 560];
    type ProdBuf = [u64; 1122];
    type NBytesBuf = [u8; 4482];
    type KBuf = [u8; 24];
    type PkBuf = [u8; 4514];
    type SkBuf = [u8; 4602];
    type CtBuf = [u8; 8978];
    type CPkeBuf = [u8; 8962];
    fn params() -> &'static HqcParameters {
        &HQC_192
    }
}

/// HQC-256 parameter marker (NIST Level 5, 256-bit security).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hqc256Params;

impl sealed::Sealed for Hqc256Params {}

impl HqcParams for Hqc256Params {
    const NAME: &'static str = "hqc256";
    const PK_BYTES: usize = 7237;
    const SK_BYTES: usize = 7333;
    const CT_BYTES: usize = 14421;
    type VecN = [u64; 901];
    type VecN1N2 = [u64; 900];
    type ProdBuf = [u64; 1802];
    type NBytesBuf = [u8; 7205];
    type KBuf = [u8; 32];
    type PkBuf = [u8; 7237];
    type SkBuf = [u8; 7333];
    type CtBuf = [u8; 14421];
    type CPkeBuf = [u8; 14405];
    fn params() -> &'static HqcParameters {
        &HQC_256
    }
}
