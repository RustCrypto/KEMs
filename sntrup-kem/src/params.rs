//! Streamlined NTRU Prime parameter definitions for all security levels.

/// Shared secret size in bytes.
pub(crate) const SS_BYTES: usize = 32;

/// Internal runtime parameter set for Streamlined NTRU Prime.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct SntrupParameters {
    /// Polynomial degree.
    pub p: usize,
    /// Modulus (prime).
    pub q: i32,
    /// Hamming weight for secret key polynomial.
    pub w: usize,
    /// (Q-1)/2, used for rounding.
    pub q12: i32,
    /// Size of small-element encoding in bytes: ceil(P/4).
    pub small_encode_size: usize,
    /// Size of rounded encoding in bytes (variable-radix).
    pub rounded_encode_size: usize,
    /// Public key size in bytes (Rq encoding).
    pub pk_size: usize,
    /// Secret key size in bytes: 3*small_encode_size + pk_size + 32.
    pub sk_size: usize,
    /// Ciphertext size in bytes: rounded_encode_size + 32.
    pub ct_size: usize,
    /// Barrett reduction constant 1: floor(2^20 / Q).
    pub barrett1: i32,
    /// Barrett reduction constant 2: floor(2^28 / Q).
    pub barrett2: i32,
}

/// sntrup653 parameters.
pub(crate) const SNTRUP653: SntrupParameters = SntrupParameters {
    p: 653,
    q: 4621,
    w: 288,
    q12: 2310,
    small_encode_size: 164,
    rounded_encode_size: 865,
    pk_size: 994,
    sk_size: 1518,
    ct_size: 897,
    barrett1: 226,
    barrett2: 58084,
};

/// sntrup761 parameters.
pub(crate) const SNTRUP761: SntrupParameters = SntrupParameters {
    p: 761,
    q: 4591,
    w: 286,
    q12: 2295,
    small_encode_size: 191,
    rounded_encode_size: 1007,
    pk_size: 1158,
    sk_size: 1763,
    ct_size: 1039,
    barrett1: 228,
    barrett2: 58470,
};

/// sntrup857 parameters.
pub(crate) const SNTRUP857: SntrupParameters = SntrupParameters {
    p: 857,
    q: 5167,
    w: 322,
    q12: 2583,
    small_encode_size: 215,
    rounded_encode_size: 1152,
    pk_size: 1322,
    sk_size: 1999,
    ct_size: 1184,
    barrett1: 202,
    barrett2: 51943,
};

/// sntrup953 parameters.
pub(crate) const SNTRUP953: SntrupParameters = SntrupParameters {
    p: 953,
    q: 6343,
    w: 396,
    q12: 3171,
    small_encode_size: 239,
    rounded_encode_size: 1317,
    pk_size: 1505,
    sk_size: 2254,
    ct_size: 1349,
    barrett1: 165,
    barrett2: 42313,
};

/// sntrup1013 parameters.
pub(crate) const SNTRUP1013: SntrupParameters = SntrupParameters {
    p: 1013,
    q: 7177,
    w: 448,
    q12: 3588,
    small_encode_size: 254,
    rounded_encode_size: 1423,
    pk_size: 1623,
    sk_size: 2417,
    ct_size: 1455,
    barrett1: 146,
    barrett2: 37398,
};

/// sntrup1277 parameters.
pub(crate) const SNTRUP1277: SntrupParameters = SntrupParameters {
    p: 1277,
    q: 7879,
    w: 492,
    q12: 3939,
    small_encode_size: 320,
    rounded_encode_size: 1815,
    pk_size: 2067,
    sk_size: 3059,
    ct_size: 1847,
    barrett1: 133,
    barrett2: 34064,
};

mod sealed {
    /// Sealed trait preventing external implementations of [`SntrupParams`](super::SntrupParams).
    pub trait Sealed {}
}

/// Trait defining a Streamlined NTRU Prime parameter set.
///
/// Sealed — cannot be implemented outside this crate. Use one of the provided
/// marker types: [`Sntrup653Params`], [`Sntrup761Params`], [`Sntrup857Params`],
/// [`Sntrup953Params`], [`Sntrup1013Params`], [`Sntrup1277Params`].
pub trait SntrupParams: sealed::Sealed + 'static {
    /// Human-readable name (e.g. `"sntrup761"`).
    const NAME: &'static str;
    /// Public key size in bytes.
    const PK_BYTES: usize;
    /// Secret key size in bytes.
    const SK_BYTES: usize;
    /// Ciphertext size in bytes.
    const CT_BYTES: usize;
    /// Shared secret size in bytes (always 32).
    const SS_BYTES: usize = SS_BYTES;

    /// Runtime parameter struct for internal operations.
    #[doc(hidden)]
    fn params() -> &'static SntrupParameters;
}

/// Define a zero-sized parameter-set marker type and its sealed [`SntrupParams`] impl.
macro_rules! sntrup_params_marker {
    ($marker:ident, $name:literal, $pk:literal, $sk:literal, $ct:literal, $runtime:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $marker;

        impl sealed::Sealed for $marker {}

        impl SntrupParams for $marker {
            const NAME: &'static str = $name;
            const PK_BYTES: usize = $pk;
            const SK_BYTES: usize = $sk;
            const CT_BYTES: usize = $ct;
            fn params() -> &'static SntrupParameters {
                &$runtime
            }
        }
    };
}

sntrup_params_marker!(
    Sntrup653Params,
    "sntrup653",
    994,
    1518,
    897,
    SNTRUP653,
    "sntrup653 parameter marker (NIST Level 1, 128-bit security).\n\n**Not recommended for production use.** Prefer [`Sntrup761Params`] or higher."
);
sntrup_params_marker!(
    Sntrup761Params,
    "sntrup761",
    1158,
    1763,
    1039,
    SNTRUP761,
    "sntrup761 parameter marker (NIST Level 2, 128-bit+ security)."
);
sntrup_params_marker!(
    Sntrup857Params,
    "sntrup857",
    1322,
    1999,
    1184,
    SNTRUP857,
    "sntrup857 parameter marker (NIST Level 3, 192-bit security)."
);
sntrup_params_marker!(
    Sntrup953Params,
    "sntrup953",
    1505,
    2254,
    1349,
    SNTRUP953,
    "sntrup953 parameter marker (NIST Level 4, 192-bit+ security)."
);
sntrup_params_marker!(
    Sntrup1013Params,
    "sntrup1013",
    1623,
    2417,
    1455,
    SNTRUP1013,
    "sntrup1013 parameter marker (NIST Level 5, 256-bit security)."
);
sntrup_params_marker!(
    Sntrup1277Params,
    "sntrup1277",
    2067,
    3059,
    1847,
    SNTRUP1277,
    "sntrup1277 parameter marker (NIST Level 5, 256-bit security)."
);
