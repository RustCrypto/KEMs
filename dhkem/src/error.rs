use core::fmt;

/// Error type.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Decapsulation failed.
    Decapsulation,

    /// Length invalid.
    Length,
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decapsulation => write!(f, "decapsulation error"),
            Error::Length => write!(f, "invalid length"),
        }
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(_: hkdf::InvalidLength) -> Self {
        Error::Length
    }
}
