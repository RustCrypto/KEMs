use core::fmt::{self, Display};

/// Error type: deliberately opaque to reduce potential sidechannel leakage.
#[derive(Clone, Copy, Debug)]
pub struct Error;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ML-KEM error")
    }
}

impl core::error::Error for Error {}
