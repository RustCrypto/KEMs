use core::fmt;

/// Error type when decapsulation fails.
#[derive(Clone, Copy, Debug)]
pub struct DecapsulationError;

impl core::error::Error for DecapsulationError {}

impl fmt::Display for DecapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Decapsulation error")
    }
}

/// Error type for `RandomScalar` fails.
#[derive(Clone, Copy, Debug)]
pub struct RejectionSamplingError;

impl core::error::Error for RejectionSamplingError {}

impl fmt::Display for RejectionSamplingError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rejection sampling error")
    }
}
