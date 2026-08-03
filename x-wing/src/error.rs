use core::fmt;

/// Error type when decapsulation failed.
#[derive(Clone, Copy, Debug)]
pub struct DecapsulationError;

impl core::error::Error for DecapsulationError {}

impl fmt::Display for DecapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decapsulation error")
    }
}
