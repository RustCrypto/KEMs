use thiserror::Error;

/// The errors that can occur for FrodoKEM
#[derive(Error, Copy, Clone, Debug)]
pub enum Error {
    /// The secret key length is invalid
    #[error("Invalid secret key length: {0}")]
    InvalidSecretKeyLength(usize),
    /// The public key length is invalid
    #[error("Invalid public key length: {0}")]
    InvalidPublicKeyLength(usize),
    /// The ciphertext length is invalid
    #[error("Invalid ciphertext length: {0}")]
    InvalidCiphertextLength(usize),
    /// The shared secret length is invalid
    #[error("Invalid shared secret length: {0}")]
    InvalidSharedSecretLength(usize),
    /// The message length is invalid
    #[error("Invalid message length: {0}")]
    InvalidMessageLength(usize),
    /// Parsing string to algorithm
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

/// The result type for FrodoKEM
pub type FrodoResult<T> = Result<T, Error>;
