//! Error types for HQC-KEM operations.

/// Errors that can occur during HQC operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid public key size.
    #[error("invalid public key size: expected {expected}, got {got}")]
    InvalidPublicKeySize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        got: usize,
    },
    /// Invalid secret key size.
    #[error("invalid secret key size: expected {expected}, got {got}")]
    InvalidSecretKeySize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        got: usize,
    },
    /// Invalid ciphertext size.
    #[error("invalid ciphertext size: expected {expected}, got {got}")]
    InvalidCiphertextSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        got: usize,
    },
    /// Invalid message size for deterministic encapsulation.
    #[error("invalid message size: expected {expected}, got {got}")]
    InvalidMessageSize {
        /// Expected size.
        expected: usize,
        /// Actual size.
        got: usize,
    },
}
