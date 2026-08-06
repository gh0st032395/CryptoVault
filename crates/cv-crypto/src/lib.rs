//! Cryptographic primitives for CryptoVault.
//!
//! This is the bottom of the dependency stack: it knows about keys, ciphers and
//! key derivation, and nothing at all about files, vaults or user interfaces.
//! Everything above it depends on this crate being correct, which is why it
//! carries the strictest test requirements in the project (see `CONTRIBUTING.md`).
//!
//! # Scope
//!
//! - Key derivation from a password ([`kdf`]).
//! - Authenticated encryption of content chunks and headers.
//! - Sub-key derivation from the vault master seed.
//! - Deterministic filename encryption.
//! - Key material that is wiped from memory when dropped.
//!
//! # Non-goals
//!
//! This crate never touches the filesystem, never allocates a path, and never
//! decides *what* to encrypt. Those are [`cv_format`] and `cv-vault` concerns.
//!
//! # Status
//!
//! Milestone M1 is where the primitives land. At M0 only the key-derivation
//! parameters exist, because they are the one piece the format specification
//! already depends on.
//!
//! [`cv_format`]: https://github.com/gh0st032395/CryptoVault

// Unit tests are allowed the shortcuts that production code is not: a panicking
// assertion in a test is a failing test, which is exactly what we want.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod kdf;

use thiserror::Error;

/// Errors produced by the cryptographic layer.
///
/// The variants deliberately carry no key material and no plaintext: error
/// values travel into logs and user-facing messages, and neither is a place for
/// secrets.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Key-derivation parameters fell outside the range CryptoVault accepts.
    ///
    /// Raised when reading a vault configuration written by another tool, or a
    /// corrupted one. Parameters weaker than our minimum are refused rather
    /// than silently upgraded, because silently accepting them would make a
    /// downgrade attack invisible.
    #[error("invalid key-derivation parameters: {reason}")]
    InvalidKdfParams {
        /// Human-readable explanation of which bound was violated.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_message_does_not_leak_structure() {
        let err = CryptoError::InvalidKdfParams {
            reason: "memory too low".into(),
        };
        assert_eq!(
            err.to_string(),
            "invalid key-derivation parameters: memory too low"
        );
    }

    #[test]
    fn errors_compare_by_value() {
        let a = CryptoError::InvalidKdfParams { reason: "x".into() };
        let b = CryptoError::InvalidKdfParams { reason: "x".into() };
        let c = CryptoError::InvalidKdfParams { reason: "y".into() };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
