//! Cryptographic primitives for CryptoVault.
//!
//! This is the bottom of the dependency stack: it knows about keys, ciphers and
//! key derivation, and nothing at all about files, vaults or user interfaces.
//! Everything above depends on this crate being correct, which is why it carries
//! the strictest test requirements in the project — every public function
//! tested, every error path exercised (see `CONTRIBUTING.md`).
//!
//! # Layout
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`secret`] | Key material that wipes itself, refuses to print, and compares in constant time |
//! | [`random`] | The one source of randomness: the operating system |
//! | [`kdf`] | Argon2id, password to key-encryption key |
//! | [`aead`] | Authenticated encryption, with the algorithm selectable |
//! | [`hierarchy`] | Master seed to labelled sub-keys, via HKDF |
//!
//! # The shape of the key hierarchy
//!
//! ```text
//! password ──Argon2id──> KEK ──unwraps──> MasterSeed ──HKDF──> sub-keys
//! ```
//!
//! The indirection through a wrapped master seed is the single most consequential
//! decision in the project. Deriving content keys straight from the password
//! works perfectly until a second unlock method is wanted, at which point every
//! file in every existing vault has to be re-encrypted. With a wrapped seed,
//! adding Touch ID or a recovery key rewrites 48 bytes.
//!
//! See `docs/ADR/0003-key-slots.md` for the full reasoning, and
//! `docs/FORMAT_SPEC.md` §4 for the normative description.
//!
//! # Non-goals
//!
//! This crate never touches the filesystem, never allocates a path, and never
//! decides *what* to encrypt. Those belong to `cv-format` and `cv-vault`.

// Unit tests are allowed the shortcuts that production code is not: a panicking
// assertion in a test is a failing test, which is exactly what we want.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod aead;
pub mod hierarchy;
pub mod kdf;
pub mod random;
pub mod secret;
pub mod siv;
pub mod slot;

pub use secret::{Key32, SecretBytes};

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
    /// Raised when reading a vault configuration that was hand-edited,
    /// corrupted, or deliberately weakened. Parameters below our minimum are
    /// refused rather than silently raised, because silently accepting them
    /// would make a downgrade attack invisible.
    #[error("invalid key-derivation parameters: {reason}")]
    InvalidKdfParams {
        /// Which bound was violated.
        reason: String,
    },

    /// Key material was not the length it had to be.
    #[error("expected {expected} bytes of key material, found {found}")]
    WrongKeyLength {
        /// Length the caller required.
        expected: usize,
        /// Length actually supplied.
        found: usize,
    },

    /// The operating system could not supply entropy.
    ///
    /// Fatal by design. Continuing would mean writing data under a key or a
    /// nonce that is not random, and both failures are silent.
    #[error("the operating system could not provide randomness: {reason}")]
    RandomnessUnavailable {
        /// What the operating system reported.
        reason: String,
    },

    /// Argon2id failed to run.
    ///
    /// Almost always means the machine could not allocate the memory the
    /// parameters ask for — a vault created on a workstation being opened on
    /// something much smaller.
    #[error("key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// What the key-derivation function reported.
        reason: String,
    },

    /// A salt was not the required length.
    #[error("expected a {expected}-byte salt, found {found}")]
    WrongSaltLength {
        /// Required salt length.
        expected: usize,
        /// Length actually supplied.
        found: usize,
    },

    /// Decryption failed: the data, the associated data, the key or the nonce
    /// is not what it was when the data was sealed.
    ///
    /// **The variant carries no detail on purpose.** Which of those four went
    /// wrong is exactly what an attacker probing a vault would like to be told,
    /// and knowing it does not help a legitimate user either — the answer is
    /// always the same, that this data cannot be read with this key.
    #[error("authentication failed: the data could not be decrypted")]
    DecryptionFailed,

    /// Encryption failed. In practice only reachable when a buffer is
    /// implausibly large for the cipher.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// What the cipher reported.
        reason: String,
    },

    /// A ciphertext was too short to contain even its own authentication tag.
    #[error("ciphertext is {len} bytes, shorter than the {minimum}-byte minimum")]
    CiphertextTooShort {
        /// Length of the data supplied.
        len: usize,
        /// Smallest length that could possibly be valid.
        minimum: usize,
    },

    /// A nonce was not the length the selected algorithm requires.
    #[error("expected a {expected}-byte nonce for this algorithm, found {found}")]
    WrongNonceLength {
        /// Nonce length the algorithm requires.
        expected: usize,
        /// Length actually supplied.
        found: usize,
    },

    /// The algorithm identifier read from a file is not one this build knows.
    #[error("unknown algorithm identifier 0x{0:02x}")]
    UnknownAlgorithm(u8),

    /// The slot-kind byte read from a vault configuration is not one this build
    /// knows.
    #[error("unknown key slot kind {0}")]
    UnknownSlotKind(u8),

    /// A key slot's stored fields are not the right shape.
    ///
    /// Distinct from [`CryptoError::DecryptionFailed`] on purpose: this means
    /// the configuration is damaged, and no password will ever open it. Telling
    /// a user to keep trying their password against a corrupted slot would be
    /// cruel and useless.
    #[error("the key slot is malformed: {reason}")]
    MalformedSlot {
        /// Which field is the wrong shape.
        reason: &'static str,
    },

    /// The vault has no slot of the requested kind.
    ///
    /// Also distinct from a wrong credential: it means the vault was never set
    /// up for this unlock method, so retrying cannot help.
    #[error("this vault has no {0:?} slot")]
    NoSuchSlot(crate::slot::SlotKind),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_read_as_sentences() {
        let cases: Vec<(CryptoError, &str)> = vec![
            (
                CryptoError::InvalidKdfParams {
                    reason: "memory too low".into(),
                },
                "memory too low",
            ),
            (
                CryptoError::WrongKeyLength {
                    expected: 32,
                    found: 16,
                },
                "32",
            ),
            (CryptoError::DecryptionFailed, "authentication failed"),
            (CryptoError::UnknownAlgorithm(0x09), "0x09"),
        ];

        for (error, expected_fragment) in cases {
            let rendered = error.to_string();
            assert!(
                rendered.contains(expected_fragment),
                "{rendered:?} should mention {expected_fragment:?}"
            );
        }
    }

    /// The failure message must not distinguish a wrong key from tampered data
    /// from a wrong nonce. Telling them apart is only useful to someone probing
    /// a vault they do not have the key to.
    #[test]
    fn decryption_failure_reveals_nothing_about_the_cause() {
        let rendered = CryptoError::DecryptionFailed.to_string();
        for forbidden in ["key", "nonce", "tag", "associated"] {
            assert!(
                !rendered.contains(forbidden),
                "the failure message names {forbidden:?}, which narrows down the cause: {rendered}"
            );
        }
    }

    #[test]
    fn errors_compare_by_value() {
        assert_eq!(
            CryptoError::WrongKeyLength {
                expected: 32,
                found: 1
            },
            CryptoError::WrongKeyLength {
                expected: 32,
                found: 1
            }
        );
        assert_ne!(
            CryptoError::WrongKeyLength {
                expected: 32,
                found: 1
            },
            CryptoError::WrongKeyLength {
                expected: 32,
                found: 2
            }
        );
    }
}
