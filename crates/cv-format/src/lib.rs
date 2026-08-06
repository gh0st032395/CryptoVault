//! The CryptoVault on-disk format.
//!
//! Everything a byte on disk means is decided here. `docs/FORMAT_SPEC.md` is the
//! normative description; this crate is its implementation, and the two are kept
//! in step deliberately — the specification is updated *before* the code, not
//! after.
//!
//! # Why the format looks the way it does
//!
//! A vault has to support random access (read 4 KiB out of a 2 GiB file without
//! decrypting 2 GiB), incremental writes, and cloud synchronisation. Those three
//! requirements between them rule out a single monolithic container and rule out
//! whole-file encryption. What is left is: one encrypted file on disk per file in
//! the vault, each split into independently authenticated chunks.
//!
//! # Layout of an encrypted file
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │ HEADER                                                         │
//! │   magic "CVF1"(4) │ ver(1) │ alg_id(1) │ mode(1) │ reserved(1) │
//! │   file_id (16, random, IMMUTABLE, cleartext but authenticated) │
//! │   nonce_hdr (12) │ meta_len (u32 LE)                           │
//! │   AEAD(K_content, nonce_hdr, file_key ‖ plain_size ‖ metadata) │
//! │   + tag (16)                                                    │
//! ├────────────────────────────────────────────────────────────────┤
//! │ CHUNK 0 : nonce(12) │ ciphertext(≤32 KiB) │ tag(16)            │
//! │ CHUNK 1 : nonce(12) │ ciphertext(≤32 KiB) │ tag(16)            │
//! │ …                                                               │
//! └────────────────────────────────────────────────────────────────┘
//! AAD of every chunk = chunk_index (u64 LE) ‖ file_id
//! ```
//!
//! Every integer in the format is little-endian, in headers, in additional
//! authenticated data and in metadata alike. One convention, so there is no
//! second one to get wrong.
//!
//! Three details in that diagram are load-bearing:
//!
//! - **`file_id`, not the header nonce, binds the chunks.** Metadata is mutable —
//!   adding a tag or marking a file for versioning re-seals the header with a
//!   fresh nonce. Had the chunks been bound to the header nonce, adding a tag
//!   would have invalidated every chunk in the file. `file_id` is generated once
//!   and never changes.
//! - **The chunk index is in the AAD**, so chunks cannot be reordered, duplicated
//!   or dropped without the authentication failing.
//! - **`plain_size` is inside the sealed header**, because an AEAD tag detects a
//!   modified file but not a truncated one.
//!
//! # Status
//!
//! Milestone M0 fixes the constants and the arithmetic that the rest of the
//! format is built on. Serialisation and encryption arrive in M1, together with
//! the frozen test vectors that make the format hard to change by accident.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod chunk;
pub mod consts;

use thiserror::Error;

/// Errors produced when reading or writing the on-disk format.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FormatError {
    /// The file does not begin with the CryptoVault magic bytes.
    #[error("not a CryptoVault file: bad magic bytes")]
    BadMagic,

    /// The format version is one this build does not know how to read.
    ///
    /// Refusing is the only safe answer: a newer version may have security
    /// properties this build cannot enforce, and guessing at the layout of an
    /// encrypted file is how silent data loss happens.
    #[error("unsupported format version {found}, this build supports up to {supported}")]
    UnsupportedVersion {
        /// Version found in the file.
        found: u8,
        /// Highest version this build understands.
        supported: u8,
    },

    /// The file-mode byte held a value that is not a known mode.
    #[error("unknown file mode byte 0x{0:02x}")]
    UnknownFileMode(u8),

    /// A size or offset would overflow the addressable range of the format.
    #[error("size or offset out of range: {reason}")]
    OutOfRange {
        /// Which quantity went out of range, and why it matters.
        reason: String,
    },
}

/// How the contents of a file are stored.
///
/// Compression and Reed-Solomon parity cannot coexist with in-place mutation:
/// compression breaks the fixed offset-to-chunk mapping, and parity would have
/// to be recomputed on every single write. Rather than half-support both, the
/// format has two explicit modes, and moving between them is a deliberate user
/// action ("Archive" / "Restore for editing").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FileMode {
    /// Uncompressed chunks, random access, writable in place. The default.
    Live = 0x01,
    /// Compressed stream with optional Reed-Solomon parity; sequential and
    /// read-only until the user restores it to [`FileMode::Live`].
    Archived = 0x02,
}

impl FileMode {
    /// The byte written to the header for this mode.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Whether files in this mode accept writes at an arbitrary offset.
    #[must_use]
    pub const fn supports_random_write(self) -> bool {
        matches!(self, Self::Live)
    }
}

impl TryFrom<u8> for FileMode {
    type Error = FormatError;

    /// Reads a mode byte from a header.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::UnknownFileMode`] for any byte that is not a mode
    /// this build knows. Unknown values are refused rather than defaulted,
    /// because defaulting would mean reading an archived file as a live one.
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::Live),
            0x02 => Ok(Self::Archived),
            other => Err(FormatError::UnknownFileMode(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_mode_round_trips_through_its_byte() {
        for mode in [FileMode::Live, FileMode::Archived] {
            assert_eq!(FileMode::try_from(mode.as_byte()).unwrap(), mode);
        }
    }

    #[test]
    fn unknown_mode_bytes_are_refused_not_defaulted() {
        for byte in [0x00_u8, 0x03, 0x7f, 0xff] {
            assert_eq!(
                FileMode::try_from(byte),
                Err(FormatError::UnknownFileMode(byte))
            );
        }
    }

    #[test]
    fn only_live_files_are_randomly_writable() {
        assert!(FileMode::Live.supports_random_write());
        assert!(!FileMode::Archived.supports_random_write());
    }

    #[test]
    fn version_error_reports_both_versions() {
        let err = FormatError::UnsupportedVersion {
            found: 9,
            supported: 1,
        };
        let msg = err.to_string();
        assert!(
            msg.contains('9'),
            "message should name the version found: {msg}"
        );
        assert!(
            msg.contains('1'),
            "message should name the supported version: {msg}"
        );
    }
}
