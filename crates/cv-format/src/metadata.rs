//! File metadata, carried encrypted inside the header.
//!
//! Everything CryptoVault remembers about a file other than its contents and its
//! name: the timestamps it had before it was imported, its permissions, whether
//! the user wants it versioned, and any tags or notes they have added.
//!
//! # Why it lives in the sealed header
//!
//! It has to be encrypted — "tagged: divorce" is as revealing as the document —
//! and it has to be readable without decrypting the file body, so that a
//! directory listing can show dates and icons cheaply. The sealed header is the
//! one place that is both.
//!
//! # Why the metadata block is mutable, and what that forced
//!
//! Adding a tag rewrites the header, which re-seals it under a fresh nonce. That
//! is the reason chunks are bound to an immutable `file_id` rather than to the
//! header nonce: otherwise adding a tag would invalidate every chunk in the
//! file. See `docs/ADR/0004-chunked-content-random-nonces.md`.
//!
//! # Forward compatibility
//!
//! Unknown fields are ignored when reading. A build that does not know a field
//! and rewrites the header **drops** it. That is acceptable for annotations and
//! would not be for file contents, which is why nothing but annotations lives
//! here.

use serde::{Deserialize, Serialize};

use crate::FormatError;
use crate::consts::MAX_METADATA_LEN;

/// What CryptoVault remembers about a file besides its contents and name.
///
/// Every field is optional. A file imported with nothing known about it has an
/// empty metadata block, which encodes to a handful of bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileMetadata {
    /// Original modification time, Unix seconds.
    ///
    /// Preserved so that exporting a file does not make everything look as
    /// though it was created today.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime: Option<u64>,

    /// Original creation time, Unix seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctime: Option<u64>,

    /// POSIX permission bits, normalised across platforms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,

    /// Whether the file is executable.
    ///
    /// Separate from `mode` because Windows has no permission bits to carry it,
    /// and a script that comes back out of a vault without its executable bit is
    /// useless.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<bool>,

    /// Whether previous versions of this file are kept.
    ///
    /// Opt-in per file, chosen by the user. In a synced vault every retained
    /// version is cloud storage and bandwidth nobody asked for, so this is off
    /// unless someone says otherwise.
    #[serde(skip_serializing_if = "is_false")]
    pub versioned: bool,

    /// User-applied labels, searchable alongside names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// A free-text note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,

    /// The original file extension.
    ///
    /// Stored so that a listing can pick an icon and a viewer without decrypting
    /// any content. It is inside the sealed header, so it does not leak.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "signature required by serde"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

impl FileMetadata {
    /// Encodes to CBOR.
    ///
    /// # Errors
    ///
    /// - [`FormatError::MetadataTooLarge`] if the result exceeds
    ///   [`MAX_METADATA_LEN`]. In practice only a very long note or a great many
    ///   tags can do this, and refusing is better than writing a header that
    ///   cannot be read back.
    /// - [`FormatError::MalformedMetadata`] if encoding fails, which should not
    ///   happen for this type and is reported rather than assumed away.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|source| {
            FormatError::MalformedMetadata {
                reason: source.to_string(),
            }
        })?;

        if encoded.len() > MAX_METADATA_LEN as usize {
            return Err(FormatError::MetadataTooLarge {
                len: encoded.len(),
                max: MAX_METADATA_LEN,
            });
        }

        Ok(encoded)
    }

    /// Decodes from CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::MalformedMetadata`] if the bytes are not valid
    /// CBOR or do not describe a metadata block.
    ///
    /// Reaching this means the header authenticated but its contents did not
    /// parse, so the cause is a bug or a version mismatch rather than tampering
    /// — an attacker cannot produce bytes that authenticate.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        ciborium::from_reader(bytes).map_err(|source| FormatError::MalformedMetadata {
            reason: source.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populated() -> FileMetadata {
        FileMetadata {
            mtime: Some(1_770_000_000),
            ctime: Some(1_769_000_000),
            mode: Some(0o644),
            exec: Some(false),
            versioned: true,
            tags: vec!["work".into(), "2026".into()],
            note: Some("the quarterly report".into()),
            ext: Some("pdf".into()),
        }
    }

    #[test]
    fn an_empty_block_round_trips() {
        let empty = FileMetadata::default();
        let encoded = empty.encode().unwrap();
        assert_eq!(FileMetadata::decode(&encoded).unwrap(), empty);
    }

    /// A file with nothing known about it is the common case, so its metadata
    /// must not cost much. Every skipped field is bytes in every header.
    #[test]
    fn an_empty_block_is_tiny() {
        let encoded = FileMetadata::default().encode().unwrap();
        assert!(
            encoded.len() < 8,
            "an empty block took {} bytes: {encoded:?}",
            encoded.len()
        );
    }

    #[test]
    fn a_populated_block_round_trips() {
        let original = populated();
        let encoded = original.encode().unwrap();
        assert_eq!(FileMetadata::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn every_field_survives_the_round_trip() {
        let decoded = FileMetadata::decode(&populated().encode().unwrap()).unwrap();
        assert_eq!(decoded.mtime, Some(1_770_000_000));
        assert_eq!(decoded.ctime, Some(1_769_000_000));
        assert_eq!(decoded.mode, Some(0o644));
        assert_eq!(decoded.exec, Some(false));
        assert!(decoded.versioned);
        assert_eq!(decoded.tags, ["work", "2026"]);
        assert_eq!(decoded.note.as_deref(), Some("the quarterly report"));
        assert_eq!(decoded.ext.as_deref(), Some("pdf"));
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(populated().encode().unwrap(), populated().encode().unwrap());
    }

    #[test]
    fn unicode_in_tags_and_notes_survives() {
        let metadata = FileMetadata {
            tags: vec!["cartelle 📁".into(), "日本語".into()],
            note: Some("note with an emoji 🔐 and accents: perché".into()),
            ..FileMetadata::default()
        };
        assert_eq!(
            FileMetadata::decode(&metadata.encode().unwrap()).unwrap(),
            metadata
        );
    }

    #[test]
    fn an_oversized_block_is_refused_rather_than_written() {
        let metadata = FileMetadata {
            note: Some("x".repeat(MAX_METADATA_LEN as usize)),
            ..Default::default()
        };

        assert!(matches!(
            metadata.encode(),
            Err(FormatError::MetadataTooLarge { .. })
        ));
    }

    #[test]
    fn a_block_just_under_the_limit_is_accepted() {
        let metadata = FileMetadata {
            note: Some("x".repeat(1000)),
            ..FileMetadata::default()
        };
        assert!(metadata.encode().unwrap().len() <= MAX_METADATA_LEN as usize);
    }

    #[test]
    fn rubbish_is_rejected_rather_than_guessed_at() {
        for bytes in [b"not cbor at all".as_slice(), &[0xFF, 0xFF, 0xFF], &[]] {
            assert!(
                matches!(
                    FileMetadata::decode(bytes),
                    Err(FormatError::MalformedMetadata { .. })
                ),
                "accepted {bytes:?}"
            );
        }
    }

    /// A newer build may add fields. An older one must ignore them and carry on,
    /// not refuse to open the file.
    #[test]
    fn unknown_fields_are_ignored() {
        #[derive(Serialize)]
        struct FromTheFuture {
            mtime: u64,
            a_field_from_a_later_version: String,
            another: Vec<u32>,
        }

        let mut encoded = Vec::new();
        ciborium::into_writer(
            &FromTheFuture {
                mtime: 42,
                a_field_from_a_later_version: "hello".into(),
                another: vec![1, 2, 3],
            },
            &mut encoded,
        )
        .unwrap();

        let decoded = FileMetadata::decode(&encoded).unwrap();
        assert_eq!(decoded.mtime, Some(42));
        assert_eq!(decoded.tags, Vec::<String>::new());
    }

    /// Missing fields must take their defaults rather than failing: a metadata
    /// block written before a field existed is still perfectly valid.
    #[test]
    fn missing_fields_fall_back_to_defaults() {
        #[derive(Serialize)]
        struct OnlyOneField {
            ext: String,
        }

        let mut encoded = Vec::new();
        ciborium::into_writer(&OnlyOneField { ext: "txt".into() }, &mut encoded).unwrap();

        let decoded = FileMetadata::decode(&encoded).unwrap();
        assert_eq!(decoded.ext.as_deref(), Some("txt"));
        assert_eq!(decoded.mtime, None);
        assert!(!decoded.versioned);
    }
}
