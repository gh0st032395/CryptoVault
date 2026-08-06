//! The header of an encrypted file: reading it, writing it, sealing it.
//!
//! Every `.cvf` opens with a header. It holds the file's own content key, the
//! authenticated plaintext length, and the metadata block — all sealed under
//! `K_content` — behind a short cleartext prefix that is authenticated as
//! associated data.
//!
//! ```text
//! magic "CVF1"(4) │ ver(1) │ alg_id(1) │ mode(1) │ reserved(1)
//! file_id(16) │ nonce(12 or 24) │ meta_len(u32 LE)          ← prefix, cleartext
//! AEAD(K_content, nonce, aad = prefix,
//!      file_key(32) ‖ plain_size(u64 LE) ‖ metadata) ‖ tag(16)
//! ```
//!
//! # The three things in here that are load-bearing
//!
//! **`file_id` is immutable and it is what binds the chunks.** Editing metadata
//! re-seals the header under a fresh nonce; if chunks were bound to the header
//! nonce instead, adding a tag would invalidate the whole file.
//!
//! **`plain_size` is authenticated.** An AEAD tag detects a modified file but
//! not a truncated one. Without a sealed length, lopping the last chunk off a
//! file would go unnoticed.
//!
//! **The nonce length depends on the algorithm**, so the header is not a fixed
//! size. It is parsed by reading the algorithm byte and sizing the rest from it,
//! never by assuming 12 bytes. Assuming would misplace every chunk in the file.
//!
//! # Parsing untrusted bytes
//!
//! Everything here reads data that may be corrupt or hostile. The order is
//! always the same: check the length before slicing, check `meta_len` against
//! its ceiling before trusting it, and authenticate before believing anything
//! from the sealed part. No allocation is sized from an unauthenticated number
//! beyond the bounded `meta_len`.

use cv_crypto::aead::{self, AeadAlgorithm};
use cv_crypto::random;
use cv_crypto::secret::Key32;

use crate::chunk::{header_len, header_prefix_len};
use crate::consts::{FILE_ID_LEN, FILE_KEY_LEN, FILE_MAGIC, FORMAT_VERSION, MAX_METADATA_LEN};
use crate::metadata::FileMetadata;
use crate::{FileMode, FormatError};

/// Length of the authenticated plaintext-size field, in bytes.
const PLAIN_SIZE_LEN: usize = 8;

/// The decoded header of an encrypted file.
///
/// Comparison is derived; the file key inside compares in constant time, so
/// equality on a whole header does too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// AEAD used for this file's header and chunks.
    pub algorithm: AeadAlgorithm,
    /// Whether the file is live (chunked, writable) or archived.
    pub mode: FileMode,
    /// Random, immutable identifier binding every chunk to this file.
    pub file_id: [u8; FILE_ID_LEN as usize],
    /// Length of the plaintext, authenticated so truncation is detectable.
    pub plain_size: u64,
    /// Timestamps, permissions, tags.
    pub metadata: FileMetadata,
    /// This file's own content key. Never leaves the sealed header.
    file_key: Key32,
}

impl FileHeader {
    /// Creates a header for a new, empty file.
    ///
    /// Generates a fresh `file_id` and a fresh per-file key. Both are random and
    /// neither is ever reused.
    ///
    /// # Errors
    ///
    /// Returns a wrapped [`cv_crypto::CryptoError`] if the operating system
    /// cannot supply randomness.
    pub fn create(
        algorithm: AeadAlgorithm,
        mode: FileMode,
        metadata: FileMetadata,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            algorithm,
            mode,
            file_id: random::array()?,
            plain_size: 0,
            metadata,
            file_key: random::secret()?,
        })
    }

    /// The file's content key, for sealing and opening its chunks.
    #[must_use]
    pub const fn file_key(&self) -> &Key32 {
        &self.file_key
    }

    /// Total on-disk length of this header once serialised.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::MetadataTooLarge`] if the metadata does not fit.
    pub fn encoded_len(&self) -> Result<u64, FormatError> {
        let metadata_len = self.metadata_len()?;
        Ok(header_len(nonce_len_of(self.algorithm), metadata_len))
    }

    /// Serialises and seals the header under the vault's content key.
    ///
    /// A fresh nonce is used every time, so two calls produce different bytes
    /// for the same header. That is why chunks are bound to `file_id`.
    ///
    /// # Errors
    ///
    /// - [`FormatError::MetadataTooLarge`] if the metadata block is too big.
    /// - A wrapped [`cv_crypto::CryptoError`] if randomness or the cipher fails.
    pub fn seal(&self, content_key: &Key32) -> Result<Vec<u8>, FormatError> {
        let metadata = self.metadata.encode()?;
        let metadata_len =
            u32::try_from(metadata.len()).map_err(|_| FormatError::MetadataTooLarge {
                len: metadata.len(),
                max: MAX_METADATA_LEN,
            })?;

        let nonce = aead::generate_nonce(self.algorithm)?;

        let mut prefix =
            Vec::with_capacity(usize_of(header_prefix_len(nonce_len_of(self.algorithm))));
        prefix.extend_from_slice(&FILE_MAGIC);
        prefix.push(FORMAT_VERSION);
        prefix.push(self.algorithm.as_byte());
        prefix.push(self.mode.as_byte());
        prefix.push(0); // reserved
        prefix.extend_from_slice(&self.file_id);
        prefix.extend_from_slice(&nonce);
        prefix.extend_from_slice(&metadata_len.to_le_bytes());

        let mut payload =
            Vec::with_capacity(FILE_KEY_LEN as usize + PLAIN_SIZE_LEN + metadata.len());
        payload.extend_from_slice(self.file_key.expose());
        payload.extend_from_slice(&self.plain_size.to_le_bytes());
        payload.extend_from_slice(&metadata);

        let sealed = aead::seal(self.algorithm, content_key, &nonce, &prefix, &payload)?;

        let mut out = prefix;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Parses and verifies a header from the start of `bytes`.
    ///
    /// Returns the header and how many bytes it occupied, so the caller knows
    /// where the first chunk begins.
    ///
    /// # Errors
    ///
    /// - [`FormatError::BadMagic`] if this is not a CryptoVault file.
    /// - [`FormatError::UnsupportedVersion`] for a format this build cannot read.
    /// - [`FormatError::ReservedByteSet`] if a reserved byte is not zero — it is
    ///   how a future version will signal a change this build must not ignore.
    /// - [`FormatError::UnknownFileMode`] for an unrecognised mode.
    /// - [`FormatError::MetadataTooLarge`] if the length field exceeds the
    ///   ceiling. Checked *before* it is used to size anything.
    /// - [`FormatError::Truncated`] if the data ends early.
    /// - A wrapped [`cv_crypto::CryptoError::DecryptionFailed`] if
    ///   authentication fails.
    pub fn open(bytes: &[u8], content_key: &Key32) -> Result<(Self, u64), FormatError> {
        // Enough for magic, version, algorithm, mode and reserved. The rest of
        // the prefix cannot be located until the algorithm is known.
        const MIN_TO_IDENTIFY: usize = 8;
        require_len(bytes, MIN_TO_IDENTIFY)?;

        if bytes[0..4] != FILE_MAGIC {
            return Err(FormatError::BadMagic);
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion {
                found: bytes[4],
                supported: FORMAT_VERSION,
            });
        }

        let algorithm = AeadAlgorithm::try_from(bytes[5])?;
        let mode = FileMode::try_from(bytes[6])?;
        if bytes[7] != 0 {
            return Err(FormatError::ReservedByteSet(bytes[7]));
        }

        let nonce_len = nonce_len_of(algorithm);
        let prefix_len = usize_of(header_prefix_len(nonce_len));
        require_len(bytes, prefix_len)?;

        let file_id: [u8; FILE_ID_LEN as usize] = bytes[8..8 + FILE_ID_LEN as usize]
            .try_into()
            .map_err(|_| FormatError::Truncated {
                needed: prefix_len as u64,
                found: bytes.len(),
            })?;

        let nonce_start = 8 + FILE_ID_LEN as usize;
        let nonce = &bytes[nonce_start..nonce_start + nonce_len as usize];

        let meta_len_start = nonce_start + nonce_len as usize;
        let metadata_len = u32::from_le_bytes(
            bytes[meta_len_start..meta_len_start + 4]
                .try_into()
                .map_err(|_| FormatError::Truncated {
                    needed: prefix_len as u64,
                    found: bytes.len(),
                })?,
        );

        // Checked before it is used for anything, so a corrupted length cannot
        // make us reserve or read an absurd amount.
        if metadata_len > MAX_METADATA_LEN {
            return Err(FormatError::MetadataTooLarge {
                len: metadata_len as usize,
                max: MAX_METADATA_LEN,
            });
        }

        let total_len = header_len(nonce_len, metadata_len);
        require_len(bytes, usize_of(total_len))?;

        let prefix = &bytes[..prefix_len];
        let sealed = &bytes[prefix_len..usize_of(total_len)];

        let payload = aead::open(algorithm, content_key, nonce, prefix, sealed)?;

        // The payload is authenticated, so its shape is guaranteed unless this
        // build disagrees with the writer about the layout. Checked anyway: an
        // assumption that only holds "unless there is a bug" is worth one `if`.
        let fixed = FILE_KEY_LEN as usize + PLAIN_SIZE_LEN;
        if payload.len() < fixed {
            return Err(FormatError::Truncated {
                needed: fixed as u64,
                found: payload.len(),
            });
        }

        let file_key = Key32::from_slice(&payload[..FILE_KEY_LEN as usize])?;
        let plain_size = u64::from_le_bytes(
            payload[FILE_KEY_LEN as usize..fixed]
                .try_into()
                .map_err(|_| FormatError::Truncated {
                    needed: fixed as u64,
                    found: payload.len(),
                })?,
        );
        let metadata = FileMetadata::decode(&payload[fixed..])?;

        Ok((
            Self {
                algorithm,
                mode,
                file_id,
                plain_size,
                metadata,
                file_key,
            },
            total_len,
        ))
    }

    fn metadata_len(&self) -> Result<u32, FormatError> {
        let encoded = self.metadata.encode()?;
        u32::try_from(encoded.len()).map_err(|_| FormatError::MetadataTooLarge {
            len: encoded.len(),
            max: MAX_METADATA_LEN,
        })
    }
}

/// Nonce length of an algorithm, as a `u32` for header arithmetic.
fn nonce_len_of(algorithm: AeadAlgorithm) -> u32 {
    // Nonce lengths are 12 and 24; the conversion cannot fail.
    u32::try_from(algorithm.nonce_len()).unwrap_or(u32::MAX)
}

/// Narrows a header offset to `usize`, saturating rather than wrapping.
///
/// Header lengths are bounded by `MAX_METADATA_LEN`, so on any platform we
/// target this is exact. Saturating keeps the conversion total without a cast
/// that could silently truncate on a 32-bit host.
fn usize_of(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn require_len(bytes: &[u8], needed: usize) -> Result<(), FormatError> {
    if bytes.len() < needed {
        return Err(FormatError::Truncated {
            needed: needed as u64,
            found: bytes.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv_crypto::CryptoError;

    fn content_key() -> Key32 {
        Key32::new([0x3C; 32])
    }

    fn other_key() -> Key32 {
        Key32::new([0x3D; 32])
    }

    fn header() -> FileHeader {
        FileHeader::create(
            AeadAlgorithm::Aes256Gcm,
            FileMode::Live,
            FileMetadata::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_header_round_trips() {
        let original = header();
        let bytes = original.seal(&content_key()).unwrap();
        let (parsed, len) = FileHeader::open(&bytes, &content_key()).unwrap();

        assert_eq!(len, bytes.len() as u64);
        assert_eq!(parsed.algorithm, original.algorithm);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.file_id, original.file_id);
        assert_eq!(parsed.plain_size, original.plain_size);
        assert_eq!(parsed.file_key(), original.file_key());
        assert_eq!(parsed.metadata, original.metadata);
    }

    #[test]
    fn an_empty_header_is_ninety_six_bytes_with_aes_gcm() {
        let bytes = header().seal(&content_key()).unwrap();
        // 96 + the few bytes an empty CBOR map costs.
        assert!(bytes.len() >= 96, "header was {} bytes", bytes.len());
        assert_eq!(bytes.len() as u64, header().encoded_len().unwrap());
    }

    #[test]
    fn metadata_survives_the_round_trip() {
        let mut original = header();
        original.metadata.tags = vec!["work".into()];
        original.metadata.mtime = Some(1_770_000_000);
        original.metadata.versioned = true;
        original.plain_size = 123_456;

        let bytes = original.seal(&content_key()).unwrap();
        let (parsed, _) = FileHeader::open(&bytes, &content_key()).unwrap();

        assert_eq!(parsed.metadata.tags, ["work"]);
        assert_eq!(parsed.metadata.mtime, Some(1_770_000_000));
        assert!(parsed.metadata.versioned);
        assert_eq!(parsed.plain_size, 123_456);
    }

    #[test]
    fn the_file_key_is_not_visible_in_the_sealed_header() {
        let original = header();
        let bytes = original.seal(&content_key()).unwrap();
        let key = original.file_key().expose();
        assert!(!bytes.windows(32).any(|window| window == key));
    }

    #[test]
    fn the_prefix_is_written_as_specified() {
        let bytes = header().seal(&content_key()).unwrap();
        assert_eq!(&bytes[0..4], b"CVF1");
        assert_eq!(bytes[4], FORMAT_VERSION);
        assert_eq!(bytes[5], AeadAlgorithm::Aes256Gcm.as_byte());
        assert_eq!(bytes[6], FileMode::Live.as_byte());
        assert_eq!(bytes[7], 0);
    }

    /// Sealing twice must differ, because the nonce is fresh each time. This is
    /// exactly why chunks are bound to `file_id` and not to the header nonce.
    #[test]
    fn sealing_twice_produces_different_bytes() {
        let original = header();
        let first = original.seal(&content_key()).unwrap();
        let second = original.seal(&content_key()).unwrap();

        assert_ne!(first, second);
        // …and the file identity survives both.
        assert_eq!(
            FileHeader::open(&first, &content_key()).unwrap().0.file_id,
            FileHeader::open(&second, &content_key()).unwrap().0.file_id
        );
    }

    /// Editing metadata must not disturb the file identity or its content key.
    /// If it did, adding a tag would orphan every chunk in the file.
    #[test]
    fn editing_metadata_keeps_the_file_id_and_key() {
        let mut original = header();
        let sealed_before = original.seal(&content_key()).unwrap();
        let (before, _) = FileHeader::open(&sealed_before, &content_key()).unwrap();

        original.metadata.tags.push("a new tag".into());
        let sealed_after = original.seal(&content_key()).unwrap();
        let (after, _) = FileHeader::open(&sealed_after, &content_key()).unwrap();

        assert_eq!(before.file_id, after.file_id);
        assert_eq!(before.file_key(), after.file_key());
        assert_ne!(before.metadata, after.metadata);
    }

    #[test]
    fn both_algorithms_work_and_have_different_header_lengths() {
        let mut lengths = Vec::new();
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::XChaCha20Poly1305] {
            let original =
                FileHeader::create(algorithm, FileMode::Live, FileMetadata::default()).unwrap();
            let bytes = original.seal(&content_key()).unwrap();
            let (parsed, len) = FileHeader::open(&bytes, &content_key()).unwrap();

            assert_eq!(parsed.algorithm, algorithm);
            assert_eq!(parsed.file_key(), original.file_key());
            lengths.push(len);
        }
        // XChaCha's nonce is 12 bytes longer, and the parser has to size the
        // header from the algorithm byte rather than assume.
        assert_eq!(lengths[1] - lengths[0], 12);
    }

    #[test]
    fn the_wrong_key_is_refused() {
        let bytes = header().seal(&content_key()).unwrap();
        assert_eq!(
            FileHeader::open(&bytes, &other_key()),
            Err(FormatError::Crypto(CryptoError::DecryptionFailed))
        );
    }

    #[test]
    fn bad_magic_is_reported_as_such() {
        let mut bytes = header().seal(&content_key()).unwrap();
        bytes[0] = b'X';
        assert_eq!(
            FileHeader::open(&bytes, &content_key()),
            Err(FormatError::BadMagic)
        );
    }

    #[test]
    fn a_future_format_version_is_refused_not_guessed_at() {
        let mut bytes = header().seal(&content_key()).unwrap();
        bytes[4] = FORMAT_VERSION + 1;
        assert_eq!(
            FileHeader::open(&bytes, &content_key()),
            Err(FormatError::UnsupportedVersion {
                found: FORMAT_VERSION + 1,
                supported: FORMAT_VERSION
            })
        );
    }

    /// The reserved byte is how a later version signals a change this build must
    /// not ignore, so a non-zero value has to stop it rather than be skipped.
    #[test]
    fn a_set_reserved_byte_stops_the_parse() {
        let mut bytes = header().seal(&content_key()).unwrap();
        bytes[7] = 1;
        assert_eq!(
            FileHeader::open(&bytes, &content_key()),
            Err(FormatError::ReservedByteSet(1))
        );
    }

    #[test]
    fn an_unknown_algorithm_is_refused() {
        let mut bytes = header().seal(&content_key()).unwrap();
        bytes[5] = 0x7F;
        assert_eq!(
            FileHeader::open(&bytes, &content_key()),
            Err(FormatError::Crypto(CryptoError::UnknownAlgorithm(0x7F)))
        );
    }

    /// A corrupted metadata length must be rejected on sight, before it is used
    /// to size anything. This is the classic way a parser is turned into a
    /// denial of service.
    #[test]
    fn an_absurd_metadata_length_is_refused_before_it_is_used() {
        let mut bytes = header().seal(&content_key()).unwrap();
        let meta_len_at = 8 + FILE_ID_LEN as usize + 12;
        bytes[meta_len_at..meta_len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(matches!(
            FileHeader::open(&bytes, &content_key()),
            Err(FormatError::MetadataTooLarge { .. })
        ));
    }

    /// Every prefix of a valid header must be refused cleanly — no panic, no
    /// out-of-bounds slice. This is the shape of input a fuzzer finds first.
    #[test]
    fn every_truncation_is_refused_cleanly() {
        let bytes = header().seal(&content_key()).unwrap();
        for cut in 0..bytes.len() {
            assert!(
                FileHeader::open(&bytes[..cut], &content_key()).is_err(),
                "a header truncated to {cut} bytes was accepted"
            );
        }
    }

    #[test]
    fn flipping_any_single_bit_is_caught() {
        let bytes = header().seal(&content_key()).unwrap();

        for byte_index in 0..bytes.len() {
            for bit in 0..8_u8 {
                let mut damaged = bytes.clone();
                damaged[byte_index] ^= 1 << bit;
                assert!(
                    FileHeader::open(&damaged, &content_key()).is_err(),
                    "bit {bit} of byte {byte_index} went undetected"
                );
            }
        }
    }

    /// Trailing bytes belong to the first chunk, so the parser must report where
    /// the header ends rather than consuming everything it is given.
    #[test]
    fn trailing_bytes_are_left_for_the_caller() {
        let mut bytes = header().seal(&content_key()).unwrap();
        let header_len = bytes.len() as u64;
        bytes.extend_from_slice(&[0xAA; 500]);

        let (_, reported) = FileHeader::open(&bytes, &content_key()).unwrap();
        assert_eq!(reported, header_len);
    }

    #[test]
    fn an_archived_header_round_trips() {
        let original = FileHeader::create(
            AeadAlgorithm::Aes256Gcm,
            FileMode::Archived,
            FileMetadata::default(),
        )
        .unwrap();
        let bytes = original.seal(&content_key()).unwrap();
        let (parsed, _) = FileHeader::open(&bytes, &content_key()).unwrap();
        assert_eq!(parsed.mode, FileMode::Archived);
    }

    #[test]
    fn every_new_header_gets_a_distinct_identity() {
        let first = header();
        let second = header();
        assert_ne!(first.file_id, second.file_id);
        assert_ne!(first.file_key(), second.file_key());
    }
}
