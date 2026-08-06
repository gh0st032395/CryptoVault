//! Sealing and opening the chunks a file's contents are stored in.
//!
//! A file body is a sequence of independently encrypted chunks, each carrying
//! 32 KiB of plaintext:
//!
//! ```text
//! nonce(12 or 24) ‖ ciphertext ‖ tag(16)
//! AAD = chunk_index(u64 LE) ‖ file_id
//! ```
//!
//! Independence is the point. It is what lets a read of four kilobytes decrypt
//! thirty-two rather than two gigabytes, and what lets a one-byte edit rewrite
//! one chunk rather than the file.
//!
//! # What the associated data buys
//!
//! A tag proves a chunk was not modified. It says nothing about *which* chunk it
//! is or *which file* it came from, and without that an attacker with disk
//! access could reorder chunks, duplicate one over another, or splice in a chunk
//! from a different file encrypted under the same key. Every one of those
//! produces a plausible file that decrypts cleanly.
//!
//! Putting the index and the file identifier in the associated data closes all
//! of it: a chunk only authenticates in the position, and in the file, it was
//! written for.
//!
//! # The nonce, again
//!
//! Fresh randomness on every write. Never the index. Chunks are rewritten in
//! place, and a nonce derived from the index would repeat under the same key on
//! different plaintext — which with GCM hands over the authentication key. The
//! failure is completely silent, which is what makes it worth this much comment.

use cv_crypto::aead;

use crate::consts::{CHUNK_PLAINTEXT_LEN, FILE_ID_LEN};
use crate::header::FileHeader;
use crate::{FileMode, FormatError};

/// Builds the associated data binding a chunk to its index and its file.
#[must_use]
pub fn chunk_aad(file_id: &[u8; FILE_ID_LEN as usize], chunk_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + FILE_ID_LEN as usize);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(file_id);
    aad
}

/// Encrypts one chunk of plaintext.
///
/// The returned bytes are `nonce ‖ ciphertext ‖ tag`, ready to be written at the
/// chunk's offset in the file.
///
/// # Errors
///
/// - [`FormatError::ChunkTooLarge`] if `plaintext` exceeds
///   [`CHUNK_PLAINTEXT_LEN`]. Silently splitting it would put data in a chunk
///   the reader will look for somewhere else.
/// - [`FormatError::NotWritable`] if the file is archived rather than live.
/// - A wrapped [`cv_crypto::CryptoError`] if randomness or the cipher fails.
pub fn seal_chunk(
    header: &FileHeader,
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, FormatError> {
    if header.mode != FileMode::Live {
        return Err(FormatError::NotWritable);
    }
    if plaintext.len() > CHUNK_PLAINTEXT_LEN as usize {
        return Err(FormatError::ChunkTooLarge {
            len: plaintext.len(),
            max: CHUNK_PLAINTEXT_LEN,
        });
    }

    let nonce = aead::generate_nonce(header.algorithm)?;
    let aad = chunk_aad(&header.file_id, chunk_index);
    let sealed = aead::seal(header.algorithm, header.file_key(), &nonce, &aad, plaintext)?;

    let mut out = nonce;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decrypts one stored chunk.
///
/// `chunk_index` must be the index the chunk was written at. Supplying a
/// different one is not a subtle error: it fails authentication, which is the
/// intended behaviour, because it means somebody moved the chunk.
///
/// # Errors
///
/// - [`FormatError::Truncated`] if the stored chunk is shorter than a nonce and
///   a tag.
/// - A wrapped [`cv_crypto::CryptoError::DecryptionFailed`] if authentication
///   fails: modified data, the wrong index, the wrong file, or the wrong key.
pub fn open_chunk(
    header: &FileHeader,
    chunk_index: u64,
    stored: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let nonce_len = header.algorithm.nonce_len();
    let minimum = nonce_len + header.algorithm.tag_len();

    if stored.len() < minimum {
        return Err(FormatError::Truncated {
            needed: minimum as u64,
            found: stored.len(),
        });
    }

    let (nonce, ciphertext) = stored.split_at(nonce_len);
    let aad = chunk_aad(&header.file_id, chunk_index);

    Ok(aead::open(
        header.algorithm,
        header.file_key(),
        nonce,
        &aad,
        ciphertext,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::{chunk_count_for_size, plaintext_len_of_chunk};
    use crate::metadata::FileMetadata;
    use cv_crypto::CryptoError;
    use cv_crypto::aead::AeadAlgorithm;

    fn header() -> FileHeader {
        FileHeader::create(
            AeadAlgorithm::Aes256Gcm,
            FileMode::Live,
            FileMetadata::default(),
        )
        .unwrap()
    }

    #[test]
    fn a_chunk_round_trips() {
        let header = header();
        let sealed = seal_chunk(&header, 0, b"the contents").unwrap();
        assert_eq!(open_chunk(&header, 0, &sealed).unwrap(), b"the contents");
    }

    #[test]
    fn an_empty_chunk_round_trips() {
        let header = header();
        let sealed = seal_chunk(&header, 0, b"").unwrap();
        assert_eq!(open_chunk(&header, 0, &sealed).unwrap(), b"");
    }

    #[test]
    fn a_full_chunk_round_trips() {
        let header = header();
        let full = vec![0x5A; CHUNK_PLAINTEXT_LEN as usize];
        let sealed = seal_chunk(&header, 0, &full).unwrap();
        assert_eq!(open_chunk(&header, 0, &sealed).unwrap(), full);
    }

    #[test]
    fn the_stored_chunk_is_the_plaintext_plus_nonce_and_tag() {
        let header = header();
        for len in [0_usize, 1, 4096, CHUNK_PLAINTEXT_LEN as usize] {
            let sealed = seal_chunk(&header, 0, &vec![0_u8; len]).unwrap();
            assert_eq!(sealed.len(), len + 12 + 16);
        }
    }

    /// Refusing an oversized chunk rather than splitting it: a split would put
    /// data in a chunk the reader will look for at a different offset.
    #[test]
    fn an_oversized_chunk_is_refused() {
        let header = header();
        let too_big = vec![0_u8; CHUNK_PLAINTEXT_LEN as usize + 1];
        assert_eq!(
            seal_chunk(&header, 0, &too_big),
            Err(FormatError::ChunkTooLarge {
                len: CHUNK_PLAINTEXT_LEN as usize + 1,
                max: CHUNK_PLAINTEXT_LEN
            })
        );
    }

    #[test]
    fn archived_files_refuse_writes() {
        let archived = FileHeader::create(
            AeadAlgorithm::Aes256Gcm,
            FileMode::Archived,
            FileMetadata::default(),
        )
        .unwrap();
        assert_eq!(
            seal_chunk(&archived, 0, b"x"),
            Err(FormatError::NotWritable)
        );
    }

    /// Reordering. A chunk only authenticates at the index it was written for.
    #[test]
    fn a_chunk_moved_to_another_index_is_refused() {
        let header = header();
        let sealed = seal_chunk(&header, 7, b"contents of chunk seven").unwrap();

        assert!(open_chunk(&header, 7, &sealed).is_ok());
        for wrong in [0_u64, 6, 8, u64::MAX] {
            assert_eq!(
                open_chunk(&header, wrong, &sealed),
                Err(FormatError::Crypto(CryptoError::DecryptionFailed)),
                "a chunk from index 7 was accepted at index {wrong}"
            );
        }
    }

    /// Splicing. A chunk from another file must not authenticate here, even
    /// though both files sit in the same vault.
    #[test]
    fn a_chunk_from_another_file_is_refused() {
        let source = header();
        // Same content key, same everything: only the file identity differs, so
        // the test isolates exactly what file_id is there to prevent.
        let mut target = source.clone();
        target.file_id[0] ^= 0xFF;

        let sealed = seal_chunk(&source, 0, b"contents").unwrap();
        assert_eq!(
            open_chunk(&target, 0, &sealed),
            Err(FormatError::Crypto(CryptoError::DecryptionFailed))
        );
    }

    /// Duplication. Copying chunk 0 over chunk 1 must be caught; without the
    /// index in the associated data it would decrypt cleanly and silently
    /// corrupt the file.
    #[test]
    fn duplicating_a_chunk_over_another_is_caught() {
        let header = header();
        let first = seal_chunk(&header, 0, b"first chunk").unwrap();
        assert!(open_chunk(&header, 1, &first).is_err());
    }

    #[test]
    fn flipping_any_single_bit_is_caught() {
        let header = header();
        let sealed = seal_chunk(&header, 3, b"a short chunk").unwrap();

        for byte_index in 0..sealed.len() {
            for bit in 0..8_u8 {
                let mut damaged = sealed.clone();
                damaged[byte_index] ^= 1 << bit;
                assert!(
                    open_chunk(&header, 3, &damaged).is_err(),
                    "bit {bit} of byte {byte_index} went undetected"
                );
            }
        }
    }

    #[test]
    fn every_truncation_is_refused_cleanly() {
        let header = header();
        let sealed = seal_chunk(&header, 0, b"some contents").unwrap();
        for cut in 0..sealed.len() {
            assert!(
                open_chunk(&header, 0, &sealed[..cut]).is_err(),
                "a chunk truncated to {cut} bytes was accepted"
            );
        }
    }

    #[test]
    fn sealing_the_same_plaintext_twice_gives_different_bytes() {
        let header = header();
        let first = seal_chunk(&header, 0, b"identical").unwrap();
        let second = seal_chunk(&header, 0, b"identical").unwrap();
        assert_ne!(
            first, second,
            "the nonce is not being refreshed on every write"
        );
    }

    /// Rewriting a chunk in place is the ordinary case for a mutable file, and
    /// the case a counter-based nonce would have broken.
    #[test]
    fn rewriting_a_chunk_in_place_works_repeatedly() {
        let header = header();
        for round in 0..20_u8 {
            let plaintext = vec![round; 100];
            let sealed = seal_chunk(&header, 5, &plaintext).unwrap();
            assert_eq!(open_chunk(&header, 5, &sealed).unwrap(), plaintext);
        }
    }

    /// A whole file, chunked, sealed, opened and reassembled. The test that
    /// would catch an off-by-one between the arithmetic and the cipher.
    #[test]
    fn a_multi_chunk_file_reassembles_exactly() {
        let header = header();
        let chunk = CHUNK_PLAINTEXT_LEN as usize;

        for size in [
            0_usize,
            1,
            chunk - 1,
            chunk,
            chunk + 1,
            3 * chunk,
            3 * chunk + 17,
        ] {
            #[allow(clippy::cast_possible_truncation, reason = "deliberate byte pattern")]
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

            let sealed: Vec<Vec<u8>> = (0..chunk_count_for_size(size as u64))
                .map(|index| {
                    let start = usize::try_from(index).unwrap() * chunk;
                    let len = usize::try_from(plaintext_len_of_chunk(index, size as u64)).unwrap();
                    seal_chunk(&header, index, &plaintext[start..start + len]).unwrap()
                })
                .collect();

            let reassembled: Vec<u8> = sealed
                .iter()
                .enumerate()
                .flat_map(|(index, bytes)| {
                    open_chunk(&header, u64::try_from(index).unwrap(), bytes).unwrap()
                })
                .collect();

            assert_eq!(
                reassembled, plaintext,
                "a {size}-byte file did not reassemble"
            );
        }
    }

    #[test]
    fn the_associated_data_is_index_then_file_id() {
        let file_id = [0xAB_u8; FILE_ID_LEN as usize];
        let aad = chunk_aad(&file_id, 1);

        assert_eq!(aad.len(), 8 + FILE_ID_LEN as usize);
        assert_eq!(&aad[..8], &1_u64.to_le_bytes());
        assert_eq!(&aad[8..], &file_id);
        assert_ne!(chunk_aad(&file_id, 1), chunk_aad(&file_id, 2));
    }

    #[test]
    fn chunks_work_with_either_algorithm() {
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::XChaCha20Poly1305] {
            let header =
                FileHeader::create(algorithm, FileMode::Live, FileMetadata::default()).unwrap();
            let sealed = seal_chunk(&header, 0, b"contents").unwrap();
            assert_eq!(sealed.len(), 8 + algorithm.nonce_len() + 16);
            assert_eq!(open_chunk(&header, 0, &sealed).unwrap(), b"contents");
        }
    }
}
