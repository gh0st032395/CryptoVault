//! Arithmetic that maps a plaintext offset onto the encrypted file on disk.
//!
//! These functions are small and dull, and they are also the part of the format
//! most likely to hide a bug that only shows up on a five-gigabyte file at three
//! in the morning. They live in their own module, they are pure, and they are
//! tested at every boundary — including the ones that need 64-bit sizes.
//!
//! Every function that can overflow returns [`Option`] rather than wrapping or
//! saturating. A wrong offset here does not produce a slightly wrong result: it
//! reads the wrong chunk, fails authentication, and looks to the user like a
//! corrupted vault.

use crate::consts::{
    CHUNK_OVERHEAD, CHUNK_PLAINTEXT_LEN, CHUNK_STORED_LEN, HEADER_FIXED_PREFIX_LEN,
    HEADER_SEALED_FIXED_LEN, TAG_LEN,
};

/// Plaintext chunk size widened once, so the rest of the module can do 64-bit
/// arithmetic without repeating the conversion.
fn chunk_plaintext_len() -> u64 {
    u64::from(CHUNK_PLAINTEXT_LEN)
}

/// Index of the chunk holding a given plaintext byte offset.
#[must_use]
pub fn chunk_index_for_offset(offset: u64) -> u64 {
    offset / chunk_plaintext_len()
}

/// Offset of a plaintext byte within its own chunk.
///
/// Returned as a [`u64`] so callers never have to reason about a narrowing
/// conversion; the value is always below [`CHUNK_PLAINTEXT_LEN`].
#[must_use]
pub fn offset_within_chunk(offset: u64) -> u64 {
    offset % chunk_plaintext_len()
}

/// Number of chunks needed to store a plaintext of the given size.
///
/// An empty file occupies zero chunks: it is a header and nothing else.
#[must_use]
pub fn chunk_count_for_size(plain_size: u64) -> u64 {
    plain_size.div_ceil(chunk_plaintext_len())
}

/// Plaintext bytes carried by one specific chunk of a file.
///
/// Every chunk is full except possibly the last. Returns `0` for an index past
/// the end of the file.
#[must_use]
pub fn plaintext_len_of_chunk(chunk_index: u64, plain_size: u64) -> u64 {
    let count = chunk_count_for_size(plain_size);
    if chunk_index >= count {
        return 0;
    }
    if chunk_index + 1 < count {
        return chunk_plaintext_len();
    }
    // Last chunk: whatever is left over. A remainder of zero means the size
    // divides exactly, so the final chunk is full.
    let remainder = plain_size % chunk_plaintext_len();
    if remainder == 0 {
        chunk_plaintext_len()
    } else {
        remainder
    }
}

/// Length of the authenticated header prefix, nonce included.
///
/// The nonce length comes from the algorithm — 12 bytes for AES-GCM, 24 for
/// XChaCha20-Poly1305 — so the prefix is not a constant. Reading a header means
/// reading the algorithm byte first and sizing the rest from it.
#[must_use]
pub fn header_prefix_len(nonce_len: u32) -> u64 {
    u64::from(HEADER_FIXED_PREFIX_LEN) + u64::from(nonce_len)
}

/// Total size of a file header.
///
/// Layout: the authenticated prefix, then the sealed block holding the file key,
/// the plaintext size and the metadata, then the authentication tag.
///
/// With AES-GCM's 12-byte nonce this is `96 + metadata_len`.
#[must_use]
pub fn header_len(nonce_len: u32, metadata_len: u32) -> u64 {
    header_prefix_len(nonce_len)
        + u64::from(HEADER_SEALED_FIXED_LEN)
        + u64::from(metadata_len)
        + u64::from(TAG_LEN)
}

/// Byte offset of a chunk within the encrypted file.
///
/// Returns [`None`] on overflow, which in practice means the header length or
/// the chunk index came from a corrupted file rather than a real one.
#[must_use]
pub fn chunk_offset_in_file(chunk_index: u64, header_len: u64) -> Option<u64> {
    chunk_index
        .checked_mul(u64::from(CHUNK_STORED_LEN))
        .and_then(|body_offset| body_offset.checked_add(header_len))
}

/// Total on-disk size of an encrypted file.
///
/// Returns [`None`] on overflow.
#[must_use]
pub fn stored_len(plain_size: u64, header_len: u64) -> Option<u64> {
    let chunks = chunk_count_for_size(plain_size);
    let overhead = chunks.checked_mul(u64::from(CHUNK_OVERHEAD))?;
    plain_size.checked_add(overhead)?.checked_add(header_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Restated independently of the constant on purpose: if someone changes the
    /// chunk size, `chunk_size_matches_the_constant` fails and forces them to
    /// look at the format specification and the user manual too.
    const CHUNK: u64 = 32 * 1024;

    #[test]
    fn chunk_size_matches_the_constant() {
        assert_eq!(CHUNK, chunk_plaintext_len());
    }

    #[test]
    fn offsets_inside_the_first_chunk_map_to_index_zero() {
        assert_eq!(chunk_index_for_offset(0), 0);
        assert_eq!(chunk_index_for_offset(1), 0);
        assert_eq!(chunk_index_for_offset(CHUNK - 1), 0);
    }

    #[test]
    fn the_chunk_boundary_advances_the_index() {
        assert_eq!(chunk_index_for_offset(CHUNK), 1);
        assert_eq!(chunk_index_for_offset(CHUNK + 1), 1);
        assert_eq!(chunk_index_for_offset(2 * CHUNK - 1), 1);
        assert_eq!(chunk_index_for_offset(2 * CHUNK), 2);
    }

    #[test]
    fn within_chunk_offset_wraps_at_the_boundary() {
        assert_eq!(offset_within_chunk(0), 0);
        assert_eq!(offset_within_chunk(CHUNK - 1), CHUNK - 1);
        assert_eq!(offset_within_chunk(CHUNK), 0);
        assert_eq!(offset_within_chunk(CHUNK + 7), 7);
    }

    #[test]
    fn index_and_within_offset_reconstruct_the_original_offset() {
        for offset in [
            0_u64,
            1,
            4095,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            5 * CHUNK + 123,
            u64::MAX,
        ] {
            let rebuilt = chunk_index_for_offset(offset) * CHUNK + offset_within_chunk(offset);
            assert_eq!(rebuilt, offset, "failed for offset {offset}");
        }
    }

    #[test]
    fn an_empty_file_has_no_chunks() {
        assert_eq!(chunk_count_for_size(0), 0);
    }

    #[test]
    fn chunk_count_rounds_up() {
        assert_eq!(chunk_count_for_size(1), 1);
        assert_eq!(chunk_count_for_size(CHUNK - 1), 1);
        assert_eq!(chunk_count_for_size(CHUNK), 1);
        assert_eq!(chunk_count_for_size(CHUNK + 1), 2);
        assert_eq!(chunk_count_for_size(2 * CHUNK), 2);
    }

    #[test]
    fn a_two_gibibyte_file_has_the_expected_chunk_count() {
        let two_gib = 2 * 1024 * 1024 * 1024_u64;
        assert_eq!(chunk_count_for_size(two_gib), two_gib / CHUNK);
    }

    #[test]
    fn last_chunk_holds_the_remainder() {
        assert_eq!(plaintext_len_of_chunk(0, 0), 0);
        assert_eq!(plaintext_len_of_chunk(0, 10), 10);
        assert_eq!(plaintext_len_of_chunk(0, CHUNK), CHUNK);
        assert_eq!(plaintext_len_of_chunk(0, CHUNK + 5), CHUNK);
        assert_eq!(plaintext_len_of_chunk(1, CHUNK + 5), 5);
    }

    #[test]
    fn an_exact_multiple_ends_with_a_full_chunk() {
        assert_eq!(plaintext_len_of_chunk(1, 2 * CHUNK), CHUNK);
    }

    #[test]
    fn chunks_past_the_end_are_empty() {
        assert_eq!(plaintext_len_of_chunk(1, 10), 0);
        assert_eq!(plaintext_len_of_chunk(u64::MAX, 10), 0);
    }

    /// The sum of every chunk's plaintext must equal the file size exactly. This
    /// is the invariant a truncation bug would break first.
    #[test]
    fn chunk_lengths_sum_to_the_file_size() {
        for size in [
            0_u64,
            1,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            3 * CHUNK,
            3 * CHUNK + 17,
        ] {
            let total: u64 = (0..chunk_count_for_size(size))
                .map(|i| plaintext_len_of_chunk(i, size))
                .sum();
            assert_eq!(total, size, "chunk lengths did not sum to {size}");
        }
    }

    /// The AES-GCM nonce is 12 bytes, which is where the familiar 96 comes from.
    #[test]
    fn header_length_with_an_aes_gcm_nonce_is_ninety_six_plus_metadata() {
        assert_eq!(header_len(12, 0), 96);
        assert_eq!(header_len(12, 1), 97);
        assert_eq!(header_len(12, 1024), 96 + 1024);
    }

    /// XChaCha20-Poly1305 uses a 24-byte nonce, so its headers are 12 bytes
    /// longer. The header layout has to be sized from the algorithm byte, not
    /// assumed — getting this wrong would misplace every chunk in the file.
    #[test]
    fn a_longer_nonce_makes_a_longer_header() {
        assert_eq!(header_len(24, 0), 108);
        assert_eq!(header_len(24, 0) - header_len(12, 0), 12);
    }

    #[test]
    fn the_prefix_is_the_fixed_part_plus_the_nonce() {
        assert_eq!(header_prefix_len(12), 40);
        assert_eq!(header_prefix_len(24), 52);
    }

    #[test]
    fn first_chunk_starts_right_after_the_header() {
        let hdr = header_len(12, 0);
        assert_eq!(chunk_offset_in_file(0, hdr), Some(hdr));
        assert_eq!(
            chunk_offset_in_file(1, hdr),
            Some(hdr + u64::from(CHUNK_STORED_LEN))
        );
    }

    #[test]
    fn chunk_offset_reports_overflow_instead_of_wrapping() {
        assert_eq!(chunk_offset_in_file(u64::MAX, 96), None);
    }

    #[test]
    fn stored_length_accounts_for_header_and_per_chunk_overhead() {
        let hdr = header_len(12, 0);
        let per_chunk = u64::from(CHUNK_OVERHEAD);

        assert_eq!(stored_len(0, hdr), Some(hdr));
        assert_eq!(stored_len(1, hdr), Some(hdr + 1 + per_chunk));
        assert_eq!(stored_len(CHUNK, hdr), Some(hdr + CHUNK + per_chunk));
        assert_eq!(
            stored_len(CHUNK + 1, hdr),
            Some(hdr + CHUNK + 1 + 2 * per_chunk)
        );
    }

    #[test]
    fn stored_length_reports_overflow_instead_of_wrapping() {
        assert_eq!(stored_len(u64::MAX, 96), None);
    }

    /// The overhead figure quoted in the format specification and in the user
    /// manual has to stay true. If the chunk size ever changes, this is the
    /// reminder that the documentation changes with it.
    #[test]
    fn overhead_on_a_large_file_stays_below_a_tenth_of_a_percent() {
        let plain = 1024 * 1024 * 1024_u64; // 1 GiB
        let hdr = header_len(12, 0);
        let stored = stored_len(plain, hdr).expect("1 GiB is far from overflowing");
        #[allow(
            clippy::cast_precision_loss,
            reason = "the ratio needs only a few digits"
        )]
        let ratio = (stored - plain) as f64 / plain as f64;
        assert!(ratio < 0.001, "storage overhead grew to {ratio}");
    }
}
