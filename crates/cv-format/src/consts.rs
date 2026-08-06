//! Constants that define the on-disk layout.
//!
//! Changing any value here changes the format. That is not forbidden, but it is
//! a decision with consequences: from milestone M1 onwards the frozen test
//! vectors in `tests/vectors/` will fail loudly, which is exactly the point. A
//! format change must be deliberate, versioned and accompanied by a migration.

/// Magic bytes at the start of every encrypted file: `CVF1`.
pub const FILE_MAGIC: [u8; 4] = *b"CVF1";

/// Highest format version this build can read and write.
pub const FORMAT_VERSION: u8 = 1;

/// Plaintext bytes carried by one chunk: 32 KiB.
///
/// The chunk size sets the cost of a small random read (you always decrypt a
/// whole chunk) against per-chunk overhead and sequential throughput. At 32 KiB
/// the overhead is 0.085% and reading four kilobytes out of a multi-gigabyte
/// file costs one chunk, not the whole file. Larger chunks would compress the
/// overhead further but make small in-place edits more expensive.
pub const CHUNK_PLAINTEXT_LEN: u32 = 32 * 1024;

/// AEAD nonce length in bytes (96 bits, the standard size for AES-GCM).
pub const NONCE_LEN: u32 = 12;

/// AEAD authentication tag length in bytes (128 bits).
pub const TAG_LEN: u32 = 16;

/// Length of the random, immutable per-file identifier.
///
/// It is stored in cleartext but covered by the header's authentication tag, and
/// it is what binds every chunk to its own file. Being random, it reveals
/// nothing; being immutable, it survives metadata edits that re-seal the header.
pub const FILE_ID_LEN: u32 = 16;

/// Length of a per-file content key in bytes (256 bits).
pub const FILE_KEY_LEN: u32 = 32;

/// Length of the vault master seed in bytes (256 bits).
pub const MASTER_SEED_LEN: u32 = 32;

/// Length of a directory identifier, in bytes.
pub const DIR_ID_LEN: u32 = 16;

/// Bytes of the authenticated header prefix **excluding the nonce**: magic,
/// version, algorithm, mode, reserved, file id and metadata length.
///
/// The nonce is not counted here because its length depends on the algorithm —
/// 12 bytes for AES-GCM, 24 for XChaCha20-Poly1305. Use
/// [`crate::chunk::header_prefix_len`] for the total.
pub const HEADER_FIXED_PREFIX_LEN: u32 = 4 + 1 + 1 + 1 + 1 + FILE_ID_LEN + 4;

/// Fixed part of the sealed header payload: the file key and the plaintext size.
/// Variable-length metadata follows it inside the same sealed block.
pub const HEADER_SEALED_FIXED_LEN: u32 = FILE_KEY_LEN + 8;

/// Largest metadata block accepted in a file header, in bytes (64 KiB).
///
/// Metadata holds timestamps, permissions, tags and a user note. The ceiling
/// keeps a corrupted or hostile length field from making the reader allocate
/// wildly before it has authenticated anything.
pub const MAX_METADATA_LEN: u32 = 64 * 1024;

/// Storage overhead added to every chunk: its nonce and its tag.
pub const CHUNK_OVERHEAD: u32 = NONCE_LEN + TAG_LEN;

/// Total on-disk size of a full chunk.
pub const CHUNK_STORED_LEN: u32 = CHUNK_PLAINTEXT_LEN + CHUNK_OVERHEAD;

/// Maximum length in bytes of an encrypted filename before it is spilled into a
/// side file.
///
/// Encrypted names are base64url text and must survive every filesystem we
/// target. Windows caps a path component at 255 UTF-16 units, and several sync
/// clients are unhappier still, so names longer than this are stored in a `.cvn`
/// companion file instead.
pub const MAX_ENCRYPTED_NAME_LEN: u32 = 220;

/// Number of leading characters of a directory hash used as a shard directory.
///
/// Without sharding, a vault with tens of thousands of files would put tens of
/// thousands of entries in one directory, which degrades on NTFS and upsets
/// several sync clients. Two base32 characters give 1024 shards.
pub const DIR_SHARD_LEN: u32 = 2;

/// File extension for an encrypted file.
pub const EXT_FILE: &str = "cvf";

/// File extension for an encrypted directory reference.
pub const EXT_DIR: &str = "cvd";

/// File extension for a spilled long name.
pub const EXT_NAME: &str = "cvn";

/// Name of the vault configuration file, the only file with a fixed name.
pub const VAULT_CONFIG_NAME: &str = "vault.cvconf";

// --- Compile-time invariants ---------------------------------------------
//
// These are properties of the format itself rather than behaviour, so they are
// checked when the crate is compiled instead of when the tests are run. A change
// that breaks one of them does not fail a test: it fails to build, which is the
// right amount of friction for altering an on-disk format.

const _: () = assert!(
    CHUNK_PLAINTEXT_LEN.is_power_of_two(),
    "the chunk size must be a power of two so that offset arithmetic stays exact"
);

const _: () = assert!(
    CHUNK_STORED_LEN == CHUNK_PLAINTEXT_LEN + NONCE_LEN + TAG_LEN,
    "a stored chunk is exactly its plaintext plus one nonce and one tag"
);

const _: () = assert!(
    // magic 4 + version 1 + alg_id 1 + mode 1 + reserved 1 + file_id 16
    // + meta_len 4 = 28, with the algorithm's nonce added on top
    HEADER_FIXED_PREFIX_LEN == 28,
    "the fixed header prefix is 28 bytes; update FORMAT_SPEC.md before changing it"
);

const _: () = assert!(
    // file_key 32 + plain_size 8 = 40
    HEADER_SEALED_FIXED_LEN == 40,
    "the fixed part of the sealed header is 40 bytes; update FORMAT_SPEC.md before changing it"
);

const _: () = assert!(
    MAX_ENCRYPTED_NAME_LEN < 255,
    "an encrypted name must fit in a single path component on every target filesystem"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_four_printable_bytes() {
        assert_eq!(&FILE_MAGIC, b"CVF1");
        assert!(FILE_MAGIC.iter().all(u8::is_ascii_graphic));
    }

    #[test]
    fn chunk_overhead_stays_under_one_tenth_of_a_percent() {
        let ratio = f64::from(CHUNK_OVERHEAD) / f64::from(CHUNK_PLAINTEXT_LEN);
        assert!(ratio < 0.001, "chunk overhead grew to {ratio}");
    }

    #[test]
    fn extensions_are_distinct() {
        assert_ne!(EXT_FILE, EXT_DIR);
        assert_ne!(EXT_FILE, EXT_NAME);
        assert_ne!(EXT_DIR, EXT_NAME);
    }
}
