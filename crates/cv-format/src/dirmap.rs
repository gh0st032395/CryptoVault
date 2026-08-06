//! Where a directory lives on disk.
//!
//! Vault directories are not nested on disk. Each one has a random identifier,
//! and its location is derived from the HMAC of that identifier:
//!
//! ```text
//! h    = HMAC-SHA256(K_mac, dir_id)
//! b32  = base32_nopad_uppercase(h)
//! path = "d/" ‖ b32[0..2] ‖ "/" ‖ b32[2..]
//! ```
//!
//! # What the flattening buys
//!
//! **Renaming a folder of ten thousand files rewrites one file.** The entry that
//! names a directory lives in its parent; the directory's own location depends
//! only on its identifier, which does not change. Move a folder across the
//! vault and nothing underneath it moves on disk.
//!
//! **Depth is invisible.** Everything is exactly two levels below `d/`, so an
//! observer cannot see how deeply the user nests their folders — only how many
//! directories there are.
//!
//! **HMAC, not a plain hash.** Without the key, `dir_id` values could be
//! confirmed by guessing: compute the hash of a candidate and look for it. With
//! `K_mac` in the construction, that is not available to anyone who cannot
//! already decrypt the vault.
//!
//! # The shard
//!
//! Two base32 characters, so 1024 shard directories. Without them a vault with
//! tens of thousands of entries would put tens of thousands of children in one
//! directory, which is slow on NTFS and upsets several sync clients.

use cv_crypto::secret::Key32;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::FormatError;
use crate::consts::{DIR_ID_LEN, DIR_SHARD_LEN};

/// Directory under the vault root that holds all content.
pub const CONTENT_ROOT: &str = "d";

/// A directory's random identifier.
pub type DirId = [u8; DIR_ID_LEN as usize];

/// The identifier of the vault root directory.
///
/// The root is the one directory whose identifier is not random — something has
/// to be the starting point. It is the vault identifier rather than a constant,
/// so that the root of two different vaults does not sit at the same relative
/// path. That would tell an observer comparing two vaults nothing very useful,
/// but it costs nothing to avoid.
#[must_use]
pub const fn root_dir_id(vault_id: DirId) -> DirId {
    vault_id
}

/// The path of a directory relative to the vault root, as `d/AB/CDEF…`.
///
/// Always uses `/` as the separator: this is a vault-relative path, and the
/// caller joins it onto a real one.
///
/// # Errors
///
/// Returns [`FormatError::WrongDirIdLength`] if `dir_id` is the wrong size.
pub fn dir_path(mac_key: &Key32, dir_id: &[u8]) -> Result<String, FormatError> {
    if dir_id.len() != DIR_ID_LEN as usize {
        return Err(FormatError::WrongDirIdLength {
            expected: DIR_ID_LEN as usize,
            found: dir_id.len(),
        });
    }

    let mut mac = <Hmac<Sha256>>::new_from_slice(mac_key.expose()).map_err(|_| {
        FormatError::WrongDirIdLength {
            expected: 32,
            found: mac_key.len(),
        }
    })?;
    mac.update(dir_id);
    let digest = mac.finalize().into_bytes();

    let encoded = BASE32_NOPAD.encode(&digest);
    let (shard, rest) = encoded.split_at(DIR_SHARD_LEN as usize);

    Ok(format!("{CONTENT_ROOT}/{shard}/{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn mac_key() -> Key32 {
        Key32::new([0x4D; 32])
    }

    const DIR_A: DirId = [0xA0; 16];
    const DIR_B: DirId = [0xA1; 16];

    #[test]
    fn a_path_has_the_documented_shape() {
        let path = dir_path(&mac_key(), &DIR_A).unwrap();
        let parts: Vec<&str> = path.split('/').collect();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], CONTENT_ROOT);
        assert_eq!(parts[1].len(), DIR_SHARD_LEN as usize);
        // SHA-256 is 32 bytes, which is 52 base32 characters without padding.
        assert_eq!(parts[1].len() + parts[2].len(), 52);
    }

    #[test]
    fn a_path_uses_only_characters_every_filesystem_accepts() {
        let path = dir_path(&mac_key(), &DIR_A).unwrap();
        // The first segment is the literal content root; the two derived
        // segments are base32, whose alphabet is A-Z and 2-7.
        for segment in path.split('/').skip(1) {
            assert!(
                segment
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "unexpected characters in {segment} of {path}"
            );
        }
    }

    #[test]
    fn the_same_identifier_always_maps_to_the_same_place() {
        assert_eq!(
            dir_path(&mac_key(), &DIR_A).unwrap(),
            dir_path(&mac_key(), &DIR_A).unwrap()
        );
    }

    #[test]
    fn different_identifiers_map_elsewhere() {
        assert_ne!(
            dir_path(&mac_key(), &DIR_A).unwrap(),
            dir_path(&mac_key(), &DIR_B).unwrap()
        );
    }

    /// A plain hash would let anyone confirm a guessed identifier. Keying the
    /// construction means the mapping is only computable by someone who could
    /// already read the vault.
    #[test]
    fn the_mapping_depends_on_the_key() {
        let other = Key32::new([0x4E; 32]);
        assert_ne!(
            dir_path(&mac_key(), &DIR_A).unwrap(),
            dir_path(&other, &DIR_A).unwrap()
        );
    }

    #[test]
    fn the_identifier_does_not_appear_in_the_path() {
        let path = dir_path(&mac_key(), &DIR_A).unwrap();
        let hex = DIR_A.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02X}");
            acc
        });
        assert!(!path.contains(&hex));
    }

    #[test]
    fn a_wrong_length_identifier_is_refused() {
        for len in [0_usize, 8, 15, 17, 32] {
            assert!(matches!(
                dir_path(&mac_key(), &vec![0_u8; len]),
                Err(FormatError::WrongDirIdLength { .. })
            ));
        }
    }

    #[test]
    fn the_root_identifier_is_the_vault_identifier() {
        let vault_id: DirId = [0x77; 16];
        assert_eq!(root_dir_id(vault_id), vault_id);
        // …so two vaults do not put their root in the same relative place.
        assert_ne!(
            dir_path(&mac_key(), &root_dir_id([0x77; 16])).unwrap(),
            dir_path(&mac_key(), &root_dir_id([0x88; 16])).unwrap()
        );
    }

    /// The shard exists to keep any one directory from collecting tens of
    /// thousands of children. It only does that if it actually spreads.
    #[test]
    fn the_shard_spreads_directories_across_many_buckets() {
        let shards: HashSet<String> = (0..1000_u32)
            .map(|i| {
                let mut dir_id = [0_u8; 16];
                dir_id[..4].copy_from_slice(&i.to_le_bytes());
                let path = dir_path(&mac_key(), &dir_id).unwrap();
                path.split('/').nth(1).unwrap().to_owned()
            })
            .collect();

        // 1000 directories over 1024 possible shards: collisions are expected,
        // clustering is not. Anything under a few hundred buckets would mean the
        // shard is not doing its job.
        assert!(
            shards.len() > 500,
            "1000 directories landed in only {} shards",
            shards.len()
        );
    }

    /// Two levels deep, always. This is what hides how the user nests folders.
    #[test]
    fn every_directory_sits_at_the_same_depth() {
        for seed in 0..50_u8 {
            let path = dir_path(&mac_key(), &[seed; 16]).unwrap();
            assert_eq!(
                path.matches('/').count(),
                2,
                "{path} is not two levels deep"
            );
        }
    }
}
