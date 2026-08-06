//! Turning a name in the vault into a name on the disk.
//!
//! ```text
//! ciphertext = AES-SIV(K_names, aad = dir_id, name)     (cv-crypto::siv)
//! stem       = base64url_nopad(ciphertext)
//! on disk    = "<stem>.cvf"   for a file
//!              "<stem>.cvd"   for a directory
//! ```
//!
//! # Long names
//!
//! A stem longer than 220 characters would not survive every filesystem and sync
//! client we target, so it spills: the stem becomes a hash of the ciphertext, and
//! the full encrypted name is written alongside in a `.cvn` companion.
//!
//! ```text
//! stem    = base64url_nopad(SHA-256(ciphertext))[..32]
//! on disk = "<stem>.cvf"   the entry
//!           "<stem>.cvn"   the full encrypted name
//! ```
//!
//! Reading a spilled entry costs one extra file read. Nothing else changes, and
//! in particular the name is no less encrypted — the `.cvn` holds the same
//! ciphertext that would otherwise have been the filename.
//!
//! # Why host filesystem rules do not apply
//!
//! What reaches the disk is base64url of a ciphertext: 64 characters, all of
//! them safe everywhere. So the user is free to name a file `CON`, `report:
//! Q1*.txt`, or `trailing dot.` — names Windows would refuse — and it works on
//! every platform. That is a real feature, not a side effect worth hiding.

// Our extensions are produced by this module and are always lowercase ASCII.
// A case-insensitive match would be wrong, not lenient: a file called `X.CVF`
// was not written by CryptoVault and must not be read as though it were.
#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "extensions are ours and always lowercase; matching case-insensitively would be wrong"
)]

use cv_crypto::secret::Key32;
use cv_crypto::siv;
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::FormatError;
use crate::consts::{DIR_ID_LEN, EXT_DIR, EXT_FILE, EXT_NAME, MAX_ENCRYPTED_NAME_LEN};

/// Characters of the hash kept when a name spills.
///
/// 32 base64url characters carry 192 bits, so an accidental collision between
/// two long names in one directory is not something that happens.
const SPILLED_STEM_LEN: usize = 32;

/// What kind of entry a name refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A file: stored as `<stem>.cvf`.
    File,
    /// A directory: stored as `<stem>.cvd`.
    Directory,
}

impl EntryKind {
    /// The extension entries of this kind carry on disk.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::File => EXT_FILE,
            Self::Directory => EXT_DIR,
        }
    }
}

/// Where an entry lives on disk, and whether its name had to spill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredName {
    /// Filename of the entry itself, extension included.
    pub file_name: String,
    /// Present when the name spilled: the `.cvn` companion to write beside the
    /// entry, and the encrypted name to put in it.
    pub companion: Option<Companion>,
}

/// The `.cvn` file written beside an entry whose name was too long to be one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Companion {
    /// Name of the companion file.
    pub file_name: String,
    /// Its contents: the full encrypted name.
    pub contents: Vec<u8>,
}

/// Encrypts `name` and works out where the entry goes on disk.
///
/// # Errors
///
/// - [`FormatError::InvalidName`] if the name is empty, is `.` or `..`, or
///   contains a separator or a NUL. Those cannot address anything in a vault,
///   and refusing them here is the second of the two defences against traversal
///   — the first being that a decrypted name is never joined onto a host path.
/// - [`FormatError::WrongDirIdLength`] if `dir_id` is the wrong size.
/// - A wrapped [`cv_crypto::CryptoError`] if encryption fails.
pub fn encode(
    names_key: &Key32,
    dir_id: &[u8],
    name: &str,
    kind: EntryKind,
) -> Result<StoredName, FormatError> {
    check_dir_id(dir_id)?;
    check_name(name)?;

    let ciphertext = siv::seal(names_key, dir_id, name.as_bytes())?;
    let stem = BASE64URL_NOPAD.encode(&ciphertext);

    if stem.len() <= MAX_ENCRYPTED_NAME_LEN as usize {
        return Ok(StoredName {
            file_name: format!("{stem}.{}", kind.extension()),
            companion: None,
        });
    }

    let hashed = BASE64URL_NOPAD.encode(&Sha256::digest(&ciphertext));
    let short = &hashed[..SPILLED_STEM_LEN];

    Ok(StoredName {
        file_name: format!("{short}.{}", kind.extension()),
        companion: Some(Companion {
            file_name: format!("{short}.{EXT_NAME}"),
            contents: ciphertext,
        }),
    })
}

/// Recovers a name from the ciphertext that encoded it.
///
/// `ciphertext` comes either from decoding an inline stem with
/// [`decode_stem`] or from reading a `.cvn` companion.
///
/// # Errors
///
/// - A wrapped [`cv_crypto::CryptoError::DecryptionFailed`] if the name does not
///   authenticate under this key and this directory.
/// - [`FormatError::InvalidName`] if the decrypted bytes are not valid UTF-8, or
///   are a name a vault cannot hold. Both are checked *after* authentication, so
///   they mean corruption or a bug rather than an attack.
pub fn decode(names_key: &Key32, dir_id: &[u8], ciphertext: &[u8]) -> Result<String, FormatError> {
    check_dir_id(dir_id)?;

    let plaintext = siv::open(names_key, dir_id, ciphertext)?;
    let name = String::from_utf8(plaintext).map_err(|_| FormatError::InvalidName {
        reason: "the decrypted name is not UTF-8",
    })?;

    // Belt and braces. An attacker cannot produce a name that authenticates, so
    // reaching this means our own writer produced something it should not have.
    check_name(&name)?;
    Ok(name)
}

/// Decodes an inline on-disk stem back to ciphertext.
///
/// # Errors
///
/// Returns [`FormatError::InvalidName`] if the stem is not valid base64url.
pub fn decode_stem(stem: &str) -> Result<Vec<u8>, FormatError> {
    BASE64URL_NOPAD
        .decode(stem.as_bytes())
        .map_err(|_| FormatError::InvalidName {
            reason: "the on-disk name is not valid base64url",
        })
}

/// Splits an on-disk filename into its stem and extension.
///
/// Returns [`None`] if the filename has no extension we recognise.
#[must_use]
pub fn split_on_disk(file_name: &str) -> Option<(&str, EntryKind)> {
    for kind in [EntryKind::File, EntryKind::Directory] {
        let suffix = format!(".{}", kind.extension());
        if let Some(stem) = file_name.strip_suffix(&suffix) {
            return Some((stem, kind));
        }
    }
    None
}

/// Whether an on-disk name refers to a spilled long name rather than an entry.
#[must_use]
pub fn is_companion(file_name: &str) -> bool {
    file_name.ends_with(&format!(".{EXT_NAME}"))
}

fn check_dir_id(dir_id: &[u8]) -> Result<(), FormatError> {
    if dir_id.len() == DIR_ID_LEN as usize {
        Ok(())
    } else {
        Err(FormatError::WrongDirIdLength {
            expected: DIR_ID_LEN as usize,
            found: dir_id.len(),
        })
    }
}

fn check_name(name: &str) -> Result<(), FormatError> {
    let reject = |reason: &'static str| Err(FormatError::InvalidName { reason });

    if name.is_empty() {
        return reject("a name cannot be empty");
    }
    if name == "." || name == ".." {
        return reject("relative names cannot address anything in a vault");
    }
    if name.contains('/') {
        return reject("a name cannot contain a path separator");
    }
    if name.contains('\0') {
        return reject("a name cannot contain a NUL byte");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv_crypto::CryptoError;

    fn key() -> Key32 {
        Key32::new([0x2E; 32])
    }

    const DIR_A: [u8; 16] = [0xA0; 16];
    const DIR_B: [u8; 16] = [0xB0; 16];

    fn round_trip(name: &str) -> String {
        let stored = encode(&key(), &DIR_A, name, EntryKind::File).unwrap();
        let ciphertext = if let Some(companion) = &stored.companion {
            companion.contents.clone()
        } else {
            let (stem, _) = split_on_disk(&stored.file_name).unwrap();
            decode_stem(stem).unwrap()
        };
        decode(&key(), &DIR_A, &ciphertext).unwrap()
    }

    #[test]
    fn a_name_round_trips() {
        assert_eq!(round_trip("invoice.pdf"), "invoice.pdf");
    }

    #[test]
    fn the_on_disk_name_carries_the_right_extension() {
        let file = encode(&key(), &DIR_A, "x", EntryKind::File).unwrap();
        let dir = encode(&key(), &DIR_A, "x", EntryKind::Directory).unwrap();

        assert!(file.file_name.ends_with(".cvf"));
        assert!(dir.file_name.ends_with(".cvd"));
        assert_eq!(split_on_disk(&file.file_name).unwrap().1, EntryKind::File);
        assert_eq!(
            split_on_disk(&dir.file_name).unwrap().1,
            EntryKind::Directory
        );
    }

    #[test]
    fn the_plaintext_name_is_nowhere_in_the_on_disk_name() {
        let stored = encode(&key(), &DIR_A, "very-distinctive", EntryKind::File).unwrap();
        assert!(!stored.file_name.contains("very-distinctive"));
    }

    #[test]
    fn encoding_is_stable_so_a_lookup_needs_no_directory_scan() {
        let first = encode(&key(), &DIR_A, "invoice.pdf", EntryKind::File).unwrap();
        let second = encode(&key(), &DIR_A, "invoice.pdf", EntryKind::File).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_same_name_lands_elsewhere_in_another_directory() {
        let in_a = encode(&key(), &DIR_A, "invoice.pdf", EntryKind::File).unwrap();
        let in_b = encode(&key(), &DIR_B, "invoice.pdf", EntryKind::File).unwrap();
        assert_ne!(in_a.file_name, in_b.file_name);
    }

    /// The name of the feature: a vault is not bound by the host filesystem's
    /// naming rules, because none of the user's characters reach the disk.
    #[test]
    fn names_the_host_filesystem_would_refuse_work_anyway() {
        for name in [
            "CON",
            "NUL",
            "report: Q1*.txt",
            "why?.md",
            "trailing space ",
            "trailing dot.",
            "back\\slash",
            "emoji 🔐 name",
            "ファイル.txt",
        ] {
            assert_eq!(round_trip(name), name, "{name:?} did not survive");

            let stored = encode(&key(), &DIR_A, name, EntryKind::File).unwrap();
            assert!(
                stored
                    .file_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
                "{name:?} produced an unsafe on-disk name: {}",
                stored.file_name
            );
        }
    }

    #[test]
    fn names_that_cannot_address_anything_are_refused() {
        for name in ["", ".", "..", "a/b", "a\0b"] {
            assert!(
                matches!(
                    encode(&key(), &DIR_A, name, EntryKind::File),
                    Err(FormatError::InvalidName { .. })
                ),
                "{name:?} was accepted"
            );
        }
    }

    #[test]
    fn a_short_name_stays_inline() {
        let stored = encode(&key(), &DIR_A, "short.txt", EntryKind::File).unwrap();
        assert!(stored.companion.is_none());
        assert!(stored.file_name.len() <= MAX_ENCRYPTED_NAME_LEN as usize + 4);
    }

    #[test]
    fn a_long_name_spills_into_a_companion() {
        let long = "x".repeat(250);
        let stored = encode(&key(), &DIR_A, &long, EntryKind::File).unwrap();

        let companion = stored
            .companion
            .as_ref()
            .expect("a 250-character name should spill");
        assert!(companion.file_name.ends_with(".cvn"));
        assert!(is_companion(&companion.file_name));
        // The entry and its companion share a stem, so finding one finds the other.
        assert_eq!(
            stored.file_name.trim_end_matches(".cvf"),
            companion.file_name.trim_end_matches(".cvn")
        );
        assert_eq!(decode(&key(), &DIR_A, &companion.contents).unwrap(), long);
    }

    #[test]
    fn a_spilled_name_stays_inside_a_path_component() {
        let stored = encode(&key(), &DIR_A, &"x".repeat(4096), EntryKind::File).unwrap();
        assert!(
            stored.file_name.len() < 64,
            "spilled name was {} chars",
            stored.file_name.len()
        );
    }

    /// The boundary between inline and spilled has to be crossed exactly once,
    /// and both sides of it have to work.
    #[test]
    fn the_spill_threshold_is_crossed_cleanly() {
        let mut saw_inline = false;
        let mut saw_spilled = false;

        for len in 1..=250 {
            let name = "a".repeat(len);
            let stored = encode(&key(), &DIR_A, &name, EntryKind::File).unwrap();
            let stem = stored.file_name.trim_end_matches(".cvf");

            if stored.companion.is_none() {
                saw_inline = true;
                assert!(
                    stem.len() <= MAX_ENCRYPTED_NAME_LEN as usize,
                    "inline stem too long"
                );
                assert_eq!(
                    decode(&key(), &DIR_A, &decode_stem(stem).unwrap()).unwrap(),
                    name
                );
            } else {
                saw_spilled = true;
            }
        }

        assert!(saw_inline && saw_spilled, "the threshold was never crossed");
    }

    #[test]
    fn the_wrong_key_or_directory_is_refused() {
        let stored = encode(&key(), &DIR_A, "invoice.pdf", EntryKind::File).unwrap();
        let ciphertext = decode_stem(stored.file_name.trim_end_matches(".cvf")).unwrap();

        assert_eq!(
            decode(&Key32::new([0x2F; 32]), &DIR_A, &ciphertext),
            Err(FormatError::Crypto(CryptoError::DecryptionFailed))
        );
        assert_eq!(
            decode(&key(), &DIR_B, &ciphertext),
            Err(FormatError::Crypto(CryptoError::DecryptionFailed))
        );
    }

    #[test]
    fn a_directory_identifier_of_the_wrong_length_is_refused() {
        for len in [0_usize, 8, 15, 17] {
            assert!(matches!(
                encode(&key(), &vec![0_u8; len], "x", EntryKind::File),
                Err(FormatError::WrongDirIdLength { .. })
            ));
        }
    }

    #[test]
    fn rubbish_stems_are_refused_rather_than_panicking() {
        for stem in ["not base64!!", "  ", "===="] {
            assert!(matches!(
                decode_stem(stem),
                Err(FormatError::InvalidName { .. })
            ));
        }
    }

    #[test]
    fn unrecognised_on_disk_names_are_not_mistaken_for_entries() {
        assert!(split_on_disk("vault.cvconf").is_none());
        assert!(split_on_disk("abc.cvn").is_none());
        assert!(split_on_disk("no-extension").is_none());
        assert!(is_companion("abc.cvn"));
        assert!(!is_companion("abc.cvf"));
    }
}
