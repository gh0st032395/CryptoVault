//! Writing a file so that no reader ever sees it half-written.
//!
//! Every `.cvf`, `.cvd`, `.cvn` and `vault.cvconf` goes through here. The
//! sequence is always the same:
//!
//! 1. Write to a temporary file **in the same directory** as the target.
//! 2. `fsync` it, so the contents reach the disk before anything points at them.
//! 3. `rename` over the target, which is atomic within a filesystem.
//! 4. `fsync` the directory, so the rename itself survives a power cut.
//!
//! # Why the temporary must share the directory
//!
//! `rename` is only atomic within one filesystem. A temporary in `/tmp` may well
//! be on a different one, in which case the rename silently degrades into a
//! copy-then-delete — which is exactly the non-atomic write this exists to
//! avoid. Same directory, always.
//!
//! # Why this matters more here than in most programs
//!
//! A vault is expected to live inside a folder that Dropbox, iCloud or OneDrive
//! is watching. A sync client that observes a half-written file does not wait to
//! see whether more is coming: it uploads what is there. Later readers then get
//! a file that is the right length, has a valid header, and fails
//! authentication in the middle — which looks to a user exactly like corruption.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::VaultError;

/// Writes `contents` to `path`, atomically.
///
/// Creates the parent directory if it does not exist, since a vault's shard
/// directories are made on demand.
///
/// # Errors
///
/// Returns [`VaultError::Io`] if any step fails. On failure the temporary file
/// is removed and the target is left exactly as it was.
pub fn write(path: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let parent = path.parent().ok_or_else(|| VaultError::Corrupt {
        reason: "a vault path with no parent directory".to_owned(),
    })?;

    fs::create_dir_all(parent)
        .map_err(|source| VaultError::io_ref("creating a directory", &source))?;

    let temporary = temporary_path(path)?;

    // Anything after this point that fails must not leave the temporary behind.
    let result = write_and_sync(&temporary, contents);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return result;
    }

    fs::rename(&temporary, path).map_err(|source| {
        let _ = fs::remove_file(&temporary);
        VaultError::io_ref("renaming a temporary file into place", &source)
    })?;

    sync_directory(parent);
    Ok(())
}

/// Removes a file, treating "it was not there" as success.
///
/// A vault operation that has to delete two files — an entry and its long-name
/// companion — must not fail because a previous interrupted run already removed
/// one of them.
///
/// # Errors
///
/// Returns [`VaultError::Io`] for any failure other than the file being absent.
pub fn remove(path: &Path) -> Result<(), VaultError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(VaultError::io_ref("removing a file", &source)),
    }
}

fn write_and_sync(temporary: &Path, contents: &[u8]) -> Result<(), VaultError> {
    let mut file = File::create(temporary)
        .map_err(|source| VaultError::io_ref("creating a temporary file", &source))?;
    file.write_all(contents)
        .map_err(|source| VaultError::io_ref("writing a temporary file", &source))?;
    file.sync_all()
        .map_err(|source| VaultError::io_ref("flushing a temporary file", &source))?;
    Ok(())
}

/// Flushes the directory entry so the rename itself survives a power cut.
///
/// Best-effort on purpose. It is not supported everywhere — Windows in
/// particular has no equivalent — and a vault that refused to write on those
/// platforms would be worse than one whose renames are merely very likely to be
/// durable. The write itself is already synced; this only hardens the last step.
fn sync_directory(directory: &Path) {
    if let Ok(handle) = File::open(directory) {
        let _ = handle.sync_all();
    }
}

/// A unique temporary name beside the target.
///
/// Random rather than sequential: two processes writing the same vault must not
/// pick the same temporary, and a leftover from a crashed run must not be
/// mistaken for a fresh one.
fn temporary_path(path: &Path) -> Result<std::path::PathBuf, VaultError> {
    let suffix: [u8; 8] = cv_crypto::random::array()?;
    let hex = suffix.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    });

    let name = path.file_name().ok_or_else(|| VaultError::Corrupt {
        reason: "a vault path with no file name".to_owned(),
    })?;

    let mut temporary = name.to_os_string();
    temporary.push(format!(".{hex}.tmp"));

    Ok(path.with_file_name(temporary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writing_creates_the_file_and_its_parents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/file.bin");

        write(&path, b"contents").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"contents");
    }

    #[test]
    fn writing_replaces_an_existing_file_completely() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");

        write(&path, b"the original, which is longer").unwrap();
        write(&path, b"short").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"short");
    }

    /// The temporary must not survive the write. A vault directory littered with
    /// `.tmp` files would confuse both the user and the sync client.
    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("file.bin"), b"contents").unwrap();

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| crate::is_temporary(name))
            .collect();

        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    /// Same filesystem, or the rename is not atomic. Checking the temporary is a
    /// sibling is the closest a test can get to that guarantee.
    #[test]
    fn the_temporary_is_a_sibling_of_the_target() {
        let target = Path::new("/some/vault/d/AB/CDEF/entry.cvf");
        let temporary = temporary_path(target).unwrap();
        assert_eq!(temporary.parent(), target.parent());
        assert!(temporary.to_string_lossy().ends_with(".tmp"));
    }

    #[test]
    fn temporary_names_do_not_repeat() {
        let target = Path::new("/vault/entry.cvf");
        let first = temporary_path(target).unwrap();
        let second = temporary_path(target).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn an_empty_file_can_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        write(&path, b"").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn removing_a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        remove(&dir.path().join("never-existed")).unwrap();
    }

    #[test]
    fn removing_an_existing_file_works() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write(&path, b"x").unwrap();

        remove(&path).unwrap();
        assert!(!path.exists());
        // …and doing it twice is still fine.
        remove(&path).unwrap();
    }
}
