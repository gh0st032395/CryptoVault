//! The filesystem interface, and the one implementation version 1 has.
//!
//! [`VaultFs`] is the boundary every consumer sits behind: the CLI today, the
//! desktop interface next, a mounted drive in milestone M14. `DirectVaultFs`
//! implements it straight on top of [`cv_vault`].
//!
//! # Why the interface is offset-based
//!
//! `read_at`, `write_at`, `truncate` — not "give me the file" and "here is a new
//! one". That is the vocabulary FUSE and WinFsp speak, and an interface built
//! the other way cannot be adapted to them, only replaced. Designing it this way
//! on the day the first implementation is written is the difference between the
//! virtual mount being a milestone and the virtual mount being a rewrite.
//!
//! # Paths, not handles — for now
//!
//! Every operation takes a [`VPath`] and resolves it, which costs one directory
//! lookup per component. For a command-line tool and a file browser that is
//! nothing; for a mount servicing four-kilobyte reads it would be wasteful, and
//! M14 will add an open/close handle pair.
//!
//! That is an addition, not a change: handles would cache the resolution, and
//! the shape of the read and write operations — which is the part that had to be
//! right from the start — stays exactly as it is.

use cv_format::dirmap::DirId;
use cv_format::names::EntryKind;
use cv_vault::{Stat, Vault, VaultError};

use crate::{VPath, VfsError};

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's name, decrypted.
    pub name: String,
    /// Whether it is a file or a directory.
    pub kind: EntryKind,
}

/// A filesystem over a vault.
///
/// Deliberately narrow. Everything a consumer needs is here, and nothing here
/// exposes how the vault stores anything.
pub trait VaultFs {
    /// What is at `path`.
    ///
    /// # Errors
    ///
    /// [`VfsError::NotFound`] if nothing is, or a wrapped vault error.
    fn stat(&self, path: &VPath) -> Result<Stat, VfsError>;

    /// Lists a directory.
    ///
    /// # Errors
    ///
    /// [`VfsError::NotFound`] or [`VfsError::NotADirectory`].
    fn read_dir(&self, path: &VPath) -> Result<Vec<DirEntry>, VfsError>;

    /// Creates a directory. The parent must exist.
    ///
    /// # Errors
    ///
    /// [`VfsError::IsRoot`] for the root itself, [`VfsError::AlreadyExists`],
    /// or a wrapped vault error.
    fn create_dir(&self, path: &VPath) -> Result<(), VfsError>;

    /// Creates every missing directory along `path`.
    ///
    /// # Errors
    ///
    /// As [`VaultFs::create_dir`], except that an existing directory is not an
    /// error.
    fn create_dir_all(&self, path: &VPath) -> Result<(), VfsError>;

    /// Creates an empty file.
    ///
    /// # Errors
    ///
    /// [`VfsError::IsRoot`], [`VfsError::AlreadyExists`], or a wrapped vault
    /// error.
    fn create_file(&self, path: &VPath) -> Result<(), VfsError>;

    /// Reads into `buf` from a plaintext offset.
    ///
    /// Returns how many bytes were read: short at the end of the file, zero
    /// past it.
    ///
    /// # Errors
    ///
    /// [`VfsError::NotFound`], [`VfsError::IsADirectory`], or a wrapped vault
    /// error.
    fn read_at(&self, path: &VPath, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;

    /// Writes at a plaintext offset, extending the file if needed.
    ///
    /// # Errors
    ///
    /// As [`VaultFs::read_at`].
    fn write_at(&self, path: &VPath, offset: u64, data: &[u8]) -> Result<(), VfsError>;

    /// Sets a file's length.
    ///
    /// # Errors
    ///
    /// As [`VaultFs::read_at`].
    fn truncate(&self, path: &VPath, size: u64) -> Result<(), VfsError>;

    /// Moves or renames an entry.
    ///
    /// # Errors
    ///
    /// [`VfsError::NotFound`], [`VfsError::AlreadyExists`],
    /// [`VfsError::WouldRecurse`] for a directory moved into itself.
    fn rename(&self, from: &VPath, to: &VPath) -> Result<(), VfsError>;

    /// Removes an entry. A directory must be empty.
    ///
    /// # Errors
    ///
    /// [`VfsError::NotFound`], [`VfsError::IsRoot`], or a wrapped vault error.
    fn remove(&self, path: &VPath) -> Result<(), VfsError>;
}

/// [`VaultFs`] implemented directly on an unlocked vault.
#[derive(Debug)]
pub struct DirectVaultFs {
    vault: Vault,
}

impl DirectVaultFs {
    /// Wraps an unlocked vault.
    #[must_use]
    pub const fn new(vault: Vault) -> Self {
        Self { vault }
    }

    /// The vault underneath.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Resolves a path to the directory it names.
    ///
    /// Walks one component at a time from the root. No decrypted name is ever
    /// joined onto a host path along the way: each step is a lookup keyed by the
    /// parent's identifier.
    ///
    /// # Errors
    ///
    /// [`VfsError::NotFound`] or [`VfsError::NotADirectory`].
    pub fn resolve_dir(&self, path: &VPath) -> Result<DirId, VfsError> {
        let mut current = self.vault.root_dir();
        for component in path.components() {
            current = self
                .vault
                .dir_id_of(current, component)
                .map_err(|error| match error {
                    VaultError::NotFound { .. } => VfsError::NotFound {
                        path: path.to_string(),
                    },
                    VaultError::WrongKind { .. } => VfsError::NotADirectory {
                        path: path.to_string(),
                    },
                    other => VfsError::Vault(other),
                })?;
        }
        Ok(current)
    }

    /// Splits a path into the directory holding it and the final name.
    fn split(&self, path: &VPath) -> Result<(DirId, String), VfsError> {
        let parent = path.parent().ok_or(VfsError::IsRoot)?;
        let name = path.file_name().ok_or(VfsError::IsRoot)?.to_owned();
        Ok((self.resolve_dir(&parent)?, name))
    }

    /// Maps a vault error to a path-aware filesystem error.
    fn contextualise(error: VaultError, path: &VPath) -> VfsError {
        match error {
            VaultError::NotFound { .. } => VfsError::NotFound {
                path: path.to_string(),
            },
            VaultError::AlreadyExists { .. } => VfsError::AlreadyExists {
                path: path.to_string(),
            },
            VaultError::WrongKind {
                expected: "file", ..
            } => VfsError::IsADirectory {
                path: path.to_string(),
            },
            VaultError::WrongKind { .. } => VfsError::NotADirectory {
                path: path.to_string(),
            },
            other => VfsError::Vault(other),
        }
    }
}

impl VaultFs for DirectVaultFs {
    fn stat(&self, path: &VPath) -> Result<Stat, VfsError> {
        if path.is_root() {
            return Ok(Stat {
                kind: EntryKind::Directory,
                size: 0,
                metadata: cv_format::FileMetadata::default(),
            });
        }

        let (dir, name) = self.split(path)?;
        self.vault
            .stat(dir, &name)
            .map_err(|error| Self::contextualise(error, path))
    }

    fn read_dir(&self, path: &VPath) -> Result<Vec<DirEntry>, VfsError> {
        let dir = self.resolve_dir(path)?;
        Ok(self
            .vault
            .read_dir(dir)?
            .into_iter()
            .map(|entry| DirEntry {
                name: entry.name,
                kind: entry.kind,
            })
            .collect())
    }

    fn create_dir(&self, path: &VPath) -> Result<(), VfsError> {
        let (parent, name) = self.split(path)?;
        self.vault
            .create_dir(parent, &name)
            .map(|_| ())
            .map_err(|error| Self::contextualise(error, path))
    }

    fn create_dir_all(&self, path: &VPath) -> Result<(), VfsError> {
        let mut current = self.vault.root_dir();
        for component in path.components() {
            current = match self.vault.lookup(current, component)? {
                Some(EntryKind::Directory) => self.vault.dir_id_of(current, component)?,
                Some(EntryKind::File) => {
                    return Err(VfsError::NotADirectory {
                        path: path.to_string(),
                    });
                }
                None => self.vault.create_dir(current, component)?,
            };
        }
        Ok(())
    }

    fn create_file(&self, path: &VPath) -> Result<(), VfsError> {
        let (dir, name) = self.split(path)?;
        self.vault
            .create_file(dir, &name, cv_format::FileMetadata::default())
            .map(|_| ())
            .map_err(|error| Self::contextualise(error, path))
    }

    fn read_at(&self, path: &VPath, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        let (dir, name) = self.split(path)?;
        let mut file = self
            .vault
            .open_file(dir, &name, false)
            .map_err(|error| Self::contextualise(error, path))?;
        Ok(file.read_at(offset, buf)?)
    }

    fn write_at(&self, path: &VPath, offset: u64, data: &[u8]) -> Result<(), VfsError> {
        let (dir, name) = self.split(path)?;
        let mut file = self
            .vault
            .open_file(dir, &name, true)
            .map_err(|error| Self::contextualise(error, path))?;
        file.write_at(offset, data)?;
        Ok(file.flush()?)
    }

    fn truncate(&self, path: &VPath, size: u64) -> Result<(), VfsError> {
        let (dir, name) = self.split(path)?;
        let mut file = self
            .vault
            .open_file(dir, &name, true)
            .map_err(|error| Self::contextualise(error, path))?;
        file.truncate(size)?;
        Ok(file.flush()?)
    }

    fn rename(&self, from: &VPath, to: &VPath) -> Result<(), VfsError> {
        // Moving a directory inside itself would detach the whole subtree: the
        // parent reference that names it would end up underneath the directory
        // it names, so nothing could reach either again.
        if to.starts_with(from) {
            return Err(VfsError::WouldRecurse {
                from: from.to_string(),
                to: to.to_string(),
            });
        }

        let (from_dir, from_name) = self.split(from)?;
        let (to_dir, to_name) = self.split(to)?;

        self.vault
            .rename(from_dir, &from_name, to_dir, &to_name)
            .map_err(|error| Self::contextualise(error, to))
    }

    fn remove(&self, path: &VPath) -> Result<(), VfsError> {
        let (dir, name) = self.split(path)?;
        self.vault
            .remove(dir, &name)
            .map_err(|error| Self::contextualise(error, path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv_crypto::kdf::Argon2Params;
    use cv_vault::CreateOptions;

    struct Fixture {
        _dir: tempfile::TempDir,
        fs: DirectVaultFs,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let options = CreateOptions {
                params: Argon2Params::new(
                    Argon2Params::MIN_MEMORY_KIB,
                    Argon2Params::MIN_ITERATIONS,
                    Argon2Params::MIN_PARALLELISM,
                )
                .unwrap(),
                ..CreateOptions::default()
            };
            let vault = Vault::create(dir.path(), b"password", options).unwrap();
            Self {
                _dir: dir,
                fs: DirectVaultFs::new(vault),
            }
        }
    }

    fn p(text: &str) -> VPath {
        VPath::parse(text).unwrap()
    }

    fn write(fs: &DirectVaultFs, path: &str, contents: &[u8]) {
        fs.create_file(&p(path)).unwrap();
        fs.write_at(&p(path), 0, contents).unwrap();
    }

    fn read(fs: &DirectVaultFs, path: &str) -> Vec<u8> {
        let size = fs.stat(&p(path)).unwrap().size;
        let mut buf = vec![0_u8; usize::try_from(size).unwrap()];
        let read = fs.read_at(&p(path), 0, &mut buf).unwrap();
        buf.truncate(read);
        buf
    }

    #[test]
    fn the_root_exists_and_is_empty() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.fs.stat(&VPath::root()).unwrap().kind,
            EntryKind::Directory
        );
        assert!(fixture.fs.read_dir(&VPath::root()).unwrap().is_empty());
    }

    #[test]
    fn a_file_at_the_root_round_trips() {
        let fixture = Fixture::new();
        write(&fixture.fs, "/notes.txt", b"contents");

        assert_eq!(read(&fixture.fs, "/notes.txt"), b"contents");
        assert_eq!(fixture.fs.stat(&p("/notes.txt")).unwrap().size, 8);
    }

    /// The point of the layer: a path with several components resolves without
    /// the caller ever knowing about directory identifiers.
    #[test]
    fn a_nested_path_resolves() {
        let fixture = Fixture::new();
        fixture
            .fs
            .create_dir_all(&p("/Documents/2026/invoices"))
            .unwrap();
        write(
            &fixture.fs,
            "/Documents/2026/invoices/january.pdf",
            b"an invoice",
        );

        assert_eq!(
            read(&fixture.fs, "/Documents/2026/invoices/january.pdf"),
            b"an invoice"
        );
        assert_eq!(fixture.fs.read_dir(&p("/Documents/2026")).unwrap().len(), 1);
    }

    #[test]
    fn create_dir_all_is_idempotent() {
        let fixture = Fixture::new();
        fixture.fs.create_dir_all(&p("/a/b/c")).unwrap();
        fixture.fs.create_dir_all(&p("/a/b/c")).unwrap();
        fixture.fs.create_dir_all(&p("/a/b")).unwrap();

        assert_eq!(fixture.fs.read_dir(&p("/a/b")).unwrap().len(), 1);
    }

    #[test]
    fn create_dir_needs_its_parent_to_exist() {
        let fixture = Fixture::new();
        assert!(matches!(
            fixture.fs.create_dir(&p("/missing/child")),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn reading_and_writing_at_offsets_works_through_the_interface() {
        let fixture = Fixture::new();
        let data: Vec<u8> = (0..100_000)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();

        write(&fixture.fs, "/big.bin", &data);
        fixture
            .fs
            .write_at(&p("/big.bin"), 50_000, b"REPLACED")
            .unwrap();

        let mut buf = [0_u8; 8];
        assert_eq!(
            fixture
                .fs
                .read_at(&p("/big.bin"), 50_000, &mut buf)
                .unwrap(),
            8
        );
        assert_eq!(&buf, b"REPLACED");
        assert_eq!(fixture.fs.stat(&p("/big.bin")).unwrap().size, 100_000);
    }

    #[test]
    fn truncating_through_the_interface_works() {
        let fixture = Fixture::new();
        write(&fixture.fs, "/f.bin", &vec![7_u8; 50_000]);

        fixture.fs.truncate(&p("/f.bin"), 100).unwrap();
        assert_eq!(fixture.fs.stat(&p("/f.bin")).unwrap().size, 100);
        assert_eq!(read(&fixture.fs, "/f.bin"), vec![7_u8; 100]);
    }

    #[test]
    fn renaming_moves_between_directories() {
        let fixture = Fixture::new();
        fixture.fs.create_dir_all(&p("/a/b")).unwrap();
        write(&fixture.fs, "/a/file.txt", b"contents");

        fixture
            .fs
            .rename(&p("/a/file.txt"), &p("/a/b/moved.txt"))
            .unwrap();

        assert!(matches!(
            fixture.fs.stat(&p("/a/file.txt")),
            Err(VfsError::NotFound { .. })
        ));
        assert_eq!(read(&fixture.fs, "/a/b/moved.txt"), b"contents");
    }

    /// Moving a directory inside itself would put the reference that names it
    /// underneath the directory it names, and nothing could reach either again.
    #[test]
    fn a_directory_cannot_be_moved_into_itself() {
        let fixture = Fixture::new();
        fixture.fs.create_dir_all(&p("/a/b")).unwrap();

        assert!(matches!(
            fixture.fs.rename(&p("/a"), &p("/a/b/a")),
            Err(VfsError::WouldRecurse { .. })
        ));
        assert!(matches!(
            fixture.fs.rename(&p("/a"), &p("/a")),
            Err(VfsError::WouldRecurse { .. })
        ));

        // A sibling with a longer name is not inside it, and must still work.
        fixture.fs.create_dir(&p("/ab")).unwrap();
        fixture.fs.rename(&p("/ab"), &p("/moved")).unwrap();
    }

    #[test]
    fn removing_works_and_the_root_is_protected() {
        let fixture = Fixture::new();
        write(&fixture.fs, "/f.txt", b"x");

        fixture.fs.remove(&p("/f.txt")).unwrap();
        assert!(matches!(
            fixture.fs.stat(&p("/f.txt")),
            Err(VfsError::NotFound { .. })
        ));

        assert!(matches!(
            fixture.fs.remove(&VPath::root()),
            Err(VfsError::IsRoot)
        ));
    }

    #[test]
    fn a_file_in_the_middle_of_a_path_is_reported_as_such() {
        let fixture = Fixture::new();
        write(&fixture.fs, "/file.txt", b"x");

        assert!(matches!(
            fixture.fs.read_dir(&p("/file.txt/inside")),
            Err(VfsError::NotADirectory { .. })
        ));
    }

    /// An error names the point where resolution broke, which is more useful
    /// than repeating what the caller already typed: told "no such entry: /a/b",
    /// a user knows which directory to create.
    #[test]
    fn errors_name_where_the_path_broke() {
        let fixture = Fixture::new();

        // The missing part is a directory partway along.
        let error = fixture.fs.stat(&p("/a/b/missing.txt")).unwrap_err();
        assert!(error.to_string().contains("/a/b"), "{error}");

        // The directories exist and only the final name is missing, so the
        // whole path is named.
        fixture.fs.create_dir_all(&p("/a/b")).unwrap();
        let error = fixture.fs.stat(&p("/a/b/missing.txt")).unwrap_err();
        assert!(error.to_string().contains("/a/b/missing.txt"), "{error}");
    }

    /// Everything above this layer speaks paths, so awkward names have to work
    /// through it too, not merely in the vault underneath.
    #[test]
    fn awkward_names_work_through_the_interface() {
        let fixture = Fixture::new();
        for name in ["CON", "report: Q1*.txt", "trailing dot.", "ファイル.txt"] {
            let path = format!("/{name}");
            write(&fixture.fs, &path, name.as_bytes());
            assert_eq!(read(&fixture.fs, &path), name.as_bytes(), "{name:?}");
        }
        assert_eq!(fixture.fs.read_dir(&VPath::root()).unwrap().len(), 4);
    }
}
