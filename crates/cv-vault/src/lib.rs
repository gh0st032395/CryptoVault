//! A vault on disk: creating one, opening it, and working with what is inside.
//!
//! This crate turns the format described by [`cv_format`] into something with a
//! filesystem underneath it. It knows about directories, entries and names; it
//! does not know about paths with slashes in them (that is `cv-vfs`) and it
//! certainly does not know about windows.
//!
//! # Locked is the safe state
//!
//! A [`Vault`] value exists only while a vault is unlocked: it holds the derived
//! sub-keys, and dropping it wipes them. There is no locked `Vault` to
//! accidentally use — locking is dropping.
//!
//! # How an entry is found
//!
//! Nothing on disk is where a naive reader would expect:
//!
//! ```text
//! /Documents/2026/invoice.pdf
//!     │
//!     ├─ the root directory's id is the vault id
//!     ├─ "Documents" → AES-SIV under the root's id → a name in d/<hmac(root)>/
//!     │  that .cvd file holds the id of the Documents directory
//!     ├─ "2026"      → AES-SIV under the Documents id → a name in d/<hmac(docs)>/
//!     └─ "invoice.pdf" → AES-SIV under the 2026 id → the .cvf that holds it
//! ```
//!
//! Each step is one file read and one decryption, and no step ever joins a
//! decrypted name onto a host path — a directory's location comes from the HMAC
//! of its identifier. That is what makes traversal impossible rather than merely
//! guarded against.
//!
//! [`cv_format`]: https://github.com/gh0st032395/CryptoVault

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod atomic;
pub mod file;

use std::fs;
use std::path::{Path, PathBuf};

use cv_crypto::aead::AeadAlgorithm;
use cv_crypto::hierarchy::SubKeys;
use cv_crypto::kdf::Argon2Params;
use cv_crypto::slot::{KeySlot, SlotKind};
use cv_format::config::{self, VaultConfig};
use cv_format::consts::{DIR_ID_LEN, VAULT_CONFIG_NAME};
use cv_format::dirmap::{self, DirId};
use cv_format::names::{self, EntryKind};
use cv_format::{FileMetadata, FormatError};
use thiserror::Error;

pub use file::VaultFile;

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The decrypted name.
    pub name: String,
    /// Whether it is a file or a directory.
    pub kind: EntryKind,
}

/// What is known about an entry without reading its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Whether it is a file or a directory.
    pub kind: EntryKind,
    /// Plaintext length. Zero for a directory.
    pub size: u64,
    /// Timestamps, permissions, tags.
    pub metadata: FileMetadata,
}

/// Errors produced by vault operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// A filesystem operation failed.
    ///
    /// The underlying [`std::io::Error`] is reduced to a message because vault
    /// errors are compared and cloned; the context says what was being attempted,
    /// which is the part that helps.
    #[error("{context} failed: {message}")]
    Io {
        /// What was being attempted.
        context: &'static str,
        /// What the operating system said.
        message: String,
    },

    /// The directory is not a vault.
    #[error("no vault at {path}: there is no {VAULT_CONFIG_NAME}")]
    NotAVault {
        /// Where we looked.
        path: String,
    },

    /// A vault already exists where one was about to be created.
    ///
    /// Creating over an existing vault would make its contents permanently
    /// unreadable — a new master seed cannot decrypt files sealed under the old
    /// one — so it is refused rather than confirmed.
    #[error("a vault already exists at {path}")]
    VaultExists {
        /// Where it is.
        path: String,
    },

    /// No entry of that name in that directory.
    #[error("no entry named {name:?}")]
    NotFound {
        /// The name that was looked up.
        name: String,
    },

    /// An entry of that name already exists.
    #[error("an entry named {name:?} already exists")]
    AlreadyExists {
        /// The name that collided.
        name: String,
    },

    /// A directory was expected and a file was found, or the other way round.
    #[error("{name:?} is not a {expected}")]
    WrongKind {
        /// The entry in question.
        name: String,
        /// What the operation needed it to be.
        expected: &'static str,
    },

    /// A directory still has entries in it.
    #[error("the directory {name:?} is not empty")]
    NotEmpty {
        /// The directory.
        name: String,
    },

    /// A write was attempted on a handle that was opened for reading.
    ///
    /// Caught here rather than left to the operating system, which would report
    /// something like "bad file descriptor" — true, and useless to anyone
    /// trying to work out what their program did wrong.
    #[error("this file was opened for reading and cannot be written to")]
    ReadOnly,

    /// The vault on disk does not make sense.
    ///
    /// Distinct from an authentication failure: this is structural damage, and
    /// no password will fix it.
    #[error("the vault is damaged: {reason}")]
    Corrupt {
        /// What did not add up.
        reason: String,
    },

    /// Something went wrong in the format layer.
    #[error(transparent)]
    Format(#[from] FormatError),

    /// Something went wrong in the cryptographic layer.
    #[error(transparent)]
    Crypto(#[from] cv_crypto::CryptoError),
}

impl VaultError {
    fn io_ref(context: &'static str, source: &std::io::Error) -> Self {
        Self::Io {
            context,
            message: source.to_string(),
        }
    }

    /// Whether this means "wrong password", at whatever depth it was wrapped.
    ///
    /// An authentication failure can arrive either straight from the crypto
    /// layer or through the format layer, and every caller that shows a message
    /// to a user needs to treat both the same way. Without this they would each
    /// have to know the nesting, and one of them would eventually get it wrong
    /// and tell someone their vault was corrupt when they had simply mistyped.
    #[must_use]
    pub fn is_wrong_credential(&self) -> bool {
        use cv_crypto::CryptoError::DecryptionFailed;
        matches!(
            self,
            Self::Crypto(DecryptionFailed) | Self::Format(FormatError::Crypto(DecryptionFailed))
        )
    }
}

/// Options for a new vault.
#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    /// AEAD for this vault's contents.
    pub algorithm: AeadAlgorithm,
    /// Argon2id cost. Calibration happens above this crate.
    pub params: Argon2Params,
    /// Whether plaintext is forbidden from leaving the vault.
    pub sealed: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            algorithm: AeadAlgorithm::Aes256Gcm,
            params: Argon2Params::default_profile(),
            sealed: false,
        }
    }
}

/// An unlocked vault.
///
/// Holds the derived sub-keys. Dropping it locks the vault and wipes them.
#[derive(Debug)]
pub struct Vault {
    root: PathBuf,
    config: VaultConfig,
    keys: SubKeys,
}

impl Vault {
    /// Creates a vault in an empty or non-existent directory.
    ///
    /// # Errors
    ///
    /// [`VaultError::VaultExists`] if there is already one there — creating over
    /// it would make its contents permanently unreadable. Otherwise
    /// [`VaultError::Io`], or a wrapped cryptographic error.
    pub fn create(
        root: &Path,
        password: &[u8],
        options: CreateOptions,
    ) -> Result<Self, VaultError> {
        if root.join(VAULT_CONFIG_NAME).exists() {
            return Err(VaultError::VaultExists {
                path: root.display().to_string(),
            });
        }

        let seed = cv_crypto::hierarchy::MasterSeed::generate()?;
        let slot = KeySlot::create(
            SlotKind::Password,
            "password",
            password,
            &seed,
            options.params,
            options.algorithm,
        )?;

        let config = VaultConfig::create(options.algorithm, options.sealed, vec![slot])?;
        let keys = SubKeys::derive(&seed, &config.vault_id)?;

        fs::create_dir_all(root)
            .map_err(|source| VaultError::io_ref("creating the vault", &source))?;
        atomic::write(&root.join(VAULT_CONFIG_NAME), &config.encode(&keys.mac)?)?;

        let vault = Self {
            root: root.to_path_buf(),
            config,
            keys,
        };

        // The root directory has to exist on disk before anything can be listed
        // in it, and an empty vault should list as empty rather than fail.
        let root_path = vault.dir_disk_path(vault.root_dir());
        fs::create_dir_all(&root_path)
            .map_err(|source| VaultError::io_ref("creating the vault root directory", &source))?;

        Ok(vault)
    }

    /// Opens an existing vault.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotAVault`] if there is no configuration there,
    /// [`cv_crypto::CryptoError::DecryptionFailed`] for a wrong password, or
    /// [`FormatError::ConfigNotAuthentic`] if the configuration was tampered
    /// with.
    pub fn open(root: &Path, password: &[u8]) -> Result<Self, VaultError> {
        let config_path = root.join(VAULT_CONFIG_NAME);
        if !config_path.exists() {
            return Err(VaultError::NotAVault {
                path: root.display().to_string(),
            });
        }

        let bytes = fs::read(&config_path)
            .map_err(|source| VaultError::io_ref("reading the vault configuration", &source))?;

        // Unwraps a slot, derives the keys and verifies the configuration, in
        // that order. There is no path here that skips the last step.
        let unlocked = config::unlock(&bytes, SlotKind::Password, password)?;

        Ok(Self {
            root: root.to_path_buf(),
            config: unlocked.config,
            keys: unlocked.keys,
        })
    }

    /// Whether a directory holds a vault.
    #[must_use]
    pub fn exists_at(root: &Path) -> bool {
        root.join(VAULT_CONFIG_NAME).is_file()
    }

    /// The vault's configuration.
    #[must_use]
    pub const fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Where the vault lives.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// The root directory's identifier.
    #[must_use]
    pub const fn root_dir(&self) -> DirId {
        dirmap::root_dir_id(self.config.vault_id)
    }

    /// Lists a directory.
    ///
    /// Cheap: it decrypts names and nothing else. Use [`Vault::stat`] for a
    /// single entry's size and metadata, which costs one header read.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] if the directory cannot be read, or a wrapped format
    /// error if an entry's name does not decrypt.
    pub fn read_dir(&self, dir: DirId) -> Result<Vec<DirEntry>, VaultError> {
        let path = self.dir_disk_path(dir);
        if !path.is_dir() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();
        let listing = fs::read_dir(&path)
            .map_err(|source| VaultError::io_ref("listing a directory", &source))?;

        for item in listing {
            let item = item.map_err(|source| VaultError::io_ref("listing a directory", &source))?;
            let file_name = item.file_name().to_string_lossy().into_owned();

            // Companions belong to the entry that shares their stem, and
            // temporaries belong to an interrupted write.
            if names::is_companion(&file_name) || is_temporary(&file_name) {
                continue;
            }

            let Some((stem, kind)) = names::split_on_disk(&file_name) else {
                continue;
            };

            let ciphertext = Self::name_ciphertext(&path, stem)?;
            entries.push(DirEntry {
                name: names::decode(&self.keys.names, &dir, &ciphertext)?,
                kind,
            });
        }

        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Whether an entry exists, and what kind it is.
    ///
    /// # Errors
    ///
    /// A wrapped format error if the name cannot be encrypted.
    pub fn lookup(&self, dir: DirId, name: &str) -> Result<Option<EntryKind>, VaultError> {
        for kind in [EntryKind::File, EntryKind::Directory] {
            if self.entry_path(dir, name, kind)?.exists() {
                return Ok(Some(kind));
            }
        }
        Ok(None)
    }

    /// Size and metadata of an entry.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if there is no such entry, otherwise an I/O or
    /// format error.
    pub fn stat(&self, dir: DirId, name: &str) -> Result<Stat, VaultError> {
        let kind = self.require(dir, name)?;
        let path = self.entry_path(dir, name, kind)?;
        let file = VaultFile::open(&path, &self.keys.content, false)?;

        Ok(Stat {
            kind,
            size: if kind == EntryKind::File {
                file.size()
            } else {
                0
            },
            metadata: file.metadata().clone(),
        })
    }

    /// Creates a directory and returns its identifier.
    ///
    /// # Errors
    ///
    /// [`VaultError::AlreadyExists`] if the name is taken, otherwise an I/O or
    /// format error.
    pub fn create_dir(&self, parent: DirId, name: &str) -> Result<DirId, VaultError> {
        if self.lookup(parent, name)?.is_some() {
            return Err(VaultError::AlreadyExists {
                name: name.to_owned(),
            });
        }

        let child: DirId = cv_crypto::random::array()?;

        // The reference first, then the directory it points at: an interrupted
        // create then leaves a reference to an empty directory, which lists as
        // empty, rather than an orphaned directory nothing can reach.
        let mut reference =
            self.write_entry(parent, name, EntryKind::Directory, FileMetadata::default())?;
        reference.write_at(0, &child)?;
        reference.flush()?;

        fs::create_dir_all(self.dir_disk_path(child))
            .map_err(|source| VaultError::io_ref("creating a directory", &source))?;

        Ok(child)
    }

    /// Resolves a child directory's identifier.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if there is no such directory,
    /// [`VaultError::WrongKind`] if the name is a file.
    pub fn dir_id_of(&self, parent: DirId, name: &str) -> Result<DirId, VaultError> {
        match self.lookup(parent, name)? {
            Some(EntryKind::Directory) => {}
            Some(EntryKind::File) => {
                return Err(VaultError::WrongKind {
                    name: name.to_owned(),
                    expected: "directory",
                });
            }
            None => {
                return Err(VaultError::NotFound {
                    name: name.to_owned(),
                });
            }
        }

        let path = self.entry_path(parent, name, EntryKind::Directory)?;
        let contents = VaultFile::open(&path, &self.keys.content, false)?.read_all()?;

        DirId::try_from(contents.as_slice()).map_err(|_| VaultError::Corrupt {
            reason: format!("the directory reference for {name:?} is not an identifier"),
        })
    }

    /// Creates a file and returns a handle to it.
    ///
    /// # Errors
    ///
    /// [`VaultError::AlreadyExists`] if the name is taken, otherwise an I/O or
    /// format error.
    pub fn create_file(
        &self,
        dir: DirId,
        name: &str,
        metadata: FileMetadata,
    ) -> Result<VaultFile, VaultError> {
        if self.lookup(dir, name)?.is_some() {
            return Err(VaultError::AlreadyExists {
                name: name.to_owned(),
            });
        }
        self.write_entry(dir, name, EntryKind::File, metadata)
    }

    /// Opens an existing file.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`], [`VaultError::WrongKind`], or an I/O or format
    /// error.
    pub fn open_file(
        &self,
        dir: DirId,
        name: &str,
        writable: bool,
    ) -> Result<VaultFile, VaultError> {
        match self.require(dir, name)? {
            EntryKind::File => {}
            EntryKind::Directory => {
                return Err(VaultError::WrongKind {
                    name: name.to_owned(),
                    expected: "file",
                });
            }
        }

        let path = self.entry_path(dir, name, EntryKind::File)?;
        VaultFile::open(&path, &self.keys.content, writable)
    }

    /// Removes an entry.
    ///
    /// A directory must be empty first: removing a populated one would leave its
    /// contents on disk with nothing pointing at them, which is a leak of space
    /// and, more importantly, of file count.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`], [`VaultError::NotEmpty`], or an I/O error.
    pub fn remove(&self, dir: DirId, name: &str) -> Result<(), VaultError> {
        let kind = self.require(dir, name)?;

        if kind == EntryKind::Directory {
            let child = self.dir_id_of(dir, name)?;
            if !self.read_dir(child)?.is_empty() {
                return Err(VaultError::NotEmpty {
                    name: name.to_owned(),
                });
            }
            // The child's own on-disk directory goes too, so an emptied vault
            // does not keep leaking its former shape through empty folders.
            let _ = fs::remove_dir(self.dir_disk_path(child));
        }

        let stored = names::encode(&self.keys.names, &dir, name, kind)?;
        let parent = self.dir_disk_path(dir);

        atomic::remove(&parent.join(&stored.file_name))?;
        if let Some(companion) = stored.companion {
            atomic::remove(&parent.join(companion.file_name))?;
        }

        Ok(())
    }

    /// Removes an entry and, for a directory, everything inside it.
    ///
    /// Separate from [`Vault::remove`] on purpose. Deleting a folder and its
    /// contents is what a person expects from a file browser and is also the
    /// operation that destroys the most with one gesture, so it is a different
    /// function with a different name — an interface has to *ask* for it, and
    /// cannot reach it by passing a directory to the ordinary remove.
    ///
    /// There is no trash yet, so this is permanent. Once M6 lands it should
    /// route through the trash instead.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if there is no such entry, otherwise an I/O or
    /// format error. A failure part-way leaves the vault consistent but
    /// partially emptied: every entry already removed stays removed.
    pub fn remove_recursive(&self, dir: DirId, name: &str) -> Result<(), VaultError> {
        if self.require(dir, name)? == EntryKind::Directory {
            let child = self.dir_id_of(dir, name)?;
            for entry in self.read_dir(child)? {
                self.remove_recursive(child, &entry.name)?;
            }
        }
        self.remove(dir, name)
    }

    /// Moves or renames an entry.
    ///
    /// Renaming a directory rewrites one file, whatever it contains: the
    /// directory's location on disk comes from its identifier, and that does not
    /// change.
    ///
    /// # Errors
    ///
    /// [`VaultError::NotFound`] if the source is missing,
    /// [`VaultError::AlreadyExists`] if the destination is taken.
    pub fn rename(
        &self,
        from_dir: DirId,
        from_name: &str,
        to_dir: DirId,
        to_name: &str,
    ) -> Result<(), VaultError> {
        let kind = self.require(from_dir, from_name)?;

        if self.lookup(to_dir, to_name)?.is_some() {
            return Err(VaultError::AlreadyExists {
                name: to_name.to_owned(),
            });
        }

        let source = self.entry_path(from_dir, from_name, kind)?;
        let target = self.entry_path(to_dir, to_name, kind)?;

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| VaultError::io_ref("creating a directory", &source))?;
        }

        fs::rename(&source, &target)
            .map_err(|source| VaultError::io_ref("moving an entry", &source))?;

        // The old companion, if any, described the old name.
        let old = names::encode(&self.keys.names, &from_dir, from_name, kind)?;
        if let Some(companion) = old.companion {
            atomic::remove(&self.dir_disk_path(from_dir).join(companion.file_name))?;
        }
        self.write_companion(to_dir, to_name, kind)?;

        Ok(())
    }

    // --- internals ---------------------------------------------------------

    /// Creates the on-disk entry for a name, plus its companion if it spilled.
    fn write_entry(
        &self,
        dir: DirId,
        name: &str,
        kind: EntryKind,
        metadata: FileMetadata,
    ) -> Result<VaultFile, VaultError> {
        let path = self.entry_path(dir, name, kind)?;
        self.write_companion(dir, name, kind)?;
        VaultFile::create(&path, &self.keys.content, self.config.algorithm, metadata)
    }

    fn write_companion(&self, dir: DirId, name: &str, kind: EntryKind) -> Result<(), VaultError> {
        let stored = names::encode(&self.keys.names, &dir, name, kind)?;
        if let Some(companion) = stored.companion {
            let path = self.dir_disk_path(dir).join(companion.file_name);
            atomic::write(&path, &companion.contents)?;
        }
        Ok(())
    }

    fn require(&self, dir: DirId, name: &str) -> Result<EntryKind, VaultError> {
        self.lookup(dir, name)?.ok_or_else(|| VaultError::NotFound {
            name: name.to_owned(),
        })
    }

    fn entry_path(&self, dir: DirId, name: &str, kind: EntryKind) -> Result<PathBuf, VaultError> {
        let stored = names::encode(&self.keys.names, &dir, name, kind)?;
        Ok(self.dir_disk_path(dir).join(stored.file_name))
    }

    /// Reads the ciphertext of a name, from the stem or from its companion.
    fn name_ciphertext(dir_path: &Path, stem: &str) -> Result<Vec<u8>, VaultError> {
        let companion = dir_path.join(format!("{stem}.cvn"));
        if companion.is_file() {
            return fs::read(&companion)
                .map_err(|source| VaultError::io_ref("reading a long name", &source));
        }
        Ok(names::decode_stem(stem)?)
    }

    /// The on-disk location of a directory.
    ///
    /// Joined component by component rather than as one string, so the `/` in
    /// the vault-relative path never reaches a Windows API as a literal.
    #[cfg_attr(not(test), allow(dead_code, reason = "used by the crate's tests"))]
    fn dir_disk_path(&self, dir: DirId) -> PathBuf {
        let relative = dirmap::dir_path(&self.keys.mac, &dir).unwrap_or_else(|_| {
            // dir_path only fails on a wrong-length identifier, and DirId is a
            // fixed-size array, so this is unreachable by construction.
            String::from("d/00/UNREACHABLE")
        });

        relative
            .split('/')
            .fold(self.root.clone(), |path, part| path.join(part))
    }
}

/// Whether an on-disk name is a leftover from an interrupted atomic write.
///
/// Matched case-sensitively on purpose: this suffix is one we produce, and a
/// `.TMP` in a vault directory was put there by something else, so quietly
/// swallowing it would hide a real question.
#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the suffix is ours and always lowercase"
)]
fn is_temporary(file_name: &str) -> bool {
    file_name.ends_with(".tmp")
}

const _: () = assert!(
    DIR_ID_LEN == 16,
    "DirId is assumed to be 16 bytes throughout this crate"
);

#[cfg(test)]
mod tests;
