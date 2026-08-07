//! Which vaults exist, which are open, and everything an interface can ask.
//!
//! This is the layer a desktop application sits on. Every operation the
//! interface needs is a method here, every value it exchanges is a plain
//! serialisable type here, and every failure it must distinguish is a variant
//! here.
//!
//! # Why this is not inside the Tauri backend
//!
//! Because then it could not be tested. State that lives inside a framework
//! gets exercised only by running the framework, and "unlock, browse, lock,
//! unlock again" is exactly the sequence where a session bug hides.
//!
//! So the Tauri layer above this is meant to be *thin*: an attribute on each
//! method and a builder. If it ever starts making decisions, they belong down
//! here instead.
//!
//! # Locking is dropping, at this level too
//!
//! An open vault is a [`cv_vfs::DirectVaultFs`] held in the registry. Locking
//! removes it, which drops it, which wipes the derived keys. There is no
//! separate "locked" state that could be got wrong — the presence of the value
//! *is* the state.
//!
//! # Which vaults exist outlives the process; which are open does not
//!
//! [`Session::open`] reads the list from a file and writes it back whenever it
//! changes, so an application does not forget where the user's vaults are every
//! time it starts. What is *never* written is the fact that a vault was
//! unlocked: every run begins with everything shut.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod registry;

use std::path::{Path, PathBuf};

use cv_crypto::kdf::{self, Argon2Params};
use cv_format::names::EntryKind;
use cv_vault::{CreateOptions, Vault, VaultError};
use cv_vfs::{DirectVaultFs, VPath, VaultFs, VfsError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use registry::{Registry, StoredVault};

/// How long vault creation is allowed to spend calibrating Argon2id.
const CALIBRATION_TARGET: std::time::Duration = std::time::Duration::from_secs(1);

/// A vault as the interface shows it in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSummary {
    /// Stable handle for the other methods.
    pub id: String,
    /// What the user calls it.
    pub name: String,
    /// Where the encrypted folder is, for them to recognise it by.
    pub path: String,
    /// Whether it is open right now.
    pub unlocked: bool,
    /// Whether plaintext is forbidden from leaving it.
    pub sealed: bool,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The decrypted name.
    pub name: String,
    /// `"file"` or `"directory"`, as the interface expects them.
    pub kind: String,
    /// Plaintext length. Zero for a directory.
    pub size: u64,
    /// Original modification time in Unix seconds, if the file carries one.
    pub modified: Option<u64>,
}

/// Everything that can go wrong, in terms an interface can act on.
///
/// `kind` exists so the interface can branch without parsing English: a wrong
/// password gets a shake and a retry, a missing vault gets an offer to find it,
/// and everything else gets the message. Matching on prose is how a translation
/// silently breaks error handling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The credential was wrong. Try again is a sensible response.
    #[error("wrong password")]
    WrongPassword,

    /// No vault with that identifier is registered.
    #[error("no vault with id {id:?}")]
    UnknownVault {
        /// The identifier that was passed.
        id: String,
    },

    /// The vault is registered but not open, and this needed it open.
    #[error("the vault is locked")]
    Locked,

    /// The path is not one a vault can hold.
    #[error("invalid path: {reason}")]
    InvalidPath {
        /// Why it was refused.
        reason: String,
    },

    /// Anything else, already phrased for a person.
    #[error("{message}")]
    Failed {
        /// What happened.
        message: String,
    },
}

impl SessionError {
    /// A stable machine-readable tag, for an interface to branch on.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::WrongPassword => "wrong-password",
            Self::UnknownVault { .. } => "unknown-vault",
            Self::Locked => "locked",
            Self::InvalidPath { .. } => "invalid-path",
            Self::Failed { .. } => "failed",
        }
    }
}

impl From<VaultError> for SessionError {
    fn from(error: VaultError) -> Self {
        if error.is_wrong_credential() {
            Self::WrongPassword
        } else {
            Self::Failed {
                message: error.to_string(),
            }
        }
    }
}

impl From<VfsError> for SessionError {
    fn from(error: VfsError) -> Self {
        match error {
            VfsError::Vault(vault) => Self::from(vault),
            VfsError::InvalidComponent { .. } | VfsError::ComponentTooLong { .. } => {
                Self::InvalidPath {
                    reason: error.to_string(),
                }
            }
            other => Self::Failed {
                message: other.to_string(),
            },
        }
    }
}

/// A registered vault, open or not.
#[derive(Debug)]
struct Registered {
    id: String,
    name: String,
    path: PathBuf,
    sealed: bool,
    /// Present exactly when the vault is unlocked. Dropping it wipes the keys.
    open: Option<DirectVaultFs>,
}

/// The vaults this application knows about.
#[derive(Debug, Default)]
pub struct Session {
    vaults: Vec<Registered>,
    next_id: u64,
    /// Where the list is written down, when it is written down at all.
    registry: Option<PathBuf>,
}

impl Session {
    /// An empty session that forgets everything when it ends.
    ///
    /// What tests use, and what an application uses only if it genuinely has
    /// nowhere to write.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A session backed by the list of vaults stored at `path`.
    ///
    /// Every vault in the file is registered, locked. The file not existing is
    /// the ordinary first run and produces an empty session; the file existing
    /// and being unreadable is an error, because replacing it with an empty list
    /// would present a user with no vaults and no way to tell why.
    ///
    /// Whether each folder is still there is deliberately not checked. A vault
    /// on a drive that is currently unplugged has not stopped existing, and an
    /// application that quietly dropped it from the list would be wrong in the
    /// one direction that loses information.
    ///
    /// # Errors
    ///
    /// [`SessionError::Failed`] if the file exists and cannot be read.
    pub fn open(path: &Path) -> Result<Self, SessionError> {
        let stored = Registry::load(path)?;

        let mut session = Self {
            registry: Some(path.to_path_buf()),
            ..Self::default()
        };
        for vault in stored.vaults {
            session.insert(&vault.name, &vault.path, vault.sealed);
        }

        Ok(session)
    }

    /// Adds a vault that already exists on disk, without opening it.
    ///
    /// # Errors
    ///
    /// [`SessionError::Failed`] if there is no vault there. Registering a
    /// folder that turns out not to be a vault would produce an entry that can
    /// never be unlocked and no explanation of why.
    ///
    /// Also if the list cannot be written. The vault is registered for this run
    /// either way — the failure is only about remembering it for the next one.
    pub fn register(&mut self, name: &str, path: &Path) -> Result<String, SessionError> {
        if !Vault::exists_at(path) {
            return Err(SessionError::Failed {
                message: format!("there is no vault at {}", path.display()),
            });
        }

        let id = self.insert(name, path, sealed_flag(path));
        self.persist()?;
        Ok(id)
    }

    /// Removes a vault from the list, leaving everything on disk alone.
    ///
    /// The folder is not touched — this is "stop showing me this", not "delete
    /// my files", and the two must never be the same button. If the vault was
    /// open it is dropped, which locks it: forgetting an open vault cannot leave
    /// its keys behind in memory.
    ///
    /// # Errors
    ///
    /// [`SessionError::UnknownVault`], or a failure to write the list.
    pub fn forget(&mut self, id: &str) -> Result<(), SessionError> {
        let index = self.index_of(id)?;
        drop(self.vaults.remove(index));
        self.persist()
    }

    /// Creates a vault and registers it, leaving it locked.
    ///
    /// Calibrates Argon2id first, so the cost matches the machine that made the
    /// vault rather than a number chosen years ago. Leaving it locked afterwards
    /// is deliberate: creation should not be a back door into an open vault, and
    /// typing the password once more immediately is the cheapest possible check
    /// that it was typed as intended.
    ///
    /// # Errors
    ///
    /// [`SessionError::Failed`] if a vault already exists there, if it cannot be
    /// written, or if the list of vaults cannot be saved afterwards. In that
    /// last case the vault itself was created and is usable for this run; the
    /// message says so, because "creation failed" over a folder that now exists
    /// is the kind of half-truth that makes people try again and hit "a vault
    /// already exists there".
    pub fn create(
        &mut self,
        name: &str,
        path: &Path,
        password: &str,
        sealed: bool,
    ) -> Result<String, SessionError> {
        let params = kdf::calibrate(CALIBRATION_TARGET).unwrap_or_else(|_| {
            // A machine that cannot calibrate can still use the default, which
            // is the floor we would have refused to go below anyway.
            Argon2Params::default_profile()
        });

        let options = CreateOptions {
            params,
            sealed,
            ..CreateOptions::default()
        };
        drop(Vault::create(path, password.as_bytes(), options)?);

        let id = self.insert(name, path, sealed);
        self.persist().map_err(|error| SessionError::Failed {
            message: format!(
                "the vault was created, but the list of vaults was not saved: {error}"
            ),
        })?;
        Ok(id)
    }

    /// Every registered vault, in the order they were added.
    #[must_use]
    pub fn list(&self) -> Vec<VaultSummary> {
        self.vaults
            .iter()
            .map(|vault| VaultSummary {
                id: vault.id.clone(),
                name: vault.name.clone(),
                path: vault.path.display().to_string(),
                unlocked: vault.open.is_some(),
                sealed: vault.sealed,
            })
            .collect()
    }

    /// Opens a vault.
    ///
    /// Unlocking an already-open vault is a no-op rather than an error: two
    /// clicks on the same button should not produce a complaint.
    ///
    /// # Errors
    ///
    /// [`SessionError::WrongPassword`], [`SessionError::UnknownVault`], or a
    /// wrapped failure.
    pub fn unlock(&mut self, id: &str, password: &str) -> Result<(), SessionError> {
        let index = self.index_of(id)?;
        if self.vaults[index].open.is_some() {
            return Ok(());
        }

        let vault = Vault::open(&self.vaults[index].path, password.as_bytes())?;

        // Now that the configuration has been authenticated, this is the value
        // to believe — `sealed_flag` read it without checking the MAC, which is
        // the best that can be done before a password exists.
        let corrected = self.vaults[index].sealed != vault.config().sealed;
        self.vaults[index].sealed = vault.config().sealed;
        self.vaults[index].open = Some(DirectVaultFs::new(vault));

        if corrected {
            // Best effort on purpose. The vault is open and the caller is about
            // to use it; failing the unlock because a badge could not be written
            // down would be a much worse answer than a stale badge.
            let _ = self.persist();
        }
        Ok(())
    }

    /// Closes a vault, wiping its keys. A no-op if it was already closed.
    ///
    /// # Errors
    ///
    /// [`SessionError::UnknownVault`].
    pub fn lock(&mut self, id: &str) -> Result<(), SessionError> {
        let index = self.index_of(id)?;
        self.vaults[index].open = None;
        Ok(())
    }

    /// Closes every vault.
    ///
    /// What the tray's panic button and the auto-lock timer call. It takes no
    /// identifier and cannot fail, because the moment someone wants everything
    /// shut is the worst possible moment to ask them which one.
    pub fn lock_all(&mut self) {
        for vault in &mut self.vaults {
            vault.open = None;
        }
    }

    /// Lists a directory inside an open vault.
    ///
    /// # Errors
    ///
    /// [`SessionError::Locked`] if the vault is not open, or a wrapped failure.
    pub fn read_dir(&self, id: &str, path: &str) -> Result<Vec<Entry>, SessionError> {
        let (fs, path) = self.opened(id, path)?;

        fs.read_dir(&path)?
            .into_iter()
            .map(|entry| {
                // Sizes and timestamps need the file's header, so a listing of
                // ten thousand entries is ten thousand opens. Recorded as R-03;
                // the search index in M5 is where the cache belongs.
                let child = path.join(&entry.name).map_err(SessionError::from)?;
                let stat = fs.stat(&child)?;
                Ok(Entry {
                    name: entry.name,
                    kind: kind_name(entry.kind).to_owned(),
                    size: stat.size,
                    modified: stat.metadata.mtime,
                })
            })
            .collect()
    }

    /// Creates a directory and any missing parents.
    ///
    /// # Errors
    ///
    /// As [`Session::read_dir`], plus a failure if it already exists as a file.
    pub fn create_dir(&self, id: &str, path: &str) -> Result<(), SessionError> {
        let (fs, path) = self.opened(id, path)?;
        Ok(fs.create_dir_all(&path)?)
    }

    /// Removes an entry, and everything inside it if it is a directory.
    ///
    /// Recursive without asking, because the interface asked: confirming a
    /// deletion is a question for the user, and asking it twice — once in a
    /// dialogue and once in an error — teaches people to click through both.
    ///
    /// # Errors
    ///
    /// As [`Session::read_dir`].
    pub fn remove(&self, id: &str, path: &str) -> Result<(), SessionError> {
        let (fs, path) = self.opened(id, path)?;
        let parent = path.parent().ok_or(SessionError::InvalidPath {
            reason: "the vault root cannot be removed".to_owned(),
        })?;
        let name = path.file_name().ok_or(SessionError::InvalidPath {
            reason: "the vault root cannot be removed".to_owned(),
        })?;

        let dir = fs.resolve_dir(&parent)?;
        Ok(fs.vault().remove_recursive(dir, name)?)
    }

    /// Moves or renames an entry.
    ///
    /// # Errors
    ///
    /// As [`Session::read_dir`].
    pub fn rename(&self, id: &str, from: &str, to: &str) -> Result<(), SessionError> {
        let (fs, from) = self.opened(id, from)?;
        Ok(fs.rename(&from, &parse(to)?)?)
    }

    // --- internals ---------------------------------------------------------

    /// Writes the list down, if this session has anywhere to write it.
    fn persist(&self) -> Result<(), SessionError> {
        let Some(path) = self.registry.as_ref() else {
            return Ok(());
        };

        let stored = Registry {
            vaults: self
                .vaults
                .iter()
                .map(|vault| StoredVault {
                    name: vault.name.clone(),
                    path: vault.path.clone(),
                    sealed: vault.sealed,
                })
                .collect(),
        };

        stored.save(path)
    }

    fn insert(&mut self, name: &str, path: &Path, sealed: bool) -> String {
        self.next_id += 1;
        let id = format!("v{}", self.next_id);

        self.vaults.push(Registered {
            id: id.clone(),
            name: name.to_owned(),
            path: path.to_path_buf(),
            sealed,
            open: None,
        });

        id
    }

    fn index_of(&self, id: &str) -> Result<usize, SessionError> {
        self.vaults
            .iter()
            .position(|vault| vault.id == id)
            .ok_or_else(|| SessionError::UnknownVault { id: id.to_owned() })
    }

    /// The filesystem of an open vault, and a validated path into it.
    fn opened(&self, id: &str, path: &str) -> Result<(&DirectVaultFs, VPath), SessionError> {
        let index = self.index_of(id)?;
        let fs = self.vaults[index]
            .open
            .as_ref()
            .ok_or(SessionError::Locked)?;
        Ok((fs, parse(path)?))
    }
}

fn parse(path: &str) -> Result<VPath, SessionError> {
    VPath::parse(path).map_err(SessionError::from)
}

/// Whether the vault at `path` is sealed, read without a password.
///
/// `vault.cvconf` is authenticated rather than encrypted, so this much is
/// legible before anyone types anything — which is the only reason a list of
/// locked vaults can show the badge at all.
///
/// It is read *unverified*: the MAC cannot be checked without the key. Someone
/// who can rewrite the configuration could therefore make a sealed vault look
/// ordinary in the list. That is acceptable here and nowhere else, because the
/// value is replaced by the authenticated one the moment the vault is opened,
/// and because an attacker who can rewrite files in the vault folder is already
/// past the point this flag protects. Anything unreadable reports `false`: a
/// folder that is not a vault has no policy to report.
fn sealed_flag(path: &Path) -> bool {
    std::fs::read(path.join(cv_format::consts::VAULT_CONFIG_NAME))
        .ok()
        .and_then(|bytes| cv_format::config::VaultConfig::decode_unverified(&bytes).ok())
        .is_some_and(|config| config.sealed)
}

const fn kind_name(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
    }
}

#[cfg(test)]
mod tests;
