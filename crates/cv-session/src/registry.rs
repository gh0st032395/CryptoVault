//! Which vaults exist, remembered between one run and the next.
//!
//! Nothing secret is written here. The registry holds where the encrypted
//! folders are and what the user calls them — the keys live in memory and die
//! with the process, because at this level locking is still dropping.
//!
//! # Why this is not the vault's business
//!
//! A vault does not know it is in a list. The list is a property of the
//! application that shows it, which is why it lives here and not in
//! [`cv_vault`]: a vault copied to another machine is complete on its own, and
//! carries no expectation of being remembered.
//!
//! # Why CBOR
//!
//! It is the encoding the rest of the project already parses, so it adds no
//! dependency and no second parser to worry about. The cost is a file that
//! cannot be read in an editor, which is a smaller loss than it sounds: the
//! question a person actually asks of a folder is "is this a vault, and what
//! kind", and `cryptovault inspect` answers that from the vault itself.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::SessionError;

/// A vault as it is written down: everything about it except whether it is open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredVault {
    /// What the user calls it.
    pub(crate) name: String,
    /// Where the encrypted folder is.
    pub(crate) path: PathBuf,
    /// Whether plaintext is forbidden from leaving it.
    pub(crate) sealed: bool,
}

/// The file itself.
///
/// A struct with one field rather than a bare list, so a later version can add
/// a second one without every existing file becoming unreadable.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Registry {
    /// The vaults, in the order they were added.
    pub(crate) vaults: Vec<StoredVault>,
}

impl Registry {
    /// Reads the registry at `path`.
    ///
    /// A file that is not there is an empty registry rather than a failure: the
    /// first run of the application is not an error condition.
    ///
    /// # Errors
    ///
    /// [`SessionError::Failed`] if the file exists and cannot be read or parsed.
    /// A registry that cannot be understood is *not* silently replaced with an
    /// empty one — that would turn a recoverable file-permissions problem into a
    /// user opening the application to find their vaults gone, with no way to
    /// tell whether the list was lost or the vaults were.
    pub(crate) fn load(path: &Path) -> Result<Self, SessionError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(SessionError::Failed {
                    message: format!("cannot read the vault list at {}: {error}", path.display()),
                });
            }
        };

        ciborium::from_reader(bytes.as_slice()).map_err(|error| SessionError::Failed {
            message: format!(
                "the vault list at {} cannot be read ({error}); move it aside to start with an \
                 empty list — the vaults themselves are untouched",
                path.display()
            ),
        })
    }

    /// Writes the registry to `path`.
    ///
    /// Atomically, through the same path every vault write takes. The registry
    /// is small and rewritten in full, so a half-written one is entirely
    /// possible on a power cut — and a truncated list is the one failure that
    /// looks exactly like losing a vault.
    ///
    /// # Errors
    ///
    /// [`SessionError::Failed`] if it cannot be encoded or written. A path that
    /// is not valid Unicode cannot be encoded, and fails loudly here rather than
    /// being written down in a lossy form that would point nowhere.
    pub(crate) fn save(&self, path: &Path) -> Result<(), SessionError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).map_err(|error| SessionError::Failed {
            message: format!("the vault list cannot be encoded: {error}"),
        })?;

        cv_vault::atomic::write(path, &bytes).map_err(SessionError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Registry {
        Registry {
            vaults: vec![
                StoredVault {
                    name: "Personale".to_owned(),
                    path: PathBuf::from("/home/someone/Vault personale"),
                    sealed: false,
                },
                StoredVault {
                    name: "Documenti riservati".to_owned(),
                    path: PathBuf::from("/home/someone/Dropbox/Riservati"),
                    sealed: true,
                },
            ],
        }
    }

    #[test]
    fn a_registry_survives_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vaults.cbor");

        sample().save(&path).unwrap();
        let loaded = Registry::load(&path).unwrap();

        assert_eq!(loaded.vaults, sample().vaults);
    }

    /// The first run of the application must not look like a failure.
    #[test]
    fn a_missing_file_loads_as_an_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = Registry::load(&dir.path().join("never-written.cbor")).unwrap();

        assert!(loaded.vaults.is_empty());
    }

    /// Saving into a directory that does not exist yet is the normal case: the
    /// application's configuration folder is created on first use.
    #[test]
    fn saving_creates_the_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config/CryptoVault/vaults.cbor");

        sample().save(&path).unwrap();
        assert!(path.exists());
    }

    /// Rubbish is reported, not swallowed. Starting again with an empty list
    /// silently is how a list gets lost without anybody noticing.
    #[test]
    fn an_unreadable_registry_is_an_error_rather_than_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vaults.cbor");
        std::fs::write(&path, b"this is not CBOR at all").unwrap();

        let error = Registry::load(&path).unwrap_err();
        assert_eq!(error.kind(), "failed");
        assert!(
            error.to_string().contains("move it aside"),
            "the message must say what to do: {error}"
        );
    }

    #[test]
    fn an_empty_registry_round_trips_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vaults.cbor");

        Registry::default().save(&path).unwrap();
        assert!(Registry::load(&path).unwrap().vaults.is_empty());
    }
}
