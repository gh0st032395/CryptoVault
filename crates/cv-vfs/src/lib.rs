//! Filesystem abstraction over a vault.
//!
//! Every consumer — the GUI, the CLI, and one day a mounted virtual drive —
//! talks to a vault through this layer and never touches the encrypted files
//! directly.
//!
//! # Why this crate exists at all in version 1
//!
//! Version 1 of CryptoVault has exactly one implementation of this abstraction,
//! which reads and writes the encrypted directory directly. A layer with one
//! implementation usually deserves suspicion. This one earns its place because
//! of what it makes possible later: FUSE and WinFsp both expect an
//! **offset-based** interface — `read_at`, `write_at`, `truncate` — and a design
//! built instead around "give me the whole file" cannot be adapted to them
//! without being rewritten.
//!
//! Designing the interface this way from the first day is the difference between
//! the virtual mount being a milestone and the virtual mount being a rewrite.
//!
//! # What is here
//!
//! [`VPath`] is the validated path type every operation takes. [`VaultFs`] is
//! the interface, and [`DirectVaultFs`] is the implementation that reads and
//! writes the encrypted directory directly.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod direct;
pub mod path;

pub use direct::{DirEntry, DirectVaultFs, VaultFs};
pub use path::VPath;

use thiserror::Error;

/// Errors produced by the filesystem abstraction.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VfsError {
    /// A path component was not something a vault can store.
    #[error("invalid path component {component:?}: {reason}")]
    InvalidComponent {
        /// The offending component, quoted in the message.
        component: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A path component exceeded the maximum length.
    #[error("path component is {len} bytes, the maximum is {max}")]
    ComponentTooLong {
        /// Length of the offending component in bytes.
        len: usize,
        /// Maximum accepted length in bytes.
        max: usize,
    },

    /// Nothing is at that path.
    #[error("no such entry: {path}")]
    NotFound {
        /// The path the caller asked about.
        path: String,
    },

    /// Something is already at that path.
    #[error("{path} already exists")]
    AlreadyExists {
        /// The path that collided.
        path: String,
    },

    /// A directory was needed and something else was found.
    #[error("{path} is not a directory")]
    NotADirectory {
        /// The path in question.
        path: String,
    },

    /// A file was needed and a directory was found.
    #[error("{path} is a directory")]
    IsADirectory {
        /// The path in question.
        path: String,
    },

    /// The operation cannot be applied to the vault root.
    #[error("the vault root cannot be created, renamed or removed")]
    IsRoot,

    /// A directory was about to be moved inside itself.
    ///
    /// The reference that names a directory lives in its parent. Moving the
    /// directory underneath itself would put that reference inside the subtree
    /// it points at, and nothing could reach either again.
    #[error("cannot move {from} into {to}, which is inside it")]
    WouldRecurse {
        /// Where the entry is now.
        from: String,
        /// Where it was going.
        to: String,
    },

    /// Something went wrong in the vault underneath.
    #[error(transparent)]
    Vault(#[from] cv_vault::VaultError),
}
