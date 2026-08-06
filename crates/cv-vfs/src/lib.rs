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
//! # Status
//!
//! Milestone M0 defines [`VPath`], the validated path type that every other
//! operation will take. The trait and its direct implementation land in M2.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod path;

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
}
