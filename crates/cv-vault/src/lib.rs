//! Vault lifecycle: creation, unlocking, locking, and the mapping from vault
//! paths to encrypted files on disk.
//!
//! This crate owns the answer to "where does this file actually live, and is the
//! vault open right now?". It sits above [`cv_format`], which decides what the
//! bytes mean, and below `cv-vfs`, which presents a filesystem-shaped interface.
//!
//! # Locked is the safe state
//!
//! A vault is locked unless something explicitly unlocked it, and every path
//! that can fail — a crash, a panic, a lost session, an auto-lock timer, the
//! machine going to sleep — has to end with the vault locked and the key
//! material wiped. Never the other way round.
//!
//! # Status
//!
//! Milestone M0 defines the state vocabulary. Creation, unlocking and the
//! directory mapping arrive in M2, on top of the format work in M1.
//!
//! [`cv_format`]: https://github.com/gh0st032395/CryptoVault

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use thiserror::Error;

/// Whether a vault is currently usable.
///
/// Deliberately a three-state enum rather than a boolean. `Unlocking` is not a
/// cosmetic detail for a progress bar: Argon2id takes about a second, and during
/// that second the interface must be able to refuse a second unlock attempt and
/// an auto-lock must not fire underneath it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VaultState {
    /// No key material in memory. The default, and the state every failure path
    /// must converge to.
    #[default]
    Locked,
    /// Key derivation is in progress.
    Unlocking,
    /// Key material is in memory and the vault can be read and written.
    Unlocked,
}

impl VaultState {
    /// Whether vault contents can be read or written right now.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Unlocked)
    }

    /// Whether an unlock attempt may be started from this state.
    #[must_use]
    pub const fn can_begin_unlock(self) -> bool {
        matches!(self, Self::Locked)
    }
}

/// Errors produced by vault operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VaultError {
    /// An operation needed an unlocked vault and did not get one.
    #[error("the vault is locked")]
    Locked,

    /// An unlock was requested while one was already running.
    #[error("an unlock attempt is already in progress")]
    UnlockInProgress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vault_defaults_to_locked() {
        assert_eq!(VaultState::default(), VaultState::Locked);
    }

    #[test]
    fn only_an_unlocked_vault_is_usable() {
        assert!(VaultState::Unlocked.is_usable());
        assert!(!VaultState::Locked.is_usable());
        assert!(!VaultState::Unlocking.is_usable());
    }

    #[test]
    fn unlocking_can_only_start_from_locked() {
        assert!(VaultState::Locked.can_begin_unlock());
        assert!(!VaultState::Unlocking.can_begin_unlock());
        assert!(!VaultState::Unlocked.can_begin_unlock());
    }
}
