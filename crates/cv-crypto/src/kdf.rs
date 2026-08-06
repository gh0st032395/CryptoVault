//! Key derivation from a user password.
//!
//! CryptoVault derives the key-encryption key (KEK) from the user's password
//! with Argon2id. The KEK never encrypts user data directly: it only unwraps the
//! vault master seed held in a key slot. That indirection is what allows a new
//! unlock method — a recovery key, Touch ID, a hardware token — to be added
//! later by writing one small slot, without re-encrypting a single file.
//!
//! # Choosing parameters
//!
//! Argon2id cost is a trade-off the user never sees but always pays. Too low and
//! an offline attacker with a GPU farm grinds through candidate passwords; too
//! high and unlocking a vault on a modest laptop takes ten seconds.
//!
//! The defaults here target roughly one second on a contemporary desktop. On
//! vault creation the application calibrates upward from the defaults if the
//! machine can afford it, and writes the resulting parameters into the vault
//! configuration. A vault created on a workstation therefore still opens on a
//! netbook — just more slowly. It is never calibrated *downward* below
//! [`Argon2Params::MIN_MEMORY_KIB`]: a weak machine is not a reason to hand an
//! attacker a cheap password guess.

use crate::CryptoError;

/// Argon2id cost parameters for deriving the key-encryption key.
///
/// Values are validated on construction, so an `Argon2Params` value is always
/// within the range CryptoVault considers acceptable. Parameters read from a
/// vault configuration go through [`Argon2Params::new`] like everything else:
/// a configuration file is untrusted input, even when it is our own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Argon2Params {
    /// Memory cost of the default profile, in kibibytes (256 MiB).
    ///
    /// Memory is the parameter that actually hurts an attacker: GPUs and ASICs
    /// have enormous parallelism but comparatively little fast memory per core.
    pub const DEFAULT_MEMORY_KIB: u32 = 256 * 1024;

    /// Time cost (number of passes) of the default profile.
    pub const DEFAULT_ITERATIONS: u32 = 3;

    /// Degree of parallelism of the default profile.
    pub const DEFAULT_PARALLELISM: u32 = 4;

    /// Lowest memory cost CryptoVault will accept, in kibibytes (64 MiB).
    ///
    /// Below this an offline attack becomes cheap enough that the password, not
    /// the cipher, is the whole of the security. Configurations asking for less
    /// are rejected instead of being quietly raised, so that a tampered vault
    /// configuration fails loudly.
    pub const MIN_MEMORY_KIB: u32 = 64 * 1024;

    /// Highest memory cost CryptoVault will accept, in kibibytes (4 GiB).
    ///
    /// The ceiling exists to stop a malformed or hostile configuration from
    /// turning an unlock attempt into an out-of-memory abort.
    pub const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;

    /// Lowest number of passes CryptoVault will accept.
    pub const MIN_ITERATIONS: u32 = 2;

    /// Highest number of passes CryptoVault will accept.
    pub const MAX_ITERATIONS: u32 = 64;

    /// Lowest degree of parallelism CryptoVault will accept.
    pub const MIN_PARALLELISM: u32 = 1;

    /// Highest degree of parallelism CryptoVault will accept.
    pub const MAX_PARALLELISM: u32 = 64;

    /// The default profile: 256 MiB, 3 passes, 4 lanes.
    ///
    /// # Panics
    ///
    /// Never. The constants are checked against the bounds by a unit test, so a
    /// change that made them invalid would fail the build rather than reach a
    /// user.
    #[must_use]
    pub const fn default_profile() -> Self {
        Self {
            memory_kib: Self::DEFAULT_MEMORY_KIB,
            iterations: Self::DEFAULT_ITERATIONS,
            parallelism: Self::DEFAULT_PARALLELISM,
        }
    }

    /// Builds a validated parameter set.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKdfParams`] if any value falls outside the
    /// accepted range. The message names the offending parameter, because the
    /// most common cause is a hand-edited or corrupted vault configuration and
    /// the user deserves to know which one.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, CryptoError> {
        let invalid = |reason: &str| CryptoError::InvalidKdfParams {
            reason: reason.to_owned(),
        };

        if memory_kib < Self::MIN_MEMORY_KIB {
            return Err(invalid("memory cost below the accepted minimum of 64 MiB"));
        }
        if memory_kib > Self::MAX_MEMORY_KIB {
            return Err(invalid("memory cost above the accepted maximum of 4 GiB"));
        }
        if iterations < Self::MIN_ITERATIONS {
            return Err(invalid("iteration count below the accepted minimum of 2"));
        }
        if iterations > Self::MAX_ITERATIONS {
            return Err(invalid("iteration count above the accepted maximum of 64"));
        }
        if parallelism < Self::MIN_PARALLELISM {
            return Err(invalid("parallelism below the accepted minimum of 1"));
        }
        if parallelism > Self::MAX_PARALLELISM {
            return Err(invalid("parallelism above the accepted maximum of 64"));
        }

        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Memory cost in kibibytes.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Number of passes over memory.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Degree of parallelism (lanes).
    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::default_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default profile must satisfy its own validation rules. If someone
    /// lowers a default below a minimum, this fails at build time rather than
    /// shipping a vault that cannot validate its own configuration.
    #[test]
    fn default_profile_is_within_bounds() {
        let p = Argon2Params::default_profile();
        assert!(Argon2Params::new(p.memory_kib(), p.iterations(), p.parallelism()).is_ok());
        assert_eq!(p, Argon2Params::default());
    }

    #[test]
    fn accessors_return_what_was_given() {
        let p = Argon2Params::new(128 * 1024, 4, 2).unwrap();
        assert_eq!(p.memory_kib(), 128 * 1024);
        assert_eq!(p.iterations(), 4);
        assert_eq!(p.parallelism(), 2);
    }

    #[test]
    fn boundary_values_are_accepted() {
        assert!(
            Argon2Params::new(
                Argon2Params::MIN_MEMORY_KIB,
                Argon2Params::MIN_ITERATIONS,
                Argon2Params::MIN_PARALLELISM,
            )
            .is_ok()
        );
        assert!(
            Argon2Params::new(
                Argon2Params::MAX_MEMORY_KIB,
                Argon2Params::MAX_ITERATIONS,
                Argon2Params::MAX_PARALLELISM,
            )
            .is_ok()
        );
    }

    #[test]
    fn memory_below_minimum_is_rejected() {
        let err = Argon2Params::new(Argon2Params::MIN_MEMORY_KIB - 1, 3, 4).unwrap_err();
        assert!(err.to_string().contains("memory cost below"));
    }

    #[test]
    fn memory_above_maximum_is_rejected() {
        let err = Argon2Params::new(Argon2Params::MAX_MEMORY_KIB + 1, 3, 4).unwrap_err();
        assert!(err.to_string().contains("memory cost above"));
    }

    #[test]
    fn iterations_out_of_range_are_rejected() {
        assert!(Argon2Params::new(Argon2Params::DEFAULT_MEMORY_KIB, 1, 4).is_err());
        assert!(Argon2Params::new(Argon2Params::DEFAULT_MEMORY_KIB, 65, 4).is_err());
    }

    #[test]
    fn parallelism_out_of_range_is_rejected() {
        assert!(Argon2Params::new(Argon2Params::DEFAULT_MEMORY_KIB, 3, 0).is_err());
        assert!(Argon2Params::new(Argon2Params::DEFAULT_MEMORY_KIB, 3, 65).is_err());
    }

    /// Zero is the value a corrupted or zeroed configuration block most often
    /// produces, so it gets its own test rather than relying on the range checks.
    #[test]
    fn an_all_zero_configuration_is_rejected() {
        assert!(Argon2Params::new(0, 0, 0).is_err());
    }
}
