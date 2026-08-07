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

use argon2::{Algorithm, Argon2, Params, Version};

use crate::CryptoError;
use crate::secret::Key32;

/// Length of the salt Argon2id is given, in bytes.
///
/// The salt is random per key slot, not per vault. Two slots with the same
/// password must not produce the same wrapped seed, or the fact that they match
/// would be visible on disk.
pub const SALT_LEN: usize = 16;

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

/// Derives the key-encryption key from a password.
///
/// The result unwraps the master seed held in a key slot, and nothing else. It
/// never encrypts user data, so changing a password re-runs this function once
/// and rewrites 48 bytes.
///
/// The caller owns the password bytes and is responsible for wiping them. This
/// function does not take ownership, because the password usually arrives from
/// a user-interface buffer whose lifetime it has no business managing.
///
/// # Errors
///
/// - [`CryptoError::WrongSaltLength`] if the salt is not [`SALT_LEN`] bytes.
/// - [`CryptoError::InvalidKdfParams`] if Argon2 rejects the parameters.
/// - [`CryptoError::KeyDerivationFailed`] if the derivation itself fails —
///   in practice, when the machine cannot allocate the memory the parameters
///   ask for, which is what happens to a vault created on a workstation and
///   opened on something much smaller.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Key32, CryptoError> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::WrongSaltLength {
            expected: SALT_LEN,
            found: salt.len(),
        });
    }

    let argon_params = Params::new(
        params.memory_kib(),
        params.iterations(),
        params.parallelism(),
        Some(Key32::zeroed().len()),
    )
    .map_err(|source| CryptoError::InvalidKdfParams {
        reason: source.to_string(),
    })?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    // Derived straight into the wrapper, so the key never sits in a plain array
    // that nothing would wipe.
    let mut kek = Key32::zeroed();
    argon
        .hash_password_into(password, salt, kek.expose_mut())
        .map_err(|source| CryptoError::KeyDerivationFailed {
            reason: source.to_string(),
        })?;

    Ok(kek)
}

/// Finds the strongest Argon2id profile this machine can run in about `target`.
///
/// Called once, when a vault is created. The result is written into the vault
/// configuration, so a vault made on a workstation still opens on a netbook —
/// just more slowly.
///
/// # How it searches, and why it only goes up
///
/// It starts at [`Argon2Params::default_profile`] and doubles the memory cost
/// while a derivation still fits inside `target`, up to
/// [`Argon2Params::MAX_MEMORY_KIB`]. It never searches *downwards*: a machine
/// too slow for the default is not a reason to hand an attacker a cheaper
/// guess, and the default is already the floor we are willing to ship.
///
/// So on a slow machine this returns the default and unlocking takes longer
/// than `target`. That is the intended outcome, not a failure.
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivationFailed`] if even the default profile
/// cannot run — in practice, if the machine cannot allocate 256 MiB.
pub fn calibrate(target: std::time::Duration) -> Result<Argon2Params, CryptoError> {
    let salt = [0_u8; SALT_LEN];
    let password = b"calibration";

    let mut best = Argon2Params::default_profile();
    let elapsed = time_one(password, &salt, best)?;

    // Already slower than asked for: stop, and keep the floor.
    if elapsed >= target {
        return Ok(best);
    }

    let mut memory = best.memory_kib();
    while let Some(doubled) = memory.checked_mul(2) {
        if doubled > Argon2Params::MAX_MEMORY_KIB {
            break;
        }

        let Ok(candidate) = Argon2Params::new(doubled, best.iterations(), best.parallelism())
        else {
            break;
        };

        // A machine that cannot allocate the next step keeps what it has,
        // rather than failing a vault creation that was going to work.
        let Ok(took) = time_one(password, &salt, candidate) else {
            break;
        };
        if took > target {
            break;
        }

        best = candidate;
        memory = doubled;
    }

    Ok(best)
}

/// One derivation, timed. Wall clock is the right measure here: it is what the
/// user waits and what an attacker spends.
fn time_one(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
) -> Result<std::time::Duration, CryptoError> {
    let started = std::time::Instant::now();
    derive_kek(password, salt, params)?;
    Ok(started.elapsed())
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

    // --- derive_kek ------------------------------------------------------
    //
    // These run at the accepted *minimum* cost rather than the default. The
    // default profile is calibrated to take about a second, which is the point
    // of it, and a suite that spends a second per derivation stops being run.
    // The minimum is still a real Argon2id derivation, which is what is being
    // tested here.

    fn cheap_params() -> Argon2Params {
        Argon2Params::new(
            Argon2Params::MIN_MEMORY_KIB,
            Argon2Params::MIN_ITERATIONS,
            Argon2Params::MIN_PARALLELISM,
        )
        .expect("the minimum is by definition within bounds")
    }

    const SALT_A: [u8; SALT_LEN] = [0x11; SALT_LEN];
    const SALT_B: [u8; SALT_LEN] = [0x22; SALT_LEN];

    #[test]
    fn derivation_is_deterministic() {
        let first = derive_kek(b"correct horse battery staple", &SALT_A, cheap_params()).unwrap();
        let second = derive_kek(b"correct horse battery staple", &SALT_A, cheap_params()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn a_different_password_gives_a_different_key() {
        let a = derive_kek(b"password one", &SALT_A, cheap_params()).unwrap();
        let b = derive_kek(b"password two", &SALT_A, cheap_params()).unwrap();
        assert_ne!(a, b);
    }

    /// Two key slots protected by the same password must not produce the same
    /// wrapped seed; if they did, the fact that they match would be readable
    /// straight off the disk.
    #[test]
    fn a_different_salt_gives_a_different_key() {
        let a = derive_kek(b"same password", &SALT_A, cheap_params()).unwrap();
        let b = derive_kek(b"same password", &SALT_B, cheap_params()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_cost_parameters_give_a_different_key() {
        let cheap = derive_kek(b"same password", &SALT_A, cheap_params()).unwrap();
        let dearer = derive_kek(
            b"same password",
            &SALT_A,
            Argon2Params::new(Argon2Params::MIN_MEMORY_KIB, 3, 1).unwrap(),
        )
        .unwrap();
        assert_ne!(cheap, dearer);
    }

    #[test]
    fn a_one_character_password_change_changes_the_whole_key() {
        let a = derive_kek(b"passwordA", &SALT_A, cheap_params()).unwrap();
        let b = derive_kek(b"passwordB", &SALT_A, cheap_params()).unwrap();

        let differing = a
            .expose()
            .iter()
            .zip(b.expose().iter())
            .filter(|(left, right)| left != right)
            .count();
        assert!(differing > 20, "only {differing} of 32 bytes changed");
    }

    #[test]
    fn an_empty_password_still_derives() {
        // Refusing an empty password is the interface's job, not the
        // primitive's. This test exists so nobody "fixes" it into a panic.
        assert!(derive_kek(b"", &SALT_A, cheap_params()).is_ok());
    }

    #[test]
    fn a_salt_of_the_wrong_length_is_rejected() {
        for len in [0_usize, 8, 15, 17, 32] {
            let err = derive_kek(b"pw", &vec![0_u8; len], cheap_params()).unwrap_err();
            assert_eq!(
                err,
                CryptoError::WrongSaltLength {
                    expected: SALT_LEN,
                    found: len
                }
            );
        }
    }

    // --- calibration -----------------------------------------------------

    /// An impossibly short target must still return the default rather than
    /// something weaker. The floor is the point.
    #[test]
    fn calibration_never_goes_below_the_default() {
        let calibrated = calibrate(std::time::Duration::from_nanos(1)).unwrap();
        assert_eq!(calibrated, Argon2Params::default_profile());
    }

    /// The result must always be a profile the validator accepts, whatever the
    /// machine decided.
    #[test]
    fn calibration_returns_something_valid_and_at_least_the_default() {
        let calibrated = calibrate(std::time::Duration::from_millis(1)).unwrap();
        assert!(
            Argon2Params::new(
                calibrated.memory_kib(),
                calibrated.iterations(),
                calibrated.parallelism()
            )
            .is_ok()
        );
        assert!(calibrated.memory_kib() >= Argon2Params::DEFAULT_MEMORY_KIB);
        assert!(calibrated.memory_kib() <= Argon2Params::MAX_MEMORY_KIB);
    }

    #[test]
    fn a_very_long_password_is_accepted() {
        let long = vec![b'x'; 4096];
        assert!(derive_kek(&long, &SALT_A, cheap_params()).is_ok());
    }
}
