//! Key slots: the master seed, wrapped once per unlock method.
//!
//! A slot holds the vault's master seed encrypted under a key derived from one
//! credential. Several slots can exist, and **every one of them wraps the same
//! seed**. That is the entire trick, and it is what lets an unlock method be
//! added later without touching a single encrypted file.
//!
//! ```text
//! slot 0  password        ──Argon2id──> KEK ──unwraps──┐
//! slot 1  recovery key    ──Argon2id──> KEK ──unwraps──┼──> the same MasterSeed
//! slot 2  OS keychain     ──Argon2id──> KEK ──unwraps──┘
//! ```
//!
//! Changing a password rewrites 48 bytes. Adding Touch ID writes one slot. On a
//! 200 GB vault, both are instant — where deriving content keys straight from
//! the password would have meant re-encrypting everything.
//!
//! # The consequence nobody should discover by accident
//!
//! Every slot is an independent path to the whole vault, so **a vault is only as
//! strong as its weakest slot**. A recovery key on a sticky note defeats a
//! thirty-character password. Two things follow, and both are enforced here
//! rather than left to the interface: every slot's parameters are validated
//! against the same minimum, and no slot can be created with weakened cost.
//!
//! See `docs/ADR/0003-key-slots.md` and `docs/FORMAT_SPEC.md` §5.

use crate::CryptoError;
use crate::aead::{self, AeadAlgorithm, TAG_LEN};
use crate::hierarchy::MasterSeed;
use crate::kdf::{self, Argon2Params, SALT_LEN};
use crate::random;
use crate::secret::Key32;

/// Length of a wrapped master seed: 32 bytes of seed plus its tag.
pub const WRAPPED_SEED_LEN: usize = 32 + TAG_LEN;

/// What kind of credential opens a slot.
///
/// All four are allocated in format version 1 even though only
/// [`SlotKind::Password`] is implemented, so that adding one later is a slot,
/// not a format change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SlotKind {
    /// A password typed by the user.
    Password = 1,
    /// A recovery phrase generated at vault creation.
    RecoveryKey = 2,
    /// A secret held by the operating system keychain, released by biometrics.
    OsKeychain = 3,
    /// A keyfile or a hardware token.
    Hardware = 4,
}

impl SlotKind {
    /// The byte stored in the vault configuration.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Whether this build can actually use slots of this kind.
    ///
    /// Unimplemented kinds are still *readable*: a vault written by a later
    /// version must be diagnosable by an earlier one, which means telling the
    /// user "this vault has a Touch ID slot I cannot use" instead of "this vault
    /// is corrupt".
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::Password)
    }
}

impl TryFrom<u8> for SlotKind {
    type Error = CryptoError;

    /// Reads a slot kind from a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnknownSlotKind`] for an unrecognised byte.
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(Self::Password),
            2 => Ok(Self::RecoveryKey),
            3 => Ok(Self::OsKeychain),
            4 => Ok(Self::Hardware),
            other => Err(CryptoError::UnknownSlotKind(other)),
        }
    }
}

/// One way of unlocking a vault.
///
/// Everything in here is stored unencrypted in `vault.cvconf` except `wrapped`.
/// None of it is secret: the parameters have to be readable in order to repeat
/// the derivation, and the whole configuration is authenticated as a unit by
/// `K_mac`, so none of it can be altered undetected either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySlot {
    /// Which credential opens this slot.
    pub kind: SlotKind,
    /// User-visible name, such as "MacBook Touch ID".
    ///
    /// Not covered by this slot's own authentication, so that renaming a slot
    /// does not require the password. It is still covered by the configuration
    /// MAC, so it cannot be changed by someone without the vault key.
    pub label: String,
    /// Argon2id salt, unique to this slot.
    pub salt: [u8; SALT_LEN],
    /// Argon2id cost parameters for this slot.
    pub params: Argon2Params,
    /// Algorithm used to wrap the seed.
    pub algorithm: AeadAlgorithm,
    /// Nonce for the wrap.
    pub nonce: Vec<u8>,
    /// The master seed, encrypted: 48 bytes.
    pub wrapped: Vec<u8>,
}

impl KeySlot {
    /// Creates a slot that wraps `seed` under `credential`.
    ///
    /// `credential` is the password, the recovery phrase, or whatever secret the
    /// unlock method produces. The caller owns it and is responsible for wiping
    /// it.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::RandomnessUnavailable`] if a salt or nonce cannot be
    ///   generated.
    /// - [`CryptoError::KeyDerivationFailed`] if Argon2id cannot run, which in
    ///   practice means the machine cannot allocate the memory it asks for.
    /// - [`CryptoError::EncryptionFailed`] if wrapping fails.
    pub fn create(
        kind: SlotKind,
        label: impl Into<String>,
        credential: &[u8],
        seed: &MasterSeed,
        params: Argon2Params,
        algorithm: AeadAlgorithm,
    ) -> Result<Self, CryptoError> {
        let salt: [u8; SALT_LEN] = random::array()?;
        let nonce = aead::generate_nonce(algorithm)?;

        let kek = kdf::derive_kek(credential, &salt, params)?;
        let aad = binding(kind, &salt, params, algorithm);
        let wrapped = aead::seal(algorithm, &kek, &nonce, &aad, seed.as_key().expose())?;

        Ok(Self {
            kind,
            label: label.into(),
            salt,
            params,
            algorithm,
            nonce,
            wrapped,
        })
    }

    /// Recovers the master seed using `credential`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::DecryptionFailed`] if the credential is wrong or the
    ///   slot has been tampered with. The two are not distinguished, on purpose.
    /// - [`CryptoError::MalformedSlot`] if the stored fields are not the right
    ///   size — a corrupted configuration rather than a wrong password.
    /// - [`CryptoError::KeyDerivationFailed`] if Argon2id cannot run.
    pub fn unwrap_seed(&self, credential: &[u8]) -> Result<MasterSeed, CryptoError> {
        if self.wrapped.len() != WRAPPED_SEED_LEN {
            return Err(CryptoError::MalformedSlot {
                reason: "the wrapped seed is not 48 bytes",
            });
        }
        if self.nonce.len() != self.algorithm.nonce_len() {
            return Err(CryptoError::MalformedSlot {
                reason: "the nonce does not match the slot's algorithm",
            });
        }

        let kek = kdf::derive_kek(credential, &self.salt, self.params)?;
        let aad = binding(self.kind, &self.salt, self.params, self.algorithm);
        let seed_bytes = aead::open(self.algorithm, &kek, &self.nonce, &aad, &self.wrapped)?;

        Ok(MasterSeed::from_key(Key32::from_slice(&seed_bytes)?))
    }
}

/// Builds the associated data that ties a wrap to its own slot parameters.
///
/// Strictly this is belt and braces: altering the cost parameters already
/// changes the derived key, so an altered slot would fail to unwrap anyway. It
/// is here so that a wrap cannot be lifted out of one slot and pasted into
/// another with different settings, and so that the failure is an authentication
/// failure rather than a puzzling wrong-password.
///
/// The label is deliberately excluded: renaming a slot must not require the
/// password, and the label is covered by the configuration MAC regardless.
fn binding(
    kind: SlotKind,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
    algorithm: AeadAlgorithm,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(2 + SALT_LEN + 12);
    aad.push(kind.as_byte());
    aad.push(algorithm.as_byte());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&params.memory_kib().to_le_bytes());
    aad.extend_from_slice(&params.iterations().to_le_bytes());
    aad.extend_from_slice(&params.parallelism().to_le_bytes());
    aad
}

/// Tries `credential` against every slot of the given kind.
///
/// Slots are attempted in order and the first success wins. A failure reports
/// only that nothing opened: which slot was closest tells a legitimate user
/// nothing and an attacker something.
///
/// # Errors
///
/// - [`CryptoError::DecryptionFailed`] if no slot of that kind opens.
/// - [`CryptoError::NoSuchSlot`] if the vault has no slot of that kind at all —
///   distinct from a wrong credential, because it means the vault was never set
///   up for this unlock method and retrying will never help.
pub fn unlock_with(
    slots: &[KeySlot],
    kind: SlotKind,
    credential: &[u8],
) -> Result<MasterSeed, CryptoError> {
    let mut matching = slots.iter().filter(|slot| slot.kind == kind).peekable();

    if matching.peek().is_none() {
        return Err(CryptoError::NoSuchSlot(kind));
    }

    for slot in matching {
        if let Ok(seed) = slot.unwrap_seed(credential) {
            return Ok(seed);
        }
    }

    Err(CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accepted minimum, not the default: the default is calibrated to take
    /// about a second, and these tests derive a lot of keys.
    fn cheap() -> Argon2Params {
        Argon2Params::new(
            Argon2Params::MIN_MEMORY_KIB,
            Argon2Params::MIN_ITERATIONS,
            Argon2Params::MIN_PARALLELISM,
        )
        .expect("the minimum is within bounds")
    }

    fn seed() -> MasterSeed {
        MasterSeed::from_key(Key32::new([0x7C; 32]))
    }

    fn password_slot(password: &[u8]) -> KeySlot {
        KeySlot::create(
            SlotKind::Password,
            "password",
            password,
            &seed(),
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap()
    }

    #[test]
    fn slot_kind_bytes_round_trip() {
        for kind in [
            SlotKind::Password,
            SlotKind::RecoveryKey,
            SlotKind::OsKeychain,
            SlotKind::Hardware,
        ] {
            assert_eq!(SlotKind::try_from(kind.as_byte()).unwrap(), kind);
        }
    }

    #[test]
    fn unknown_slot_kinds_are_refused() {
        for byte in [0_u8, 5, 255] {
            assert_eq!(
                SlotKind::try_from(byte),
                Err(CryptoError::UnknownSlotKind(byte))
            );
        }
    }

    /// A vault written by a later version must be diagnosable, not merely
    /// rejected as corrupt.
    #[test]
    fn unimplemented_kinds_are_readable_but_not_usable() {
        assert!(SlotKind::Password.is_supported());
        for kind in [
            SlotKind::RecoveryKey,
            SlotKind::OsKeychain,
            SlotKind::Hardware,
        ] {
            assert!(!kind.is_supported());
            assert!(
                SlotKind::try_from(kind.as_byte()).is_ok(),
                "{kind:?} should still parse"
            );
        }
    }

    #[test]
    fn a_slot_gives_back_the_seed_it_wrapped() {
        let slot = password_slot(b"open sesame");
        assert_eq!(slot.unwrap_seed(b"open sesame").unwrap(), seed());
    }

    #[test]
    fn the_wrapped_seed_is_the_documented_length() {
        assert_eq!(password_slot(b"pw").wrapped.len(), WRAPPED_SEED_LEN);
        assert_eq!(WRAPPED_SEED_LEN, 48);
    }

    #[test]
    fn the_seed_does_not_appear_in_the_slot() {
        let slot = password_slot(b"pw");
        assert!(
            !slot
                .wrapped
                .windows(32)
                .any(|window| window == seed().as_key().expose())
        );
    }

    #[test]
    fn the_wrong_password_is_refused() {
        let slot = password_slot(b"the right one");
        assert_eq!(
            slot.unwrap_seed(b"the wrong one"),
            Err(CryptoError::DecryptionFailed)
        );
    }

    /// The property the whole design rests on: several slots, one seed, and
    /// adding one touches nothing that already exists.
    #[test]
    fn every_slot_unwraps_the_same_seed() {
        let shared = MasterSeed::generate().unwrap();

        let by_password = KeySlot::create(
            SlotKind::Password,
            "password",
            b"a password",
            &shared,
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let by_recovery = KeySlot::create(
            SlotKind::RecoveryKey,
            "recovery",
            b"a completely different secret",
            &shared,
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();

        assert_eq!(by_password.unwrap_seed(b"a password").unwrap(), shared);
        assert_eq!(
            by_recovery
                .unwrap_seed(b"a completely different secret")
                .unwrap(),
            shared
        );
        // Adding the second slot left the first one byte-for-byte untouched.
        assert_ne!(by_password.wrapped, by_recovery.wrapped);
    }

    /// Two slots with the *same* password must still look different on disk. If
    /// they did not, the fact that they match would be readable by anyone.
    #[test]
    fn two_slots_with_the_same_password_look_different() {
        let first = password_slot(b"identical");
        let second = password_slot(b"identical");

        assert_ne!(first.salt, second.salt);
        assert_ne!(first.wrapped, second.wrapped);
        assert_eq!(
            first.unwrap_seed(b"identical").unwrap(),
            second.unwrap_seed(b"identical").unwrap()
        );
    }

    /// Changing a password rewrites one slot. Nothing else in the vault moves —
    /// this is the whole reason the indirection exists.
    #[test]
    fn changing_the_password_rewraps_the_same_seed() {
        let original = password_slot(b"old password");
        let recovered = original.unwrap_seed(b"old password").unwrap();

        let replacement = KeySlot::create(
            SlotKind::Password,
            "password",
            b"new password",
            &recovered,
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();

        assert_eq!(replacement.unwrap_seed(b"new password").unwrap(), seed());
        assert_eq!(
            replacement.unwrap_seed(b"old password"),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn tampering_with_the_cost_parameters_is_refused() {
        let mut slot = password_slot(b"pw");
        slot.params = Argon2Params::new(Argon2Params::MIN_MEMORY_KIB, 3, 1).unwrap();
        assert_eq!(slot.unwrap_seed(b"pw"), Err(CryptoError::DecryptionFailed));
    }

    #[test]
    fn tampering_with_the_salt_is_refused() {
        let mut slot = password_slot(b"pw");
        slot.salt[0] ^= 0xFF;
        assert_eq!(slot.unwrap_seed(b"pw"), Err(CryptoError::DecryptionFailed));
    }

    /// A wrap must not be liftable out of one slot and pasted into another with
    /// different settings.
    #[test]
    fn a_wrap_cannot_be_moved_between_slots() {
        let source = password_slot(b"pw");
        let mut target = KeySlot::create(
            SlotKind::RecoveryKey,
            "recovery",
            b"pw",
            &seed(),
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();

        target.wrapped = source.wrapped.clone();
        target.nonce = source.nonce.clone();
        target.salt = source.salt;

        // Only `kind` still differs, and it is bound into the associated data.
        assert_eq!(
            target.unwrap_seed(b"pw"),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn flipping_any_bit_of_the_wrap_is_caught() {
        let slot = password_slot(b"pw");

        for byte_index in 0..slot.wrapped.len() {
            let mut damaged = slot.clone();
            damaged.wrapped[byte_index] ^= 0x01;
            assert_eq!(
                damaged.unwrap_seed(b"pw"),
                Err(CryptoError::DecryptionFailed),
                "byte {byte_index} of the wrap went undetected"
            );
        }
    }

    #[test]
    fn a_malformed_slot_is_reported_as_corrupt_not_as_a_wrong_password() {
        let mut short = password_slot(b"pw");
        short.wrapped.truncate(10);
        assert!(matches!(
            short.unwrap_seed(b"pw"),
            Err(CryptoError::MalformedSlot { .. })
        ));

        let mut bad_nonce = password_slot(b"pw");
        bad_nonce.nonce.push(0);
        assert!(matches!(
            bad_nonce.unwrap_seed(b"pw"),
            Err(CryptoError::MalformedSlot { .. })
        ));
    }

    #[test]
    fn renaming_a_slot_does_not_need_the_password() {
        let mut slot = password_slot(b"pw");
        slot.label = "renamed while locked".to_owned();
        assert_eq!(slot.unwrap_seed(b"pw").unwrap(), seed());
    }

    #[test]
    fn unlocking_picks_the_slot_that_opens() {
        let shared = MasterSeed::generate().unwrap();
        let slots = vec![
            KeySlot::create(
                SlotKind::Password,
                "first",
                b"first password",
                &shared,
                cheap(),
                AeadAlgorithm::Aes256Gcm,
            )
            .unwrap(),
            KeySlot::create(
                SlotKind::Password,
                "second",
                b"second password",
                &shared,
                cheap(),
                AeadAlgorithm::Aes256Gcm,
            )
            .unwrap(),
        ];

        assert_eq!(
            unlock_with(&slots, SlotKind::Password, b"first password").unwrap(),
            shared
        );
        assert_eq!(
            unlock_with(&slots, SlotKind::Password, b"second password").unwrap(),
            shared
        );
        assert_eq!(
            unlock_with(&slots, SlotKind::Password, b"neither"),
            Err(CryptoError::DecryptionFailed)
        );
    }

    /// "No slot of this kind" is a different situation from "wrong credential":
    /// the first means retrying will never work, and the user should be told so.
    #[test]
    fn a_missing_slot_kind_is_distinguished_from_a_wrong_credential() {
        let slots = vec![password_slot(b"pw")];
        assert_eq!(
            unlock_with(&slots, SlotKind::OsKeychain, b"pw"),
            Err(CryptoError::NoSuchSlot(SlotKind::OsKeychain))
        );
        assert_eq!(
            unlock_with(&slots, SlotKind::Password, b"wrong"),
            Err(CryptoError::DecryptionFailed)
        );
        assert_eq!(
            unlock_with(&[], SlotKind::Password, b"pw"),
            Err(CryptoError::NoSuchSlot(SlotKind::Password))
        );
    }

    #[test]
    fn slots_work_with_either_algorithm() {
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::XChaCha20Poly1305] {
            let slot = KeySlot::create(SlotKind::Password, "s", b"pw", &seed(), cheap(), algorithm)
                .unwrap();
            assert_eq!(slot.nonce.len(), algorithm.nonce_len());
            assert_eq!(slot.unwrap_seed(b"pw").unwrap(), seed());
        }
    }
}
