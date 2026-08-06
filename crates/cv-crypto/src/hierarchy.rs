//! The master seed and the sub-keys derived from it.
//!
//! A vault has exactly one secret that matters: a 32-byte [`MasterSeed`],
//! generated at creation and stored only in wrapped form inside a key slot.
//! Every key the vault actually uses is derived from it with HKDF-SHA256 under a
//! distinct label.
//!
//! ```text
//! MasterSeed ──HKDF-SHA256(salt = vault_id, info = label)──> sub-key
//! ```
//!
//! # Why the seed never encrypts anything directly
//!
//! Two separate reasons, and both matter.
//!
//! **Separation.** Filenames, file contents, the audit log and the local search
//! index are encrypted under different keys. A weakness in how one of them is
//! used cannot reach the others, and any single sub-key can be retired by
//! bumping its label — the labels carry a version suffix for exactly that.
//!
//! **Substitutability.** Because the seed is only ever unwrapped, an unlock
//! method can be added or removed by rewriting one key slot instead of
//! re-encrypting a vault. See `docs/ADR/0003-key-slots.md`.
//!
//! # Why `vault_id` is the HKDF salt
//!
//! Two vaults could, through some failure of randomness, end up with the same
//! master seed. Salting with the vault identifier means their sub-keys still
//! differ, so one such failure does not become two vaults sharing every key.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;
use crate::random;
use crate::secret::Key32;

/// Length of a vault identifier, in bytes.
pub const VAULT_ID_LEN: usize = 16;

/// The one secret a vault has.
///
/// Wraps a [`Key32`] in its own type so it cannot be passed where a derived
/// sub-key is expected, or the other way round. The two are both 32 bytes and
/// confusing them would be silent.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed(Key32);

impl MasterSeed {
    /// Generates a new random master seed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RandomnessUnavailable`] if the operating system
    /// could not supply entropy. Creating the vault must then fail: a
    /// predictable master seed is not a secret.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random::secret::<32>()?))
    }

    /// Wraps existing key material as a master seed.
    ///
    /// Used when unwrapping a key slot, and when reconstructing a vault from a
    /// recovery key.
    #[must_use]
    pub const fn from_key(key: Key32) -> Self {
        Self(key)
    }

    /// Borrows the seed as a key, for wrapping or derivation.
    #[must_use]
    pub const fn as_key(&self) -> &Key32 {
        &self.0
    }
}

/// The purposes a sub-key can be derived for.
///
/// Each maps to a distinct HKDF label, so the keys are independent. The `/v1`
/// suffix means a sub-key can be rotated later without colliding with the one it
/// replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubKey {
    /// Seals file headers. Each file's own content key lives inside its header.
    Content,
    /// Deterministic filename encryption (AES-SIV).
    Names,
    /// Directory placement (`HMAC(dir_id)`) and the vault configuration MAC.
    Mac,
    /// The local, per-machine audit log.
    Audit,
    /// The local, per-machine search index cache.
    Meta,
}

impl SubKey {
    /// Every sub-key, for deriving them all at unlock time.
    pub const ALL: [Self; 5] = [
        Self::Content,
        Self::Names,
        Self::Mac,
        Self::Audit,
        Self::Meta,
    ];

    /// The HKDF label.
    ///
    /// These strings are part of the on-disk format: changing one makes every
    /// existing vault underivable. They are listed in `docs/FORMAT_SPEC.md` §4.
    #[must_use]
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Content => b"cv/content/v1",
            Self::Names => b"cv/names/v1",
            Self::Mac => b"cv/mac/v1",
            Self::Audit => b"cv/audit/v1",
            Self::Meta => b"cv/meta/v1",
        }
    }
}

/// Derives one sub-key from the master seed.
///
/// # Errors
///
/// - [`CryptoError::WrongSaltLength`] if `vault_id` is not [`VAULT_ID_LEN`] bytes.
///
/// HKDF expansion itself cannot fail for a 32-byte output, but the length is
/// checked rather than assumed, because `vault_id` arrives from a configuration
/// file and a configuration file is untrusted input.
pub fn derive_subkey(
    seed: &MasterSeed,
    vault_id: &[u8],
    subkey: SubKey,
) -> Result<Key32, CryptoError> {
    if vault_id.len() != VAULT_ID_LEN {
        return Err(CryptoError::WrongSaltLength {
            expected: VAULT_ID_LEN,
            found: vault_id.len(),
        });
    }

    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), seed.as_key().expose());

    let mut derived = Key32::zeroed();
    hkdf.expand(subkey.label(), derived.expose_mut())
        .map_err(|source| CryptoError::KeyDerivationFailed {
            reason: source.to_string(),
        })?;

    Ok(derived)
}

/// Every sub-key of an unlocked vault, derived once at unlock.
///
/// Held together so the set is derived in one place and dropped in one place:
/// locking a vault means dropping this value, and everything in it is wiped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubKeys {
    /// Seals file headers.
    pub content: Key32,
    /// Encrypts filenames.
    pub names: Key32,
    /// Directory placement and configuration authentication.
    pub mac: Key32,
    /// The local audit log.
    pub audit: Key32,
    /// The local search index cache.
    pub meta: Key32,
}

impl SubKeys {
    /// Derives the whole set from a master seed.
    ///
    /// # Errors
    ///
    /// As [`derive_subkey`].
    pub fn derive(seed: &MasterSeed, vault_id: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            content: derive_subkey(seed, vault_id, SubKey::Content)?,
            names: derive_subkey(seed, vault_id, SubKey::Names)?,
            mac: derive_subkey(seed, vault_id, SubKey::Mac)?,
            audit: derive_subkey(seed, vault_id, SubKey::Audit)?,
            meta: derive_subkey(seed, vault_id, SubKey::Meta)?,
        })
    }

    /// Borrows the key for a given purpose.
    #[must_use]
    pub const fn get(&self, subkey: SubKey) -> &Key32 {
        match subkey {
            SubKey::Content => &self.content,
            SubKey::Names => &self.names,
            SubKey::Mac => &self.mac,
            SubKey::Audit => &self.audit,
            SubKey::Meta => &self.meta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const VAULT_A: [u8; VAULT_ID_LEN] = [0xA1; VAULT_ID_LEN];
    const VAULT_B: [u8; VAULT_ID_LEN] = [0xB2; VAULT_ID_LEN];

    fn seed() -> MasterSeed {
        MasterSeed::from_key(Key32::new([0x5A; 32]))
    }

    #[test]
    fn generated_seeds_are_random() {
        let a = MasterSeed::generate().unwrap();
        let b = MasterSeed::generate().unwrap();
        assert_ne!(a, b);
        assert_ne!(a.as_key().expose(), &[0_u8; 32]);
    }

    #[test]
    fn a_seed_does_not_print_its_contents() {
        let printed = format!("{:?}", seed());
        assert!(printed.contains("redacted"), "{printed}");
        assert!(
            !printed.contains("90"),
            "the seed leaked into Debug: {printed}"
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let first = derive_subkey(&seed(), &VAULT_A, SubKey::Content).unwrap();
        let second = derive_subkey(&seed(), &VAULT_A, SubKey::Content).unwrap();
        assert_eq!(first, second);
    }

    /// The point of the labels. If two purposes ever derived the same key, a
    /// weakness in one would reach the other, and the separation the design
    /// claims would be imaginary.
    #[test]
    fn every_purpose_gets_a_different_key() {
        let mut seen = HashSet::new();
        for subkey in SubKey::ALL {
            let derived = derive_subkey(&seed(), &VAULT_A, subkey).unwrap();
            assert!(
                seen.insert(*derived.expose()),
                "{subkey:?} collided with another sub-key"
            );
        }
        assert_eq!(seen.len(), SubKey::ALL.len());
    }

    #[test]
    fn labels_are_distinct_and_versioned() {
        let mut seen = HashSet::new();
        for subkey in SubKey::ALL {
            let label = subkey.label();
            assert!(seen.insert(label), "{subkey:?} reuses a label");
            let text = std::str::from_utf8(label).unwrap();
            assert!(text.starts_with("cv/"), "{text} is not namespaced");
            assert!(text.ends_with("/v1"), "{text} carries no version");
        }
    }

    /// Two vaults that somehow shared a master seed must still not share keys.
    #[test]
    fn the_vault_identifier_separates_two_vaults_with_the_same_seed() {
        let in_a = derive_subkey(&seed(), &VAULT_A, SubKey::Content).unwrap();
        let in_b = derive_subkey(&seed(), &VAULT_B, SubKey::Content).unwrap();
        assert_ne!(in_a, in_b);
    }

    #[test]
    fn a_different_seed_gives_different_keys() {
        let other = MasterSeed::from_key(Key32::new([0x5B; 32]));
        let from_one = derive_subkey(&seed(), &VAULT_A, SubKey::Content).unwrap();
        let from_other = derive_subkey(&other, &VAULT_A, SubKey::Content).unwrap();
        assert_ne!(from_one, from_other);
    }

    #[test]
    fn a_vault_identifier_of_the_wrong_length_is_rejected() {
        for len in [0_usize, 8, 15, 17, 32] {
            let err = derive_subkey(&seed(), &vec![0_u8; len], SubKey::Content).unwrap_err();
            assert_eq!(
                err,
                CryptoError::WrongSaltLength {
                    expected: VAULT_ID_LEN,
                    found: len
                }
            );
            assert!(SubKeys::derive(&seed(), &vec![0_u8; len]).is_err());
        }
    }

    #[test]
    fn the_derived_set_matches_deriving_each_key_individually() {
        let keys = SubKeys::derive(&seed(), &VAULT_A).unwrap();
        for subkey in SubKey::ALL {
            assert_eq!(
                keys.get(subkey),
                &derive_subkey(&seed(), &VAULT_A, subkey).unwrap(),
                "{subkey:?} did not match"
            );
        }
    }

    #[test]
    fn the_derived_set_is_reproducible() {
        assert_eq!(
            SubKeys::derive(&seed(), &VAULT_A).unwrap(),
            SubKeys::derive(&seed(), &VAULT_A).unwrap()
        );
    }
}
