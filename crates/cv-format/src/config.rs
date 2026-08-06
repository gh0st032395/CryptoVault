//! `vault.cvconf`: the only file in a vault with a predictable name.
//!
//! It holds everything needed to *attempt* an unlock — the vault identifier, the
//! algorithm, the policy, and one key slot per unlock method — and nothing that
//! is secret. The master seed is in there, but wrapped.
//!
//! # Why the MAC is computed over the exact bytes
//!
//! The configuration is authenticated with `K_mac`, so that nobody with disk
//! access can weaken a vault by lowering the Argon2id parameters, switching the
//! algorithm or clearing the sealed flag.
//!
//! Doing that over a *structure* would need a canonical encoding, and canonical
//! serialisation rules are a classic source of subtle bugs: two encoders
//! disagreeing by one byte means an authentication failure nobody can explain.
//!
//! So the file is a two-element array instead:
//!
//! ```text
//! cvconf = [ body: bstr, mac: bstr(32) ]
//! mac    = HMAC-SHA256(K_mac, body)
//! ```
//!
//! `body` is the CBOR encoding of the configuration, stored as an opaque byte
//! string. The MAC covers the bytes actually on disk, so there is nothing to
//! canonicalise and no encoder to disagree with.
//!
//! # The order of operations at unlock, which cannot be got wrong by accident
//!
//! `K_mac` is derived from the master seed, and the master seed comes out of a
//! slot in this very file. So the MAC can only be checked *after* a successful
//! unwrap:
//!
//! 1. Parse the body without trusting it, to reach the slots.
//! 2. Unwrap a slot with the credential, obtaining the master seed.
//! 3. Derive the sub-keys, including `K_mac`.
//! 4. **Verify the MAC.** If it fails, refuse — the parameters just used may
//!    have been weakened.
//!
//! Step 4 is easy to forget, so [`unlock`] does all four and is the only
//! function that hands back usable keys. [`VaultConfig::decode_unverified`]
//! exists for diagnostics and says so in its name.

use cv_crypto::aead::AeadAlgorithm;
use cv_crypto::hierarchy::{MasterSeed, SubKeys};
use cv_crypto::kdf::{Argon2Params, SALT_LEN};
use cv_crypto::random;
use cv_crypto::secret::Key32;
use cv_crypto::slot::{self, KeySlot, SlotKind};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::FormatError;
use crate::consts::{DIR_ID_LEN, FORMAT_VERSION};

/// Marker at the start of the configuration body.
const CONFIG_MAGIC: &str = "CVCONF1";

/// Length of the configuration MAC, in bytes.
const MAC_LEN: usize = 32;

/// A vault's configuration, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    /// Random identifier, stable across devices. Also the root directory's id.
    pub vault_id: [u8; DIR_ID_LEN as usize],
    /// When the vault was created, Unix seconds. Informational only.
    pub created: u64,
    /// AEAD used for this vault's content.
    pub algorithm: AeadAlgorithm,
    /// Whether plaintext is forbidden from leaving the vault.
    ///
    /// An application policy, not a cryptographic boundary: anyone with the
    /// password can extract the data with the CLI. It is authenticated so that
    /// it cannot be cleared by someone *without* the password.
    pub sealed: bool,
    /// One per unlock method. Every slot wraps the same master seed.
    pub slots: Vec<KeySlot>,
}

impl VaultConfig {
    /// Creates a configuration for a brand-new vault.
    ///
    /// # Errors
    ///
    /// Returns a wrapped [`cv_crypto::CryptoError`] if randomness is unavailable.
    pub fn create(
        algorithm: AeadAlgorithm,
        sealed: bool,
        slots: Vec<KeySlot>,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            vault_id: random::array()?,
            created: now_seconds(),
            algorithm,
            sealed,
            slots,
        })
    }

    /// Serialises and authenticates the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::MalformedConfig`] if encoding fails.
    pub fn encode(&self, mac_key: &Key32) -> Result<Vec<u8>, FormatError> {
        let body = encode_body(&Body::from_config(self))?;
        let mac = compute_mac(mac_key, &body)?;

        let file = ConfigFile {
            body: serde_bytes::ByteBuf::from(body),
            mac: mac.to_vec().into(),
        };
        encode_file(&file)
    }

    /// Parses a configuration **without checking its authenticity**.
    ///
    /// Needed because `K_mac` is only available after a slot has been unwrapped,
    /// and the slots live in here. Everything it returns must be treated as
    /// attacker-controlled until [`verify`] has passed — which is why callers
    /// should use [`unlock`] rather than this.
    ///
    /// It is also what a diagnostic command uses to report on a vault it cannot
    /// open.
    ///
    /// # Errors
    ///
    /// - [`FormatError::MalformedConfig`] if the bytes are not a configuration.
    /// - [`FormatError::UnsupportedVersion`] for a format this build cannot read.
    /// - Wrapped [`cv_crypto::CryptoError`] variants for unreadable slot fields.
    pub fn decode_unverified(bytes: &[u8]) -> Result<Self, FormatError> {
        let file = decode_file(bytes)?;
        let body: Body = decode_body(&file.body)?;

        if body.magic != CONFIG_MAGIC {
            return Err(FormatError::MalformedConfig {
                reason: "wrong configuration marker",
            });
        }
        if body.format != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion {
                found: body.format,
                supported: FORMAT_VERSION,
            });
        }

        body.into_config()
    }
}

/// Everything an unlocked vault needs.
#[derive(Debug)]
pub struct UnlockedVault {
    /// The verified configuration.
    pub config: VaultConfig,
    /// The recovered master seed.
    pub seed: MasterSeed,
    /// The sub-keys derived from it.
    pub keys: SubKeys,
}

/// Opens a vault: unwraps a slot, derives the keys, and verifies the
/// configuration — in that order, every time.
///
/// This is the only function that returns usable keys, because step four is the
/// one an unlock path can silently omit and the one that stops a weakened
/// configuration from being used.
///
/// # Errors
///
/// - Everything [`VaultConfig::decode_unverified`] can return.
/// - [`cv_crypto::CryptoError::DecryptionFailed`] if the credential is wrong.
/// - [`cv_crypto::CryptoError::NoSuchSlot`] if the vault has no slot of that
///   kind, which means retrying will never help.
/// - [`FormatError::ConfigNotAuthentic`] if the MAC does not match: the
///   configuration was altered by somebody without the vault key.
pub fn unlock(
    bytes: &[u8],
    kind: SlotKind,
    credential: &[u8],
) -> Result<UnlockedVault, FormatError> {
    let config = VaultConfig::decode_unverified(bytes)?;
    let seed = slot::unlock_with(&config.slots, kind, credential)?;
    let keys = SubKeys::derive(&seed, &config.vault_id)?;

    verify(bytes, &keys.mac)?;

    Ok(UnlockedVault { config, seed, keys })
}

/// Checks the configuration's authentication tag.
///
/// # Errors
///
/// - [`FormatError::MalformedConfig`] if the bytes do not parse.
/// - [`FormatError::ConfigNotAuthentic`] if the tag does not match.
pub fn verify(bytes: &[u8], mac_key: &Key32) -> Result<(), FormatError> {
    let file = decode_file(bytes)?;

    if file.mac.len() != MAC_LEN {
        return Err(FormatError::MalformedConfig {
            reason: "the authentication tag is the wrong size",
        });
    }

    let expected = compute_mac(mac_key, &file.body)?;

    // Constant-time: a variable-time comparison here would leak how much of a
    // forged tag was right, one byte at a time.
    let mut difference = 0_u8;
    for (a, b) in expected.iter().zip(file.mac.iter()) {
        difference |= a ^ b;
    }

    if difference == 0 {
        Ok(())
    } else {
        Err(FormatError::ConfigNotAuthentic)
    }
}

/// HMAC-SHA256 accepts a key of any length, so this cannot fail for a 32-byte
/// key. The error is propagated rather than unwrapped anyway: "cannot fail" is
/// an argument, and arguments are how impossible branches become reachable.
fn compute_mac(mac_key: &Key32, body: &[u8]) -> Result<[u8; MAC_LEN], FormatError> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(mac_key.expose()).map_err(|_| {
        FormatError::MalformedConfig {
            reason: "the MAC key is the wrong size",
        }
    })?;
    mac.update(body);
    Ok(mac.finalize().into_bytes().into())
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

// --- Wire types ------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    body: serde_bytes::ByteBuf,
    mac: serde_bytes::ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct Body {
    magic: String,
    format: u8,
    vault_id: serde_bytes::ByteBuf,
    created: u64,
    alg_id: u8,
    sealed: bool,
    slots: Vec<SlotRecord>,
}

#[derive(Serialize, Deserialize)]
struct SlotRecord {
    kind: u8,
    label: String,
    kdf: String,
    salt: serde_bytes::ByteBuf,
    m_kib: u32,
    t: u32,
    p: u32,
    alg_id: u8,
    nonce: serde_bytes::ByteBuf,
    wrapped: serde_bytes::ByteBuf,
}

impl Body {
    fn from_config(config: &VaultConfig) -> Self {
        Self {
            magic: CONFIG_MAGIC.to_owned(),
            format: FORMAT_VERSION,
            vault_id: config.vault_id.to_vec().into(),
            created: config.created,
            alg_id: config.algorithm.as_byte(),
            sealed: config.sealed,
            slots: config.slots.iter().map(SlotRecord::from_slot).collect(),
        }
    }

    fn into_config(self) -> Result<VaultConfig, FormatError> {
        let vault_id: [u8; DIR_ID_LEN as usize] =
            self.vault_id
                .as_ref()
                .try_into()
                .map_err(|_| FormatError::MalformedConfig {
                    reason: "the vault identifier is the wrong size",
                })?;

        let slots = self
            .slots
            .iter()
            .map(SlotRecord::to_slot)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(VaultConfig {
            vault_id,
            created: self.created,
            algorithm: AeadAlgorithm::try_from(self.alg_id)?,
            sealed: self.sealed,
            slots,
        })
    }
}

impl SlotRecord {
    fn from_slot(slot: &KeySlot) -> Self {
        Self {
            kind: slot.kind.as_byte(),
            label: slot.label.clone(),
            kdf: "argon2id".to_owned(),
            salt: slot.salt.to_vec().into(),
            m_kib: slot.params.memory_kib(),
            t: slot.params.iterations(),
            p: slot.params.parallelism(),
            alg_id: slot.algorithm.as_byte(),
            nonce: slot.nonce.clone().into(),
            wrapped: slot.wrapped.clone().into(),
        }
    }

    fn to_slot(&self) -> Result<KeySlot, FormatError> {
        if self.kdf != "argon2id" {
            return Err(FormatError::MalformedConfig {
                reason: "unknown key-derivation function",
            });
        }

        let salt: [u8; SALT_LEN] =
            self.salt
                .as_ref()
                .try_into()
                .map_err(|_| FormatError::MalformedConfig {
                    reason: "the slot salt is the wrong size",
                })?;

        Ok(KeySlot {
            kind: SlotKind::try_from(self.kind)?,
            label: self.label.clone(),
            salt,
            // Validated on the way in: a configuration asking for weakened cost
            // is refused, never quietly raised to the minimum.
            params: Argon2Params::new(self.m_kib, self.t, self.p)?,
            algorithm: AeadAlgorithm::try_from(self.alg_id)?,
            nonce: self.nonce.to_vec(),
            wrapped: self.wrapped.to_vec(),
        })
    }
}

fn encode_body(body: &Body) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    ciborium::into_writer(body, &mut out).map_err(|_| FormatError::MalformedConfig {
        reason: "the configuration could not be encoded",
    })?;
    Ok(out)
}

fn decode_body(bytes: &[u8]) -> Result<Body, FormatError> {
    ciborium::from_reader(bytes).map_err(|_| FormatError::MalformedConfig {
        reason: "the configuration body is not valid CBOR",
    })
}

fn encode_file(file: &ConfigFile) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    ciborium::into_writer(file, &mut out).map_err(|_| FormatError::MalformedConfig {
        reason: "the configuration file could not be encoded",
    })?;
    Ok(out)
}

fn decode_file(bytes: &[u8]) -> Result<ConfigFile, FormatError> {
    ciborium::from_reader(bytes).map_err(|_| FormatError::MalformedConfig {
        reason: "this is not a CryptoVault configuration",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cv_crypto::CryptoError;

    fn cheap() -> Argon2Params {
        Argon2Params::new(
            Argon2Params::MIN_MEMORY_KIB,
            Argon2Params::MIN_ITERATIONS,
            Argon2Params::MIN_PARALLELISM,
        )
        .expect("the minimum is within bounds")
    }

    /// A complete vault configuration with one password slot, plus the keys it
    /// unlocks to.
    fn vault(password: &[u8]) -> (Vec<u8>, SubKeys, MasterSeed) {
        let seed = MasterSeed::generate().unwrap();
        let slot = KeySlot::create(
            SlotKind::Password,
            "password",
            password,
            &seed,
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();

        let config = VaultConfig::create(AeadAlgorithm::Aes256Gcm, false, vec![slot]).unwrap();
        let keys = SubKeys::derive(&seed, &config.vault_id).unwrap();
        let bytes = config.encode(&keys.mac).unwrap();

        (bytes, keys, seed)
    }

    #[test]
    fn a_configuration_round_trips() {
        let (bytes, keys, _) = vault(b"pw");
        let decoded = VaultConfig::decode_unverified(&bytes).unwrap();

        assert_eq!(decoded.algorithm, AeadAlgorithm::Aes256Gcm);
        assert!(!decoded.sealed);
        assert_eq!(decoded.slots.len(), 1);
        assert_eq!(decoded.slots[0].kind, SlotKind::Password);
        assert_eq!(decoded.slots[0].label, "password");
        verify(&bytes, &keys.mac).unwrap();
    }

    #[test]
    fn unlocking_recovers_the_seed_and_the_keys() {
        let (bytes, keys, seed) = vault(b"open sesame");
        let unlocked = unlock(&bytes, SlotKind::Password, b"open sesame").unwrap();

        assert_eq!(unlocked.seed, seed);
        assert_eq!(unlocked.keys, keys);
    }

    #[test]
    fn the_wrong_password_does_not_unlock() {
        let (bytes, _, _) = vault(b"right");
        assert_eq!(
            unlock(&bytes, SlotKind::Password, b"wrong").unwrap_err(),
            FormatError::Crypto(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn a_missing_slot_kind_is_distinguished_from_a_wrong_password() {
        let (bytes, _, _) = vault(b"pw");
        assert_eq!(
            unlock(&bytes, SlotKind::OsKeychain, b"pw").unwrap_err(),
            FormatError::Crypto(CryptoError::NoSuchSlot(SlotKind::OsKeychain))
        );
    }

    #[test]
    fn the_seed_is_not_visible_in_the_encoded_configuration() {
        let (bytes, _, seed) = vault(b"pw");
        assert!(
            !bytes
                .windows(32)
                .any(|window| window == seed.as_key().expose())
        );
    }

    #[test]
    fn a_correct_mac_verifies_and_a_wrong_key_does_not() {
        let (bytes, keys, _) = vault(b"pw");
        verify(&bytes, &keys.mac).unwrap();
        assert_eq!(
            verify(&bytes, &Key32::new([0; 32])),
            Err(FormatError::ConfigNotAuthentic)
        );
    }

    /// The attack the MAC exists to stop: weaken the vault on disk so the next
    /// unlock uses cheaper parameters or a different algorithm. It must fail,
    /// and it must fail as an authentication failure.
    #[test]
    fn weakening_the_configuration_is_detected() {
        // Built at a cost there is room to lower, so the tampering is real.
        let dear = Argon2Params::new(Argon2Params::MIN_MEMORY_KIB * 2, 3, 1).unwrap();
        let seed = MasterSeed::generate().unwrap();
        let slot = KeySlot::create(
            SlotKind::Password,
            "p",
            b"pw",
            &seed,
            dear,
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();
        let config = VaultConfig::create(AeadAlgorithm::Aes256Gcm, false, vec![slot]).unwrap();
        let keys = SubKeys::derive(&seed, &config.vault_id).unwrap();
        let bytes = config.encode(&keys.mac).unwrap();

        let mut config = VaultConfig::decode_unverified(&bytes).unwrap();

        // Recompute the file with a lowered cost but the *original* tag — which
        // is all an attacker without the password can do.
        config.slots[0].params = cheap();
        assert_ne!(
            config.slots[0].params, dear,
            "the test must actually change something"
        );
        let tampered_body = encode_body(&Body::from_config(&config)).unwrap();
        let forged = encode_file(&ConfigFile {
            body: serde_bytes::ByteBuf::from(tampered_body),
            mac: decode_file(&bytes).unwrap().mac,
        })
        .unwrap();

        assert_eq!(
            verify(&forged, &keys.mac),
            Err(FormatError::ConfigNotAuthentic)
        );
    }

    #[test]
    fn clearing_the_sealed_flag_is_detected() {
        let seed = MasterSeed::generate().unwrap();
        let slot = KeySlot::create(
            SlotKind::Password,
            "p",
            b"pw",
            &seed,
            cheap(),
            AeadAlgorithm::Aes256Gcm,
        )
        .unwrap();
        let mut config = VaultConfig::create(AeadAlgorithm::Aes256Gcm, true, vec![slot]).unwrap();
        let keys = SubKeys::derive(&seed, &config.vault_id).unwrap();
        let honest = config.encode(&keys.mac).unwrap();
        assert!(VaultConfig::decode_unverified(&honest).unwrap().sealed);

        config.sealed = false;
        let tampered_body = encode_body(&Body::from_config(&config)).unwrap();
        let forged = encode_file(&ConfigFile {
            body: serde_bytes::ByteBuf::from(tampered_body),
            mac: decode_file(&honest).unwrap().mac,
        })
        .unwrap();

        assert_eq!(
            verify(&forged, &keys.mac),
            Err(FormatError::ConfigNotAuthentic)
        );
    }

    /// A configuration asking for weakened cost is refused outright rather than
    /// quietly raised to the minimum, so the tampering is loud.
    #[test]
    fn a_slot_below_the_minimum_cost_is_refused_at_parse_time() {
        let (bytes, _, _) = vault(b"pw");
        let mut body: Body = decode_body(&decode_file(&bytes).unwrap().body).unwrap();
        body.slots[0].m_kib = 1024; // far below the 64 MiB minimum

        let forged = encode_file(&ConfigFile {
            body: serde_bytes::ByteBuf::from(encode_body(&body).unwrap()),
            mac: serde_bytes::ByteBuf::from(vec![0_u8; MAC_LEN]),
        })
        .unwrap();

        assert!(matches!(
            VaultConfig::decode_unverified(&forged),
            Err(FormatError::Crypto(CryptoError::InvalidKdfParams { .. }))
        ));
    }

    #[test]
    fn a_future_format_version_is_refused() {
        let (bytes, _, _) = vault(b"pw");
        let mut body: Body = decode_body(&decode_file(&bytes).unwrap().body).unwrap();
        body.format = FORMAT_VERSION + 1;

        let forged = encode_file(&ConfigFile {
            body: serde_bytes::ByteBuf::from(encode_body(&body).unwrap()),
            mac: serde_bytes::ByteBuf::from(vec![0_u8; MAC_LEN]),
        })
        .unwrap();

        assert!(matches!(
            VaultConfig::decode_unverified(&forged),
            Err(FormatError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn rubbish_is_refused_rather_than_panicking() {
        for bytes in [b"not cbor".as_slice(), &[0xFF; 40], &[]] {
            assert!(VaultConfig::decode_unverified(bytes).is_err());
            assert!(verify(bytes, &Key32::new([0; 32])).is_err());
        }
    }

    #[test]
    fn every_truncation_is_refused_cleanly() {
        let (bytes, keys, _) = vault(b"pw");
        for cut in 0..bytes.len() {
            let _ = VaultConfig::decode_unverified(&bytes[..cut]);
            let _ = verify(&bytes[..cut], &keys.mac);
            // The requirement is that neither panics, and that neither reports
            // success on a partial file.
            assert!(
                verify(&bytes[..cut], &keys.mac).is_err(),
                "{cut} bytes verified"
            );
        }
    }

    /// Several slots in one configuration, all unlocking the same vault. This is
    /// what adding Touch ID will look like.
    #[test]
    fn several_slots_all_open_the_same_vault() {
        let seed = MasterSeed::generate().unwrap();
        let slots = vec![
            KeySlot::create(
                SlotKind::Password,
                "password",
                b"the password",
                &seed,
                cheap(),
                AeadAlgorithm::Aes256Gcm,
            )
            .unwrap(),
            KeySlot::create(
                SlotKind::RecoveryKey,
                "recovery",
                b"the recovery phrase",
                &seed,
                cheap(),
                AeadAlgorithm::Aes256Gcm,
            )
            .unwrap(),
        ];

        let config = VaultConfig::create(AeadAlgorithm::Aes256Gcm, false, slots).unwrap();
        let keys = SubKeys::derive(&seed, &config.vault_id).unwrap();
        let bytes = config.encode(&keys.mac).unwrap();

        assert_eq!(
            unlock(&bytes, SlotKind::Password, b"the password")
                .unwrap()
                .seed,
            seed
        );
        assert_eq!(
            unlock(&bytes, SlotKind::RecoveryKey, b"the recovery phrase")
                .unwrap()
                .seed,
            seed
        );
    }

    #[test]
    fn two_vaults_get_different_identifiers() {
        let (first, _, _) = vault(b"pw");
        let (second, _, _) = vault(b"pw");
        assert_ne!(
            VaultConfig::decode_unverified(&first).unwrap().vault_id,
            VaultConfig::decode_unverified(&second).unwrap().vault_id
        );
    }
}
