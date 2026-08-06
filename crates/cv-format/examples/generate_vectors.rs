//! Regenerates the frozen format vectors in `crates/cv-format/tests/vectors/`.
//!
//! ```text
//! cargo run -p cv-format --example generate_vectors
//! ```
//!
//! **Running this is not a routine action.** The vectors exist so that a change
//! to the on-disk format cannot happen quietly: when `frozen_vectors.rs` starts
//! failing, that is the safety net doing its job, and the first question is
//! whether the change was intended at all.
//!
//! Regenerate only when the format has been changed deliberately, the
//! specification has already been updated, and the commit message says so.
//! See `CONTRIBUTING.md`, "Changing the on-disk format".

// A generator run by hand, not shipped code. Panicking on a broken invariant is
// the right behaviour here, and the sizes are fixed constants.
#![allow(
    clippy::cast_possible_truncation,
    reason = "all sizes in this generator are fixed constants"
)]

use std::fs;
use std::path::Path;

use cv_crypto::aead::AeadAlgorithm;
use cv_crypto::hierarchy::{MasterSeed, SubKey, SubKeys, derive_subkey};
use cv_crypto::kdf::{self, Argon2Params};
use cv_crypto::secret::Key32;
use cv_crypto::siv;
use cv_crypto::slot::{KeySlot, SlotKind};
use cv_format::config::VaultConfig;
use cv_format::content::seal_chunk;
use cv_format::dirmap::dir_path;
use cv_format::names::{self, EntryKind};
use cv_format::{FileHeader, FileMetadata, FileMode};

/// Fixed inputs. These are test values and are not secret; they are here so the
/// vectors are reproducible in the parts that can be reproduced.
mod fixed {
    pub(crate) const CONTENT_KEY: [u8; 32] = [0x01; 32];
    pub(crate) const NAMES_KEY: [u8; 32] = [0x02; 32];
    pub(crate) const MAC_KEY: [u8; 32] = [0x03; 32];
    pub(crate) const MASTER_SEED: [u8; 32] = [0x04; 32];
    pub(crate) const VAULT_ID: [u8; 16] = [0x05; 16];
    pub(crate) const SALT: [u8; 16] = [0x06; 16];
    pub(crate) const DIR_ID: [u8; 16] = [0x07; 16];
    pub(crate) const PASSWORD: &[u8] = b"vector password";
    pub(crate) const PLAINTEXT_LEN: usize = 70_000; // spans three chunks
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir)?;

    write_encrypted_file(&dir)?;
    write_vault_config(&dir)?;
    write_derivations(&dir)?;

    println!("vectors written to {}", dir.display());
    Ok(())
}

/// A complete encrypted file spanning three chunks.
///
/// The nonces inside are random, so these bytes are not reproducible — and they
/// do not need to be. What the vector guarantees is the direction that matters:
/// a file written today must still be *readable* by every future build.
fn write_encrypted_file(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let content_key = Key32::new(fixed::CONTENT_KEY);

    let metadata = FileMetadata {
        mtime: Some(1_770_000_000),
        ctime: Some(1_769_000_000),
        mode: Some(0o644),
        exec: Some(false),
        versioned: true,
        tags: vec!["work".into(), "2026".into()],
        note: Some("frozen format vector".into()),
        ext: Some("bin".into()),
    };

    let mut header = FileHeader::create(AeadAlgorithm::Aes256Gcm, FileMode::Live, metadata)?;
    header.plain_size = fixed::PLAINTEXT_LEN as u64;

    let plaintext = vector_plaintext();
    let mut out = header.seal(&content_key)?;

    let chunk = cv_format::consts::CHUNK_PLAINTEXT_LEN as usize;
    for (index, piece) in plaintext.chunks(chunk).enumerate() {
        out.extend_from_slice(&seal_chunk(&header, index as u64, piece)?);
    }

    fs::write(dir.join("file.cvf"), out)?;
    Ok(())
}

/// A vault configuration with one password slot.
fn write_vault_config(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let seed = MasterSeed::from_key(Key32::new(fixed::MASTER_SEED));
    let params = Argon2Params::new(
        Argon2Params::MIN_MEMORY_KIB,
        Argon2Params::MIN_ITERATIONS,
        Argon2Params::MIN_PARALLELISM,
    )?;

    let slot = KeySlot::create(
        SlotKind::Password,
        "vector password slot",
        fixed::PASSWORD,
        &seed,
        params,
        AeadAlgorithm::Aes256Gcm,
    )?;

    let mut config = VaultConfig::create(AeadAlgorithm::Aes256Gcm, false, vec![slot])?;
    config.vault_id = fixed::VAULT_ID;
    config.created = 1_770_000_000;

    let keys = SubKeys::derive(&seed, &config.vault_id)?;
    fs::write(dir.join("vault.cvconf"), config.encode(&keys.mac)?)?;
    Ok(())
}

/// The parts of the format that *are* fully deterministic.
///
/// Key derivation, sub-key derivation, filename encryption and directory
/// placement all produce the same bytes for the same inputs, for ever. If any of
/// them changes, every existing vault becomes unreadable, so they are frozen as
/// exact expected values.
fn write_derivations(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let seed = MasterSeed::from_key(Key32::new(fixed::MASTER_SEED));
    let names_key = Key32::new(fixed::NAMES_KEY);
    let mac_key = Key32::new(fixed::MAC_KEY);

    let params = Argon2Params::new(
        Argon2Params::MIN_MEMORY_KIB,
        Argon2Params::MIN_ITERATIONS,
        Argon2Params::MIN_PARALLELISM,
    )?;

    let mut lines = vec![
        "# Frozen derivation vectors for the CryptoVault format, version 1.".to_owned(),
        "# Regenerate only with `cargo run -p cv-format --example generate_vectors`,".to_owned(),
        "# and only when the format has been changed deliberately.".to_owned(),
        String::new(),
        format!(
            "kek = {}",
            hex(kdf::derive_kek(fixed::PASSWORD, &fixed::SALT, params)?.expose())
        ),
    ];

    for subkey in SubKey::ALL {
        let derived = derive_subkey(&seed, &fixed::VAULT_ID, subkey)?;
        lines.push(format!(
            "subkey.{} = {}",
            label(subkey),
            hex(derived.expose())
        ));
    }

    lines.push(format!(
        "siv.invoice = {}",
        hex(&siv::seal(&names_key, &fixed::DIR_ID, b"invoice.pdf")?)
    ));
    lines.push(format!(
        "name.invoice = {}",
        names::encode(&names_key, &fixed::DIR_ID, "invoice.pdf", EntryKind::File)?.file_name
    ));
    lines.push(format!("dirpath = {}", dir_path(&mac_key, &fixed::DIR_ID)?));

    fs::write(dir.join("derivations.txt"), lines.join("\n") + "\n")?;
    Ok(())
}

/// The plaintext inside `file.cvf`: a repeating pattern, so a chunk written at
/// the wrong offset shows up as a mismatch rather than as plausible data.
fn vector_plaintext() -> Vec<u8> {
    (0..fixed::PLAINTEXT_LEN)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

fn label(subkey: SubKey) -> &'static str {
    match subkey {
        SubKey::Content => "content",
        SubKey::Names => "names",
        SubKey::Mac => "mac",
        SubKey::Audit => "audit",
        SubKey::Meta => "meta",
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}
