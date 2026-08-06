//! Fuzzes the vault-configuration parser.
//!
//! `vault.cvconf` is the most exposed parser in the project. It is CBOR, it is
//! read before anything can be authenticated — the key needed to check its MAC
//! is wrapped inside it — and it is the first file any tool touches. Every
//! length in it, including the slot count and the size of every byte string,
//! arrives untrusted.
//!
//! Both entry points are exercised: parsing, and verification against a key
//! that will essentially never match.

#![no_main]

use cv_crypto::secret::Key32;
use cv_crypto::slot::SlotKind;
use cv_format::config::{self, VaultConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = VaultConfig::decode_unverified(data);
    let _ = config::verify(data, &Key32::new([0x42; 32]));

    // The unlock path too, but only for inputs small enough that Argon2id does
    // not dominate the run. A slot has to parse before any derivation happens,
    // so most inputs bail out long before then.
    if data.len() < 4096 {
        let _ = config::unlock(data, SlotKind::Password, b"password");
    }
});
