//! Deterministic authenticated encryption, for filenames.
//!
//! Everything else in a vault is encrypted with a fresh random nonce, so the
//! same plaintext looks different every time. Filenames cannot work that way.
//!
//! # Why names must encrypt deterministically
//!
//! Opening `/Reports/2026.pdf` has to find one file on disk. With randomised
//! encryption there would be no way to compute the name it is stored under, so
//! every lookup would mean listing the whole directory and decrypting every
//! entry — turning an O(1) open into an O(n) scan of a folder that might hold
//! ten thousand files, and requiring the whole directory to be decrypted just to
//! read one file from it.
//!
//! AES-SIV solves this: the same plaintext under the same key and the same
//! associated data always produces the same ciphertext, and it is still
//! authenticated. It is also misuse-resistant, which matters because there is no
//! nonce here to get wrong.
//!
//! # What determinism costs
//!
//! Exactly what it sounds like: **two identical names in the same directory are
//! identical on disk.** An observer who can read the encrypted folder learns
//! when two names match. The parent directory's identifier is mixed in as
//! associated data, so the same name in two different folders does *not* match,
//! which limits the leak to within one directory.
//!
//! That is the price of being able to open a file without decrypting its
//! neighbours, and it is recorded in `docs/THREAT_MODEL.md` §7 rather than
//! glossed over.
//!
//! # The key size
//!
//! AES-256-SIV needs 512 bits of key, because SIV runs two keyed constructions.
//! Sub-keys in the hierarchy are 256 bits, so the SIV key is expanded from
//! `K_names` with one HKDF step under its own label. Keeping the quirk here
//! rather than making one branch of the key hierarchy a different width from all
//! the others confines it to the module that cares.

use aes_siv::Aes256SivAead;
use aes_siv::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::CryptoError;
use crate::secret::{Key32, SecretBytes};

/// Bytes AES-SIV adds to a plaintext: the synthetic initialisation vector,
/// which doubles as the authentication tag.
pub const SIV_TAG_LEN: usize = 16;

/// Length of the AES-256-SIV key, in bytes.
const SIV_KEY_LEN: usize = 64;

/// HKDF label for expanding `K_names` into the SIV key.
///
/// Part of the on-disk format: changing it makes every existing filename
/// undecryptable. Recorded in `docs/FORMAT_SPEC.md` §8.
const SIV_KEY_LABEL: &[u8] = b"cv/names/siv/v1";

/// SIV is used deterministically, so the nonce is a constant.
///
/// This is not nonce reuse in the dangerous sense. With SIV the nonce is simply
/// one more associated-data input, and the construction is designed to stay
/// secure when it repeats — that is the whole point of choosing SIV here.
/// Determinism is the requirement, not an accident.
const FIXED_NONCE: [u8; 16] = [0_u8; 16];

/// Encrypts `plaintext` deterministically, binding `aad` to the result.
///
/// The output is `SIV_TAG_LEN + plaintext.len()` bytes. Calling this twice with
/// the same arguments returns identical bytes, by design.
///
/// # Errors
///
/// - [`CryptoError::KeyDerivationFailed`] if the SIV key cannot be expanded.
/// - [`CryptoError::EncryptionFailed`] if the cipher refuses the input.
pub fn seal(names_key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = cipher(names_key)?;
    cipher
        .encrypt(
            &FIXED_NONCE.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|source| CryptoError::EncryptionFailed {
            reason: source.to_string(),
        })
}

/// Verifies and decrypts data produced by [`seal`].
///
/// # Errors
///
/// - [`CryptoError::CiphertextTooShort`] if the input cannot contain a tag.
/// - [`CryptoError::DecryptionFailed`] if authentication fails — the wrong key,
///   the wrong directory identifier, or a modified name. Which one is not
///   reported, for the reason given on that variant.
/// - [`CryptoError::KeyDerivationFailed`] if the SIV key cannot be expanded.
pub fn open(names_key: &Key32, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < SIV_TAG_LEN {
        return Err(CryptoError::CiphertextTooShort {
            len: ciphertext.len(),
            minimum: SIV_TAG_LEN,
        });
    }

    let cipher = cipher(names_key)?;
    cipher
        .decrypt(
            &FIXED_NONCE.into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Expands `K_names` into the double-width SIV key and builds the cipher.
fn cipher(names_key: &Key32) -> Result<Aes256SivAead, CryptoError> {
    let hkdf = Hkdf::<Sha256>::from_prk(names_key.expose()).map_err(|source| {
        CryptoError::KeyDerivationFailed {
            reason: source.to_string(),
        }
    })?;

    let mut siv_key = SecretBytes::<SIV_KEY_LEN>::zeroed();
    hkdf.expand(SIV_KEY_LABEL, siv_key.expose_mut())
        .map_err(|source| CryptoError::KeyDerivationFailed {
            reason: source.to_string(),
        })?;

    Aes256SivAead::new_from_slice(siv_key.expose()).map_err(|_| CryptoError::WrongKeyLength {
        expected: SIV_KEY_LEN,
        found: siv_key.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key32 {
        Key32::new([0x11; 32])
    }

    fn other_key() -> Key32 {
        Key32::new([0x22; 32])
    }

    const DIR_A: &[u8] = b"directory-identifier-a";
    const DIR_B: &[u8] = b"directory-identifier-b";

    #[test]
    fn names_round_trip() {
        let sealed = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        assert_eq!(open(&key(), DIR_A, &sealed).unwrap(), b"invoice.pdf");
    }

    /// The property the whole directory layout depends on. Without it, opening a
    /// file would mean decrypting every name in its folder.
    #[test]
    fn sealing_is_deterministic() {
        let first = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        let second = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        assert_eq!(first, second);
    }

    /// The other half: the same name in two folders must *not* look the same, so
    /// the leak determinism creates is confined to a single directory.
    #[test]
    fn the_same_name_differs_between_directories() {
        let in_a = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        let in_b = seal(&key(), DIR_B, b"invoice.pdf").unwrap();
        assert_ne!(in_a, in_b);
    }

    #[test]
    fn different_names_in_one_directory_differ() {
        let one = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        let two = seal(&key(), DIR_A, b"invoicf.pdf").unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn the_output_is_the_input_plus_a_tag() {
        for len in [0_usize, 1, 11, 255] {
            let sealed = seal(&key(), DIR_A, &vec![b'x'; len]).unwrap();
            assert_eq!(sealed.len(), len + SIV_TAG_LEN);
        }
    }

    #[test]
    fn an_empty_name_round_trips() {
        // Rejecting empty names is the path layer's job; the primitive must not
        // panic on one.
        let sealed = seal(&key(), DIR_A, b"").unwrap();
        assert_eq!(open(&key(), DIR_A, &sealed).unwrap(), b"");
    }

    #[test]
    fn the_name_does_not_appear_in_the_ciphertext() {
        let name = b"very-distinctive-name.txt";
        let sealed = seal(&key(), DIR_A, name).unwrap();
        assert!(!sealed.windows(name.len()).any(|window| window == name));
    }

    #[test]
    fn the_wrong_key_is_refused() {
        let sealed = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        assert_eq!(
            open(&other_key(), DIR_A, &sealed),
            Err(CryptoError::DecryptionFailed)
        );
    }

    /// A name lifted from one directory and dropped into another must not
    /// decrypt there. This is what stops an attacker with disk access from
    /// rearranging a vault.
    #[test]
    fn a_name_moved_to_another_directory_is_refused() {
        let sealed = seal(&key(), DIR_A, b"invoice.pdf").unwrap();
        assert_eq!(
            open(&key(), DIR_B, &sealed),
            Err(CryptoError::DecryptionFailed)
        );
    }

    #[test]
    fn flipping_any_single_bit_is_caught() {
        let sealed = seal(&key(), DIR_A, b"invoice.pdf").unwrap();

        for byte_index in 0..sealed.len() {
            for bit in 0..8_u8 {
                let mut damaged = sealed.clone();
                damaged[byte_index] ^= 1 << bit;
                assert_eq!(
                    open(&key(), DIR_A, &damaged),
                    Err(CryptoError::DecryptionFailed),
                    "bit {bit} of byte {byte_index} went undetected"
                );
            }
        }
    }

    #[test]
    fn a_ciphertext_shorter_than_a_tag_is_reported_as_such() {
        assert_eq!(
            open(&key(), DIR_A, &[0_u8; 4]),
            Err(CryptoError::CiphertextTooShort {
                len: 4,
                minimum: SIV_TAG_LEN
            })
        );
    }

    /// Names the host filesystem forbids are ordinary names in a vault, because
    /// what reaches the disk is an encoding of this ciphertext. The primitive
    /// must handle every byte sequence a name can be.
    #[test]
    fn awkward_names_round_trip() {
        for name in [
            "CON",
            "report: Q1*.txt",
            "trailing space ",
            "trailing dot.",
            "back\\slash",
            "emoji 🔐 name",
            "ファイル.txt",
            "..",
            "a/b",
        ] {
            let sealed = seal(&key(), DIR_A, name.as_bytes()).unwrap();
            assert_eq!(
                open(&key(), DIR_A, &sealed).unwrap(),
                name.as_bytes(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_long_name_round_trips() {
        let long = "x".repeat(4096);
        let sealed = seal(&key(), DIR_A, long.as_bytes()).unwrap();
        assert_eq!(open(&key(), DIR_A, &sealed).unwrap(), long.as_bytes());
    }
}
