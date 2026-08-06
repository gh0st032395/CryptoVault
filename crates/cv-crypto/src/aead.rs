//! Authenticated encryption, with the algorithm chosen at runtime.
//!
//! Everything encrypted in a vault goes through here: file headers, content
//! chunks, wrapped master seeds. The algorithm is a value rather than a type,
//! because the byte that selects it is stored in every file — that is what makes
//! it possible to introduce a new cipher without a flag day.
//!
//! # Algorithm agility, used sparingly
//!
//! Two algorithms are implemented. Version 1 builds only ever *write*
//! [`AeadAlgorithm::Aes256Gcm`]; the other exists so that switching does not
//! require a format change:
//!
//! | Byte | Algorithm | Nonce | Why it is here |
//! |---|---|---|---|
//! | `0x01` | AES-256-GCM | 12 | Hardware-accelerated on every desktop target |
//! | `0x02` | XChaCha20-Poly1305 | 24 | Fast in software, and a much larger nonce |
//!
//! Agility is a liability as well as an asset — every extra algorithm is more
//! code, and a selector read from a file is a selector an attacker can try to
//! influence. It is kept to two, and the selector is always covered by an
//! authentication tag, so a modified one fails to decrypt rather than
//! downgrading anything.
//!
//! # Nonces
//!
//! [`generate_nonce`] is the only way a nonce should ever be produced. Random,
//! every single time, never derived from a counter or an index — see
//! `docs/ADR/0004-chunked-content-random-nonces.md` for why that distinction
//! decides whether the format is sound.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::CryptoError;
use crate::random;
use crate::secret::Key32;

/// Length of the authentication tag, in bytes. The same for both algorithms.
pub const TAG_LEN: usize = 16;

/// An authenticated encryption algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum AeadAlgorithm {
    /// AES-256-GCM with a 96-bit nonce. The default and the only one written by
    /// version 1 builds.
    #[default]
    Aes256Gcm = 0x01,
    /// XChaCha20-Poly1305 with a 192-bit nonce. Implemented and tested, not yet
    /// selectable through the interface.
    XChaCha20Poly1305 = 0x02,
}

impl AeadAlgorithm {
    /// The byte written into a file header to select this algorithm.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Nonce length in bytes.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    /// Authentication tag length in bytes.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        TAG_LEN
    }

    /// Human-readable name, for diagnostics and the `inspect` command.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }
}

impl TryFrom<u8> for AeadAlgorithm {
    type Error = CryptoError;

    /// Reads an algorithm selector from a file.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnknownAlgorithm`] for any other byte. Unknown
    /// selectors are refused rather than defaulted: a file written by a future
    /// version must not be read as though it used today's cipher.
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::Aes256Gcm),
            0x02 => Ok(Self::XChaCha20Poly1305),
            other => Err(CryptoError::UnknownAlgorithm(other)),
        }
    }
}

/// Returns a fresh random nonce of the right length for `algorithm`.
///
/// # Errors
///
/// Returns [`CryptoError::RandomnessUnavailable`] if the operating system could
/// not supply entropy. The operation must then fail: a predictable nonce breaks
/// GCM completely, and it does so silently.
pub fn generate_nonce(algorithm: AeadAlgorithm) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = vec![0_u8; algorithm.nonce_len()];
    random::fill(&mut nonce)?;
    Ok(nonce)
}

/// Encrypts and authenticates `plaintext`, binding `aad` to the result.
///
/// Returns the ciphertext with its authentication tag appended, so the output is
/// `plaintext.len() + TAG_LEN` bytes long.
///
/// The associated data is authenticated but not encrypted: it is how the format
/// binds a chunk to its index and its file, so that chunks cannot be reordered
/// or transplanted.
///
/// # Errors
///
/// - [`CryptoError::WrongNonceLength`] if the nonce does not match the algorithm.
/// - [`CryptoError::EncryptionFailed`] if the cipher refuses the input, which in
///   practice needs an implausibly large buffer.
pub fn seal(
    algorithm: AeadAlgorithm,
    key: &Key32,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce_len(algorithm, nonce)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let sealed = match algorithm {
        AeadAlgorithm::Aes256Gcm => cipher_aes(key)?.encrypt(nonce.into(), payload),
        AeadAlgorithm::XChaCha20Poly1305 => cipher_xchacha(key)?.encrypt(nonce.into(), payload),
    };

    sealed.map_err(|source| CryptoError::EncryptionFailed {
        reason: source.to_string(),
    })
}

/// Verifies and decrypts data produced by [`seal`].
///
/// # Errors
///
/// - [`CryptoError::WrongNonceLength`] if the nonce does not match the algorithm.
/// - [`CryptoError::CiphertextTooShort`] if the input cannot even contain a tag.
/// - [`CryptoError::DecryptionFailed`] if authentication fails.
///
/// That last error deliberately does not say whether the key, the nonce, the
/// associated data or the ciphertext was wrong. Distinguishing them helps nobody
/// who has the key, and helps somebody who does not.
pub fn open(
    algorithm: AeadAlgorithm,
    key: &Key32,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_nonce_len(algorithm, nonce)?;

    if ciphertext.len() < algorithm.tag_len() {
        return Err(CryptoError::CiphertextTooShort {
            len: ciphertext.len(),
            minimum: algorithm.tag_len(),
        });
    }

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    let opened = match algorithm {
        AeadAlgorithm::Aes256Gcm => cipher_aes(key)?.decrypt(nonce.into(), payload),
        AeadAlgorithm::XChaCha20Poly1305 => cipher_xchacha(key)?.decrypt(nonce.into(), payload),
    };

    // The underlying error is discarded on purpose; see the doc comment.
    opened.map_err(|_| CryptoError::DecryptionFailed)
}

fn check_nonce_len(algorithm: AeadAlgorithm, nonce: &[u8]) -> Result<(), CryptoError> {
    if nonce.len() == algorithm.nonce_len() {
        Ok(())
    } else {
        Err(CryptoError::WrongNonceLength {
            expected: algorithm.nonce_len(),
            found: nonce.len(),
        })
    }
}

fn cipher_aes(key: &Key32) -> Result<Aes256Gcm, CryptoError> {
    Aes256Gcm::new_from_slice(key.expose()).map_err(|_| CryptoError::WrongKeyLength {
        expected: 32,
        found: key.len(),
    })
}

fn cipher_xchacha(key: &Key32) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::WrongKeyLength {
        expected: 32,
        found: key.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: [AeadAlgorithm; 2] = [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::XChaCha20Poly1305];

    fn key() -> Key32 {
        Key32::new([0x42; 32])
    }

    fn other_key() -> Key32 {
        Key32::new([0x43; 32])
    }

    #[test]
    fn algorithm_bytes_round_trip() {
        for algorithm in BOTH {
            assert_eq!(
                AeadAlgorithm::try_from(algorithm.as_byte()).unwrap(),
                algorithm
            );
        }
    }

    #[test]
    fn unknown_algorithm_bytes_are_refused_not_defaulted() {
        for byte in [0x00_u8, 0x03, 0xff] {
            assert_eq!(
                AeadAlgorithm::try_from(byte),
                Err(CryptoError::UnknownAlgorithm(byte))
            );
        }
    }

    #[test]
    fn the_default_is_aes_gcm() {
        assert_eq!(AeadAlgorithm::default(), AeadAlgorithm::Aes256Gcm);
        assert_eq!(AeadAlgorithm::Aes256Gcm.as_byte(), 0x01);
    }

    #[test]
    fn generated_nonces_have_the_right_length_and_differ() {
        for algorithm in BOTH {
            let first = generate_nonce(algorithm).unwrap();
            let second = generate_nonce(algorithm).unwrap();
            assert_eq!(first.len(), algorithm.nonce_len());
            assert_ne!(
                first,
                second,
                "{} produced the same nonce twice",
                algorithm.name()
            );
        }
    }

    #[test]
    fn sealed_data_opens_again() {
        for algorithm in BOTH {
            let nonce = generate_nonce(algorithm).unwrap();
            let sealed = seal(algorithm, &key(), &nonce, b"aad", b"the plaintext").unwrap();
            let opened = open(algorithm, &key(), &nonce, b"aad", &sealed).unwrap();
            assert_eq!(opened, b"the plaintext", "{} failed", algorithm.name());
        }
    }

    #[test]
    fn the_ciphertext_is_the_plaintext_length_plus_a_tag() {
        for algorithm in BOTH {
            let nonce = generate_nonce(algorithm).unwrap();
            for len in [0_usize, 1, 15, 16, 1000] {
                let sealed = seal(algorithm, &key(), &nonce, b"", &vec![0_u8; len]).unwrap();
                assert_eq!(sealed.len(), len + TAG_LEN);
            }
        }
    }

    #[test]
    fn an_empty_plaintext_round_trips() {
        for algorithm in BOTH {
            let nonce = generate_nonce(algorithm).unwrap();
            let sealed = seal(algorithm, &key(), &nonce, b"aad", b"").unwrap();
            assert_eq!(
                open(algorithm, &key(), &nonce, b"aad", &sealed).unwrap(),
                b""
            );
        }
    }

    #[test]
    fn the_plaintext_does_not_appear_in_the_ciphertext() {
        let algorithm = AeadAlgorithm::Aes256Gcm;
        let nonce = generate_nonce(algorithm).unwrap();
        let plaintext = b"SECRETSECRETSECRET";
        let sealed = seal(algorithm, &key(), &nonce, b"", plaintext).unwrap();
        assert!(
            !sealed
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
    }

    /// The four ways decryption can legitimately fail. Each must be refused, and
    /// each must produce the *same* error, so that failing tells an attacker
    /// nothing about which part they got wrong.
    #[test]
    fn every_kind_of_tampering_is_refused_identically() {
        for algorithm in BOTH {
            let nonce = generate_nonce(algorithm).unwrap();
            let other_nonce = generate_nonce(algorithm).unwrap();
            let sealed = seal(algorithm, &key(), &nonce, b"aad", b"plaintext").unwrap();

            let mut flipped = sealed.clone();
            flipped[0] ^= 0x01;

            let mut tag_flipped = sealed.clone();
            let last = tag_flipped.len() - 1;
            tag_flipped[last] ^= 0x01;

            let attempts = [
                open(algorithm, &other_key(), &nonce, b"aad", &sealed),
                open(algorithm, &key(), &other_nonce, b"aad", &sealed),
                open(algorithm, &key(), &nonce, b"different aad", &sealed),
                open(algorithm, &key(), &nonce, b"aad", &flipped),
                open(algorithm, &key(), &nonce, b"aad", &tag_flipped),
            ];

            for attempt in attempts {
                assert_eq!(
                    attempt,
                    Err(CryptoError::DecryptionFailed),
                    "{} accepted tampered input or reported a distinguishable error",
                    algorithm.name()
                );
            }
        }
    }

    /// Flipping any single bit anywhere must be caught. This is the property the
    /// whole integrity story rests on, so it is checked exhaustively over a
    /// small message rather than at a couple of sampled positions.
    #[test]
    fn flipping_any_single_bit_is_caught() {
        let algorithm = AeadAlgorithm::Aes256Gcm;
        let nonce = generate_nonce(algorithm).unwrap();
        let sealed = seal(
            algorithm,
            &key(),
            &nonce,
            b"aad",
            b"twenty-four byte message",
        )
        .unwrap();

        for byte_index in 0..sealed.len() {
            for bit in 0..8_u8 {
                let mut damaged = sealed.clone();
                damaged[byte_index] ^= 1 << bit;
                assert_eq!(
                    open(algorithm, &key(), &nonce, b"aad", &damaged),
                    Err(CryptoError::DecryptionFailed),
                    "bit {bit} of byte {byte_index} went undetected"
                );
            }
        }
    }

    /// Truncation is the failure an authentication tag does not catch on its
    /// own, which is why the format stores an authenticated length. Here it must
    /// at least be refused rather than silently returning a short plaintext.
    #[test]
    fn truncated_ciphertext_is_refused() {
        let algorithm = AeadAlgorithm::Aes256Gcm;
        let nonce = generate_nonce(algorithm).unwrap();
        let sealed = seal(algorithm, &key(), &nonce, b"", b"some plaintext here").unwrap();

        for cut in 1..sealed.len() {
            assert!(
                open(algorithm, &key(), &nonce, b"", &sealed[..cut]).is_err(),
                "a ciphertext truncated to {cut} bytes was accepted"
            );
        }
    }

    #[test]
    fn a_ciphertext_shorter_than_a_tag_is_reported_as_such() {
        let algorithm = AeadAlgorithm::Aes256Gcm;
        let nonce = generate_nonce(algorithm).unwrap();
        assert_eq!(
            open(algorithm, &key(), &nonce, b"", &[0_u8; 4]),
            Err(CryptoError::CiphertextTooShort {
                len: 4,
                minimum: TAG_LEN
            })
        );
    }

    #[test]
    fn a_nonce_of_the_wrong_length_is_refused_by_both_directions() {
        for algorithm in BOTH {
            let wrong = vec![0_u8; algorithm.nonce_len() + 1];
            let expected = Err(CryptoError::WrongNonceLength {
                expected: algorithm.nonce_len(),
                found: wrong.len(),
            });
            assert_eq!(seal(algorithm, &key(), &wrong, b"", b"x"), expected);
            assert_eq!(open(algorithm, &key(), &wrong, b"", &[0_u8; 32]), expected);
        }
    }

    /// Data sealed with one algorithm must not open with the other, even though
    /// both take a 32-byte key. Only the 12-byte nonce case is testable, since
    /// the lengths differ.
    #[test]
    fn algorithms_do_not_interoperate() {
        let nonce = generate_nonce(AeadAlgorithm::Aes256Gcm).unwrap();
        let sealed = seal(AeadAlgorithm::Aes256Gcm, &key(), &nonce, b"", b"plaintext").unwrap();
        assert!(
            open(
                AeadAlgorithm::XChaCha20Poly1305,
                &key(),
                &nonce,
                b"",
                &sealed
            )
            .is_err()
        );
    }

    /// Two seals of identical input under different nonces must differ. If they
    /// did not, a nonce would not be doing its job and equal plaintexts would be
    /// visibly equal on disk.
    #[test]
    fn the_same_plaintext_seals_differently_under_different_nonces() {
        for algorithm in BOTH {
            let first_nonce = generate_nonce(algorithm).unwrap();
            let second_nonce = generate_nonce(algorithm).unwrap();
            let first = seal(algorithm, &key(), &first_nonce, b"", b"identical").unwrap();
            let second = seal(algorithm, &key(), &second_nonce, b"", b"identical").unwrap();
            assert_ne!(
                first,
                second,
                "{} produced identical ciphertexts",
                algorithm.name()
            );
        }
    }
}
