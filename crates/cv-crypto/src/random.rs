//! Randomness, from the operating system and nowhere else.
//!
//! Every random value in CryptoVault — master seeds, file keys, nonces, salts,
//! identifiers — comes through this module, and this module has exactly one
//! source: the operating system's CSPRNG.
//!
//! # Why every function returns a `Result`
//!
//! The usual convenience wrappers panic if the OS refuses to provide entropy.
//! Panicking is the wrong answer *and* so is continuing: a nonce that is not
//! random breaks AES-GCM outright, and a "random" key that is not random is not
//! a key. Both failures are silent — the file encrypts, the vault opens,
//! everything looks fine.
//!
//! So the error is propagated and the operation fails loudly. Losing an unlock
//! attempt is recoverable; writing a file under a predictable key is not.
//!
//! In practice this failure is close to unheard of on a healthy desktop. It is
//! handled anyway, because the cost of handling it is three lines and the cost
//! of not handling it is unbounded.

use rand::RngCore;
use rand::rngs::OsRng;

use crate::CryptoError;
use crate::secret::SecretBytes;

/// Fills a buffer with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`CryptoError::RandomnessUnavailable`] if the operating system could
/// not provide entropy.
pub fn fill(buffer: &mut [u8]) -> Result<(), CryptoError> {
    OsRng
        .try_fill_bytes(buffer)
        .map_err(|source| CryptoError::RandomnessUnavailable {
            reason: source.to_string(),
        })
}

/// Returns an array of random bytes.
///
/// Used for values that are not secret but must be unpredictable: nonces,
/// salts, file identifiers, directory identifiers.
///
/// # Errors
///
/// As [`fill`].
pub fn array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    fill(&mut bytes)?;
    Ok(bytes)
}

/// Returns a fresh secret key of `N` bytes.
///
/// The buffer is created zeroed inside its wrapper and filled in place, so the
/// key never exists in a plain array that nothing would wipe.
///
/// # Errors
///
/// As [`fill`].
pub fn secret<const N: usize>() -> Result<SecretBytes<N>, CryptoError> {
    let mut key = SecretBytes::<N>::zeroed();
    fill(key.expose_mut())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Key32;
    use std::collections::HashSet;

    #[test]
    fn fill_replaces_the_whole_buffer() {
        let mut buffer = [0_u8; 64];
        fill(&mut buffer).unwrap();
        assert!(
            buffer.iter().any(|&b| b != 0),
            "the buffer was left untouched"
        );
    }

    #[test]
    fn filling_an_empty_buffer_is_not_an_error() {
        fill(&mut []).unwrap();
    }

    /// Not a statistical test — a real one belongs to the OS, not to us. This
    /// catches the failure that actually happens in practice: a wiring mistake
    /// that returns the same bytes, or zeros, every time.
    #[test]
    fn successive_values_differ() {
        let mut seen = HashSet::new();
        for _ in 0..64 {
            assert!(
                seen.insert(array::<32>().unwrap()),
                "a 32-byte value repeated"
            );
        }
    }

    #[test]
    fn secret_keys_are_random_and_not_zero() {
        let a: Key32 = secret().unwrap();
        let b: Key32 = secret().unwrap();

        assert_ne!(a, b);
        assert_ne!(a.expose(), &[0_u8; 32], "the key came back all zeros");
    }

    #[test]
    fn arrays_of_every_size_we_use_are_filled() {
        assert!(array::<12>().unwrap().iter().any(|&b| b != 0)); // AEAD nonce
        assert!(array::<16>().unwrap().iter().any(|&b| b != 0)); // file id, salt
        assert!(array::<24>().unwrap().iter().any(|&b| b != 0)); // XChaCha nonce
        assert!(array::<32>().unwrap().iter().any(|&b| b != 0)); // key material
    }
}
