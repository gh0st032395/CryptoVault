//! Fixed-size secret byte arrays that clean up after themselves.
//!
//! Every key in CryptoVault is a [`SecretBytes`]. The type exists to make three
//! mistakes hard to commit by accident:
//!
//! 1. **Leaving key material in freed memory.** The buffer is wiped on drop.
//! 2. **Printing a key.** [`Debug`] prints a placeholder, so a stray
//!    `dbg!`, a log line or a formatted error can never spill one.
//! 3. **Comparing keys in variable time.** Equality is constant-time, so a
//!    comparison cannot be turned into an oracle by measuring it.
//!
//! Reading the bytes requires calling [`SecretBytes::expose`], which is
//! deliberately ugly. Every call site is a place where a secret leaves its
//! wrapper, and it should be visible in review.
//!
//! # What wiping on drop does and does not do
//!
//! It removes one class of accident: the buffer is not left readable in memory
//! the allocator hands to something else. It does **not** defend against an
//! attacker who can read process memory while the value is alive — see
//! `docs/THREAT_MODEL.md` §B3. There is no way to hold a key in RAM and use it
//! without it being in RAM.

use std::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::CryptoError;

/// A 256-bit key: the size of every key in CryptoVault.
pub type Key32 = SecretBytes<32>;

/// A fixed-size buffer of secret bytes, wiped when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Wraps an existing array.
    ///
    /// The caller's copy is *not* wiped — arrays are `Copy`, so there is no way
    /// for this function to reach it. Prefer building the value in place with
    /// [`SecretBytes::zeroed`] and [`SecretBytes::expose_mut`] when the source
    /// bytes would otherwise linger.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// An all-zero buffer, ready to be filled in place.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self { bytes: [0_u8; N] }
    }

    /// Wraps a slice that must be exactly `N` bytes long.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::WrongKeyLength`] if the slice is the wrong size.
    /// This is the path taken by material read from disk, where the length is
    /// whatever a possibly corrupted file claimed.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; N] = slice.try_into().map_err(|_| CryptoError::WrongKeyLength {
            expected: N,
            found: slice.len(),
        })?;
        Ok(Self { bytes })
    }

    /// Borrows the secret bytes.
    ///
    /// Named to stand out at the call site: this is where a secret leaves its
    /// wrapper, and the copy you make from it is yours to look after.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Borrows the secret bytes mutably, for filling a buffer in place.
    #[must_use]
    pub const fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// Length in bytes. Always `N`; present so generic code need not name it.
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the buffer has no bytes. Only ever true for `SecretBytes<0>`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

/// Prints a placeholder, never the contents.
///
/// Without this, one `#[derive(Debug)]` on a struct three layers up is enough to
/// put a master key into a log file.
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(redacted)")
    }
}

/// Constant-time equality.
///
/// A variable-time comparison leaks how many leading bytes matched, which turns
/// "is this the right key?" into a way of discovering the key one byte at a time.
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_new_and_expose() {
        let key = Key32::new([7_u8; 32]);
        assert_eq!(key.expose(), &[7_u8; 32]);
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());
    }

    #[test]
    fn zeroed_starts_empty_and_can_be_filled_in_place() {
        let mut key = Key32::zeroed();
        assert_eq!(key.expose(), &[0_u8; 32]);

        key.expose_mut()[0] = 0xAB;
        assert_eq!(key.expose()[0], 0xAB);
    }

    #[test]
    fn from_slice_accepts_the_exact_length() {
        let key = Key32::from_slice(&[3_u8; 32]).unwrap();
        assert_eq!(key.expose(), &[3_u8; 32]);
    }

    #[test]
    fn from_slice_rejects_any_other_length() {
        for len in [0_usize, 1, 31, 33, 64] {
            let err = Key32::from_slice(&vec![0_u8; len]).unwrap_err();
            assert_eq!(
                err,
                CryptoError::WrongKeyLength {
                    expected: 32,
                    found: len
                }
            );
        }
    }

    #[test]
    fn equality_compares_contents() {
        let a = Key32::new([1_u8; 32]);
        let b = Key32::new([1_u8; 32]);
        let mut different = [1_u8; 32];
        different[31] = 2;
        let c = Key32::new(different);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// The whole point of the manual `Debug`: a key must not be printable, not
    /// even by accident, not even three layers up in a derived `Debug`.
    #[test]
    fn debug_output_contains_no_key_material() {
        let key = Key32::new([0xAB_u8; 32]);
        let printed = format!("{key:?}");

        assert_eq!(printed, "SecretBytes<32>(redacted)");
        assert!(
            !printed.contains("ab"),
            "the key leaked into Debug: {printed}"
        );
        assert!(
            !printed.contains("171"),
            "the key leaked into Debug: {printed}"
        );
    }

    /// A secret nested inside a derived `Debug` must stay redacted too — this is
    /// the realistic way a key reaches a log.
    #[test]
    fn debug_stays_redacted_when_nested() {
        #[derive(Debug)]
        struct Wrapper {
            #[allow(dead_code, reason = "the field exists so Debug prints it")]
            key: Key32,
        }

        let printed = format!(
            "{:?}",
            Wrapper {
                key: Key32::new([0xCD_u8; 32])
            }
        );
        assert!(printed.contains("redacted"), "{printed}");
        assert!(
            !printed.contains("cd"),
            "the key leaked through a derived Debug: {printed}"
        );
    }

    #[test]
    fn cloning_produces_an_equal_but_independent_value() {
        let original = Key32::new([9_u8; 32]);
        let mut copy = original.clone();
        assert_eq!(original, copy);

        copy.expose_mut()[0] = 0;
        assert_ne!(original, copy);
    }
}
