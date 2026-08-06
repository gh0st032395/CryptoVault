//! Fuzzes filename decoding.
//!
//! Two things are being probed here, and the second is the one that matters.
//!
//! The first is ordinary robustness: `decode_stem` takes text straight from a
//! directory listing, and `decode` takes whatever that produced.
//!
//! The second is the traversal boundary. A decrypted name is never joined onto
//! a host path — a directory's location comes from the HMAC of its identifier —
//! but the parser is still required to refuse anything that could not address an
//! entry: `.`, `..`, a separator, a NUL. This target asserts that no input can
//! produce such a name, so the second of the two defences is real and not
//! merely intended.

#![no_main]

use cv_crypto::secret::Key32;
use cv_format::names;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = Key32::new([0x42; 32]);
    let dir_id = [0x07_u8; 16];

    // Arbitrary bytes as an on-disk stem.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(ciphertext) = names::decode_stem(text) {
            check(names::decode(&key, &dir_id, &ciphertext));
        }
        let _ = names::split_on_disk(text);
        let _ = names::is_companion(text);
    }

    // Arbitrary bytes as the contents of a `.cvn` companion.
    check(names::decode(&key, &dir_id, data));
});

/// A name that comes back out of the vault must always be one that could have
/// gone in. Anything else means the traversal defence has a hole.
fn check(result: Result<String, cv_format::FormatError>) {
    if let Ok(name) = result {
        assert!(!name.is_empty(), "decoded an empty name");
        assert!(name != "." && name != "..", "decoded a relative name: {name:?}");
        assert!(!name.contains('/'), "decoded a name containing a separator: {name:?}");
        assert!(!name.contains('\0'), "decoded a name containing a NUL: {name:?}");
    }
}
