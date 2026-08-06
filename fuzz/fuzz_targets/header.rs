//! Fuzzes the file-header parser with arbitrary bytes.
//!
//! The header is the first thing read from any file in a vault, and it is read
//! *before* anything has been authenticated. Its parser therefore sees whatever
//! is on disk: a truncated file, a corrupted one, or one written by somebody
//! who would like it to misbehave.
//!
//! The property under test is not that parsing succeeds — almost every input
//! here should be rejected. It is that parsing always *terminates cleanly*: no
//! panic, no out-of-bounds slice, no allocation sized from an unchecked length
//! field, no arithmetic overflow.

#![no_main]

use cv_crypto::secret::Key32;
use cv_format::FileHeader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = Key32::new([0x42; 32]);

    // Success is possible in principle and vanishingly unlikely in practice;
    // either way the only requirement is that we get here without panicking.
    if let Ok((header, len)) = FileHeader::open(data, &key) {
        // If a header ever does authenticate, its reported length must be
        // consistent with what was parsed — a caller uses it to locate the
        // first chunk.
        assert!(len as usize <= data.len());
        let _ = header.encoded_len();
    }
});
