//! Fuzzes chunk decryption with arbitrary stored bytes.
//!
//! A chunk read from disk may be truncated by a crash, half-written by a sync
//! client, or deliberately mangled. `open_chunk` must reject all of it without
//! panicking — in particular it must not index past the end when splitting the
//! nonce from the ciphertext, which is the obvious way to get this wrong.
//!
//! The chunk index is taken from the input too, so the target also covers the
//! associated-data construction at arbitrary indices, including `u64::MAX`.

#![no_main]

use cv_crypto::aead::AeadAlgorithm;
use cv_format::content::open_chunk;
use cv_format::{FileHeader, FileMetadata, FileMode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A header is needed to supply the file key and identity. It is created
    // once per input rather than reused, which is slower but keeps the target
    // free of shared state.
    let Ok(header) =
        FileHeader::create(AeadAlgorithm::Aes256Gcm, FileMode::Live, FileMetadata::default())
    else {
        return;
    };

    // Take the chunk index from the front of the input so the fuzzer can steer
    // it, including to the boundaries.
    let (index, stored) = if data.len() >= 8 {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&data[..8]);
        (u64::from_le_bytes(bytes), &data[8..])
    } else {
        (0, data)
    };

    let _ = open_chunk(&header, index, stored);
});
