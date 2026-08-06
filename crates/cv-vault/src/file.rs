//! Reading and writing an encrypted file at arbitrary offsets.
//!
//! This is where the chunked format stops being a description and starts being
//! a filesystem. Everything above — the VFS trait, the CLI, one day a mounted
//! drive — is expressed in terms of `read_at`, `write_at` and `truncate`, and
//! all three land here.
//!
//! # The read-modify-write cycle
//!
//! Chunks are the unit of encryption, so they are also the unit of change.
//! Writing one byte at offset 40 000 means: decrypt chunk 1, replace one byte,
//! re-encrypt the whole chunk under a **fresh nonce**, write it back. There is
//! no way to edit ciphertext in place, and pretending otherwise is how
//! authenticated encryption gets broken.
//!
//! The fresh nonce is not incidental. A chunk gets rewritten every time the user
//! touches it, so a nonce derived from the chunk index would repeat under the
//! same key on different plaintext — which with GCM discloses the
//! authentication key, silently. See `docs/ADR/0004`.
//!
//! # Growing a file
//!
//! Writing past the end must not leave a hole. A sparse region would read back
//! as a chunk that never existed, which fails authentication and looks like
//! corruption. So a write beyond the current size zero-fills the gap with real,
//! encrypted chunks first.
//!
//! # When the header is rewritten
//!
//! The plaintext length lives inside the sealed header, so any change to the
//! size means re-sealing it. That is deferred to [`VaultFile::flush`] rather
//! than done per write: a thousand small appends should cost one header rewrite,
//! not a thousand.
//!
//! Metadata, by contrast, is fixed for the lifetime of a handle. Changing it can
//! change the header's length, which would move every chunk in the file, so it
//! is a whole-file operation and not something a write can trigger by accident.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cv_crypto::aead::AeadAlgorithm;
use cv_crypto::secret::Key32;
use cv_format::chunk::{
    chunk_count_for_size, chunk_index_for_offset, offset_within_chunk, plaintext_len_of_chunk,
};
use cv_format::consts::CHUNK_PLAINTEXT_LEN;
use cv_format::content::{open_chunk, seal_chunk};
use cv_format::{FileHeader, FileMetadata, FileMode};

use crate::VaultError;

/// An open encrypted file.
///
/// Holds the decrypted header — and therefore the file's content key — for as
/// long as it exists. Dropping it wipes that key.
#[derive(Debug)]
pub struct VaultFile {
    file: File,
    path: PathBuf,
    content_key: Key32,
    header: FileHeader,
    header_len: u64,
    /// Physical bytes a full chunk occupies, for this file's algorithm.
    stored_chunk_len: u64,
    /// Set when `plain_size` has changed and the header no longer matches.
    header_stale: bool,
    /// Whether the handle was opened for writing.
    writable: bool,
}

impl VaultFile {
    /// Creates a new, empty encrypted file.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] if the file cannot be created or written,
    /// [`VaultError::Format`] if the header cannot be sealed.
    pub fn create(
        path: &Path,
        content_key: &Key32,
        algorithm: AeadAlgorithm,
        metadata: FileMetadata,
    ) -> Result<Self, VaultError> {
        let header = FileHeader::create(algorithm, FileMode::Live, metadata)?;
        let bytes = header.seal(content_key)?;

        crate::atomic::write(path, &bytes)?;

        let mut opened = Self::open(path, content_key, true)?;
        opened.header_stale = false;
        Ok(opened)
    }

    /// Opens an existing encrypted file.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] if it cannot be opened or read, [`VaultError::Format`]
    /// if the header does not parse or does not authenticate under `content_key`.
    pub fn open(path: &Path, content_key: &Key32, writable: bool) -> Result<Self, VaultError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(writable)
            .open(path)
            .map_err(|source| VaultError::io_ref("opening an encrypted file", &source))?;

        // The header is bounded, so reading a fixed prefix is enough to parse it
        // however large the file is. 64 KiB covers the metadata ceiling with
        // room to spare.
        let mut prefix = vec![0_u8; 128 * 1024];
        let read = read_up_to(&mut file, &mut prefix)?;
        prefix.truncate(read);

        let (header, header_len) = FileHeader::open(&prefix, content_key)?;
        let stored_chunk_len = u64::from(CHUNK_PLAINTEXT_LEN)
            + as_u64(header.algorithm.nonce_len())
            + as_u64(header.algorithm.tag_len());

        Ok(Self {
            file,
            path: path.to_path_buf(),
            content_key: content_key.clone(),
            header,
            header_len,
            stored_chunk_len,
            header_stale: false,
            writable,
        })
    }

    /// Length of the plaintext.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.header.plain_size
    }

    /// The file's metadata.
    #[must_use]
    pub const fn metadata(&self) -> &FileMetadata {
        &self.header.metadata
    }

    /// Where this file sits on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads into `buf`, starting at plaintext offset `offset`.
    ///
    /// Returns the number of bytes read, which is short at the end of the file
    /// and zero past it — the same contract as a POSIX read.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] on a read failure, [`VaultError::Format`] if a chunk
    /// does not authenticate.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, VaultError> {
        let size = self.size();
        if offset >= size || buf.is_empty() {
            return Ok(0);
        }

        let wanted = usize_of(size - offset)?.min(buf.len());
        let mut done = 0_usize;

        while done < wanted {
            let position = offset + as_u64(done);
            let index = chunk_index_for_offset(position);
            let within = usize_of(offset_within_chunk(position))?;

            let plain = self.read_chunk(index)?;
            if within >= plain.len() {
                return Err(VaultError::Corrupt {
                    reason: format!("chunk {index} is shorter than the file's length claims"),
                });
            }

            let take = (plain.len() - within).min(wanted - done);
            buf[done..done + take].copy_from_slice(&plain[within..within + take]);
            done += take;
        }

        Ok(done)
    }

    /// Reads the whole file.
    ///
    /// # Errors
    ///
    /// As [`VaultFile::read_at`].
    pub fn read_all(&mut self) -> Result<Vec<u8>, VaultError> {
        let mut out = vec![0_u8; usize_of(self.size())?];
        let read = self.read_at(0, &mut out)?;
        out.truncate(read);
        Ok(out)
    }

    /// Writes `data` at plaintext offset `offset`, extending the file if needed.
    ///
    /// A write beyond the current end zero-fills the gap with real encrypted
    /// chunks rather than leaving a hole: a sparse region would read back as a
    /// chunk that was never written, fail authentication, and be indisputable
    /// from actual corruption.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] on a write failure, [`VaultError::Format`] if sealing
    /// fails, [`VaultError::ReadOnly`] if the handle was not opened for writing.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), VaultError> {
        self.require_writable()?;

        if data.is_empty() {
            return Ok(());
        }

        if offset > self.size() {
            self.zero_extend_to(offset)?;
        }

        let mut written = 0_usize;
        while written < data.len() {
            let position = offset + as_u64(written);
            let index = chunk_index_for_offset(position);
            let within = usize_of(offset_within_chunk(position))?;

            let capacity = usize_of(u64::from(CHUNK_PLAINTEXT_LEN))? - within;
            let take = capacity.min(data.len() - written);

            let mut plain = if index < chunk_count_for_size(self.size()) {
                self.read_chunk(index)?
            } else {
                Vec::new()
            };

            // A write that starts past the end of an existing partial chunk pads
            // the gap. This is the within-chunk case of the same rule as above.
            if plain.len() < within {
                plain.resize(within, 0);
            }
            if plain.len() < within + take {
                plain.resize(within + take, 0);
            }
            plain[within..within + take].copy_from_slice(&data[written..written + take]);

            self.write_chunk(index, &plain)?;

            let reached = position + as_u64(take);
            if reached > self.header.plain_size {
                self.header.plain_size = reached;
                self.header_stale = true;
            }

            written += take;
        }

        Ok(())
    }

    /// Sets the file's length, growing with zeros or discarding the tail.
    ///
    /// # Errors
    ///
    /// As [`VaultFile::write_at`], plus [`VaultError::Io`] if the underlying
    /// file cannot be resized.
    pub fn truncate(&mut self, new_size: u64) -> Result<(), VaultError> {
        self.require_writable()?;

        let current = self.size();

        if new_size > current {
            return self.zero_extend_to(new_size);
        }
        if new_size == current {
            return Ok(());
        }

        // Shrinking. The chunk the new end falls inside has to be re-encrypted
        // shorter; everything after it simply stops existing.
        let physical = if new_size == 0 {
            self.header_len
        } else {
            let last = chunk_index_for_offset(new_size - 1);
            let keep = usize_of(plaintext_len_of_chunk(last, new_size))?;

            let mut plain = self.read_chunk(last)?;
            plain.truncate(keep);

            // plain_size is lowered first so write_chunk seals a chunk whose
            // length agrees with the file it is about to belong to.
            self.header.plain_size = new_size;
            self.write_chunk(last, &plain)?;

            self.chunk_offset(last)? + as_u64(keep) + self.chunk_overhead()
        };

        self.header.plain_size = new_size;
        self.header_stale = true;

        self.file
            .set_len(physical)
            .map_err(|source| VaultError::io_ref("shortening an encrypted file", &source))?;

        Ok(())
    }

    /// Re-seals the header if the size has changed, and flushes to disk.
    ///
    /// Deferred rather than done per write: appending a thousand small pieces
    /// should cost one header rewrite. Every path that finishes with a file —
    /// including [`Drop`] — goes through here.
    ///
    /// # Errors
    ///
    /// [`VaultError::Io`] or [`VaultError::Format`] if the header cannot be
    /// written.
    pub fn flush(&mut self) -> Result<(), VaultError> {
        if self.header_stale {
            let bytes = self.header.seal(&self.content_key)?;

            // Re-sealing produces the same length, because the metadata has not
            // changed, so this overwrite cannot disturb the chunks behind it.
            if as_u64(bytes.len()) != self.header_len {
                return Err(VaultError::Corrupt {
                    reason: "re-sealing the header changed its length".to_owned(),
                });
            }

            self.seek(0)?;
            self.file
                .write_all(&bytes)
                .map_err(|source| VaultError::io_ref("rewriting a file header", &source))?;
            self.header_stale = false;
        }

        self.file
            .sync_all()
            .map_err(|source| VaultError::io_ref("flushing an encrypted file", &source))
    }

    // --- internals ---------------------------------------------------------

    fn require_writable(&self) -> Result<(), VaultError> {
        if self.writable {
            Ok(())
        } else {
            Err(VaultError::ReadOnly)
        }
    }

    fn chunk_overhead(&self) -> u64 {
        self.stored_chunk_len - u64::from(CHUNK_PLAINTEXT_LEN)
    }

    fn chunk_offset(&self, index: u64) -> Result<u64, VaultError> {
        index
            .checked_mul(self.stored_chunk_len)
            .and_then(|body| body.checked_add(self.header_len))
            .ok_or_else(|| VaultError::Corrupt {
                reason: format!("chunk {index} is beyond the addressable range"),
            })
    }

    fn read_chunk(&mut self, index: u64) -> Result<Vec<u8>, VaultError> {
        let plain_len = plaintext_len_of_chunk(index, self.size());
        if plain_len == 0 {
            return Ok(Vec::new());
        }

        let stored_len = usize_of(plain_len + self.chunk_overhead())?;
        let mut stored = vec![0_u8; stored_len];

        self.seek(self.chunk_offset(index)?)?;
        self.file
            .read_exact(&mut stored)
            .map_err(|source| VaultError::io_ref("reading a chunk", &source))?;

        Ok(open_chunk(&self.header, index, &stored)?)
    }

    fn write_chunk(&mut self, index: u64, plain: &[u8]) -> Result<(), VaultError> {
        let sealed = seal_chunk(&self.header, index, plain)?;

        self.seek(self.chunk_offset(index)?)?;
        self.file
            .write_all(&sealed)
            .map_err(|source| VaultError::io_ref("writing a chunk", &source))
    }

    /// Grows the file to `target` with zeros, one real chunk at a time.
    fn zero_extend_to(&mut self, target: u64) -> Result<(), VaultError> {
        while self.size() < target {
            let position = self.size();
            let index = chunk_index_for_offset(position);
            let within = usize_of(offset_within_chunk(position))?;

            let room = usize_of(u64::from(CHUNK_PLAINTEXT_LEN))? - within;
            let take = room.min(usize_of(target - position)?);

            let mut plain = if index < chunk_count_for_size(self.size()) {
                self.read_chunk(index)?
            } else {
                Vec::new()
            };
            plain.resize(within + take, 0);

            self.write_chunk(index, &plain)?;
            self.header.plain_size = position + as_u64(take);
            self.header_stale = true;
        }
        Ok(())
    }

    fn seek(&mut self, position: u64) -> Result<(), VaultError> {
        self.file
            .seek(SeekFrom::Start(position))
            .map(|_| ())
            .map_err(|source| VaultError::io_ref("seeking in an encrypted file", &source))
    }
}

impl Drop for VaultFile {
    /// A handle dropped without an explicit flush still writes its header.
    ///
    /// Losing the length of a file because a caller forgot to flush would mean
    /// losing the data past the old end — recorded chunks that nothing points
    /// at. The error cannot be reported from here, so callers that care call
    /// [`VaultFile::flush`] themselves; this is the safety net, not the plan.
    fn drop(&mut self) {
        if self.header_stale {
            let _ = self.flush();
        }
    }
}

/// Reads as much as the buffer holds, tolerating a short file.
fn read_up_to(file: &mut File, buf: &mut [u8]) -> Result<usize, VaultError> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(source) => return Err(VaultError::io_ref("reading a file header", &source)),
        }
    }
    Ok(filled)
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn usize_of(value: u64) -> Result<usize, VaultError> {
    usize::try_from(value).map_err(|_| VaultError::Corrupt {
        reason: format!("{value} bytes is beyond what this machine can address"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHUNK: u64 = 32 * 1024;

    struct Fixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
        key: Key32,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("entry.cvf");
            Self {
                _dir: dir,
                path,
                key: Key32::new([0x11; 32]),
            }
        }

        fn create(&self) -> VaultFile {
            VaultFile::create(
                &self.path,
                &self.key,
                AeadAlgorithm::Aes256Gcm,
                FileMetadata::default(),
            )
            .unwrap()
        }

        fn reopen(&self) -> VaultFile {
            VaultFile::open(&self.path, &self.key, true).unwrap()
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    #[test]
    fn a_new_file_is_empty() {
        let fixture = Fixture::new();
        let file = fixture.create();
        assert_eq!(file.size(), 0);
    }

    #[test]
    fn writing_and_reading_back_round_trips() {
        let fixture = Fixture::new();
        let mut file = fixture.create();

        file.write_at(0, b"hello vault").unwrap();
        file.flush().unwrap();

        assert_eq!(file.size(), 11);
        assert_eq!(file.read_all().unwrap(), b"hello vault");
    }

    #[test]
    fn contents_survive_closing_and_reopening() {
        let fixture = Fixture::new();
        {
            let mut file = fixture.create();
            file.write_at(0, b"persisted").unwrap();
            file.flush().unwrap();
        }
        assert_eq!(fixture.reopen().read_all().unwrap(), b"persisted");
    }

    /// A handle dropped without flushing must not lose the file's length —
    /// the chunks are on disk, and a stale header would orphan them.
    #[test]
    fn dropping_without_flushing_still_records_the_length() {
        let fixture = Fixture::new();
        {
            let mut file = fixture.create();
            file.write_at(0, b"never explicitly flushed").unwrap();
        }
        assert_eq!(
            fixture.reopen().read_all().unwrap(),
            b"never explicitly flushed"
        );
    }

    #[test]
    fn files_spanning_several_chunks_round_trip() {
        for size in [1_usize, 4096, 32_768, 32_769, 70_000, 200_000] {
            let fixture = Fixture::new();
            let data = pattern(size);

            let mut file = fixture.create();
            file.write_at(0, &data).unwrap();
            file.flush().unwrap();

            assert_eq!(file.size(), size as u64, "size wrong for {size}");
            assert_eq!(
                fixture.reopen().read_all().unwrap(),
                data,
                "contents wrong for {size}"
            );
        }
    }

    /// The whole point of chunking: reading a small range must not require the
    /// rest of the file, and must land on the right bytes.
    #[test]
    fn reading_at_an_offset_returns_the_right_window() {
        let fixture = Fixture::new();
        let data = pattern(100_000);

        let mut file = fixture.create();
        file.write_at(0, &data).unwrap();
        file.flush().unwrap();

        for (offset, len) in [
            (0_u64, 10_usize),
            (1, 10),
            (CHUNK - 5, 10),
            (CHUNK, 10),
            (99_990, 10),
        ] {
            let mut buf = vec![0_u8; len];
            let read = file.read_at(offset, &mut buf).unwrap();
            let start = usize::try_from(offset).unwrap();
            assert_eq!(read, len, "short read at {offset}");
            assert_eq!(buf, &data[start..start + len], "wrong window at {offset}");
        }
    }

    #[test]
    fn reading_past_the_end_returns_nothing() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, b"short").unwrap();

        let mut buf = [0_u8; 16];
        assert_eq!(file.read_at(5, &mut buf).unwrap(), 0);
        assert_eq!(file.read_at(1000, &mut buf).unwrap(), 0);
    }

    #[test]
    fn a_read_straddling_the_end_is_short_rather_than_padded() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, b"12345").unwrap();

        let mut buf = [0_u8; 16];
        assert_eq!(file.read_at(3, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"45");
    }

    /// Overwriting in the middle is the read-modify-write path, and it must not
    /// disturb a byte on either side.
    #[test]
    fn overwriting_in_place_changes_only_what_it_should() {
        let fixture = Fixture::new();
        let mut data = pattern(100_000);

        let mut file = fixture.create();
        file.write_at(0, &data).unwrap();

        file.write_at(50_000, b"REPLACED").unwrap();
        data[50_000..50_008].copy_from_slice(b"REPLACED");
        file.flush().unwrap();

        assert_eq!(file.size(), 100_000);
        assert_eq!(fixture.reopen().read_all().unwrap(), data);
    }

    /// A write that spans a chunk boundary touches two chunks and must stitch
    /// them back together exactly.
    #[test]
    fn a_write_across_a_chunk_boundary_is_seamless() {
        let fixture = Fixture::new();
        let mut data = pattern(70_000);

        let mut file = fixture.create();
        file.write_at(0, &data).unwrap();

        let across = pattern(100);
        let at = CHUNK - 50;
        file.write_at(at, &across).unwrap();
        data[usize::try_from(at).unwrap()..usize::try_from(at).unwrap() + 100]
            .copy_from_slice(&across);
        file.flush().unwrap();

        assert_eq!(fixture.reopen().read_all().unwrap(), data);
    }

    /// Rewriting the same chunk many times is the ordinary case for a document
    /// being edited, and the case a counter-based nonce would have broken.
    #[test]
    fn a_chunk_can_be_rewritten_repeatedly() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, &pattern(1000)).unwrap();

        for round in 0..50_u8 {
            file.write_at(100, &[round; 10]).unwrap();
            let mut buf = [0_u8; 10];
            file.read_at(100, &mut buf).unwrap();
            assert_eq!(buf, [round; 10], "round {round}");
        }
    }

    /// A hole would read back as a chunk that was never written, fail
    /// authentication, and be indistinguishable from corruption.
    #[test]
    fn writing_past_the_end_zero_fills_the_gap() {
        let fixture = Fixture::new();
        let mut file = fixture.create();

        file.write_at(0, b"start").unwrap();
        file.write_at(70_000, b"end").unwrap();
        file.flush().unwrap();

        let contents = fixture.reopen().read_all().unwrap();
        assert_eq!(contents.len(), 70_003);
        assert_eq!(&contents[..5], b"start");
        assert!(
            contents[5..70_000].iter().all(|&b| b == 0),
            "the gap is not zeros"
        );
        assert_eq!(&contents[70_000..], b"end");
    }

    #[test]
    fn truncating_shorter_discards_the_tail() {
        let fixture = Fixture::new();
        let data = pattern(100_000);

        let mut file = fixture.create();
        file.write_at(0, &data).unwrap();

        for new_size in [70_000_u64, 32_769, 32_768, 32_767, 100, 1] {
            file.truncate(new_size).unwrap();
            file.flush().unwrap();

            let mut reopened = fixture.reopen();
            assert_eq!(reopened.size(), new_size);
            let expected = &data[..usize::try_from(new_size).unwrap()];
            assert_eq!(
                reopened.read_all().unwrap(),
                expected,
                "wrong after {new_size}"
            );
        }
    }

    #[test]
    fn truncating_to_zero_leaves_a_valid_empty_file() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, &pattern(100_000)).unwrap();

        file.truncate(0).unwrap();
        file.flush().unwrap();

        let mut reopened = fixture.reopen();
        assert_eq!(reopened.size(), 0);
        assert_eq!(reopened.read_all().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn truncating_longer_grows_with_zeros() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, b"abc").unwrap();

        file.truncate(50_000).unwrap();
        file.flush().unwrap();

        let contents = fixture.reopen().read_all().unwrap();
        assert_eq!(contents.len(), 50_000);
        assert_eq!(&contents[..3], b"abc");
        assert!(contents[3..].iter().all(|&b| b == 0));
    }

    /// Shrinking must actually reclaim space. A truncate that only changed the
    /// recorded length would leave the discarded ciphertext on disk.
    #[test]
    fn truncating_shrinks_the_file_on_disk() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, &pattern(200_000)).unwrap();
        file.flush().unwrap();

        let before = std::fs::metadata(&fixture.path).unwrap().len();
        file.truncate(1000).unwrap();
        file.flush().unwrap();
        let after = std::fs::metadata(&fixture.path).unwrap().len();

        assert!(after < before / 10, "{after} bytes left of {before}");
    }

    /// A write to a read-only handle must say so, rather than surfacing
    /// whatever the operating system calls a write to a read-only descriptor.
    #[test]
    fn writing_to_a_read_only_handle_is_refused_clearly() {
        let fixture = Fixture::new();
        fixture.create().write_at(0, b"contents").unwrap();

        let mut read_only = VaultFile::open(&fixture.path, &fixture.key, false).unwrap();
        assert_eq!(read_only.read_all().unwrap(), b"contents");
        assert_eq!(read_only.write_at(0, b"nope"), Err(VaultError::ReadOnly));
        assert_eq!(read_only.truncate(0), Err(VaultError::ReadOnly));

        // …and nothing changed.
        assert_eq!(fixture.reopen().read_all().unwrap(), b"contents");
    }

    #[test]
    fn the_wrong_key_cannot_open_the_file() {
        let fixture = Fixture::new();
        fixture.create().write_at(0, b"secret").unwrap();

        assert!(VaultFile::open(&fixture.path, &Key32::new([0x99; 32]), false).is_err());
    }

    #[test]
    fn the_plaintext_is_not_present_on_disk() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, b"VERY-DISTINCTIVE-PLAINTEXT").unwrap();
        file.flush().unwrap();

        let raw = std::fs::read(&fixture.path).unwrap();
        assert!(!raw.windows(26).any(|w| w == b"VERY-DISTINCTIVE-PLAINTEXT"));
    }

    #[test]
    fn both_algorithms_work_end_to_end() {
        for algorithm in [AeadAlgorithm::Aes256Gcm, AeadAlgorithm::XChaCha20Poly1305] {
            let fixture = Fixture::new();
            let data = pattern(70_000);

            let mut file = VaultFile::create(
                &fixture.path,
                &fixture.key,
                algorithm,
                FileMetadata::default(),
            )
            .unwrap();
            file.write_at(0, &data).unwrap();
            file.flush().unwrap();

            assert_eq!(
                fixture.reopen().read_all().unwrap(),
                data,
                "{algorithm:?} failed"
            );
        }
    }

    #[test]
    fn metadata_survives_a_round_trip() {
        let fixture = Fixture::new();
        let metadata = FileMetadata {
            mtime: Some(1_770_000_000),
            tags: vec!["work".into()],
            ..FileMetadata::default()
        };

        VaultFile::create(
            &fixture.path,
            &fixture.key,
            AeadAlgorithm::Aes256Gcm,
            metadata,
        )
        .unwrap()
        .write_at(0, b"x")
        .unwrap();

        let reopened = fixture.reopen();
        assert_eq!(reopened.metadata().mtime, Some(1_770_000_000));
        assert_eq!(reopened.metadata().tags, ["work"]);
    }

    #[test]
    fn an_empty_write_changes_nothing() {
        let fixture = Fixture::new();
        let mut file = fixture.create();
        file.write_at(0, b"abc").unwrap();
        file.write_at(1, b"").unwrap();
        assert_eq!(file.size(), 3);
    }

    /// Appending in many small pieces is what an import does, and it must
    /// produce the same file as one large write.
    #[test]
    fn many_small_appends_build_the_same_file() {
        let fixture = Fixture::new();
        let data = pattern(50_000);

        let mut file = fixture.create();
        let mut written = 0_u64;
        for piece in data.chunks(997) {
            file.write_at(written, piece).unwrap();
            written += u64::try_from(piece.len()).unwrap();
        }
        file.flush().unwrap();

        assert_eq!(fixture.reopen().read_all().unwrap(), data);
    }
}
