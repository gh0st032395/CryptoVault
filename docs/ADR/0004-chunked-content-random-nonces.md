# 0004 — Chunked content with a random nonce per write

**Status:** Accepted
**Date:** 2026-08-06

## Context

Vault files are mutable and can be large. Two requirements follow: reading a
small range must not decrypt the whole file, and writing a small range must not
rewrite the whole file.

That means splitting content into independently encrypted chunks. Which
immediately raises the question every chunked format has to answer: where does
each chunk's nonce come from?

The tempting answer is to derive it from the chunk index. It is deterministic,
costs no storage, and each file already has its own key, so indices cannot
collide across files.

It is also a trap.

## Decision

- Plaintext chunks of **32 KiB**, each stored as `nonce(12) ‖ ciphertext ‖ tag(16)`.
- **The nonce is fresh random bytes on every single chunk write.** Never derived
  from the index, the offset, or a counter.
- The additional authenticated data of chunk `i` is `u64_le(i) ‖ file_id`.
- `file_id` is random, 16 bytes, and **immutable for the life of the file**.
- The plaintext size lives inside the sealed header.

## Consequences

**Why the nonce must be random.** Chunks are rewritten in place. Edit a document
and chunk 3 is written again, with different content, under the same file key.
With a nonce derived from the index, that is a reused (key, nonce) pair on
different plaintext — which under GCM does not merely leak a relationship
between the two plaintexts, it discloses the authentication key and lets an
attacker forge chunks at will. The failure is silent: everything keeps working,
and the vault is broken.

Random 96-bit nonces under a per-file key leave a large margin — a collision
needs on the order of 2³² writes to the same file — at a cost of 12 bytes per
chunk.

**Why the AAD binds the index and `file_id`.** The index stops chunks being
reordered, duplicated or dropped. `file_id` stops a chunk being transplanted
from another file encrypted under the same content key.

**Why `file_id` and not the header nonce.** Metadata is mutable: adding a tag or
marking a file for versioning re-seals the header with a fresh nonce. Had the
chunks been bound to the header nonce, adding a tag would have invalidated every
chunk in the file — a bug that would have surfaced only once metadata editing
was implemented, well after the format was frozen.

**Why the size is in the header.** An AEAD tag detects a modified file but not a
truncated one. Without an authenticated length, chopping off the last chunk goes
unnoticed.

**Costs**

- 28 bytes per 32 KiB — 0.085% — plus 96 bytes of header.
- A one-byte write costs a read-modify-write of a whole 32 KiB chunk.
- Compression cannot be applied to a live file: it would break the fixed
  offset-to-chunk mapping. This is what pushed compression into a separate
  archived mode.

## Alternatives considered

- **Nonce derived from the chunk index.** Saves 12 bytes per chunk and is
  perfectly safe for write-once files. Catastrophic for mutable ones, as above.
- **Nonce derived from (index, write counter).** Safe, and saves the storage,
  but requires the counter to be tracked reliably across crashes, restores from
  backup and sync conflicts. A vault restored from yesterday's backup would
  replay counters. Not worth 12 bytes.
- **XChaCha20-Poly1305 with 192-bit nonces.** Removes any collision concern and
  is faster in software without AES-NI. Kept as `alg_id = 0x02` rather than made
  the default, since AES-NI is present on every desktop target and AES-256-GCM
  is what the Cryptera code already exercises.
- **Larger chunks (64 KiB or 1 MiB).** Lower overhead, better sequential
  throughput, worse small random writes. 32 KiB is the conventional balance and
  aligns with the page cache.
