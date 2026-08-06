# 0002 — One encrypted file per vault file, not a single container

**Status:** Accepted
**Date:** 2026-08-06

## Context

There are two established ways to build an encrypted vault.

A **single container** — VeraCrypt's model — puts everything in one large file
with a filesystem inside it. It hides the number of files, their sizes and the
whole structure.

**Per-file encryption** — Cryptomator's model — stores each vault file as its
own encrypted file on disk, with names and directory structure encrypted too.

The requirements pull hard in one direction:

1. The vault must live inside a folder synced by Dropbox, iCloud, Drive or
   OneDrive. This was chosen as a first-class use case, not a nice-to-have.
2. Reading 4 KiB from a 2 GiB file must not decrypt 2 GiB.
3. A crash or an interrupted sync must not be able to destroy everything.

## Decision

Per-file encryption. Each vault file is one `.cvf` on disk; names are encrypted
with AES-SIV and directories are placed by the HMAC of a random identifier.

## Consequences

**Good**

- A sync client uploads only what changed. With a container, editing one text
  file re-uploads a multi-gigabyte blob.
- Corruption is bounded: a damaged file costs that file, not the vault.
- Random access is straightforward — there is no internal filesystem, no block
  allocator, no free list, no journal to write and get wrong.
- Renaming a directory of 10 000 files rewrites one file, because placement
  comes from an identifier and not from a path.

**Bad, and accepted**

- **The number of files is visible**, as are their approximate sizes (to within
  32 KiB), their timestamps and their modification pattern over time. For an
  observer who watches the synced folder for months, that is genuinely
  informative. It is written down in the threat model rather than glossed over.
- Tens of thousands of small files stress the host filesystem and some sync
  clients. Mitigated by sharding directories two characters deep.
- Plausible deniability becomes structurally weak: a hidden vault would usually
  be detectable from the file count alone. Hence the decision to defer that
  feature rather than ship a version of it that does not hold up.

## Alternatives considered

- **Single container.** Hides everything the above leaks, and would let
  Reed-Solomon protect the whole vault uniformly. Rejected on requirement 1: it
  is fundamentally hostile to incremental sync, and it would mean writing a
  filesystem — allocation, free lists, journalling — which is a large amount of
  code whose bugs lose all of a user's data at once.
- **Hybrid: small files and metadata in a container, large files outside.** Hides
  more than per-file while syncing better than a container. Rejected as the
  variant with the most implementation complexity and the least precedent, for a
  partial improvement in a property the threat model already discloses.
