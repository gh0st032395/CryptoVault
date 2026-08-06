# 0005 — External applications first, virtual mount later

**Status:** Accepted
**Date:** 2026-08-06

## Context

"Using" a file in a vault can mean three things.

A **virtual mounted drive** — FUSE on macOS and Linux, WinFsp on Windows — makes
the vault look like an ordinary volume. Every application works with it
transparently and no plaintext ever reaches a disk. It is the best answer, and
the most expensive one: three different driver stacks, an external dependency
the user must install, elevated permissions, a system extension approval on
recent macOS, and a support burden that lands squarely on the least technical
users.

**Decrypt to a temporary file and open it with the system's default
application** works everywhere today, needs no drivers and no permissions, and
gives the user the applications they already know. The cost is that plaintext
exists on disk for the duration of the session.

**Internal viewers only** never let plaintext out, and cannot open a `.docx`.

## Decision

Ship the temporary-file approach in version 1, with the virtual mount as
milestone M14 — and design the filesystem abstraction from day one so that the
mount is an adapter rather than a rewrite.

Concretely, `cv-vfs::VaultFs` is **offset-based**: `read_at`, `write_at`,
`truncate`, `stat`, `read_dir`. That is precisely the vocabulary FUSE and WinFsp
speak.

## Consequences

**Good**

- A usable product months earlier, with no installation friction and no elevated
  privileges.
- The abstraction is not speculative architecture: it is the exact shape the
  mount needs, and building it later would mean rewriting everything above it.
- The internal viewers built for sealed vaults (M5) are useful on their own.

**Bad, and accepted**

- **Plaintext exists on disk during a session**, and secure deletion afterwards
  is best-effort: SSD wear levelling, copy-on-write on APFS and Btrfs, and Time
  Machine snapshots all defeat overwriting. This is threat model R1, stated in
  the interface as well as the document.
- Every external application saves differently. Word writes and renames
  repeatedly; some editors truncate then rewrite. M4 needs a per-application
  test matrix, and it is where the surprises will be.
- A crash can leave plaintext temporaries behind. Mitigated with a session
  journal that is checked at startup.

**Mitigations before M14**

- Volatile storage where the platform offers it: `/dev/shm` on Linux, an
  optional RAM disk on macOS.
- Session directories at `0700`, removed on lock, on quit and on timeout.
- Sealed vaults, which forbid external applications entirely and rely on the
  internal viewers.

## Alternatives considered

- **Mount first.** The technically superior answer, and the wrong first move: it
  puts the hardest, most platform-specific, most support-heavy component before
  anything works at all, and it cannot be tested without solving distribution
  first.
- **Internal viewers only.** Genuinely secure and genuinely limited — no `.docx`,
  no `.psd`, no editing. Kept as the *sealed vault* mode, which is where that
  trade-off is the right one, rather than imposed on every vault.
