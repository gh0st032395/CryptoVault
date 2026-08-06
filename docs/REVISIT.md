# Things to revisit

A running register of decisions that were right *for now* and need looking at
again later — shortcuts taken deliberately, limits accepted with a reason,
questions parked because answering them was premature.

## Why this file exists

Every one of these was obvious to somebody on the day it was written down. None
of them will be obvious in four months. Without a list they turn into the worst
kind of technical debt: the kind nobody remembers taking on, that gets
discovered when it breaks.

This is **not** a backlog of features — `PLAN.md` has those — and not a bug
list. It is the set of places where the code is knowingly less than it should
eventually be.

## How to use it

- **Add an entry** when you write something you would not defend as final.
  Say what it is, why it is like that, and what would make it wrong.
- **Give it a milestone** if you know when it must be dealt with, or `—` if it
  just needs periodic re-reading.
- **Remove an entry** when it is resolved, in the commit that resolves it.
- **Re-read the whole file at the end of every milestone.** That is when the
  entries that have quietly become urgent make themselves known.

Severity is about what happens if it is never revisited:

| | |
|---|---|
| 🔴 | Users could lose data or be misled about their security |
| 🟠 | Real limitation; will hurt at scale or on some platform |
| 🟡 | Quality, ergonomics, or a decision that deserves a second look |

---

## Open

### 🔴 R-01 — Secure deletion of session temporaries cannot be guaranteed
**From:** M0 threat model · **Due:** M4, resolved by M14

Overwriting a temporary file does not reliably erase it on an SSD (wear
levelling), on APFS or Btrfs (copy-on-write), or where Time Machine or Volume
Shadow Copy has already snapshotted it.

*Revisit when:* M4 implements external-application sessions. The interface must
say this where the user can see it, not only in the threat model. The real fix
is the virtual mount in M14.

### 🔴 R-02 — No recovery key yet, and the format is ready for one
**From:** M1 · **Due:** M11

Slot kind 2 exists in the format and nothing generates one. Until then, a lost
password is unrecoverable with no second chance at all.

*Revisit when:* before any public release. Shipping a vault people put real data
in, with exactly one way to open it and no warning at creation beyond text, is a
decision to make deliberately rather than by default.

### 🟠 R-03 — Directory listing opens every entry to report sizes
**From:** M2 · **Due:** M5

`Vault::read_dir` decrypts names only, but `stat` opens a file header per entry.
A browser showing sizes for a directory of 10 000 files does 10 000 opens.

*Revisit when:* M5 builds the search index — the same cache can carry sizes.
Until then the interface should show sizes lazily rather than up front.

### 🟠 R-04 — The VFS resolves a path on every operation
**From:** M2 · **Due:** M14

`read_at` and `write_at` take a path and walk it component by component. Fine
for a CLI and a file browser; wasteful for a mount servicing 4 KiB reads.

*Revisit when:* M14. Adding an open/close handle pair is an addition — the
offset-based shape does not change — but it must happen before the mount, not
after.

### 🟠 R-05 — Linux is built and tested only by CI
**From:** M0 · **Due:** M10

No one runs the application on Linux by hand. The bugs that only appear in
interactive use will not be found by the test suite.

*Revisit when:* M10. Either Linux ships labelled beta, or there is a public test
phase before the label comes off.

### 🟡 R-06 — Argon2id parameters are not calibrated on the machine
**From:** M1 · **Due:** M3

`Argon2Params::default_profile()` is a fixed 256 MiB / 3 / 4. The documentation
says vault creation calibrates upward from it; nothing does yet.

*Revisit when:* M3 adds vault creation in the interface, which is the first place
a calibration could run and show its result.

### 🟡 R-07 — `verify` reads a whole vault serially
**From:** M2 · **Due:** M6

Single-threaded, one file at a time. On a large vault it will be slow enough
that people stop running it, which makes it useless.

*Revisit when:* M6 makes integrity checking a product feature. Cryptera's
`rayon` parallelism is the obvious answer.

### 🟡 R-08 — No cancellation or progress in long operations
**From:** M2 · **Due:** M3

`add` and `get` copy in a loop with no way to stop them and nothing to report.
Deferred from M2 because progress needs somewhere to be shown.

*Revisit when:* M3, together with the operation queue in the interface.

### 🟡 R-09 — Removing a directory requires it to be empty
**From:** M2 · **Due:** M3

There is no recursive remove. Correct and safe, and not what a user expects from
a file browser.

*Revisit when:* M3. A recursive delete needs a confirmation and — once M6 lands
— should route through the trash rather than actually deleting.

### 🟡 R-10 — Metadata cannot be changed on an open file
**From:** M2 · **Due:** M6

Changing metadata can change the header's length, which would move every chunk,
so `VaultFile` fixes it for the lifetime of a handle. Tags and the versioning
flag therefore cannot be edited yet.

*Revisit when:* M6 introduces per-file versioning, which the user has to be able
to switch on. Options: rewrite the file, or pad the metadata block to a fixed
size so the header length stops depending on it.

### 🟡 R-11 — Nothing detects a vault opened from two machines
**From:** M2 · **Due:** M7

`.cvlock` is specified and not implemented. Two machines can write the same
synced vault at once, and the second one to write wins silently.

*Revisit when:* M7.

### 🟡 R-12 — Key material is not locked out of swap
**From:** M1 · **Due:** M10

The plan calls for `mlock`/`VirtualLock` on key material. `Zeroizing` is in
place; the memory locking is not, so a derived key can be paged to disk.

*Revisit when:* M10 at the latest. It needs one `unsafe` call per platform and a
graceful fallback where the operating system refuses.

### 🟠 R-13 — The interface runs on a demonstration backend
**From:** M3 · **Due:** M3

`ui/src/lib/backend.ts` keeps a tree in memory. Nothing in the interface has
ever spoken to a real vault, so every screen is unproven against real latency,
real errors, and real directories.

*Revisit when:* the Tauri wiring lands, which is the rest of M3. The boundary is
one interface, so the swap is contained — but "it worked against the mock" is
not evidence of anything.

### 🟠 R-14 — The file list is not virtualised
**From:** M3 · **Due:** M3

Every row is rendered. The plan calls for virtualisation from the start
precisely so it does not have to be retrofitted, and a directory of 10 000
entries will make the current list unusable.

*Revisit when:* before M3 closes, and certainly before anyone points the
interface at a large vault.

### 🟡 R-15 — Auto-lock has one policy, not three
**From:** M3 · **Due:** M3

The plan settled on three user-selectable policies (warn and force, force
immediately, never while files are open). Only the default is implemented, and
it is not configurable.

*Revisit when:* the settings panel grows past appearance and language.

### 🟡 R-16 — Tooltips do not avoid the window edge
**From:** M3 · **Due:** M3

They render centred above or below their trigger with no collision detection, so
one near the right edge of a narrow window will overflow.

*Revisit when:* the window can be resized small, or a tooltip appears in a
sidebar. Neither is true yet.

### 🟡 R-17 — The password strength meter is a heuristic
**From:** M3 · **Due:** —

Length and character variety, nothing more. It cannot tell that
"Password123!" is on every wordlist. The tooltip beside it says so, which is the
honest minimum, but a real estimator (zxcvbn or similar) would be better — at
the cost of a dependency and a dictionary.

*Revisit when:* deciding what goes into the release. Registered so the tradeoff
is a decision rather than an omission.

### 🟡 R-18 — Vite's hot reload does not work in development
**From:** M3 · **Due:** —

The content security policy sets `connect-src 'none'`, which blocks Vite's
websocket. The policy is correct and the blocked connection in the console is
the policy working; the cost is that changes need a manual reload.

*Revisit when:* it becomes annoying enough. A development-only relaxation is
possible and must never reach a build.

---

## Resolved

Kept for the record: an entry that was removed without explanation looks like an
entry that was forgotten.

| | Entry | Resolved in |
|---|---|---|
| — | *(nothing yet)* | |
