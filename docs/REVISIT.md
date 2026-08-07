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

### 🟡 R-07 — `verify` reads a whole vault serially
**From:** M2 · **Due:** M6

Single-threaded, one file at a time. On a large vault it will be slow enough
that people stop running it, which makes it useless.

*Revisit when:* M6 makes integrity checking a product feature. Cryptera's
`rayon` parallelism is the obvious answer.

### 🟡 R-08 — No cancellation or progress in long operations
**From:** M2 · **Due:** M4 (moved)

`add` and `get` copy in a loop with no way to stop them and nothing to report.
Deferred from M2 because progress needs somewhere to be shown.

*Revisit when:* it is wired to a real backend. Progress bars over a mock are
theatre, so this waits for R-13 rather than being built against invented
latency.

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

### 🟠 R-13 — The interface still runs on a demonstration backend
**From:** M3 · **Due:** M3

`ui/src/lib/backend.ts` keeps a tree in memory. Nothing on screen has ever
spoken to a real vault, so every screen is unproven against real latency, real
errors and real directories.

The Rust half now exists: `cv-session` holds the registry of vaults, which are
open, and every operation the interface needs, tested against real vaults on
disk. What is missing is only the Tauri shim — an attribute per method, a
builder, a window, and a TypeScript client that calls them.

*Revisit when:* that shim lands. It is deliberately thin, and if it ever starts
making decisions they belong in `cv-session` instead.

### 🟡 R-22 — Creating a vault costs a second of calibration in every test
**From:** M3 · **Due:** —

`Session::create` calibrates Argon2id, which is right in production and makes
`cv-session`'s tests take about six seconds because each one makes a vault.

*Revisit when:* it becomes the slowest part of the suite. The fix is a way to
pass fixed parameters in — but an option that skips calibration is also an
option a caller can reach for in production, so it needs to be shaped as
"tests only" rather than "faster".

### 🟡 R-15 — The third auto-lock policy is a stand-in
**From:** M3 · **Due:** M4

Three policies are implemented and selectable: warn then lock, lock at once,
and never lock automatically. The plan's third option was "do not lock while
files are open", which cannot mean anything until M4 gives files a way to *be*
open. "Only when I ask" is the honest stand-in, and its tooltip says outright
that a vault left open stays open — including all night, which is the exact
failure auto-lock exists to prevent.

*Revisit when:* M4 lands external-application sessions and there is a real
notion of a file being open to postpone against.

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

### 🟡 R-19 — CI actions are pinned to v4, one major behind
**From:** M3 · **Due:** —

`actions/checkout@v7` and `actions/cache@v6` repeatedly failed to resolve at
"Set up job" with an internal error on GitHub's side, on a different runner each
time. They are pinned back to v4, which is cached everywhere and works, at the
cost of a Node 20 deprecation warning on every job.

*Revisit when:* the warning becomes an error, or the newer majors have been out
long enough to resolve reliably. Not before — a pipeline that fails at random is
worse than a warning, because it teaches you to ignore a red run.

### 🟠 R-20 — Pull requests are gated on Linux only
**From:** M3 · **Due:** M10

The everyday check is one Ubuntu job. Windows and macOS moved to
`cross-platform.yml`, which runs on merges to main, nightly, and on demand — so
a platform break is caught within minutes of landing rather than before.

The reason is queueing: seven jobs each waited for their own runner and the
result arrived twenty minutes later, or never, because a job that never starts
is eventually cancelled. A check nobody waits for is not a check.

*Revisit when:* M10, when a release makes "broken on Windows for an hour" more
expensive than it is now. Also worth reconsidering the moment the project has a
second contributor, since the assumption that main gets fixed immediately is
really an assumption about one person being available.

### 🟡 R-21 — A row bleeds past the sticky column header when scrolled
**From:** M3 · **Due:** M3

Scrolled deep into a long list, a sliver of a row is visible above the sticky
`NAME / SIZE / MODIFIED` header. Purely cosmetic, and not diagnosed: the header
has an opaque background and sits at `top: 0` of the scroll container, so the
obvious explanation is not the right one.

*Revisit when:* the next pass over the browser screen. Worth ten minutes with
devtools rather than a guessed fix.

---

## Resolved

Kept for the record: an entry that was removed without explanation looks like an
entry that was forgotten.

| | Entry | Resolved in |
|---|---|---|
| 🟠 | **R-14** — the file list is not virtualised | M3 · only the visible rows exist in the DOM; 5000 entries render 33 |
| 🟡 | **R-06** — Argon2id parameters are not calibrated | M3 · `kdf::calibrate` searches upward from the default and never below it |
| 🟡 | **R-09** — removing a directory requires it to be empty | M3 · `Vault::remove_recursive`, deliberately a separate function |

