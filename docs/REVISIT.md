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

Since M3 there is a second caller with less excuse: the folder tree reads a
directory to find out which of its entries are folders, and pays for every size
and timestamp in it to learn something it then throws away.

*Revisit when:* M5 builds the search index — the same cache can carry sizes.
Until then the interface should show sizes lazily rather than up front, and a
listing that only needs names and kinds should be able to ask for only those.

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

This got substantially worse in M3, and the entry is kept at 🟠 only because the
answer has not changed. Until M3 the Linux risk was a library behaving
differently; now it is a *window*. The interface runs on WebKitGTK rather than
the WebView2 and WKWebView that were actually looked at, the file dialogue is a
different implementation, and the tray is the part of the desktop that varies
most between Linux environments — several have none at all. The code handles
that (a missing tray is a warning, not a failure) and nobody has ever seen it
happen.

*Revisit when:* M10. Either Linux ships labelled beta, or there is a public test
phase before the label comes off. Somebody opening the application on GNOME and
KDE once, by hand, would answer more than the test suite can.

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

*Revisit when:* M4. The backend is real now, so the objection that progress bars
over a mock are theatre no longer applies — what is left is that the operations
needing progress are the ones that copy plaintext in and out, which is the
subject M4 exists for.

The two buttons that need this — Add files and Extract — are disabled in the
browser, and their tooltips say they are not built rather than leaving a control
that swallows a click. Everything on that toolbar that does not need progress
is wired.

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

### 🟡 R-29 — The folder tree is not windowed, and the file list is
**From:** M3 · **Due:** —

The file list renders only the rows in view (R-14). The tree beside it renders
every folder that is open, all of them, in the DOM. A vault with a few hundred
folders is fine; one with ten thousand in a single parent is the same defect
R-14 existed to fix, in the other half of the same screen.

It is deliberately not fixed yet, for two reasons. The tree is already flattened
into a list of rows, which is the shape windowing needs — the work is small and
can wait until it is needed. And a folder that big is speculative in a way a
*file* directory that big is not: the demonstration vault has five thousand
files in one folder because that is ordinary, and nobody has yet described a
vault with five thousand sibling folders.

*Revisit when:* somebody has a tree that stutters, or M5's index makes the shape
of real vaults clearer. Not before — this is the kind of thing that gets built
for a case that never arrives.

### 🟡 R-28 — Closing the window quits, so the tray goes with it
**From:** M3 · **Due:** M9

The tray's lock button is meant to be reachable when the window is not. It is —
behind other applications, minimised — but not after the window is closed,
because closing the last window ends the process.

That default is the *safe* one, and deliberately kept: ending the process drops
the session, which wipes every key, so closing the window locks everything.
The alternative, hiding to the tray, would leave unlocked vaults in a program
with no visible window, which is the state auto-lock exists to prevent.

So this is not a bug, it is a trade with a cost: the panic button is absent
exactly when someone has tidied the window away. Hiding to the tray *and*
locking on hide would give both, and needs a decision about what "close" should
mean rather than a patch.

*Revisit when:* M9 builds the rest of the system integration — tray, global
lock hotkey, context menus — which is where this question belongs and where a
global hotkey would make the window's presence irrelevant anyway.

### 🟡 R-23 — The password crosses to Rust as an ordinary string
**From:** M3 · **Due:** M10

`unlock` and `create_vault` take the password as JSON. It therefore exists as a
JavaScript string in the webview's heap, as a `String` in the Tauri command, and
as a `&str` on the way into `cv-session` — none of which are wiped, and the
first of which cannot be, because a JavaScript engine moves and copies strings
as it pleases.

Everything below `cv-session` is careful about this: `SecretBytes` wipes on drop
and `Zeroizing` covers the derived keys. The boundary is where the care stops,
which is worth writing down rather than leaving as an implication.

*Revisit when:* M10, with [R-12] — memory locking and password lifetime are the
same conversation, and the same one that biometrics in M11 changes, since a
credential that never passes through the window has none of this problem.

[R-12]: #-r-12--key-material-is-not-locked-out-of-swap

### 🟡 R-27 — Nothing automated proves the commands are wired up
**From:** M3 · **Due:** M4

`cv-desktop`'s error conversion has tests, and everything underneath it has 356.
What has no test is the wiring itself: that `generate_handler!` lists every
command, and that the argument names in `ui/src/lib/tauri.ts` match the Rust
parameters. Tauri matches those by name and treats a name that matches nothing
as an absent argument, so a rename on one side fails silently on the other —
which is the one class of mistake the type checkers on both sides cannot see.

It was checked by hand for this milestone: create, unlock, list, make a
directory, read it back, rename, lock, and both error tags, driven through the
real IPC of a packaged build against a real vault on disk. That is evidence, and
it is not a test — it does not run again tomorrow.

*Revisit when:* M4 adds commands. `tauri::test::mock_builder` runs commands
without a window, which is the shape this needs.

### 🟡 R-24 — A damaged vault list stops the application from starting
**From:** M3 · **Due:** —

`Session::open` refuses to start on a registry it cannot parse, and the desktop
application turns that into a message on standard error and an exit code. For a
user with no terminal open, that is an application that does not launch.

Silently starting with an empty list would be worse — vaults gone, no
explanation — so the behaviour is right and the presentation is not. The file is
also trivially replaceable: deleting it loses the list of vaults, never a vault.

*Revisit when:* there is anywhere to show a startup failure. A window that opens
and says what happened, with a button to start a fresh list, is the whole fix.

### 🟡 R-25 — Sixteen unmaintained crates arrived with Tauri
**From:** M3 · **Due:** M10

`deny.toml` ignores sixteen RUSTSEC advisories, listed individually with
reasons. Every one is *unmaintained* rather than a vulnerability: the gtk-rs
GTK3 bindings (Linux only, and upstream's migration to GTK4 to make), the
`unic-*` Unicode tables, and `proc-macro-error`, which runs only at build time.

Unmaintained is a slow risk rather than an urgent one — nobody is watching those
crates for the next bug — and it is not one this project can fix from here.

*Revisit when:* M10. Shipping a binary is when "we depend on something nobody
maintains" stops being a build-time observation.

### 🟡 R-22 — Creating a vault costs a second of calibration in every test
**From:** M3 · **Due:** —

`Session::create` calibrates Argon2id, which is right in production and makes
`cv-session`'s tests take about nine seconds because each one makes a vault. The
registry tests added three more.

*Revisit when:* it becomes the slowest part of the suite — which it now is. The
fix is a way to pass fixed parameters in, but an option that skips calibration
is also an option a caller can reach for in production, so it needs to be shaped
as "tests only" rather than "faster".

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

The content security policy's `connect-src` allows Tauri's IPC and nothing else,
which blocks Vite's websocket. The policy is correct and the blocked connection
in the console is the policy working; the cost is that changes need a manual
reload.

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

---

## Resolved

Kept for the record: an entry that was removed without explanation looks like an
entry that was forgotten.

| | Entry | Resolved in |
|---|---|---|
| 🟠 | **R-13** — the interface runs on a demonstration backend | M3 · `cv-desktop` puts a Tauri window over `cv-session`; the demonstration backend stays, for reviewing the interface in a browser |
| 🟠 | **R-26** — half the browser's toolbar does nothing | M3 · new folder, rename and delete are wired; the two that need progress are disabled and say why |
| 🟡 | **R-21** — a row bleeds past the sticky column header | M3 · not a gap — the header measures flush at every offset — but sub-pixel rounding at 2×; the header now paints its own background above itself, where the scroll box clips it |
| 🟡 | **R-16** — tooltips do not avoid the window edge | M3 · measured when the tooltip mounts and slid back inside, 8 px from the edge |
| 🟠 | **R-14** — the file list is not virtualised | M3 · only the visible rows exist in the DOM; 5000 entries render 33 |
| 🟡 | **R-06** — Argon2id parameters are not calibrated | M3 · `kdf::calibrate` searches upward from the default and never below it |
| 🟡 | **R-09** — removing a directory requires it to be empty | M3 · `Vault::remove_recursive`, deliberately a separate function |

