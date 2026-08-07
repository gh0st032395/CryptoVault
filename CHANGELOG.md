# Changelog

All notable changes to CryptoVault are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/). Until 1.0 the
vault format may change between versions; when it does, it is called out here in
its own **Format** section.

---

## [Unreleased]

### Milestone M0 — Foundations

Nothing here is usable yet: there is no vault, no encryption and no interface.
M0 builds the frame that the rest hangs off, and writes down the decisions that
are expensive to revisit later.

#### Added

- **Cargo workspace** with seven crates in a strict one-way dependency chain —
  `cv-crypto`, `cv-format`, `cv-vault`, `cv-vfs`, `cv-ops`, `cv-render`,
  `cv-cli` — so that nothing below `cv-ops` can learn a GUI exists.
- **`docs/THREAT_MODEL.md`** — what CryptoVault defends against, what it
  explicitly does not, and what leaks even when everything works.
- **`docs/FORMAT_SPEC.md`** — normative specification of the on-disk format:
  key hierarchy, key slots, file header, chunked contents, filename encryption,
  directory mapping.
- **Argon2id parameter validation** (`cv-crypto::kdf`) with bounds that reject
  weakened configurations rather than silently raising them.
- **Chunk arithmetic** (`cv-format::chunk`) mapping plaintext offsets onto the
  encrypted file, with overflow reported rather than wrapped.
- **Format constants** (`cv-format::consts`) with compile-time invariants: a
  change that breaks one does not fail a test, it fails the build.
- **`VPath`** (`cv-vfs::path`) — validated vault-internal paths. Traversal
  components are rejected, and because names are encrypted, names the host
  filesystem forbids (`CON`, `report: Q1*.txt`, trailing dots) are storable.
- **`scripts/check.sh` / `check.ps1`** — one verification command, identical to
  CI: formatting, clippy with warnings as errors, tests, documentation, and the
  supply-chain audit.
- **CI** on Windows, macOS and Linux, with `cargo-deny` and `cargo-audit`.
- Project documentation: bilingual README, `CONTRIBUTING.md` with the Definition
  of Done, `SECURITY.md`, `CODE_OF_CONDUCT.md`, the first architecture decision
  records, and the user manual skeleton.

#### Format

- **Format version 1** specified.

### Milestone M1 — Cryptographic core and format

Still nothing a user can run: there is no vault to open and no interface. What
exists is everything a vault will be built out of, specified and tested.

#### Added

- **`cv-crypto`** — `SecretBytes` (wiped on drop, redacted in `Debug`,
  constant-time comparison), randomness that fails loudly rather than silently
  producing weak keys, Argon2id key derivation, AEAD with the algorithm selected
  at runtime (AES-256-GCM and XChaCha20-Poly1305), HKDF sub-key derivation,
  AES-SIV for deterministic filenames, and key slots.
- **`cv-format`** — CBOR metadata, file headers, chunked content with random
  access, filename encoding with a companion file for long names, directory
  placement, and an authenticated `vault.cvconf`.
- **Frozen format vectors** — a committed encrypted file and vault
  configuration that every future build must still be able to read, plus exact
  expected bytes for every deterministic derivation.
- **Four fuzz targets** covering the header, chunk, configuration and filename
  parsers, running weekly in CI.

#### Format

Two corrections found by implementing the specification, both made in the
specification first:

- The header prefix is not a fixed 40 bytes. It is 28 plus the algorithm's
  nonce, so a reader must size it from the algorithm byte rather than assuming
  12 — assuming would misplace every chunk offset in a XChaCha-encrypted file.
- The configuration MAC covers the body as an opaque byte string, which removes
  the need for a canonical CBOR encoding entirely.

Two open points resolved: the root directory uses the vault identifier rather
than all zeros, and canonical encoding is no longer needed.

**The format is now frozen.** Changing it breaks the vectors on purpose.

### Milestone M2 — Vault, filesystem abstraction and command-line tool

**A vault can now be created, filled and read back.** From a terminal, not from
a window — the desktop interface is M3 — but the thing itself works.

#### Added

- **`cv-vault`** — creating and opening a vault, directories, entries, and
  reading and writing files at arbitrary offsets. Writing past the end
  zero-fills the gap with real encrypted chunks rather than leaving a hole,
  which would read back as a chunk that never existed. Atomic writes
  throughout: temporary in the same directory, `fsync`, `rename`.
- **`cv-vfs`** — the `VaultFs` trait and `DirectVaultFs`. Paths in, vault
  operations out; the offset-based shape FUSE and WinFsp expect.
- **`cryptovault`** — `init`, `ls`, `mkdir`, `add`, `get`, `rm`, `mv`,
  `verify`, `inspect`. Exit codes are a contract: 0 success, 1 the operation
  failed, 2 a bad command line, 3 wrong password.
- **`verify`** walks a whole vault and checks every authentication tag without
  writing a byte of plaintext anywhere.
- **`inspect`** describes a vault *without* a password, because it is the
  command for a vault that will not open.

#### Notes

- Locking a vault is dropping it. There is no locked handle to use by accident.
- The command-line tool is the project's own test instrument and is not yet
  documented in the user manual or supported for scripting.
- The password comes from an environment variable or standard input. There is
  no interactive prompt yet, and the help text says plainly that an environment
  variable is a poor place for a password.

### Milestone M3 — The desktop application

**There is an application now.** It has a window, it makes vaults, it opens
them, and it browses them. What it cannot do is bring a file in from your disk
or write one back out — that is M4 — so it is a place to keep folders rather
than files, and the two buttons for it are visible, disabled, and say why.

#### Added

- **`cv-session`** — which vaults exist, which are open, and every operation an
  interface needs, as plain serialisable types and errors carrying a stable tag
  to branch on. It lives below the window on purpose: state inside a
  user-interface framework can only be exercised by running the framework, and
  "unlock, browse, lock, unlock again" is where a session bug hides.
- **The list of vaults survives restarts**, in the platform's configuration
  folder. It records names, paths and whether a vault is sealed. It never
  records that a vault was *open*: every start begins with everything shut.
- **`cv-desktop`** — Tauri v2 over `cv-session`, deliberately thin. Each command
  takes the lock, calls one method, converts the error; if one ever starts
  deciding something, the decision belongs a layer down.
- **Creating a vault**, with a password strength meter that says outright what
  it cannot judge, an unmissable warning that the password cannot be recovered,
  and the sealed/normal choice. Argon2id is calibrated against the machine that
  creates the vault, so the cost matches the hardware rather than a number
  chosen years ago. It comes back locked: typing the password once more is the
  cheapest check that it was typed as intended.
- **Multi-vault management** — add an existing vault by pointing at its folder,
  and remove one from the list without touching a byte on disk.
- **A file browser** with a folder tree, a breadcrumb trail, sorting by name,
  size and date, filtering within a folder, multiple selection, and new folder,
  rename and delete. The list is **windowed**: only the rows in view exist in
  the DOM, so a folder of five thousand entries renders thirty-three of them.
- **Auto-lock** with the three policies, and a **tray** whose lock button shuts
  every vault at once — reachable when the window is behind something else.
- **Light, dark and system themes**, and Italian and English throughout,
  including the tray, which is told the language rather than guessing at it.
- **A content security policy** that names `ipc:` and `http://ipc.localhost` in
  `connect-src` and nothing else. Both are custom protocols answered in the same
  process; no scheme that could reach a network is present.

#### Notes

- Vault *contents* never cross into the window. The interface asks for a
  directory listing and gets names, sizes and dates; file bytes have no command
  and no path across, and will not get one before M4 gives them somewhere to go
  that is not a webview.
- Passwords do cross, as ordinary strings, and are not wiped on either side.
  Written down as R-23 rather than left as an implication.
- A vault is still only openable with its password. The recovery key that the
  format has had room for since M1 is M11, and until then a forgotten password
  is a lost vault.
- The desktop binary embeds the built interface, so `ui/dist` has to exist
  before the Rust build. `scripts/check.sh` and CI build it first.
- Sixteen unmaintained advisories and one weak-copyleft licence arrive with
  Tauri's dependency tree. Every one is listed individually, with a reason, in
  `deny.toml`.

---

[Unreleased]: https://github.com/gh0st032395/CryptoVault/commits/main
