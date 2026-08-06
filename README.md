<div align="center">

# CryptoVault

**An encrypted area on your disk where files are actually used, not just stored.**

[![CI](https://github.com/gh0st032395/CryptoVault/actions/workflows/ci.yml/badge.svg)](https://github.com/gh0st032395/CryptoVault/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licence)
[![Status](https://img.shields.io/badge/status-pre--alpha%20(M1)-orange.svg)](#project-status)

[Italiano](README.it.md) · [Development plan](PLAN.md) · [Threat model](docs/THREAT_MODEL.md) · [Format specification](docs/FORMAT_SPEC.md)

</div>

---

## ⚠️ Project status

**CryptoVault does not work yet. Do not put real data anywhere near it.**

Milestone **M1** is done: the cryptographic core and the on-disk format exist,
are specified, and are covered by 229 tests, frozen format vectors and four fuzz
targets. What does not exist yet is everything above them — no vault to open, no
files to put in one, no interface. The first build worth using daily arrives at
the end of M4; see the [roadmap](#roadmap).

This warning gets removed when it stops being true.

---

## What it is

CryptoVault creates encrypted vaults on your disk. You unlock one with a
password, browse your files, open them, edit them, and close them again —
and nothing exists in plaintext except for the duration of a session you
started deliberately.

No cloud of ours, no account, no telemetry. The only network connection the
application ever makes is an update check, and only when you ask for one.

- **Files stay usable.** Double-click a document and it opens in the
  application you normally use; it is re-encrypted when you close it. A virtual
  mounted drive, which removes the temporary file entirely, is planned.
- **Built for cloud sync.** Each file in the vault is one encrypted file on
  disk, so Dropbox, iCloud, Drive and OneDrive can sync it incrementally.
  Names, folder structure and contents are all encrypted client-side.
- **Nothing is hidden from you.** The [threat model](docs/THREAT_MODEL.md) lists
  what CryptoVault does *not* protect against, and what still leaks when
  everything works correctly. That section is longer than the reassuring one.

## Relationship with Cryptera

[Cryptera](https://github.com/gh0st032395/Cryptera) — by the same author —
encrypts a file into a `.ecf` and back. That is a one-shot transformation: the
whole file is read, encrypted and written.

A vault is a different problem. It needs random access, incremental writes, a
directory hierarchy and an unlocked/locked state, none of which a whole-file
format can provide — reading 4 KiB out of a `.ecf` means decrypting all of it.

So CryptoVault reuses Cryptera's *primitives* and its discipline (Argon2id,
AES-256-GCM, `zeroize`, Reed-Solomon, its approach to testing and fuzzing) and
redesigns the *format*. The two stay connected in one direction that matters:
CryptoVault will export files as Cryptera-compatible `.ecf`, so sharing works
without inventing a protocol.

## Design at a glance

| | |
|---|---|
| **Content encryption** | AES-256-GCM in 32 KiB chunks, each independently authenticated. 0.085% overhead |
| **Key derivation** | Argon2id, 256 MiB by default, calibrated on vault creation |
| **Key hierarchy** | Password → KEK → wrapped master seed, in independent key slots |
| **Names** | AES-SIV, deterministic, so a lookup needs no directory scan |
| **Directories** | Placed by HMAC of a random identifier, so renaming a folder of 10 000 files rewrites one file |
| **Storage** | One encrypted file per vault file — sync-friendly, no global index to conflict over |
| **Stack** | Rust + Tauri v2 + Svelte + TypeScript |

The key slots are worth a sentence of their own: every unlock method wraps the
*same* master seed independently, so adding Touch ID or a recovery key later
rewrites 48 bytes rather than re-encrypting every file. That is why they are in
version 1 of the format even though only the password slot is implemented.

Full details in [`docs/FORMAT_SPEC.md`](docs/FORMAT_SPEC.md).

## Roadmap

| | Milestone | |
|---|---|---|
| ✅ | **M0** Foundations — workspace, CI, threat model, format specification | done |
| ✅ | **M1** Cryptographic core and format, with frozen test vectors and fuzzing | done |
| ⬜ | **M2** Vault, filesystem abstraction, internal CLI | next |
| ⬜ | **M3** Desktop interface — browser, multi-vault, auto-lock | |
| ⬜ | **M4** Opening files in external applications | ← *first genuinely usable build* |
| ⬜ | **M5** Search, opt-in previews, sandboxed PDF viewer | |
| ⬜ | **M6** Trash, per-file versioning, integrity check, archived mode | |
| ⬜ | **M7** Sync hardening — conflict detection, cooperative locking | |
| ⬜ | **M8** Import/export, `.ecf` sharing, backup and single-file archive | |
| ⬜ | **M9** System integration — tray, context menu, global lock hotkey | |
| ⬜ | **M10** Release — signed installers for Windows, macOS and Linux | |
| ⬜ | **M11+** Recovery key, biometrics, hardware keys, virtual mount | |

The full plan, with the reasoning behind each decision, is in [`PLAN.md`](PLAN.md).

## Building from source

Requires the Rust toolchain; the exact version is pinned in `rust-toolchain.toml`
and `rustup` will fetch it for you.

```bash
git clone https://github.com/gh0st032395/CryptoVault.git
cd CryptoVault
cargo build --workspace
```

Before every commit, run the single verification command — the same steps CI runs:

```bash
./scripts/check.sh
```

On Windows:

```powershell
.\scripts\check.ps1
```

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. The short version: every
feature ships with the test that proves it, with doc comments explaining *why*,
and with its section of the user manual updated in the same commit.

Security issues go to [`SECURITY.md`](SECURITY.md), not to the public issue
tracker.

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your
option — the same terms as Cryptera.

For a tool that asks you to trust it with your files, being able to read the
code is part of the offer.
