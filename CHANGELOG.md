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

- **Format version 1** specified. Not yet implemented, and not yet frozen: it
  may still change during M1, after which the test vectors lock it.

---

[Unreleased]: https://github.com/gh0st032395/CryptoVault/commits/main
