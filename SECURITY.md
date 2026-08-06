# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for anything affecting the confidentiality
or integrity of user data.**

Use GitHub's private vulnerability reporting:

> **[Report a vulnerability](https://github.com/gh0st032395/CryptoVault/security/advisories/new)**
> — Security tab → *Report a vulnerability*

That channel is private between you and the maintainer until a fix is published.

A useful report contains: what you did, what happened, what you expected, and
the version or commit. A proof of concept helps enormously and is never
required. Reports in Italian or English are equally welcome.

### What to expect

| | |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix or a stated plan | depends on severity; you will be told which |
| Public disclosure | after a fix ships, coordinated with you |

This is a spare-time project by one person. Those are honest targets rather than
a service-level agreement, and if a deadline slips you will be told rather than
left waiting.

You will be credited in the advisory and the changelog unless you prefer not to
be. There is no bug bounty.

## Scope

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) first — it is the document
that decides what counts as a vulnerability here.

### In scope

- Anything that discloses plaintext, key material or file names to someone who
  should not have them
- Weaknesses in the cryptographic construction: key derivation, the key
  hierarchy, nonce handling, authentication, the wrapping of key slots
- Bypassing a lock: reading vault contents without the password
- Corruption or data loss caused by ordinary use, crashes, or interrupted syncs
- Path traversal, or any way to make the application write outside a vault
- An unexpected network connection, or any telemetry
- Sandbox escape from the `cv-render` helper process

### Out of scope

These are documented limits, not bugs. Each is explained in the threat model:

- Attacks that require malware already running with the user's privileges,
  keyloggers, or the ability to read process memory
- Recovering plaintext from a temporary file after a session, on an SSD or a
  copy-on-write filesystem — secure deletion is best-effort and is documented as
  such (threat model R1)
- Extracting data from a "sealed" vault while holding the password. Sealed mode
  is an application policy, not a cryptographic boundary (threat model B6)
- Metadata visible to a cloud provider: file count, sizes to within 32 KiB,
  timestamps, modification patterns (threat model §5)
- The absence of hidden vaults or a duress password (threat model B5)
- Weak user passwords

If you think one of those limits is drawn in the wrong place, that is a
legitimate discussion — open a normal issue for it.

## Supported versions

Pre-release. Only the latest commit on `main` is supported, and no vault format
compatibility is promised until version 1.0.

**Do not store data you care about in a CryptoVault vault yet.**

## Security practices in this repository

- Dependencies are kept deliberately few and audited in CI with `cargo-deny`
  and `cargo-audit` on every push
- The toolchain is pinned, and warnings are errors
- `unsafe` is denied by default; each exception must carry a justification
- All parsers are fuzzed from milestone M1
- The format has frozen test vectors, so it cannot change by accident
- No telemetry, no analytics, no crash reporting. The only outbound connection
  is a user-initiated update check, whose payload is signature-verified
