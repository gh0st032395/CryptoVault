# 0003 — Key slots wrapping a single master seed

**Status:** Accepted
**Date:** 2026-08-06

## Context

Version 1 unlocks a vault with a password and nothing else. But the intended
path is clear: a recovery key, then Touch ID and Windows Hello, then keyfiles
and FIDO2 tokens, and possibly a duress password much later.

The naive construction derives the content key from the password directly. It
works perfectly, right up to the day a second unlock method is wanted — at which
point every file in every existing vault has to be decrypted and re-encrypted.
For a 200 GB vault on a laptop, that is hours of work, an enormous window for
something to go wrong halfway, and a full re-upload for anyone syncing to a
cloud.

## Decision

Insert one level of indirection, in the format from version 1:

```
password ──Argon2id──> KEK ──unwraps──> MasterSeed ──HKDF──> sub-keys
```

`MasterSeed` is random, generated once at vault creation, and stored only in
wrapped form inside `vault.cvconf`, in an array of **key slots**. Each slot
wraps the *same* seed independently with a KEK obtained from its own method.

Slot kinds are allocated now even though only kind 1 is implemented: password,
recovery key, OS keychain, keyfile/FIDO2.

## Consequences

**Good**

- Adding an unlock method writes one slot — 48 bytes of wrapped seed plus its
  parameters. No file is re-encrypted. No format version changes.
- Changing the password rewrites one slot. On a 200 GB vault it is instant.
- Removing a method removes a slot and nothing else.
- Sub-keys derived by HKDF with versioned labels mean any one of them can be
  rotated without touching the others.

**Bad, and accepted**

- One more indirection to understand and to specify. The format is slightly
  larger and the unlock path slightly longer.
- Every slot is an independent path to the same seed, so **the vault is only as
  strong as its weakest slot**. A recovery key written on a sticky note defeats
  a strong password. The interface has to be explicit about this at the moment a
  slot is created, and the parameters of every slot are validated against the
  same minimum.
- Slot metadata is unencrypted, so the number of unlock methods and their labels
  are visible on disk. Labels are user-supplied, so the interface should not
  encourage putting anything sensitive in them.

## Alternatives considered

- **Derive the content key straight from the password.** Simpler, one less
  concept, and it is what a first implementation naturally does. Rejected
  because the migration cost when the second method arrives is paid by users,
  in hours and in re-uploaded gigabytes, on data they cannot afford to have
  half-converted.
- **Re-encrypt when adding a method.** Keeps the simple construction and makes
  the cost explicit. Rejected for the same reason: a multi-hour operation over
  a user's entire vault is a data-loss risk, and it would make adding Touch ID
  feel like a dangerous act rather than a setting.
- **A separate keystore file per method.** Equivalent in effect, but scatters
  material across several files that must stay consistent — exactly the wrong
  shape for a folder being synced by a cloud client.
