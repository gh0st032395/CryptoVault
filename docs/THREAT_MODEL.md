# CryptoVault Threat Model

**Status:** current as of milestone M0 (2026-08-06).
This document is normative for the project: it decides what counts as a security
bug and what counts as a documented limit. It is revisited at every milestone
that changes what the application does, and it is written before the code it
describes.

---

## 1. Why this document exists first

A security tool that has not written down what it protects against will,
sooner or later, be praised for protecting against something it does not. That
is worse than offering no protection at all, because a user who believes they
are safe behaves as though they are.

So the uncomfortable half of this document — section 4, the attackers we do not
stop — matters more than the flattering half.

---

## 2. Assets

In order of how badly their loss would hurt.

| Asset | Where it lives | Loss means |
|---|---|---|
| **Vault master seed** | In memory only, while unlocked; wrapped in `vault.cvconf` at rest | Total compromise: every file, past and future |
| **User password** | Never stored anywhere | Same as above, plus reuse elsewhere |
| **File contents** | Encrypted on disk, in chunks | Disclosure of the data the user chose to protect |
| **File and folder names** | Encrypted on disk | Often as revealing as the contents — `divorce-lawyer/` says plenty |
| **Vault structure** | Flattened and hashed on disk | Reveals how the user organises their life |
| **Session plaintext** | Temporary files, while a file is open in an external application | Disclosure of whatever was open |
| **Search index and audit log** | Local, encrypted, per machine | Names and access patterns |

---

## 3. Attackers we defend against

### A1 — Someone who obtains the storage

A stolen or lost laptop, a disk sold on, a backup drive, a discarded SSD, a
seized machine. The vault is **locked** at the time.

*Capability:* full, unlimited, offline access to every byte of the vault.
*Defence:* AES-256-GCM content encryption under a master seed that exists only
wrapped, behind Argon2id at 256 MiB. Offline password guessing is possible in
principle and expensive in practice; the user's password strength is the
remaining variable, which is why the interface is blunt about it.

### A2 — The cloud provider, or anyone who reads the synced folder

Dropbox, iCloud, Google Drive, OneDrive, a NAS, a shared network drive; the
provider itself, an employee, a subpoena served on the provider, or an attacker
who has breached them.

*Capability:* reads every encrypted file, watches them change over time, keeps
old copies indefinitely.
*Defence:* contents and names are encrypted client-side; the provider never sees
a key. **What still leaks is listed in section 5** — this is the attacker with
the most metadata, and pretending otherwise would be dishonest.

### A3 — Brief physical access to a running machine

The classic "left the laptop on the desk for ten minutes". The vault is locked,
or auto-lock fires while they are there.

*Defence:* auto-lock on idle, on sleep, on screen lock; a global hotkey that
locks everything at once; the tray icon as a one-click panic button. Key
material is wiped on lock, and the session temporary directory goes with it.

### A4 — A network attacker

*Capability:* full control of the network path.
*Defence:* there is almost nothing to attack. CryptoVault makes exactly one kind
of outbound connection — the update check, only when the user asks for it — and
verifies a signature on anything it downloads. The webview is locked down with
`connect-src 'none'`, so a compromised page cannot phone home. No telemetry, no
crash reporting, no analytics.

### A5 — Another user of the same computer

A separate operating-system account, or a shared machine.

*Defence:* the vault is encrypted regardless of filesystem permissions; the
session temporary directory is created `0700`; the local index and audit log are
encrypted with keys derived from the vault.

---

## 4. Attackers we do **not** defend against

Every item here is a deliberate scope decision, not an oversight. If any of them
is your adversary, CryptoVault is the wrong tool and no configuration of it will
help.

### B1 — Malware running as the user

If code is executing with your privileges, it can read the vault while it is
unlocked, log your password as you type it, screenshot the file you are viewing,
or simply wait and copy the master seed out of our memory. No user-space
application can defend against this, and any that claims to is selling
something. **Keep the machine clean; the vault assumes you have.**

### B2 — Keyloggers and screen capture

A special case of B1, called out separately because it is the most common way
these tools are actually defeated in practice.

### B3 — An attacker who can read process memory

Cold-boot attacks, DMA over Thunderbolt, a debugger attached to the process, a
kernel-level attacker, a hypervisor underneath us. While a vault is unlocked its
master seed is in RAM, and it has to be.

*Partial mitigations, not defences:* key material is held in `Zeroizing`
buffers and wiped on lock; `mlock`/`VirtualLock` keeps it out of swap where the
operating system allows. Neither survives an attacker who can read RAM directly.

### B4 — Evil maid with persistence

Someone who can modify the CryptoVault binary, the bootloader or the firmware
between two of your sessions can hand you a version that keeps your password.
Signed installers and reproducible builds raise the cost; they do not remove the
attack. Full-disk encryption and Secure Boot are the right tools here, and they
sit below us.

### B5 — Compelled disclosure

CryptoVault version 1 has no hidden vaults and no duress password. If you are
forced to hand over a password, the data is handed over with it.

This is not just an unimplemented feature. With per-file storage, the number of
files and their approximate sizes are visible on disk, so a hidden vault would
often be *detectable* — and a deniability feature that does not hold up is worse
than none, because someone will trust it under exactly the circumstances where
being wrong is most costly. If this ever ships (milestone M13), it ships with an
honest statement of how far it goes.

### B6 — The owner of the vault

The **sealed vault** mode blocks drag-out, plaintext export and opening files in
external applications. It is an *application policy*, enforced by the
application. Anyone who knows the password can extract the data with the CLI, a
modified build, or fifty lines of Rust.

Sealed mode protects against your own distraction and against someone who has
your unlocked session for five minutes. It does not protect against you, and it
is not a licensing or DRM mechanism.

### B7 — Side channels

Timing, power and electromagnetic analysis are out of scope. We use constant-time
primitives where the underlying crates provide them, but no hardening beyond that.

---

## 5. What leaks even when everything works

Encrypting a filesystem hides contents; it cannot hide the shape of the
container. Anyone with access to the encrypted directory — including your cloud
provider — can determine:

| Observable | Why it cannot be hidden | Mitigation |
|---|---|---|
| **Number of files** | Each vault file is one file on disk | None in v1. A single-container format would hide it, at the cost of cloud sync |
| **Size of each file**, to within 32 KiB | Encryption does not compress or pad | Padding to fixed buckets is possible and is not implemented; it would cost storage and sync bandwidth |
| **Modification times** | The host filesystem records them | None |
| **Access and edit patterns** | The provider sees which encrypted file changed and when | None. Over months this is genuinely informative |
| **Number of directories, and roughly how the tree branches** | Each directory is a directory on disk | Depth is hidden by the flat hashed layout; branching factor is not |
| **That it is a CryptoVault vault** | `vault.cvconf` and the file extensions | None, and hiding it is not a goal |
| **Number of devices using the vault** | Only if the audit log is stored in the vault — which is why it defaults to local-only | Keep the audit log local (the default) |

**Not** observable: file names, folder names, contents, tags, notes, permissions,
original timestamps, and where in the tree any given file sits.

---

## 6. Named residual risks

These are real weaknesses of the design as chosen. They are listed here, and they
are also stated in the user interface at the point where they matter.

### R1 — Plaintext exists during an external-application session

When you open a file in Word or Preview, it is decrypted to a temporary
directory for as long as it is open. Two consequences:

- While it is open, that file is an ordinary unencrypted file. Anything that can
  read your files can read it.
- **Secure deletion afterwards is best-effort and cannot be guaranteed.** On an
  SSD, wear levelling means overwriting a block does not overwrite the physical
  block. On APFS and Btrfs, copy-on-write means the same. Time Machine and
  Volume Shadow Copy may already have snapshotted it.

*Mitigations:* volatile storage where the platform offers it (`/dev/shm` on
Linux, an optional RAM disk on macOS); `0700` session directories; a journal so
that orphaned temporaries are found and removed after a crash; the sealed vault
mode, which forbids external applications entirely.

*Real fix:* the virtual mount (milestone M14), where plaintext never reaches a
disk at all.

### R2 — Preview and viewer parsers

Rendering a document means parsing hostile input. Image and text viewers use
pure-Rust decoders in-process; **PDF is rendered in a separate sandboxed process
with no vault keys, no filesystem and no network**, so a parser exploit lands in
an empty process. Previews are off by default and are enabled per folder, after
re-entering the password — deliberately a decision, not a default.

### R3 — Sync conflicts and provider version history

Sync clients keep their own history. Deleting a file from your vault does not
delete the encrypted copies the provider has retained, and those remain
decryptable with your password. Two machines writing the same vault at once can
produce conflict copies; we detect and surface them, but we cannot merge them.

### R4 — Password loss is unrecoverable

There is no back door, no key escrow and no reset. Without the password — and,
once implemented, without the recovery key — the data is gone permanently. This
is a design goal and the most common real-world way users lose data with tools
of this kind.

### R5 — Clipboard

Copying content out of a viewer puts it on the system clipboard, which is
readable by other applications and may be synchronised across devices by the
operating system. CryptoVault does not control that.

---

## 7. Cryptographic assumptions

We assume, and depend on:

- AES-256-GCM is a secure AEAD, and GCM's authentication holds provided a
  (key, nonce) pair is never reused. **This assumption is load-bearing**: the
  format uses a fresh random nonce for every chunk write for exactly this reason,
  never a nonce derived from the chunk index, because chunks are rewritten in
  place and a derived nonce would repeat.
- Argon2id with the parameters in `cv-crypto::kdf` makes offline guessing
  expensive in proportion to password entropy. It does not make a weak password
  strong.
- HKDF-SHA256 gives independent sub-keys from one master seed.
- AES-SIV is secure as a deterministic AEAD for filenames, accepting that
  determinism is what leaks: identical names in the same directory produce
  identical ciphertext. That is the price of being able to look a file up
  without decrypting the whole directory.
- The operating system's CSPRNG is sound.

---

## 8. Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Please do not open a public issue for
anything that affects the confidentiality of user data.

---

## 9. Change log of this document

| Date | Milestone | Change |
|---|---|---|
| 2026-08-06 | M0 | First version, written before any cryptographic code |
