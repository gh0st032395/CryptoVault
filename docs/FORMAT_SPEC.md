# CryptoVault Format Specification

**Format version:** 1
**Document status:** Draft — milestone M0. Sections marked *(reserved)* are named
but not yet fully specified.
**Last updated:** 2026-08-06

---

## 0. How this document is used

This specification is **normative**. The code in `crates/cv-format` implements
it; where the two disagree, this document is right and the code is a bug.

It is also updated *before* the code, not after. From milestone M1 there are
frozen test vectors in `tests/vectors/`, generated with fixed seeds and nonces,
whose expected bytes are checked in. Any change to the format breaks them
loudly. That is deliberate: an on-disk format is the one part of this project
that cannot be quietly revised once somebody's files are stored in it.

### Compatibility policy

- A build **must refuse** a vault whose format version it does not recognise.
  Guessing at the layout of an encrypted file is how silent data loss happens.
- New optional metadata fields may be added within a version; readers ignore
  fields they do not know.
- Anything that changes the meaning of existing bytes requires a version bump
  and a migration path.

---

## 1. Conventions

- **Integers are little-endian**, unsigned, throughout — in headers, in
  additional authenticated data, and in metadata. One convention everywhere;
  there is no second one to get wrong.
- **`‖`** denotes concatenation.
- Sizes are in bytes unless stated otherwise. `KiB` = 1024 bytes.
- **AEAD** means the algorithm selected by `alg_id`:

  | `alg_id` | Algorithm | Nonce | Tag | Status |
  |---|---|---|---|---|
  | `0x01` | AES-256-GCM | 12 | 16 | Default |
  | `0x02` | XChaCha20-Poly1305 | 24 | 16 | Reserved, implemented in M1, not exposed |

  Only `0x01` is written by version 1 builds. Readers must reject any other value.
- **Nonces are generated at random from the OS CSPRNG for every single write.**
  Never derived from a counter, an index or an offset. See §6.4.

---

## 2. Vault directory layout

```
<vault root>/
├── vault.cvconf              Configuration and key slots (§3). The only fixed name.
├── .cvlock                   Cooperative multi-machine lock (§11)
├── d/                        All content, in a flat two-level tree (§9)
│   └── <SH>/<REST>/          <SH> = first 2 chars, <REST> = remainder of the
│       │                     base32 of HMAC-SHA256(K_mac, dir_id)
│       ├── <name>.cvf        An encrypted file (§6)
│       ├── <name>.cvd        A subdirectory reference (§9.2)
│       └── <name>.cvn        A spilled long name (§8.3)
├── .trash/                   Deleted entries awaiting purge (§10)
└── .versions/                Previous versions of files marked for versioning (§10)
```

Nothing outside `vault.cvconf` has a predictable name, and no directory on disk
corresponds positionally to a directory in the vault.

**Atomicity requirement.** Every write of a `.cvf`, `.cvd`, `.cvn` or
`vault.cvconf` is performed as: write to a temporary file *in the same
directory*, `fsync`, then `rename` over the target. A sync client must never be
able to observe a half-written file that looks complete.

---

## 3. `vault.cvconf`

CBOR, unencrypted but fully authenticated. CBOR rather than JSON because the
metadata format is already CBOR, and a second serialisation format would mean a
second parser to fuzz for no real gain. `cryptovault inspect` prints it in
readable form for disaster recovery.

```
{
  "magic":        "CVCONF1",          text, constant
  "format":       1,                  uint, format version
  "vault_id":     bytes(16),          random, identifies the vault across devices
  "created":      uint,               Unix seconds, informational
  "alg_id":       1,                  uint, content AEAD selector
  "policy": {
    "sealed":     bool,               true = no plaintext may leave the vault (§12)
  },
  "slots":        [ KeySlot, ... ],   one per unlock method (§5)
  "mac":          bytes(32)           HMAC-SHA256 over the canonical encoding of
                                      every field above, keyed with K_mac
}
```

The `mac` field is what stops an attacker with disk access from weakening the
vault: lowering the Argon2id parameters, switching `alg_id`, or clearing
`policy.sealed` all invalidate it, and the unlock fails rather than proceeding
with weaker settings. It is verified **after** a slot has been unwrapped, since
`K_mac` derives from the master seed.

---

## 4. Key hierarchy

```
password ──Argon2id(salt, params)──> KEK          (32, never persisted)
                                      │ unwraps
                                 MasterSeed       (32, random at creation)
                                      │
   HKDF-SHA256(MasterSeed, salt = vault_id, info = <label>)
                                      │
   ┌────────────┬────────────┬────────┴────┬─────────────┐
"cv/content" "cv/names"  "cv/mac"    "cv/audit"    "cv/meta"
     │            │           │            │             │
 K_content     K_names     K_mac      K_audit       K_meta
```

| Sub-key | Label | Used for |
|---|---|---|
| `K_content` | `cv/content/v1` | Sealing file headers; each file's own key is inside its header |
| `K_names` | `cv/names/v1` | AES-SIV filename encryption (§8) |
| `K_mac` | `cv/mac/v1` | `HMAC(dir_id)` for directory placement (§9), and the config MAC (§3) |
| `K_audit` | `cv/audit/v1` | The local, per-machine audit log |
| `K_meta` | `cv/meta/v1` | The local, per-machine search index cache |

All sub-keys are 32 bytes. Labels carry a version suffix so a future key can be
rotated without colliding with an old one.

The master seed **never** encrypts user data directly. Everything goes through a
sub-key, so any one of them can be retired without touching the others.

---

## 5. Key slots

A key slot wraps the master seed for one unlock method. Every slot wraps the
**same** master seed independently.

```
KeySlot {
  "kind":        uint,        1 = password, 2 = recovery key,
                              3 = OS keychain, 4 = keyfile/FIDO2
  "label":       text,        user-visible name, e.g. "MacBook Touch ID"
  "kdf":         "argon2id",
  "salt":        bytes(16),   unique per slot
  "m_kib":       uint,        Argon2id memory cost
  "t":           uint,        Argon2id iterations
  "p":           uint,        Argon2id parallelism
  "alg_id":      uint,        AEAD used for the wrap
  "nonce":       bytes(12),
  "wrapped":     bytes(48)    AEAD(KEK, nonce, aad = binding, MasterSeed) ‖ tag
}
```

The wrap's associated data ties it to its own slot:

```
binding = kind(1) ‖ alg_id(1) ‖ salt(16) ‖ m_kib(u32) ‖ t(u32) ‖ p(u32)
```

Strictly this is belt and braces — altering a cost parameter already changes the
derived key, so a tampered slot would fail to unwrap regardless. It is specified
so that a wrap cannot be lifted out of one slot and pasted into another with
different settings, and so that such an attempt fails as an authentication
failure rather than as a puzzling wrong password.

`label` is deliberately **excluded** from the binding: renaming a slot must not
require the password. It is covered by the configuration MAC in §3, so it still
cannot be changed by anyone without the vault key.

Consequences worth stating plainly, because this is the single design decision
that most affects what the project can do later:

- **Changing the password rewrites 48 bytes.** No file is re-encrypted.
- **Adding Touch ID, a recovery key or a hardware token adds one slot.** No file
  is re-encrypted, and no format version changes.
- Removing a slot removes one unlock method and nothing else.
- A slot whose `m_kib`, `t` or `p` is below the minimum in `cv-crypto::kdf` is
  **rejected**, not silently raised.

Unlocking tries the supplied credential against each slot of the matching kind
and stops at the first success. A failure is reported as a single generic
"wrong password": which slot failed is not the user's business and not an
attacker's either.

---

## 6. Encrypted file format (`.cvf`)

### 6.1 Overall structure

```
┌───────────────────────────────────────────────────────────┐
│ HEADER PREFIX  (40 bytes, cleartext, authenticated as AAD)│
├───────────────────────────────────────────────────────────┤
│ SEALED HEADER  (40 + meta_len bytes + 16 tag)             │
├───────────────────────────────────────────────────────────┤
│ CHUNK 0, CHUNK 1, … CHUNK n-1                             │
└───────────────────────────────────────────────────────────┘
```

### 6.2 Header prefix — 40 bytes, cleartext

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `CVF1` |
| 4 | 1 | `version` | `0x01` |
| 5 | 1 | `alg_id` | `0x01` = AES-256-GCM |
| 6 | 1 | `mode` | `0x01` live, `0x02` archived (§7) |
| 7 | 1 | `reserved` | Must be `0x00`; readers reject anything else |
| 8 | 16 | `file_id` | Random, **immutable for the life of the file** |
| 24 | 12 | `nonce_hdr` | Fresh on every header write |
| 36 | 4 | `meta_len` | Length of the metadata inside the sealed block, ≤ 64 KiB |

The whole 40-byte prefix is the AAD of the sealed header, so none of it can be
altered without detection.

### 6.3 Sealed header

```
sealed = AEAD_encrypt(
    key   = K_content,
    nonce = nonce_hdr,
    aad   = header_prefix (40 bytes),
    data  = file_key(32) ‖ plain_size(u64) ‖ metadata(meta_len)
)
```

Total header size = `40 + 32 + 8 + meta_len + 16` = **96 + `meta_len`**.

`plain_size` lives inside the sealed block because an AEAD tag detects a
*modified* file but not a *truncated* one. Without it, chopping the last chunk
off a file would go unnoticed.

### 6.4 Chunks

Chunk `i` on disk:

```
nonce_i (12) ‖ ciphertext_i ‖ tag_i (16)

ciphertext_i = AEAD_encrypt(
    key   = file_key,
    nonce = nonce_i,                       ← fresh random bytes on every write
    aad   = u64_le(i) ‖ file_id,
    data  = plaintext chunk i
)
```

- Plaintext chunk size is **32768 bytes**; every chunk is full except possibly
  the last. A zero-length file has no chunks at all.
- On-disk chunk size is 32796 bytes. Overhead is 28 bytes per 32 KiB, or
  **0.085%**.
- Chunk `i` begins at `header_len + i * 32796`.

Three properties this arrangement buys, and the reason each matters:

1. **Random access.** The chunk containing plaintext offset `o` is `o / 32768`.
   Reading 4 KiB from a 2 GiB file decrypts 32 KiB, not 2 GiB.
2. **Chunks cannot be reordered, duplicated or dropped**, because the index is
   in the AAD.
3. **Chunks cannot be transplanted from another file**, because `file_id` is in
   the AAD.

**On `file_id` rather than `nonce_hdr` in the AAD.** Metadata is mutable: adding
a tag or marking a file for versioning re-seals the header with a fresh nonce.
Had chunks been bound to the header nonce, adding a tag would have invalidated
every chunk in the file. `file_id` is generated once and never changes.

**On random nonces.** Each file has its own `file_key`, so a counter-based nonce
would look safe. It is not: chunks are rewritten in place, and rewriting chunk
`i` with nonce `i` would reuse the (key, nonce) pair on different plaintext,
which with GCM discloses the authentication key. Random 96-bit nonces under a
per-file key leave an enormous margin — a collision needs on the order of 2³²
chunk writes to the same file.

---

## 7. Archived mode *(reserved — milestone M6)*

`mode = 0x02`. A user action ("Archive") rewrites a file as a compressed stream
with optional Reed-Solomon parity over GF(256). Archived files are sequential
and read-only until restored.

The mode exists because compression and parity are both incompatible with
in-place mutation — compression breaks the offset-to-chunk mapping, and parity
would have to be recomputed on every write. Rather than half-supporting them,
the format makes it an explicit state.

Layout to be specified in M6.

---

## 8. Filename encryption

### 8.1 Algorithm

```
K_siv      = HKDF-Expand(prk = K_names, info = "cv/names/siv/v1", L = 64)
ciphertext = AES-256-SIV(K_siv, nonce = 0^16, aad = dir_id, plaintext = name_utf8)
on_disk    = base64url_nopad(ciphertext) ‖ "." ‖ extension
```

The ciphertext is `16 + len(name)` bytes: AES-SIV prepends the synthetic
initialisation vector, which doubles as the authentication tag.

Two details that look odd and are not:

- **The SIV key is 64 bytes, not 32.** AES-256-SIV runs two keyed constructions
  and needs double-width key material. Rather than making one branch of the key
  hierarchy a different width from every other, `K_names` stays 32 bytes like
  its siblings and is expanded here under its own label.
- **The nonce is a constant zero.** With SIV the nonce is just one more
  associated-data input, and the construction is specifically built to remain
  secure when it repeats. Determinism is the requirement here, not an accident,
  and SIV is the algorithm chosen because it makes determinism safe.

AES-SIV is **deterministic**, which is required: opening `/Reports/2026.pdf`
must compute the on-disk name directly, without listing and decrypting the whole
directory. The parent's `dir_id` is the associated data, so the same name in two
directories yields different ciphertext.

The price of determinism is stated in the threat model: identical names in the
same directory are identical on disk.

### 8.2 What names are legal

Because what reaches the disk is base64url of a ciphertext, the host
filesystem's naming rules do not apply to the user's names. `CON`, `NUL`,
`report: Q1*.txt`, trailing dots and trailing spaces are all storable, on every
platform. The rules are only:

- Not empty, not `.`, not `..`
- No `/` and no NUL
- At most 255 bytes of UTF-8

### 8.3 Long names

If the encoded name exceeds **220 bytes**, the on-disk name becomes
`base64url(SHA-256(ciphertext))[0..32] ‖ ".cvn"`, and the full encrypted name is
stored inside that file. Costs one extra read; keeps every path component inside
the limits of NTFS, APFS, ext4 and every sync client we have tested.

---

## 9. Directory mapping

### 9.1 Placement

Every directory has a random 16-byte `dir_id`. The vault root's `dir_id` is
all zeros. A directory's location on disk is:

```
h    = HMAC-SHA256(K_mac, dir_id)
b32  = base32_nopad_uppercase(h)
path = "d/" ‖ b32[0..2] ‖ "/" ‖ b32[2..]
```

Two consequences:

- **Renaming or moving a directory with 10 000 files rewrites one file** — the
  parent's `.cvd` entry. Nothing under it moves on disk.
- The depth of the vault tree is invisible: everything is two levels deep.

The 2-character shard keeps any single directory from accumulating tens of
thousands of entries, which degrades on NTFS and upsets several sync clients.

### 9.2 Subdirectory references (`.cvd`)

A `.cvd` file sits in the parent's on-disk directory, named with the encrypted
child name, and contains a sealed block holding the child's `dir_id` and the
directory's own metadata (including `previews_enabled`).

### 9.3 Traversal is impossible by construction

A decrypted name is **never** concatenated onto a host path — the location is
derived from the HMAC of a `dir_id`. Even a name that reads `../../etc/passwd`
addresses nothing. Independently, `VPath` parsing rejects `.`, `..`, separators
and NUL, so such a name cannot enter a vault in the first place. Two layers,
because one is never enough for this class of bug.

---

## 10. Metadata, trash and versions

### 10.1 File metadata (CBOR, inside the sealed header)

```
{
  "mtime":      uint,          Unix seconds, original modification time
  "ctime":      uint,          Unix seconds, original creation time
  "mode":       uint,          POSIX permission bits, normalised across platforms
  "exec":       bool,          executable flag
  "versioned":  bool,          this file is kept in .versions/ when it changes
  "tags":       [text],        user labels
  "note":       text,          user annotation
  "ext":        text,          original extension, so an icon can be chosen
                               without decrypting any content
}
```

All fields optional; unknown fields are preserved on rewrite where possible and
otherwise ignored. Total encoded size ≤ 64 KiB.

Extended attributes and system tags are deliberately **not** stored: they are the
least portable metadata across the three platforms, and the complexity is out of
proportion to the benefit.

### 10.2 Trash and versions *(reserved — milestone M6)*

`.trash/` holds deleted entries with their original path sealed alongside, so a
restore can put them back. `.versions/` holds previous copies of files whose
metadata has `versioned = true` — versioning is opt-in **per file**, chosen by
the user, because in a synced vault every retained version is cloud storage and
bandwidth the user did not ask for.

---

## 11. `.cvlock` *(reserved — milestone M7)*

An advisory, cooperative lock: machine identifier, timestamp, heartbeat. Its
purpose is to warn a user who is about to open the same vault from a second
machine. It is a warning, never a hard block — a stale lock file must never be
able to make a vault inaccessible.

---

## 12. Sealed vaults

`policy.sealed = true` in `vault.cvconf`, covered by the config MAC. A sealed
vault refuses drag-out, plaintext export and opening files in external
applications; contents are reachable only through the internal viewers, and
sharing only through encrypted `.ecf` export.

**This is an application policy, not a cryptographic guarantee.** Anyone holding
the password can extract the data with the CLI or a modified build. It protects
against your own distraction and against someone borrowing your unlocked
session. It does not protect against the vault's owner, and it is not a DRM
mechanism. See `THREAT_MODEL.md` §B6.

---

## 13. Worked example

A 100 000-byte file with 48 bytes of metadata:

```
header_len   = 96 + 48                              =        144 bytes
chunks       = ceil(100000 / 32768)                 =          4
overhead     = 4 * 28                               =        112 bytes
on disk      = 144 + 100000 + 112                   =    100 256 bytes
overhead     = 256 / 100000                         =      0.256 %
```

The same file at 1 GiB: 32 768 chunks, 917 504 bytes of overhead, **0.085%**.

---

## 14. Open points

Tracked here until resolved, then moved into the body of the specification.

1. **Size padding.** Padding file sizes to fixed buckets would hide the exact
   size from a cloud provider, at a cost in storage and sync traffic. Not
   decided; currently not done, and disclosed in the threat model.
2. **Canonical CBOR encoding.** The MAC in §3 requires one, and the exact rules
   need pinning before M1 ships.
3. **Root `dir_id`.** All zeros is simple, but it makes the root directory's
   on-disk location identical across every vault. Using `vault_id` instead costs
   nothing and is probably better; to be decided in M1.
4. **Archived mode layout** — M6.
5. **`.ecf` export compatibility** with Cryptera — M8.

---

## 15. Version history

| Format version | Milestone | Change |
|---|---|---|
| 1 | M0 | First specification |
