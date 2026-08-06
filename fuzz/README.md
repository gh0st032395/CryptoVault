# Fuzzing

Every parser in CryptoVault reads bytes that may be corrupt, truncated by a
crash, half-written by a sync client, or crafted by somebody who would like the
reader to misbehave. These targets exist to keep that honest.

## Running

Fuzzing needs a nightly toolchain. This directory is deliberately its **own**
workspace, so the pinned stable toolchain at the repository root is unaffected.

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

```bash
cargo +nightly fuzz run header
```

Run for a fixed time instead of until interrupted:

```bash
cargo +nightly fuzz run config -- -max_total_time=300
```

## Targets

| Target | What it probes |
|---|---|
| `header` | The file-header parser, which reads before anything is authenticated |
| `chunk` | Chunk decryption, including truncated chunks and arbitrary chunk indices |
| `config` | `vault.cvconf`: CBOR, read before its own MAC can be checked |
| `name` | Filename decoding, and the assertion that no input yields a traversal name |

## What the targets assert

Mostly nothing, on purpose. Almost every input should be **rejected**, and the
property under test is that rejection is always clean: no panic, no
out-of-bounds slice, no allocation sized from an unchecked length field, no
arithmetic overflow.

`name` is the exception. It asserts that a decoded name can never be `.`, `..`,
empty, or contain a separator or NUL. Directory traversal is already impossible
by construction — a decrypted name is never joined onto a host path, because a
directory's location comes from the HMAC of its identifier — and this makes the
second layer of that defence something a fuzzer verifies rather than something
the code merely intends.

## When a target finds something

`cargo fuzz` writes the input to `fuzz/artifacts/<target>/`. **Do not commit
it**: it is untriaged input, and the artifacts directory is in `.gitignore`.

Reproduce, fix, and add the case as an ordinary unit test next to the code —
a fuzzer finding the same bug twice means the first fix was never pinned down.

If the finding affects the confidentiality or integrity of user data, follow
[`SECURITY.md`](../SECURITY.md) rather than opening a public issue.
