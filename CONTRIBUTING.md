# Contributing to CryptoVault

Thank you for looking. This document is short on ceremony and specific about the
bar, because the bar is the point: CryptoVault asks people to trust it with
files they cannot afford to lose.

---

## The Definition of Done

A change is **finished** when all six are true. Not five.

### 1. It is verified by a test

No feature is merged without a test that exercises it. Unit tests next to the
code, integration tests in `tests/`, property tests where the input varies,
frozen vectors where the on-disk format is involved.

*A test that would still pass if the function were broken does not count as a
test.* When you write one, break the code on purpose and check that it goes red.

### 2. The code is structured and maintainable

- One module, one responsibility.
- Short functions, at a single level of abstraction.
- Typed errors with `thiserror`. No `unwrap()` outside tests, no `panic!` on
  user input — a panic in a vault is data the user can no longer reach.
- No duplication: the second occurrence gets extracted.
- `unsafe` is denied workspace-wide. If you genuinely need it, opt in at that
  one site with `#[allow(unsafe_code)]` and a comment justifying it.

### 3. The code is commented

- Doc comments (`///`) on **every** public item. `missing_docs` is denied, so CI
  enforces this.
- Comments in the body explain **why**, not what. The code says what.
- Every non-obvious cryptographic choice carries its reasoning next to it, and a
  reference where one exists. Six months from now, "why a random nonce here and
  not a counter?" must be answerable without archaeology.

### 4. The user manual is updated in the same commit

Every user-visible feature updates its section in `docs/manual/it/` and
`docs/manual/en/`.

Not at the end of the project. At the end of a project nobody remembers why an
option exists. And organise the code *so that it can be described*: if a
function takes more than two sentences to explain, the problem is usually the
function.

### 5. You re-checked what you changed

After every modification, re-read the code you touched and re-run the full
verification **before** committing. This applies to small changes too —
that is where regressions come from.

### 6. The changelog is updated

If the change is visible to a user, add a line to `CHANGELOG.md` under
*Unreleased*.

---

## The verification command

One command. Identical to what CI runs.

```bash
./scripts/check.sh
```

```powershell
.\scripts\check.ps1
```

It runs formatting, clippy with warnings as errors, the full test suite,
documentation with warnings as errors, and the supply-chain audit. Add `--fast`
(or `-Fast`) to skip the last one while iterating.

If it fails, the commit waits. There is no "it's only a small change" exception.

---

## Test coverage by area

There is no target percentage. Chasing a number produces tests that exist for
the statistic. The rule is: **every behaviour described in the user manual has a
test that demonstrates it.**

| Area | Requirement |
|---|---|
| `cv-crypto`, `cv-format` | Every public function tested **and every error path exercised**. Frozen test vectors. All parsers fuzzed |
| `cv-vault`, `cv-vfs` | Integration tests against real temporary vaults; full round trips; concurrency edge cases |
| `cv-ops` | Realistically sized files (generated, never committed); cancellation and resumption |
| UI | Components with non-trivial state are tested; the rest has a documented manual check |
| Performance | Benchmarks in CI with thresholds — a regression over 20% fails the build |

---

## Commits, branches and pull requests

- **Frequent and atomic.** One commit is one coherent, complete change with its
  verification passing. Ten small commits beat one of two thousand lines.
- **[Conventional Commits](https://www.conventionalcommits.org/):** `feat:`,
  `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`, `sec:`.
- **Branches:** one per milestone (`feat/m1-core-crypto`), merged by pull
  request so CI acts as the gate. `main` is always green and always buildable.
- **Never commit** secrets, private keys, test vaults, or large fixtures. A
  committed vault is a committed secret, even when it is "just a test". The
  `.gitignore` blocks the obvious cases; it is not a substitute for looking at
  `git diff --staged`.

---

## Project language

**Code, comments, doc comments, commit messages, issues and pull requests in
English** — the project is open source and English is what lets anyone
contribute.

**User-facing documentation in Italian and English:** the manual, the READMEs,
release notes and the interface.

---

## Getting started

```bash
git clone https://github.com/gh0st032395/CryptoVault.git
cd CryptoVault
cargo build --workspace
./scripts/check.sh --fast
```

The toolchain version is pinned in `rust-toolchain.toml`; `rustup` fetches it
automatically. `cargo install cargo-deny` enables the supply-chain step.

Worth reading before your first change:

1. [`PLAN.md`](PLAN.md) — what is being built and, more usefully, why each
   decision went the way it did
2. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what counts as a security bug
3. [`docs/FORMAT_SPEC.md`](docs/FORMAT_SPEC.md) — normative; if the code and the
   specification disagree, the code is wrong

---

## Changing the on-disk format

Treated with more care than anything else in the repository, because it is the
one thing that cannot be quietly revised once somebody's files depend on it.

1. Update `docs/FORMAT_SPEC.md` **first**, including its version history.
2. Then change the code.
3. The frozen vectors in `tests/vectors/` will fail. That is the mechanism
   working. Regenerate them only once you are certain the change is intended,
   and say so explicitly in the commit message.
4. Provide a migration path, or bump the format version so old builds refuse the
   vault rather than misreading it.

---

## Reporting a security issue

Not here. See [`SECURITY.md`](SECURITY.md).
