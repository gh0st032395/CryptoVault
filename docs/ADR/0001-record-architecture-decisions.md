# 0001 — Record architecture decisions

**Status:** Accepted
**Date:** 2026-08-06

## Context

CryptoVault's design is a chain of trade-offs rather than a set of obvious
answers. Sync-friendliness costs metadata privacy. Random access rules out
compression. Mutable files rule out counter-based nonces. Each of those was
decided after weighing something real against something else real.

Written down as conclusions, they look arbitrary. Someone — most likely the
author, months later — will see one, fail to remember the constraint behind it,
and "simplify" it straight back into the problem it was solving.

`PLAN.md` carries the reasoning for the decisions taken at the outset, but it is
a plan: it describes a moment in time and does not accumulate.

## Decision

Keep short, numbered, append-only architecture decision records in `docs/ADR/`.

One record per decision that is costly to reverse. Each states the forces, the
choice, the consequences including the unpleasant ones, and the alternatives
with the reason each was rejected.

Records are never rewritten to change their conclusion. A reversal marks the old
record *Superseded by NNNN* and adds a new one.

## Consequences

- A design question can be answered by reading one page instead of excavating
  git history or a conversation nobody kept.
- The rejected alternatives stay visible, which is what stops the same
  discussion from being had four times.
- It costs perhaps twenty minutes per significant decision, and it is tempting
  to skip when moving fast. The mitigation is keeping records genuinely short.

## Alternatives considered

- **Keep the reasoning in `PLAN.md`.** Works for the initial decisions, which is
  why they are there. A plan does not accumulate later decisions without turning
  into an unreadable pile.
- **Rely on commit messages.** Good commit messages help, and this project
  writes them. But a decision often spans many commits, and nobody finds it by
  searching a log.
- **Rely on code comments.** Right for local reasoning and used heavily. Wrong
  for a choice that shaped six crates and has no single place to live.
