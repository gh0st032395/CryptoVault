# Architecture Decision Records

Short documents recording decisions that were expensive to make and would be
expensive to reverse — together with the alternatives that were rejected and
why.

The reason for keeping them is narrow and practical: in eight months someone
(probably the author) will look at a design choice, fail to remember the
constraint that forced it, and "simplify" it back into the problem it solved.

## Index

| # | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-per-file-storage.md) | One encrypted file per vault file, not a single container | Accepted |
| [0003](0003-key-slots.md) | Key slots wrapping a single master seed | Accepted |
| [0004](0004-chunked-content-random-nonces.md) | Chunked content with a random nonce per write | Accepted |
| [0005](0005-external-apps-before-mount.md) | External applications first, virtual mount later | Accepted |

## Writing one

Copy the shape of an existing record: **Context** (the forces, not the
solution), **Decision**, **Consequences** (including the bad ones), and
**Alternatives considered** with the reason each was dropped.

A record is never edited to change its decision. If a decision is reversed, its
status becomes *Superseded by NNNN* and a new record explains what changed —
the record of a wrong turn is often more useful than the record of the right
one.
