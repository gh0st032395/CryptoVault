# The user manual

This directory holds the CryptoVault user manual, in Italian (`it/`) and English
(`en/`). It is written for people using the application, not for people
developing it.

## The rule

**Every user-visible feature updates its manual section in the same commit that
implements it.** Point 4 of the Definition of Done in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

Not at the end of the project. By the end of a project nobody remembers why an
option exists, which is exactly how manuals end up describing what a button is
called instead of when to press it.

There is a second, less obvious reason. Writing the manual entry while the code
is fresh is a design check: **if a feature takes more than two paragraphs to
explain, the problem is usually the feature.** More than one option in this
project will be simplified because its manual section came out unreadable.

## Structure

Chapters are numbered files. Each chapter says which milestone delivers it;
chapters for unbuilt features do not exist yet, because a manual describing
software that does not exist is worse than no manual.

| Chapter | Milestone | Status |
|---|---|---|
| 01 Introduction | — | written |
| 02 Installation | M10 | pending |
| 03 Creating your first vault | M3 | pending |
| 04 Unlocking and locking | M3 | pending |
| 05 Adding and organising files | M3 | pending |
| 06 Opening files in other applications | M4 | pending |
| 07 Search and previews | M5 | pending |
| 08 Trash, versions and integrity | M6 | pending |
| 09 Using a vault with cloud storage | M7 | pending |
| 10 Sharing, backup and archives | M8 | pending |
| 11 Losing your password | M11 | pending |
| 12 What CryptoVault does not protect against | — | written |
| 13 Troubleshooting | M10 | pending |

## What is deliberately not in here

The `cryptovault` command-line tool. It exists and it works, but it is the
project's own test instrument rather than a product: its command surface is
still moving, and documenting it in a user manual would promise a stability
nobody should rely on yet. Its `--help` output is its documentation until it
ships as a supported tool, after the desktop release.

Recorded here rather than left as a silent gap, so that nobody has to wonder
whether it was forgotten.

## Writing style

- **Second person, plain language.** "Choose a folder", not "the user selects a
  directory".
- **Say when, not just how.** A reader can see the button. What they cannot see
  is whether they should press it.
- **State the limits where they are relevant**, not only in chapter 12. A reader
  deciding whether to open a file in Word deserves to know about the temporary
  file right there.
- **Never promise more than the software delivers.** For a security tool this is
  the whole of the manual's credibility.
- The two languages stay in step. Translating is part of the same commit, not a
  separate chore.
