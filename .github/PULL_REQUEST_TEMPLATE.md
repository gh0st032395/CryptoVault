<!--
Thanks for contributing. The checklist below is the Definition of Done from
CONTRIBUTING.md. It is short on purpose; please do not tick anything you have
not actually done.
-->

## What this changes

<!-- What it does, and why. The "why" is the part a reviewer cannot reconstruct. -->

## Definition of Done

- [ ] **Tested.** A test exercises the change, and it fails when the code is broken (check by breaking it on purpose)
- [ ] **Structured.** One responsibility per module; no `unwrap()` or `panic!` outside tests; no duplication
- [ ] **Commented.** Doc comments on every public item; comments in the body explain *why*
- [ ] **Manual updated** in `docs/manual/it/` and `docs/manual/en/`, if anything is visible to a user
- [ ] **Re-checked.** I re-read what I changed and ran `./scripts/check.sh` — it passes
- [ ] **Changelog updated**, if the change is user-visible

## Format changes

<!-- Delete this section if the on-disk format is untouched. -->

- [ ] `docs/FORMAT_SPEC.md` updated **before** the code, including its version history
- [ ] Frozen test vectors regenerated deliberately, and the commit message says so
- [ ] A migration path exists, or the format version is bumped so older builds refuse the vault instead of misreading it

## Security

- [ ] No new dependency, or a new one justified below
- [ ] No new `unsafe`, or each site carries a comment justifying it
- [ ] Nothing new reaches the network
- [ ] No secret, key, test vault or large fixture committed (`git diff --staged` checked, not just `.gitignore` trusted)

<!--
A vulnerability report does not belong in a pull request. See SECURITY.md.
-->
