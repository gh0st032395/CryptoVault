#!/usr/bin/env bash
#
# The single verification command for CryptoVault.
#
# Run it before every commit. CI runs exactly the same steps, so a green run here
# means a green run there. If it fails, the commit waits — there is no "it's only
# a small change" exception, because that is where regressions come from.
#
# Usage:
#   ./scripts/check.sh          full check
#   ./scripts/check.sh --fast   skip the slow supply-chain audit

set -euo pipefail

cd "$(dirname "$0")/.."

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

step() { printf '\n\033[1;34m▸ %s\033[0m\n' "$1"; }
skip() { printf '\n\033[1;33m▸ %s (skipped: %s)\033[0m\n' "$1" "$2"; }

# The interface comes first, and not for tidiness: `cv-desktop` embeds
# `ui/dist` at compile time, so without this step `cargo clippy` and
# `cargo test` fail outright on a clean checkout — and on a dirty one they
# quietly check the interface as it was the last time somebody built it.
step "Interface (types, Svelte, and the build the desktop binary embeds)"
if [[ ! -d ui/node_modules ]]; then
    printf '\033[1;31mui/node_modules is missing. Run:\033[0m npm --prefix ui ci\n' >&2
    exit 1
fi
npm --prefix ui run check
npm --prefix ui run build

step "Formatting"
cargo fmt --all -- --check

step "Lints (warnings are errors)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

step "Tests"
cargo test --workspace --all-features

step "Documentation builds without warnings"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

if [[ $FAST -eq 1 ]]; then
    skip "Supply chain" "--fast"
elif command -v cargo-deny >/dev/null 2>&1; then
    step "Supply chain (licences, advisories, sources)"
    cargo deny check
else
    skip "Supply chain" "cargo-deny not installed — cargo install cargo-deny"
fi

printf '\n\033[1;32m✓ All checks passed\033[0m\n'
