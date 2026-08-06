//! `cryptovault` — command-line interface to a vault.
//!
//! Built first as the project's own test instrument: it lets every vault
//! operation be exercised end to end before a single pixel of interface exists,
//! which is the only way to keep the format honest during milestone M1.
//!
//! It is published as a supported tool only after the desktop release, once the
//! command surface has stopped moving. Until then its interface may change
//! between commits, and the `--help` output says so.

use std::process::ExitCode;

/// Version of the CryptoVault workspace, taken from `Cargo.toml`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("cryptovault {VERSION}");
            ExitCode::SUCCESS
        }
        None | Some("--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(unknown) => {
            eprintln!("cryptovault: unknown command {unknown:?}");
            eprintln!("Try 'cryptovault --help'.");
            // 2 is the conventional exit code for a usage error, distinct from 1
            // for an operation that ran and failed. Scripts rely on the
            // difference.
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "\
cryptovault {VERSION}
Command-line interface to a CryptoVault encrypted vault.

USAGE:
    cryptovault <COMMAND> [OPTIONS]

STATUS:
    Milestone M0. No command is implemented yet; the vault operations arrive in
    milestone M2. This interface is not stable and is not yet supported for
    scripting.

PLANNED COMMANDS:
    init      Create a new vault
    unlock    Unlock a vault for the current session
    ls        List a directory inside a vault
    add       Add a file or folder to a vault
    get       Extract a file from a vault
    rm        Remove a file or folder from a vault
    mv        Move or rename inside a vault
    verify    Check the integrity of a vault without decrypting its contents

OPTIONS:
    -h, --help       Print this help
    -V, --version    Print the version

CryptoVault never sends anything over the network. See
https://github.com/gh0st032395/CryptoVault for the documentation."
    );
}
