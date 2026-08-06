//! `cv-render` — renders untrusted documents in a process of its own.
//!
//! # Why this is a separate program
//!
//! Rendering a PDF means handing a large C parser a file that may have been
//! crafted to exploit it. Doing that inside the application that holds the vault
//! keys would mean one parser bug is enough to walk away with the keys.
//!
//! So it does not happen inside that process. `cv-render` is spawned as a child,
//! receives already-decrypted bytes on its standard input, and writes back raw
//! pixels. It has no vault keys, no filesystem access, and no network. If the
//! parser is exploited, the attacker lands in an empty process holding a copy of
//! a document they already supplied.
//!
//! The sandbox is enforced by the operating system, not by good intentions:
//! Seatbelt on macOS, a low-integrity job object on Windows, seccomp and Landlock
//! on Linux.
//!
//! Images and plain text are handled in-process by pure-Rust decoders and never
//! reach this program.
//!
//! # Status
//!
//! Milestone M0 reserves the binary and pins the protocol version. The IPC
//! protocol and the sandbox profiles are milestone M5.

use std::process::ExitCode;

/// Version of the renderer IPC protocol.
///
/// The parent refuses to talk to a child that reports a different number. A
/// mismatch means a stale binary is installed next to a new application, and
/// guessing at the protocol would be a fine way to feed a parser the wrong
/// bytes.
const PROTOCOL_VERSION: u32 = 1;

/// Version of the CryptoVault workspace, taken from `Cargo.toml`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--protocol-version") => {
            println!("{PROTOCOL_VERSION}");
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!("cv-render {VERSION} (protocol {PROTOCOL_VERSION})");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "cv-render is an internal helper of CryptoVault and is not meant to be run \
                 directly.\nIt is spawned by the application to render untrusted documents in \
                 isolation."
            );
            ExitCode::from(2)
        }
    }
}
