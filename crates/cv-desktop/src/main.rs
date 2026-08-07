//! CryptoVault, as a window.
//!
//! This crate is deliberately the thinnest thing in the workspace. It owns a
//! window, a session behind a lock, and a table of commands — and that is the
//! entire list. Everything a vault does lives in [`cv_session`] and below, where
//! it is tested against real vaults on disk rather than by opening the
//! application and clicking.
//!
//! # Why so little
//!
//! Because logic that lives inside a user-interface framework can only be
//! exercised by running the framework, and "unlock, browse, lock, unlock again"
//! is exactly the sequence where a session bug hides. The rule that keeps it
//! that way is stated in [`commands`]: a command takes the lock, calls one
//! method, converts the error. If one ever needs to decide something, the
//! decision belongs a layer down.
//!
//! # What crosses the boundary
//!
//! JSON, in both directions. Vault contents never do — the interface asks for a
//! directory listing and gets names, sizes and dates; file bytes have no command
//! and no path across, and will not get one before M4 gives them somewhere to go
//! that is not a webview.
//!
//! Passwords do cross, as ordinary strings. That is a known weakness and is
//! written down as R-23: the string exists in the webview's heap and in a Rust
//! `String`, and neither is wiped.
//!
//! # Which vaults exist
//!
//! Kept in the platform's configuration folder, not next to the vaults. A vault
//! is complete on its own and knows nothing about being in a list; the list is a
//! property of this application, so it lives with this application.
//!
//! # Running it
//!
//! Two loops, and the difference between them is not the cargo profile — it is
//! whether the Tauri CLI was involved. A plain `cargo build --release` still
//! points the window at the development server.
//!
//! Development, with the interface reloading from Vite:
//!
//! ```text
//! npm --prefix ui run dev        # in one terminal, and leave it
//! cargo run -p cv-desktop        # in another
//! ```
//!
//! The application itself, with the interface embedded in the binary:
//!
//! ```text
//! npm --prefix ui run build
//! cd crates/cv-desktop && tauri build --no-bundle
//! ```
//!
//! `--no-bundle` because installers are M10. Dropping it produces an unsigned
//! `.app` or `.msi`, which is worse than no installer at all.

// A release build must not open a console window behind the application on
// Windows. Debug builds keep it, because that is where panics are read.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod commands;

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

use cv_session::Session;

/// The list of vaults, inside the platform's configuration folder.
const REGISTRY_FILE: &str = "vaults.cbor";

/// Everything the commands share.
///
/// One lock around the whole session rather than one per vault. Vault
/// operations are not the bottleneck — a single unlock spends about a second in
/// Argon2id by design — and a single lock cannot deadlock against itself, which
/// a finer-grained scheme would eventually find a way to do.
pub(crate) struct AppState {
    /// The vaults this application knows about, and which are open.
    session: Mutex<Session>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cryptovault: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let context = tauri::generate_context!();

    // The vault list is read before the application is built, and that ordering
    // is the whole point rather than a detail.
    //
    // The obvious place for this is Tauri's `setup` hook, which is also the one
    // place where an error is not an error: Tauri turns a failed setup into a
    // panic, so a vault list that could not be parsed would abort the process
    // with a Rust backtrace instead of the sentence written to explain it. Out
    // here a failure is an ordinary `Err`, and the user gets the message and an
    // exit code.
    //
    // The cost is resolving the configuration directory ourselves rather than
    // asking the app handle, which is why `config_directory` exists below.
    let registry = config_directory(&context.config().identifier)?.join(REGISTRY_FILE);
    let session = Session::open(&registry)?;

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            session: Mutex::new(session),
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_vaults,
            commands::create_vault,
            commands::register_vault,
            commands::forget_vault,
            commands::unlock,
            commands::lock,
            commands::read_dir,
            commands::create_dir,
            commands::remove,
            commands::rename,
        ])
        .run(context)?;

    Ok(())
}

/// Where this application keeps its own files.
///
/// The same folder Tauri's path resolver would give — `Application Support` on
/// macOS, `AppData\Roaming` on Windows, `~/.config` on Linux, each with the
/// application identifier under it — computed without a running application so
/// that it can be used before there is one.
///
/// The identifier comes from the generated context rather than a constant here,
/// so that changing it in `tauri.conf.json5` cannot leave this pointing at a
/// folder nothing else uses.
fn config_directory(identifier: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = dirs::config_dir()
        .ok_or("this system has no configuration directory to keep the vault list in")?;

    Ok(base.join(identifier))
}
