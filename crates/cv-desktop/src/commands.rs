//! One command per thing the interface can ask.
//!
//! Every function here does the same three things and nothing else: take the
//! lock, call the matching [`cv_session::Session`] method, convert the error.
//! There is no branching, no validation and no policy — those live a layer
//! down, where they can be tested without starting a window.
//!
//! That is a rule rather than a description. The moment a command here starts
//! deciding something, the decision has escaped the tested layer, and the only
//! way to exercise it is to run the application and click.

// A command's parameters are where Tauri deserialises the incoming JSON, so
// they have to own what they hold: there is nothing on the other side of the
// boundary for a `&str` to borrow from. Clippy is right in general and wrong
// here, and the alternative — copying every argument into an owned value inside
// the body — would satisfy the lint by doing the same allocation one line
// later.
#![allow(clippy::needless_pass_by_value)]

use std::path::{Path, PathBuf};

use cv_session::{Entry, SessionError, VaultSummary};
use serde::Serialize;
use tauri::{AppHandle, State};

use crate::AppState;

/// A failure on its way to the interface.
///
/// Two fields, and the split matters. `kind` is [`SessionError::kind`] — a
/// stable tag the interface branches on, so that a wrong password can get a
/// shake and a retry without anyone matching on English prose. `message` is for
/// the person reading the screen, and is the only part that will ever change
/// wording.
#[derive(Debug, Serialize)]
pub(crate) struct CommandError {
    /// The stable machine-readable tag.
    kind: &'static str,
    /// The failure, already phrased for a person.
    message: String,
}

impl From<SessionError> for CommandError {
    fn from(error: SessionError) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl CommandError {
    /// The session lock could not be taken, because a previous command panicked
    /// while holding it.
    ///
    /// This should not happen — the layer underneath does not panic on user
    /// input — but a poisoned lock is a state the type system makes us handle,
    /// and the honest answer is that the application no longer knows what it is
    /// holding. Saying so beats carrying on with a session in an unknown state.
    fn poisoned() -> Self {
        Self {
            kind: "failed",
            message: "the application is in an unknown state after an internal error; \
                      close it and open it again"
                .to_owned(),
        }
    }
}

/// Runs `work` with the session locked.
///
/// Every command is this shape, so it is written once. The closure takes the
/// session by unique reference because half the operations need it, and having
/// two helpers to save a `mut` on the other half would be worse.
fn with_session<T>(
    state: &State<'_, AppState>,
    work: impl FnOnce(&mut cv_session::Session) -> Result<T, SessionError>,
) -> Result<T, CommandError> {
    let mut session = state.session.lock().map_err(|_| CommandError::poisoned())?;
    work(&mut session).map_err(CommandError::from)
}

/// Every vault the application knows about, open or not.
#[tauri::command]
pub(crate) fn list_vaults(state: State<'_, AppState>) -> Result<Vec<VaultSummary>, CommandError> {
    with_session(&state, |session| Ok(session.list()))
}

/// Creates a vault in `parent`, in a folder named after it, and registers it.
///
/// The interface asks for a name and a place to put it, and this is where those
/// two become one path. Joining them here rather than in the interface is not
/// tidiness: `Path::join` uses the separator the platform actually wants, and a
/// path built by string concatenation in a webview would be subtly wrong on
/// Windows and only there.
///
/// It comes back locked, which is [`cv_session::Session::create`]'s decision and
/// worth repeating: typing the password once more immediately is the cheapest
/// possible check that it was typed as intended.
#[tauri::command]
pub(crate) fn create_vault(
    state: State<'_, AppState>,
    name: String,
    parent: String,
    password: String,
    sealed: bool,
) -> Result<String, CommandError> {
    let path = PathBuf::from(parent).join(&name);
    with_session(&state, |session| {
        session.create(&name, &path, &password, sealed)
    })
}

/// Adds a vault that already exists on disk to the list.
#[tauri::command]
pub(crate) fn register_vault(
    state: State<'_, AppState>,
    name: String,
    path: String,
) -> Result<String, CommandError> {
    with_session(&state, |session| session.register(&name, Path::new(&path)))
}

/// Drops a vault from the list without touching the folder it names.
#[tauri::command]
pub(crate) fn forget_vault(state: State<'_, AppState>, id: String) -> Result<(), CommandError> {
    with_session(&state, |session| session.forget(&id))
}

/// Opens a vault. About a second of Argon2id, on purpose.
#[tauri::command]
pub(crate) fn unlock(
    state: State<'_, AppState>,
    id: String,
    password: String,
) -> Result<(), CommandError> {
    with_session(&state, |session| session.unlock(&id, &password))
}

/// Shuts a vault, wiping its keys.
#[tauri::command]
pub(crate) fn lock(state: State<'_, AppState>, id: String) -> Result<(), CommandError> {
    with_session(&state, |session| session.lock(&id))
}

/// Lists a directory inside an open vault.
#[tauri::command]
pub(crate) fn read_dir(
    state: State<'_, AppState>,
    id: String,
    path: String,
) -> Result<Vec<Entry>, CommandError> {
    with_session(&state, |session| session.read_dir(&id, &path))
}

/// Creates a directory, and any of its parents that are missing.
#[tauri::command]
pub(crate) fn create_dir(
    state: State<'_, AppState>,
    id: String,
    path: String,
) -> Result<(), CommandError> {
    with_session(&state, |session| session.create_dir(&id, &path))
}

/// Removes an entry, and everything inside it if it is a directory.
#[tauri::command]
pub(crate) fn remove(
    state: State<'_, AppState>,
    id: String,
    path: String,
) -> Result<(), CommandError> {
    with_session(&state, |session| session.remove(&id, &path))
}

/// Tells the tray which language the interface is speaking.
///
/// The one command that is not a vault operation. The tray's menu is built in
/// Rust and its words have to match the window's, and the window is where the
/// language is chosen — so it says, rather than the tray guessing from the
/// system locale and disagreeing the moment somebody changes the setting.
#[tauri::command]
pub(crate) fn set_language(app: AppHandle, language: String) {
    crate::tray::relabel(&app, &language);
}

/// Moves or renames an entry.
#[tauri::command]
pub(crate) fn rename(
    state: State<'_, AppState>,
    id: String,
    from: String,
    to: String,
) -> Result<(), CommandError> {
    with_session(&state, |session| session.rename(&id, &from, &to))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag has to survive the trip. The interface branches on it, so an
    /// error that arrives as `"failed"` when it should say `"wrong-password"`
    /// turns a retry prompt into a dead end.
    #[test]
    fn a_session_error_keeps_its_tag_and_its_words() {
        let error = CommandError::from(SessionError::WrongPassword);

        assert_eq!(error.kind, "wrong-password");
        assert_eq!(error.message, "wrong password");
    }

    /// Field names are the contract with the interface, and renaming a field in
    /// Rust would break a branch in TypeScript with nothing to catch it.
    #[test]
    fn an_error_crosses_as_kind_and_message() {
        let error = CommandError::from(SessionError::UnknownVault {
            id: "v3".to_owned(),
        });
        let json = serde_json::to_string(&error).unwrap();

        assert!(json.contains(r#""kind":"unknown-vault""#), "{json}");
        assert!(json.contains(r#""message":"#), "{json}");
        assert!(json.contains("v3"), "{json}");
    }

    #[test]
    fn a_poisoned_lock_reports_something_a_person_can_act_on() {
        let error = CommandError::poisoned();

        assert_eq!(error.kind, "failed");
        assert!(error.message.contains("open it again"));
    }
}
