//! The tray icon, and the one thing it is really for.
//!
//! **Lock every vault** is the point of this file. It is the control someone
//! reaches for when they hear footsteps, and the whole value of it is that it
//! is reachable when the window is not — behind another application, minimised,
//! on another desktop. A panic button you have to go and find first is not one.
//!
//! Everything else here — showing the window, quitting — is there because a
//! tray menu with a single item looks broken.
//!
//! # It locks, and then it says so
//!
//! Locking happens in Rust, so the window would otherwise carry on showing a
//! file browser for a vault whose keys are gone. Every entry in it would fail
//! the moment it was touched, which looks exactly like corruption. So the lock
//! is followed by an event, and the window returns to the vault list.

use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::AppState;

/// Announced after the tray locks everything, so the window can catch up.
pub(crate) const LOCKED_EVENT: &str = "vaults-locked";

const LOCK_ALL: &str = "lock-all";
const SHOW: &str = "show";
const QUIT: &str = "quit";

/// The tray's words. Short ones: a menu is not the place to explain.
struct Labels {
    lock_all: &'static str,
    show: &'static str,
    quit: &'static str,
}

const ENGLISH: Labels = Labels {
    lock_all: "Lock every vault",
    show: "Show CryptoVault",
    quit: "Quit CryptoVault",
};

const ITALIAN: Labels = Labels {
    lock_all: "Blocca tutti i vault",
    show: "Mostra CryptoVault",
    quit: "Esci da CryptoVault",
};

const fn labels(language: &str) -> &'static Labels {
    // `starts_with` rather than equality: the window sends its own two-letter
    // code today, and a full locale tomorrow would otherwise silently fall back
    // to English.
    if language.len() >= 2 && language.as_bytes()[0] == b'i' && language.as_bytes()[1] == b't' {
        &ITALIAN
    } else {
        &ENGLISH
    }
}

/// The menu items, kept so their words can follow the interface's language.
pub(crate) struct Tray {
    lock_all: MenuItem<Wry>,
    show: MenuItem<Wry>,
    quit: MenuItem<Wry>,
}

/// Builds the tray and hands it to the application to own.
///
/// # Errors
///
/// Whatever the platform says. A machine with no system tray at all — some
/// Linux desktops — fails here, and the caller treats that as a warning rather
/// than a reason not to start: the window has its own lock button, and refusing
/// to run would be a worse answer than running without a menu-bar icon.
pub(crate) fn install(app: &AppHandle) -> tauri::Result<()> {
    // English until the window says otherwise, which it does as soon as it
    // loads. Guessing from the system locale here would be a second opinion
    // about the same question, and the two would disagree the moment somebody
    // changed the language in the settings.
    let words = &ENGLISH;

    let lock_all = MenuItem::with_id(app, LOCK_ALL, words.lock_all, true, None::<&str>)?;
    let show = MenuItem::with_id(app, SHOW, words.show, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, QUIT, words.quit, true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;

    // Locking sits above the separator, on its own. It is the item people will
    // hit in a hurry, and it must not be adjacent to "Quit".
    let menu = Menu::with_items(app, &[&lock_all, &separator, &show, &quit])?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("CryptoVault")
        .show_menu_on_left_click(true)
        // Tauri hands the event over by value; the handler only reads it.
        .on_menu_event(|app, event| on_menu_event(app, &event));

    builder = with_icon(app, builder);
    builder.build(app)?;

    app.manage(Tray {
        lock_all,
        show,
        quit,
    });

    Ok(())
}

/// Puts the tray's words into `language`.
///
/// Does nothing when there is no tray, which is the ordinary state of affairs
/// on a desktop that has none.
pub(crate) fn relabel(app: &AppHandle, language: &str) {
    let Some(tray) = app.try_state::<Tray>() else {
        return;
    };

    let words = labels(language);
    // Best effort: a menu item that will not rename itself is not a reason to
    // fail the call that renamed the other two.
    let _ = tray.lock_all.set_text(words.lock_all);
    let _ = tray.show.set_text(words.show);
    let _ = tray.quit.set_text(words.quit);
}

/// The menu-bar icon.
///
/// macOS wants a *template* image: it is drawn from the alpha channel alone, so
/// the system can invert it for a dark menu bar. That rules out the application
/// icon, which is an opaque tinted square and would arrive as a solid black
/// block. Everywhere else the tray is a small colour icon like any other, and
/// the application icon is the right one.
fn with_icon(app: &AppHandle, builder: TrayIconBuilder<Wry>) -> TrayIconBuilder<Wry> {
    #[cfg(target_os = "macos")]
    {
        let _ = app;
        match tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png")) {
            Ok(icon) => builder.icon(icon).icon_as_template(true),
            Err(_) => builder,
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        match app.default_window_icon() {
            Some(icon) => builder.icon(icon.clone()),
            None => builder,
        }
    }
}

fn on_menu_event(app: &AppHandle, event: &MenuEvent) {
    match event.id().as_ref() {
        LOCK_ALL => lock_everything(app),
        SHOW => show_window(app),
        QUIT => app.exit(0),
        _ => {}
    }
}

/// Shuts every vault, then tells the window.
fn lock_everything(app: &AppHandle) {
    let state = app.state::<AppState>();

    let mut session = match state.session.lock() {
        Ok(session) => session,
        // A poisoned lock means an earlier command panicked while holding it.
        // Everywhere else that is reported and the operation refused; here it
        // is recovered from deliberately. This is the control whose entire
        // purpose is to work when something has gone wrong, and `lock_all`
        // only removes values — there is no half-written state for a previous
        // panic to have left behind that dropping the keys could make worse.
        Err(poisoned) => poisoned.into_inner(),
    };

    session.lock_all();
    drop(session);

    let _ = app.emit(LOCKED_EVENT, ());
}

fn show_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };

    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}
