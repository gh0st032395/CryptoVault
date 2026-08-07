/**
 * The two things the interface needs from the machine it is running on.
 *
 * Kept apart from `backend.ts` because neither is a vault operation: one is
 * "which of the two worlds am I in", and the other is a system dialogue that
 * happens to return a path.
 */

import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open } from '@tauri-apps/plugin-dialog';

/**
 * Whether this is the desktop application rather than a browser.
 *
 * Read once, at startup. Tauri sets the flag before any of our code runs, so
 * there is nothing to wait for, and a value that cannot change during a session
 * should not be a function that looks as though it might.
 */
export const isDesktop: boolean = isTauri();

/**
 * Asks the system for a folder, and returns its absolute path.
 *
 * Null when the user cancelled — and also in a browser, where there is nothing
 * to ask. Callers treat the two the same way, which is the right behaviour for
 * both: leave whatever was typed alone.
 *
 * A folder picker rather than a text field because a path is not something to
 * type. `~/Documents` is a shell convention rather than a directory, a typo
 * puts a vault somewhere the user will not find it again, and the separator is
 * not the same on every platform. The system dialogue has none of those
 * problems and is the widget people already know.
 */
export async function chooseFolder(title: string): Promise<string | null> {
  if (!isDesktop) return null;

  const chosen = await open({ directory: true, multiple: false, title });
  return typeof chosen === 'string' ? chosen : null;
}

/**
 * Tells the tray which language to speak.
 *
 * The tray's menu is built in Rust and cannot read the interface's settings, so
 * the interface says. Sending it rather than letting the tray read the system
 * locale keeps one answer to the question: change the language in the settings
 * and the menu bar changes with it.
 */
export async function useLanguage(language: string): Promise<void> {
  if (!isDesktop) return;

  await invoke('set_language', { language });
}

/**
 * Runs `handler` when something outside the window locks every vault.
 *
 * Today that is the tray's lock button. The window has to hear about it,
 * because otherwise it carries on showing a file browser for a vault whose keys
 * are gone — every row in it would fail the moment it was touched, which looks
 * like a corrupted vault rather than a locked one.
 *
 * Returns the function that stops listening.
 */
export function onVaultsLocked(handler: () => void): () => void {
  if (!isDesktop) return () => {};

  const listening = listen('vaults-locked', () => handler());
  return () => void listening.then((stop) => stop());
}
