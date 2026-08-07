/**
 * The two things the interface needs from the machine it is running on.
 *
 * Kept apart from `backend.ts` because neither is a vault operation: one is
 * "which of the two worlds am I in", and the other is a system dialogue that
 * happens to return a path.
 */

import { isTauri } from '@tauri-apps/api/core';
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
