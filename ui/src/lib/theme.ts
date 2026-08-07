/**
 * Appearance and language preferences, and where they are kept.
 *
 * Both are stored locally and nowhere else. They are not secret, but they are
 * also nobody's business, and a preference that travels is a preference that
 * needed somewhere to travel to.
 */

import type { Language } from './i18n';

export type ThemeChoice = 'light' | 'dark' | 'system';

const THEME_KEY = 'cryptovault.theme';
const LANGUAGE_KEY = 'cryptovault.language';

/** Applies a choice to the document, resolving `system` against the OS. */
export function applyTheme(choice: ThemeChoice): void {
  const dark =
    choice === 'dark' ||
    (choice === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  document.documentElement.dataset['theme'] = dark ? 'dark' : 'light';
}

export function loadTheme(): ThemeChoice {
  const stored = localStorage.getItem(THEME_KEY);
  return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system';
}

export function saveTheme(choice: ThemeChoice): void {
  localStorage.setItem(THEME_KEY, choice);
}

export function loadLanguage(fallback: Language): Language {
  const stored = localStorage.getItem(LANGUAGE_KEY);
  return stored === 'it' || stored === 'en' ? stored : fallback;
}

export function saveLanguage(language: Language): void {
  localStorage.setItem(LANGUAGE_KEY, language);
}

/**
 * A rough password strength, from length and variety.
 *
 * Deliberately not dressed up as more than it is. It cannot tell whether a
 * password is *guessable* — "Password123!" scores well and is on every list —
 * and the tooltip beside it says so. A meter that implies more precision than
 * it has is worse than no meter, because people trust it.
 */
export function passwordStrength(password: string): 0 | 1 | 2 | 3 {
  if (password.length === 0) return 0;

  const variety =
    Number(/[a-z]/.test(password)) +
    Number(/[A-Z]/.test(password)) +
    Number(/[0-9]/.test(password)) +
    Number(/[^a-zA-Z0-9]/.test(password));

  // Length dominates, because it should: a long passphrase of ordinary words
  // beats a short one with punctuation sprinkled through it.
  const score = password.length / 5 + variety;

  if (password.length < 8 || score < 4) return 0;
  if (score < 6) return 1;
  if (score < 8) return 2;
  return 3;
}
