/**
 * The boundary between the interface and the vault.
 *
 * Everything the interface can ask for is in this one type, and it has two
 * implementations: {@link TauriBackend} in `tauri.ts`, which calls into Rust,
 * and {@link DemoBackend} in `demo.ts`, which keeps a tree in memory.
 *
 * The demonstration one has not been kept out of nostalgia. It is what lets the
 * interface be developed, looked at and reviewed in a browser — a much faster
 * loop than rebuilding a desktop application for every change of padding — and
 * it is the only way to see a directory of five thousand entries without first
 * making one.
 *
 * Which one is in use is decided once, in `App.svelte`, from `isDesktop`.
 */

export type EntryKind = 'file' | 'directory';

export interface Entry {
  readonly name: string;
  readonly kind: EntryKind;
  /** Plaintext length in bytes. Zero for a directory. */
  readonly size: number;
  /** Unix seconds, or null when the file carries no original timestamp. */
  readonly modified: number | null;
}

export interface VaultSummary {
  readonly id: string;
  readonly name: string;
  /** Where the encrypted folder lives, for the user to recognise it by. */
  readonly path: string;
  readonly unlocked: boolean;
  readonly sealed: boolean;
}

/**
 * A failure that came back from the vault.
 *
 * `kind` is the same stable tag `SessionError::kind` produces in Rust, and it
 * is what the interface branches on. Matching on the message instead would work
 * until the day somebody translates it, and then fail silently.
 */
export class VaultFailure extends Error {
  readonly kind: string;

  constructor(kind: string, message: string) {
    super(message);
    this.name = 'VaultFailure';
    this.kind = kind;
  }
}

/** The credential was wrong. Trying again is a sensible response. */
export class WrongPassword extends VaultFailure {
  constructor() {
    super('wrong-password', 'wrong password');
    this.name = 'WrongPassword';
  }
}

export interface Backend {
  listVaults(): Promise<VaultSummary[]>;
  /**
   * Creates a vault in a folder named after it, inside `parent`, and registers
   * it. It is left locked, deliberately.
   */
  createVault(name: string, parent: string, password: string, sealed: boolean): Promise<string>;
  /** Adds a vault that already exists on disk. Rejects if `path` holds none. */
  registerVault(name: string, path: string): Promise<string>;
  /** Drops a vault from the list. Does not touch the folder it names. */
  forgetVault(id: string): Promise<void>;
  /** Rejects with {@link WrongPassword} if the credential is wrong. */
  unlock(id: string, password: string): Promise<void>;
  lock(id: string): Promise<void>;
  readDir(id: string, path: string): Promise<Entry[]>;
  createDir(id: string, path: string): Promise<void>;
  remove(id: string, path: string): Promise<void>;
  rename(id: string, from: string, to: string): Promise<void>;
}

/** Human-readable size. Binary units, because that is what a disk reports. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

/** A date, in the interface's language. */
export function formatDate(unixSeconds: number | null, language: string): string {
  if (unixSeconds === null) return '—';
  return new Date(unixSeconds * 1000).toLocaleDateString(language, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/** The last component of a path, whichever separator the platform uses. */
export function basename(path: string): string {
  const parts = path.split(/[/\\]/).filter((part) => part.length > 0);
  return parts[parts.length - 1] ?? path;
}
