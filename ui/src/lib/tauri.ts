/**
 * The real backend: every call is one command in `cv-desktop`.
 *
 * There is no logic here beyond turning a rejected `invoke` back into a typed
 * error. That is on purpose and it mirrors the rule on the Rust side — a
 * command takes the lock, calls one method, converts the error — because logic
 * split across an inter-process boundary is logic that can only be tested by
 * running both halves.
 *
 * # Argument names
 *
 * Tauri matches the keys of the object below onto the parameters of the Rust
 * function by name, converting camelCase to snake_case. A key that matches
 * nothing is not an error at either end: the parameter simply arrives empty. So
 * the names here are a contract with `commands.rs`, and are the one thing in
 * this file worth reading twice.
 */

import { invoke } from '@tauri-apps/api/core';

import { VaultFailure, WrongPassword, type Backend, type Entry, type VaultSummary } from './backend';

/** The shape every command failure arrives in, from `CommandError` in Rust. */
interface CommandError {
  readonly kind: string;
  readonly message: string;
}

function isCommandError(value: unknown): value is CommandError {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as CommandError).kind === 'string' &&
    typeof (value as CommandError).message === 'string'
  );
}

/**
 * Turns whatever `invoke` rejected with into an error the screens understand.
 *
 * A wrong password becomes {@link WrongPassword} rather than staying a tagged
 * string, so that the one failure with its own handling keeps having it.
 * Anything that is not a `CommandError` — the IPC itself failing, for
 * instance — is passed along rather than dressed up as a vault failure, because
 * "the vault said no" and "the application is broken" should not look alike.
 */
function asError(thrown: unknown): Error {
  if (isCommandError(thrown)) {
    return thrown.kind === 'wrong-password'
      ? new WrongPassword()
      : new VaultFailure(thrown.kind, thrown.message);
  }
  return thrown instanceof Error ? thrown : new Error(String(thrown));
}

async function call<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (thrown) {
    throw asError(thrown);
  }
}

export class TauriBackend implements Backend {
  listVaults(): Promise<VaultSummary[]> {
    return call<VaultSummary[]>('list_vaults');
  }

  createVault(name: string, parent: string, password: string, sealed: boolean): Promise<string> {
    return call<string>('create_vault', { name, parent, password, sealed });
  }

  registerVault(name: string, path: string): Promise<string> {
    return call<string>('register_vault', { name, path });
  }

  forgetVault(id: string): Promise<void> {
    return call<void>('forget_vault', { id });
  }

  unlock(id: string, password: string): Promise<void> {
    return call<void>('unlock', { id, password });
  }

  lock(id: string): Promise<void> {
    return call<void>('lock', { id });
  }

  readDir(id: string, path: string): Promise<Entry[]> {
    return call<Entry[]>('read_dir', { id, path });
  }

  createDir(id: string, path: string): Promise<void> {
    return call<void>('create_dir', { id, path });
  }

  remove(id: string, path: string): Promise<void> {
    return call<void>('remove', { id, path });
  }

  rename(id: string, from: string, to: string): Promise<void> {
    return call<void>('rename', { id, from, to });
  }
}
