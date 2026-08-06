/**
 * The boundary between the interface and the vault.
 *
 * Everything the interface can ask for is in this one type. The implementation
 * today is a demonstration one that keeps a tree in memory; the Tauri
 * implementation, which calls into `cv-vfs`, drops in behind the same interface
 * without the screens noticing.
 *
 * Keeping the boundary explicit has a second use: the interface can be
 * developed, looked at and reviewed in a browser, which is a much faster loop
 * than rebuilding a desktop application for every change of padding.
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

export class WrongPassword extends Error {
  constructor() {
    super('wrong password');
    this.name = 'WrongPassword';
  }
}

export interface Backend {
  listVaults(): Promise<VaultSummary[]>;
  /** Rejects with {@link WrongPassword} if the credential is wrong. */
  unlock(id: string, password: string): Promise<void>;
  lock(id: string): Promise<void>;
  readDir(id: string, path: string): Promise<Entry[]>;
  createDir(id: string, path: string): Promise<void>;
  remove(id: string, path: string): Promise<void>;
  rename(id: string, from: string, to: string): Promise<void>;
}

// --- demonstration backend --------------------------------------------------

/** Marks the interface as running on invented data, so it can say so. */
export const IS_DEMO = true;

interface DemoNode {
  kind: EntryKind;
  size: number;
  modified: number | null;
  children?: Record<string, DemoNode>;
}

const DEMO_PASSWORD = 'cryptovault';

function file(size: number, modified: number): DemoNode {
  return { kind: 'file', size, modified };
}

function folder(children: Record<string, DemoNode>): DemoNode {
  return { kind: 'directory', size: 0, modified: null, children };
}

/**
 * An in-memory vault, so the interface has something to show.
 *
 * The awkward names are not padding: they are the ones a host filesystem would
 * refuse, and the interface has to render them correctly because a real vault
 * can hold them.
 */
function demoTree(): DemoNode {
  return folder({
    Documenti: folder({
      '2026': folder({
        'fattura marzo.pdf': file(184_320, 1_772_000_000),
        'report: Q1*.txt': file(4_096, 1_771_400_000),
        'note di riunione.md': file(11_240, 1_771_900_000),
      }),
      'contratto firmato.pdf': file(892_311, 1_769_000_000),
    }),
    Foto: folder({
      'panorama 🏔️.jpg': file(3_884_102, 1_768_100_000),
      'scansione documento.png': file(1_204_558, 1_767_500_000),
    }),
    'chiavi ssh': folder({
      id_ed25519: file(464, 1_760_000_000),
      'id_ed25519.pub': file(98, 1_760_000_000),
    }),
    'archivio.tar.zst': file(52_428_800, 1_766_000_000),
    'password del wifi.txt': file(37, 1_772_100_000),
  });
}

/** Splits `/a/b/c` into its components, ignoring empty ones. */
function components(path: string): string[] {
  return path.split('/').filter((part) => part.length > 0);
}

export class DemoBackend implements Backend {
  #tree = demoTree();
  #unlocked = new Set<string>();

  #vaults: VaultSummary[] = [
    {
      id: 'personal',
      name: 'Personale',
      path: '~/Documents/Vault personale',
      unlocked: false,
      sealed: false,
    },
    {
      id: 'sealed',
      name: 'Documenti riservati',
      path: '~/Dropbox/Riservati',
      unlocked: false,
      sealed: true,
    },
  ];

  /** The password every demonstration vault opens with. */
  static readonly password = DEMO_PASSWORD;

  async listVaults(): Promise<VaultSummary[]> {
    return this.#vaults.map((vault) => ({
      ...vault,
      unlocked: this.#unlocked.has(vault.id),
    }));
  }

  async unlock(id: string, password: string): Promise<void> {
    // The real unlock spends about a second in Argon2id. Reproducing the delay
    // matters: an interface that feels instant here would be designed around a
    // wait that does not exist, and would need reworking the moment it did.
    await pause(900);
    if (password !== DEMO_PASSWORD) {
      throw new WrongPassword();
    }
    this.#unlocked.add(id);
  }

  async lock(id: string): Promise<void> {
    this.#unlocked.delete(id);
  }

  async readDir(_id: string, path: string): Promise<Entry[]> {
    const node = this.#resolve(path);
    const children = node?.children ?? {};

    return Object.entries(children)
      .map(([name, child]) => ({
        name,
        kind: child.kind,
        size: child.size,
        modified: child.modified,
      }))
      .sort(byKindThenName);
  }

  async createDir(_id: string, path: string): Promise<void> {
    const parts = components(path);
    const name = parts.pop();
    if (name === undefined) return;

    const parent = this.#resolve('/' + parts.join('/'));
    if (parent?.children) {
      parent.children[name] = folder({});
    }
  }

  async remove(_id: string, path: string): Promise<void> {
    const parts = components(path);
    const name = parts.pop();
    if (name === undefined) return;

    const parent = this.#resolve('/' + parts.join('/'));
    if (parent?.children) {
      delete parent.children[name];
    }
  }

  async rename(_id: string, from: string, to: string): Promise<void> {
    const fromParts = components(from);
    const fromName = fromParts.pop();
    const toParts = components(to);
    const toName = toParts.pop();
    if (fromName === undefined || toName === undefined) return;

    const source = this.#resolve('/' + fromParts.join('/'));
    const target = this.#resolve('/' + toParts.join('/'));
    const node = source?.children?.[fromName];

    if (source?.children && target?.children && node) {
      delete source.children[fromName];
      target.children[toName] = node;
    }
  }

  #resolve(path: string): DemoNode | undefined {
    let node: DemoNode | undefined = this.#tree;
    for (const part of components(path)) {
      node = node?.children?.[part];
    }
    return node;
  }
}

function byKindThenName(a: Entry, b: Entry): number {
  if (a.kind !== b.kind) return a.kind === 'directory' ? -1 : 1;
  return a.name.localeCompare(b.name);
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
