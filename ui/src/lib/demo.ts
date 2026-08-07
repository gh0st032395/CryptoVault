/**
 * A vault that is not a vault: an in-memory tree, so the interface has
 * something to show in a browser.
 *
 * This exists to make the interface reviewable without a build of the desktop
 * application, and to hold a directory big enough that the windowing in the
 * file browser is exercised by simply opening it rather than by a test nobody
 * runs. It is never reachable from the desktop application — `App.svelte`
 * chooses between this and the real backend once, from `isDesktop`.
 */

import {
  WrongPassword,
  type Backend,
  type Entry,
  type EntryKind,
  type VaultSummary,
} from './backend';

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
 * The tree.
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
    // A directory large enough that rendering every row would be visible as
    // sluggishness. It is here so the windowing is exercised by simply opening
    // the demonstration vault, rather than only by a test nobody runs.
    'molti file': folder(
      Object.fromEntries(
        Array.from({ length: 5000 }, (_, i) => [
          `documento ${String(i).padStart(4, '0')}.txt`,
          file(1024 + i * 7, 1_760_000_000 + i * 3600),
        ]),
      ),
    ),
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

  async createVault(
    name: string,
    parent: string,
    _password: string,
    sealed: boolean,
  ): Promise<string> {
    await pause(1100); // calibration plus creation, roughly
    const id = `created-${this.#vaults.length}`;
    // Locked, matching `cv-session`: creation is not a back door into an open
    // vault, and typing the password once more is the cheapest check that it
    // was typed as intended.
    this.#vaults = [
      ...this.#vaults,
      { id, name, path: `${parent}/${name}`, unlocked: false, sealed },
    ];
    return id;
  }

  async registerVault(name: string, path: string): Promise<string> {
    const id = `registered-${this.#vaults.length}`;
    this.#vaults = [...this.#vaults, { id, name, path, unlocked: false, sealed: false }];
    return id;
  }

  async forgetVault(id: string): Promise<void> {
    this.#vaults = this.#vaults.filter((vault) => vault.id !== id);
    this.#unlocked.delete(id);
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
