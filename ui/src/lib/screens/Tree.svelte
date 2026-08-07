<!--
  The folder tree beside the list.

  Two things shape it. It loads a folder's children only when that folder is
  opened, because a vault can be deep and reading a directory is not free — the
  session opens every entry to report its size (R-03), so walking the whole tree
  up front would mean opening every file in the vault to draw a sidebar.

  And it is flattened into rows rather than nested components. The state is a
  map from path to what is known about that path, and what gets rendered is the
  list of rows currently visible. That keeps the recursion in one small function
  instead of in the component graph, and it is the shape that can be windowed
  later if somebody turns up with ten thousand folders.
-->
<script lang="ts">
  import type { Backend } from '../backend';
  import type { Dictionary } from '../i18n';
  import Icon from '../components/Icon.svelte';

  interface Props {
    backend: Backend;
    vaultId: string;
    /** The folder the list is showing. The tree follows it. */
    path: string;
    /** Bumped by the browser when a folder is added, renamed or removed. */
    reloads: number;
    t: Dictionary;
    onnavigate: (path: string) => void;
  }

  const { backend, vaultId, path, reloads, t, onnavigate }: Props = $props();

  /** What is known about one folder. */
  interface Node {
    /** Sub-folder names, or null while they have never been read. */
    children: string[] | null;
    open: boolean;
    /** Set when reading it failed, so a retry is a click rather than a mystery. */
    failed: boolean;
  }

  /** One line on screen. */
  interface Row {
    path: string;
    name: string;
    depth: number;
  }

  const ROOT = '/';

  let nodes = $state<Map<string, Node>>(new Map([[ROOT, { children: null, open: true, failed: false }]]));

  function join(parent: string, name: string): string {
    return parent === ROOT ? `/${name}` : `${parent}/${name}`;
  }

  /** Every ancestor of `target`, roots first, including the target itself. */
  function ancestry(target: string): string[] {
    const parts = target.split('/').filter((part) => part.length > 0);
    const out = [ROOT];
    let walked = '';
    for (const part of parts) {
      walked += `/${part}`;
      out.push(walked);
    }
    return out;
  }

  /**
   * Folders being read right now.
   *
   * Deliberately not reactive. The effect below re-runs whenever `nodes`
   * changes, and a folder whose read is still in flight still looks unread — so
   * without this, revealing a path four levels deep would ask for the same
   * directories several times over. Reading a directory opens every entry in it
   * (R-03), so a redundant read is not free.
   */
  const loading = new Set<string>();

  async function load(folder: string) {
    if (loading.has(folder)) return;
    loading.add(folder);

    let entries;
    try {
      entries = await backend.readDir(vaultId, folder);
    } catch {
      update(folder, (node) => ({ ...node, failed: true }));
      return;
    } finally {
      loading.delete(folder);
    }

    const children = entries
      .filter((entry) => entry.kind === 'directory')
      .map((entry) => entry.name)
      .sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

    update(folder, (node) => ({ ...node, children, failed: false }));
  }

  function update(folder: string, change: (node: Node) => Node) {
    const next = new Map(nodes);
    next.set(folder, change(next.get(folder) ?? { children: null, open: false, failed: false }));
    nodes = next;
  }

  /**
   * Whether this folder's children still have to be read.
   *
   * True both for a folder that has never been seen and for one that is in the
   * map with nothing read yet. Those two are easy to conflate — a folder that
   * has never been seen is *absent*, not present with `children: null` — and
   * conflating them means opening a folder and watching nothing happen.
   */
  function needsLoading(folder: string): boolean {
    const node = nodes.get(folder);
    return node === undefined || node.children === null;
  }

  function toggle(folder: string) {
    const open = !isOpen(folder);
    const unread = needsLoading(folder);

    update(folder, (current) => ({ ...current, open }));
    if (open && unread) void load(folder);
  }

  /*
   * Following the list.
   *
   * Walking into a folder from the list, or through the breadcrumbs, has to
   * reveal it here — a tree that disagrees with the thing beside it is worse
   * than no tree. Every folder on the way is opened, and any that has never
   * been read is read now.
   */
  $effect(() => {
    const wanted = ancestry(path);
    const missing = wanted.filter((folder) => nodes.get(folder)?.children == null);

    if (wanted.some((folder) => !(nodes.get(folder)?.open ?? false))) {
      const next = new Map(nodes);
      for (const folder of wanted) {
        next.set(folder, {
          ...(next.get(folder) ?? { children: null, failed: false }),
          open: true,
        } as Node);
      }
      nodes = next;
    }

    for (const folder of missing) void load(folder);
  });

  /*
   * Re-reading after a change.
   *
   * Only the folder that changed, because that is the only one that can have
   * gained or lost a child: the browser bumps `reloads` after making, renaming
   * or deleting something in the folder it is showing.
   */
  let seen = $state(0);
  $effect(() => {
    if (reloads === seen) return;
    seen = reloads;
    void load(path);
  });

  /** The visible lines, in order, computed from what is open. */
  const rows = $derived.by(() => {
    const out: Row[] = [];

    const walk = (folder: string, depth: number) => {
      const node = nodes.get(folder);
      if (!node?.open || node.children === null) return;

      for (const name of node.children) {
        const child = join(folder, name);
        out.push({ path: child, name, depth });
        walk(child, depth + 1);
      }
    };

    walk(ROOT, 1);
    return out;
  });

  function isOpen(folder: string): boolean {
    return nodes.get(folder)?.open ?? false;
  }

  /**
   * Whether a folder is worth offering a twisty for.
   *
   * A folder that has been read and holds no sub-folders gets none. One that
   * has never been read gets one, because the alternative is reading the whole
   * vault to find out — which is the thing this tree exists to avoid.
   */
  function mayHaveChildren(folder: string): boolean {
    return needsLoading(folder) || (nodes.get(folder)?.children?.length ?? 0) > 0;
  }
</script>

<!--
  The root is a row like any other. Writing it out separately was tempting and
  wrong: it would have been the one row whose twisty did not toggle, which is
  exactly the sort of difference nobody notices until they click it.
-->
{#snippet line(folder: string, name: string, depth: number)}
  <div class="line" style:--depth={depth}>
    {#if mayHaveChildren(folder)}
      <button
        class="twisty"
        class:open={isOpen(folder)}
        onclick={() => toggle(folder)}
        aria-label={isOpen(folder) ? t.collapse : t.expand}
        aria-expanded={isOpen(folder)}
        type="button"
      >
        <Icon name="chevron" size={12} />
      </button>
    {:else}
      <span class="twisty"></span>
    {/if}

    <button
      class="node"
      class:current={path === folder}
      onclick={() => onnavigate(folder)}
      type="button"
    >
      <Icon name="folder" size={15} />
      <span class="label">{name}</span>
      {#if nodes.get(folder)?.failed}
        <span class="failed" title={t.couldNotRead}><Icon name="warning" size={13} /></span>
      {/if}
    </button>
  </div>
{/snippet}

<nav class="tree" aria-label={t.folders}>
  {@render line(ROOT, t.vaultRoot, 0)}
  {#each rows as row (row.path)}
    {@render line(row.path, row.name, row.depth)}
  {/each}
</nav>

<style>
  .tree {
    display: flex;
    flex-direction: column;
    gap: 1px;
    width: 216px;
    flex: none;
    padding: 10px 8px;
    overflow: auto;
    background: var(--surface);
    border-right: 1px solid var(--border);
  }

  /* The indent lives on the row, so the twisty and the name can never drift
     apart: one number moves both. */
  .line {
    display: flex;
    align-items: center;
    padding-left: calc(var(--depth, 0) * 13px);
  }

  .node {
    display: flex;
    align-items: center;
    gap: 7px;
    flex: 1;
    min-width: 0;
    height: 27px;
    padding-right: 8px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    font-size: 13px;
    text-align: left;
    cursor: pointer;
  }

  .node:hover {
    background: var(--surface-sunken);
    color: var(--text);
  }

  .node.current {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 550;
  }

  .label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .twisty {
    display: grid;
    place-items: center;
    width: 18px;
    height: 27px;
    flex: none;
    padding: 0;
    border: 0;
    background: transparent;
    color: var(--text-faint);
  }

  button.twisty {
    cursor: pointer;
  }

  button.twisty:hover {
    color: var(--text);
  }

  .twisty :global(svg) {
    transition: transform var(--quick) ease;
  }

  .twisty.open :global(svg) {
    transform: rotate(90deg);
  }

  .failed {
    display: inline-flex;
    color: var(--danger);
  }
</style>
