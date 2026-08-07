<!--
  The file browser: what an unlocked vault looks like.

  Two things are load-bearing in the layout. The lock button sits alone at the
  right of the toolbar, away from everything else, because it is the one control
  a user may need to hit in a hurry. And the destructive action is the only one
  in red and the only one that is not adjacent to a common one.
-->
<script lang="ts">
  import type { Backend, Entry, VaultSummary } from '../backend';
  import { formatDate, formatSize } from '../backend';
  import type { Dictionary, Language } from '../i18n';
  import { loadShowTree, saveShowTree } from '../theme';
  import Button from '../components/Button.svelte';
  import Dialog from '../components/Dialog.svelte';
  import Icon from '../components/Icon.svelte';
  import Tooltip from '../components/Tooltip.svelte';
  import Tree from './Tree.svelte';

  interface Props {
    backend: Backend;
    vault: VaultSummary;
    t: Dictionary;
    language: Language;
    onlock: () => void;
  }

  const { backend, vault, t, language, onlock }: Props = $props();

  /** Which column the list is ordered by. */
  type SortKey = 'name' | 'size' | 'modified';

  /** The question currently on screen, if any. */
  type Action =
    | { kind: 'new-folder' }
    | { kind: 'rename'; name: string }
    | { kind: 'remove'; names: string[] };

  let path = $state('/');
  let entries = $state<Entry[]>([]);
  let selection = $state<Set<string>>(new Set());
  let filter = $state('');
  /** Why this folder is not on screen, when it is not. */
  let problem = $state<string | null>(null);
  /** Bumped to read the current folder again after changing something in it. */
  let reloads = $state(0);

  let sortKey = $state<SortKey>('name');
  let ascending = $state(true);
  let showTree = $state(loadShowTree());

  let action = $state<Action | null>(null);
  let actionBusy = $state(false);
  let actionProblem = $state<string | null>(null);

  const segments = $derived(path.split('/').filter((part) => part.length > 0));

  /*
   * Ordering happens here rather than in the vault.
   *
   * `read_dir` returns entries in the order the filesystem hands them over,
   * which is no order at all — the encrypted names are scattered across shards,
   * so a directory comes back looking shuffled. Sorting is also something the
   * user changes by clicking, which makes it a property of the view and not of
   * the vault.
   *
   * Directories first in both directions. Reversing the sort should turn the
   * list over, not mix folders into the middle of the files.
   */
  const sorted = $derived.by(() => {
    const factor = ascending ? 1 : -1;
    return [...entries].sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === 'directory' ? -1 : 1;
      return factor * compare(a, b);
    });
  });

  const visible = $derived(
    filter.trim() === ''
      ? sorted
      : sorted.filter((entry) => entry.name.toLowerCase().includes(filter.trim().toLowerCase())),
  );

  const hasSelection = $derived(selection.size > 0);
  const onlyOneSelected = $derived(selection.size === 1);

  function compare(a: Entry, b: Entry): number {
    if (sortKey === 'size') return a.size - b.size;
    // A file with no recorded time sorts as the oldest thing there is, rather
    // than jumping to the top of a "newest first" list it has no claim to.
    if (sortKey === 'modified') return (a.modified ?? 0) - (b.modified ?? 0);
    // `numeric` is what puts "documento 2" before "documento 10". Without it a
    // folder of numbered files is sorted into an order nobody asked for.
    return a.name.localeCompare(b.name, language, { numeric: true, sensitivity: 'base' });
  }

  function sortBy(key: SortKey) {
    if (sortKey === key) {
      ascending = !ascending;
    } else {
      sortKey = key;
      // Names read best A→Z; sizes and dates are almost always wanted biggest
      // and newest first, which is why this is not simply `true`.
      ascending = key === 'name';
    }
  }

  /*
   * Windowing.
   *
   * A vault directory can hold tens of thousands of entries, and rendering a
   * row for each one makes the browser unusable long before that. Only the
   * rows in view exist in the DOM; the rest is two spacers holding the
   * scrollbar at the right length.
   *
   * Rows are a fixed height, which is what makes the arithmetic trivial: the
   * first visible index is the scroll position divided by that height. A
   * variable height would need measurement, and measurement would need a
   * layout pass per row — which is the cost we are avoiding.
   */
  const ROW_HEIGHT = 37;
  const OVERSCAN = 8;

  let viewport = $state<HTMLDivElement | null>(null);
  let scrollTop = $state(0);
  let viewportHeight = $state(600);

  const firstIndex = $derived(
    Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN),
  );
  const lastIndex = $derived(
    Math.min(visible.length, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + OVERSCAN),
  );
  const window_ = $derived(visible.slice(firstIndex, lastIndex));
  const padTop = $derived(firstIndex * ROW_HEIGHT);
  const padBottom = $derived(Math.max(0, (visible.length - lastIndex) * ROW_HEIGHT));

  $effect(() => {
    if (viewport === null) return;
    const observer = new ResizeObserver(() => {
      viewportHeight = viewport?.clientHeight ?? 600;
    });
    observer.observe(viewport);
    return () => observer.disconnect();
  });

  // A new folder starts at the top; keeping the old offset would land the user
  // in the middle of a list they have not seen.
  $effect(() => {
    void path;
    scrollTop = 0;
    viewport?.scrollTo({ top: 0 });
  });

  /*
   * Reading a directory can fail now that there is a real vault under it — a
   * folder removed by something else, a disk that went away, a vault that
   * locked itself while the listing was in flight.
   *
   * The guard on `current` is what keeps a slow answer from overwriting a fast
   * one: click into a large folder, click back out before it lands, and without
   * it the browser would show the first folder's contents under the second
   * folder's name.
   */
  $effect(() => {
    const current = path;
    void reloads;
    problem = null;

    void backend
      .readDir(vault.id, current)
      .then((list) => {
        if (current !== path) return;
        entries = list;
        selection = new Set();
      })
      .catch((error: unknown) => {
        if (current !== path) return;
        entries = [];
        selection = new Set();
        problem = error instanceof Error ? error.message : t.couldNotRead;
      });
  });

  function go(to: string) {
    path = to === '' ? '/' : to;
    filter = '';
  }

  /** The full vault path of something in the folder being shown. */
  function child(name: string): string {
    return `${path === '/' ? '' : path}/${name}`;
  }

  function enter(entry: Entry) {
    if (entry.kind === 'directory') {
      go(child(entry.name));
    }
  }

  function ask(next: Action) {
    action = next;
    actionProblem = null;
  }

  /**
   * Carries out whatever the dialogue was asking about.
   *
   * The three of them share this because they share what matters: the failure
   * stays in the dialogue rather than closing it, so a name that is already
   * taken can be corrected in the field the user is already looking at; and the
   * folder is read again either way, because a deletion that failed halfway
   * through has still deleted something.
   */
  async function carryOut(value: string) {
    if (action === null) return;
    const current = action;

    actionBusy = true;
    actionProblem = null;
    try {
      if (current.kind === 'new-folder') {
        await backend.createDir(vault.id, child(value));
      } else if (current.kind === 'rename') {
        await backend.rename(vault.id, child(current.name), child(value));
      } else {
        // One at a time, stopping at the first failure. Carrying on would
        // report the last error and hide the others, and "some of them are
        // gone, and I cannot tell you which" is not an answer.
        for (const name of current.names) {
          await backend.remove(vault.id, child(name));
        }
      }
      action = null;
      selection = new Set();
    } catch (error) {
      actionProblem = error instanceof Error ? error.message : String(error);
    } finally {
      actionBusy = false;
      reloads += 1;
    }
  }

  /** The dialogue's wording, derived from what it is asking about. */
  const dialog = $derived.by(() => {
    if (action === null) return null;

    switch (action.kind) {
      case 'new-folder':
        return {
          title: t.newFolder,
          name: '',
          confirmLabel: t.create,
          confirmTip: t.tipNewFolder,
          destructive: false,
          body: undefined as string | undefined,
        };
      case 'rename':
        return {
          title: t.rename,
          name: action.name,
          confirmLabel: t.rename,
          confirmTip: t.tipRename,
          destructive: false,
          body: undefined as string | undefined,
        };
      default: {
        const what =
          action.names.length === 1
            ? `“${action.names[0]}”`
            : `${action.names.length} ${t.itemsSelected}`;
        return {
          title: t.removeTitle,
          name: undefined as string | undefined,
          confirmLabel: t.remove,
          confirmTip: t.tipRemove,
          destructive: true,
          body: `${what} — ${t.removeBody}`,
        };
      }
    }
  });

  const columns = $derived([
    { key: 'name' as const, label: t.nameColumn, tip: t.tipSortName, right: false },
    { key: 'size' as const, label: t.sizeColumn, tip: t.tipSortSize, right: true },
    { key: 'modified' as const, label: t.modifiedColumn, tip: t.tipSortModified, right: true },
  ]);

  function toggle(name: string, event: MouseEvent) {
    const next = new Set(event.metaKey || event.ctrlKey ? selection : []);
    if (next.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
    }
    selection = next;
  }

  function breadcrumbTo(index: number): string {
    return '/' + segments.slice(0, index + 1).join('/');
  }
</script>

<div class="browser">
  <div class="toolbar">
    <div class="trail">
      <Button
        tip={t.tipTree}
        variant="ghost"
        icon="folder"
        iconOnly
        label={t.folders}
        onclick={() => {
          showTree = !showTree;
          saveShowTree(showTree);
        }}
        tipPlacement="bottom"
      />
      <button class="crumb root" onclick={() => go('/')} type="button">{vault.name}</button>
      {#each segments as segment, index (index)}
        <Icon name="chevron" size={14} />
        <button class="crumb" onclick={() => go(breadcrumbTo(index))} type="button">
          {segment}
        </button>
      {/each}
    </div>

    <div class="tools">
      <Tooltip text={t.tipSearch} placement="bottom">
        <span class="search">
          <Icon name="search" size={15} />
          <input bind:value={filter} placeholder={t.search} aria-label={t.search} />
        </span>
      </Tooltip>

      <Button tip={t.tipNewFolder} icon="plus" onclick={() => ask({ kind: 'new-folder' })}>
        {t.newFolder}
      </Button>
      <!-- Not yet wired: copying files in needs progress and a way to stop it,
           which is M4. Disabled and saying so beats a button that swallows a
           click, which reads as a broken vault rather than an unbuilt feature. -->
      <Button tip={t.tipAddFilesSoon} variant="primary" icon="file" disabled>
        {t.addFiles}
      </Button>

      <span class="divider"></span>

      <!-- Alone at the right, because it is the control someone may need fast. -->
      <Button tip={t.tipLockNow} icon="lock" onclick={onlock}>{t.lockNow}</Button>
    </div>
  </div>

  {#if hasSelection}
    <div class="selection-bar">
      <span class="count">{selection.size} {t.itemsSelected}</span>
      <!-- Extracting is the other half of M4: it writes plaintext out, which
           needs progress, cancellation and the warning that goes with it. -->
      <Button tip={t.tipExtractSoon} variant="ghost" icon="download" disabled>
        {t.extract}
      </Button>
      <Button
        tip={t.tipRename}
        variant="ghost"
        icon="pencil"
        disabled={!onlyOneSelected}
        onclick={() => ask({ kind: 'rename', name: [...selection][0] ?? '' })}
      >
        {t.rename}
      </Button>
      <Button
        tip={t.tipRemove}
        variant="danger"
        icon="trash"
        onclick={() => ask({ kind: 'remove', names: [...selection] })}
      >
        {t.remove}
      </Button>
    </div>
  {/if}

  <div class="panes">
    {#if showTree}
      <Tree {backend} vaultId={vault.id} {path} {reloads} {t} onnavigate={go} />
    {/if}

    <div
      class="listing"
      bind:this={viewport}
      onscroll={(event) => (scrollTop = event.currentTarget.scrollTop)}
    >
      {#if problem !== null}
        <div class="empty problem" role="alert">
          <Icon name="warning" size={26} />
          <h2>{t.couldNotRead}</h2>
          <p class="muted">{problem}</p>
        </div>
      {:else if visible.length === 0}
        <div class="empty">
          <Icon name="folder" size={26} />
          <h2>{t.emptyFolder}</h2>
          <p class="muted">{t.emptyFolderBody}</p>
        </div>
      {:else}
        <div class="head">
          {#each columns as column (column.key)}
            <span class="head-cell" class:right={column.right}>
              <Tooltip text={column.tip} placement="bottom">
                <button
                  class="sort"
                  class:on={sortKey === column.key}
                  onclick={() => sortBy(column.key)}
                  aria-pressed={sortKey === column.key}
                  type="button"
                >
                  {column.label}
                  {#if sortKey === column.key}
                    <span class="arrow" class:up={ascending}><Icon name="chevron" size={11} /></span>
                  {/if}
                </button>
              </Tooltip>
            </span>
          {/each}
        </div>

        <ul style:padding-top="{padTop}px" style:padding-bottom="{padBottom}px">
          {#each window_ as entry (entry.name)}
            <li>
              <button
                class="row"
                class:selected={selection.has(entry.name)}
                onclick={(event) => toggle(entry.name, event)}
                ondblclick={() => enter(entry)}
                type="button"
              >
                <span class="cell name">
                  <span class="glyph" class:dir={entry.kind === 'directory'}>
                    <Icon name={entry.kind === 'directory' ? 'folder' : 'file'} size={16} />
                  </span>
                  <span class="text">{entry.name}</span>
                </span>
                <span class="cell right mono faint">
                  {entry.kind === 'directory' ? '—' : formatSize(entry.size)}
                </span>
                <span class="cell right faint">{formatDate(entry.modified, language)}</span>
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>
</div>

<!-- Keyed on the question, so each one gets a fresh dialogue rather than
     inheriting the text field of the one before it. -->
{#if dialog !== null}
  {#key action}
    <Dialog
      title={dialog.title}
      body={dialog.body}
      name={dialog.name}
      confirmLabel={dialog.confirmLabel}
      confirmTip={dialog.confirmTip}
      cancelLabel={t.cancel}
      destructive={dialog.destructive}
      busy={actionBusy}
      problem={actionProblem}
      onconfirm={carryOut}
      oncancel={() => (action = null)}
    />
  {/key}
{/if}

<style>
  .browser {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 10px 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }

  .trail {
    display: flex;
    align-items: center;
    gap: 3px;
    min-width: 0;
    color: var(--text-faint);
  }

  .crumb {
    padding: 4px 7px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    font-size: 13.5px;
    color: var(--text-muted);
    cursor: pointer;
    white-space: nowrap;
  }

  .crumb:hover {
    background: var(--surface-sunken);
    color: var(--text);
  }

  .crumb.root {
    font-weight: 550;
    color: var(--text);
  }

  .tools {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .divider {
    width: 1px;
    height: 22px;
    background: var(--border);
  }

  .search {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 34px;
    padding: 0 11px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-raised);
    color: var(--text-faint);
  }

  .search:focus-within {
    border-color: var(--accent);
  }

  .search input {
    width: 130px;
    border: 0;
    background: transparent;
    outline: none;
    font-size: 13px;
  }

  .selection-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 7px 14px;
    background: var(--accent-soft);
    border-bottom: 1px solid var(--border);
  }

  .count {
    margin-right: 6px;
    font-size: 12.5px;
    font-weight: 550;
    color: var(--accent);
  }

  /* The tree and the list scroll independently, so a deep folder structure
     does not drag the file list up and down with it. */
  .panes {
    display: flex;
    flex: 1;
    min-height: 0;
  }

  .listing {
    flex: 1;
    min-width: 0;
    overflow: auto;
    padding: 0 14px 20px;
  }

  .head,
  .row {
    display: grid;
    grid-template-columns: 1fr 110px 130px;
    gap: 12px;
    align-items: center;
  }

  /*
   * The sticky column header.
   *
   * `::before` is not decoration. Measured, the header sits exactly at the top
   * of the scroll box at every offset — the gap is zero to three decimal
   * places — and yet on a 2× display a hairline of the row behind it shows
   * along its top edge, because the row's position and the header's round to
   * different device pixels. Rather than chase the rounding, the header paints
   * a few pixels of its own background above itself, where the scroll box
   * clips it. There is nothing for the seam to show through any more.
   */
  .head {
    position: sticky;
    top: 0;
    z-index: 1;
    padding: 11px 10px 7px;
    background: var(--surface-sunken);
    font-size: 11.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-faint);
  }

  .head::before {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: 100%;
    height: 6px;
    /* `inherit` rather than the variable again, so the header's colour is
       stated in exactly one place. */
    background: inherit;
  }

  .head-cell {
    display: flex;
    min-width: 0;
  }

  .head-cell.right {
    justify-content: flex-end;
  }

  .sort {
    display: inline-flex;
    align-items: center;
    gap: 3px;
    padding: 0;
    border: 0;
    background: transparent;
    font: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    color: inherit;
    cursor: pointer;
  }

  .sort:hover,
  .sort.on {
    color: var(--text-muted);
  }

  /* The chevron points right at rest, so it becomes a caret by rotating a
     quarter turn one way or the other. */
  .arrow {
    display: inline-flex;
    transform: rotate(90deg);
  }

  .arrow.up {
    transform: rotate(-90deg);
  }

  ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .row {
    /* Fixed, and matching ROW_HEIGHT above: the windowing arithmetic depends
       on it, so the two must not drift apart. */
    height: 37px;
    width: 100%;
    padding: 0 10px;
    border: 0;
    border-radius: var(--radius-sm);
    background: transparent;
    text-align: left;
    cursor: default;
    transition: background var(--quick) ease;
  }

  .row:hover {
    background: var(--surface);
  }

  .row.selected {
    background: var(--accent-soft);
  }

  .cell {
    min-width: 0;
    font-size: 13.5px;
  }

  .right {
    text-align: right;
  }

  .name {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .glyph {
    display: grid;
    place-items: center;
    width: 26px;
    height: 26px;
    flex: none;
    border-radius: 7px;
    background: var(--surface-sunken);
    color: var(--text-faint);
  }

  .glyph.dir {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .text {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: 76px 20px;
    color: var(--text-faint);
    text-align: center;
  }

  .empty.problem {
    color: var(--danger);
  }

  .empty.problem .muted {
    max-width: 52ch;
    overflow-wrap: anywhere;
  }
</style>
