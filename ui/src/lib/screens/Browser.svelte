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
  import Button from '../components/Button.svelte';
  import Icon from '../components/Icon.svelte';
  import Tooltip from '../components/Tooltip.svelte';

  interface Props {
    backend: Backend;
    vault: VaultSummary;
    t: Dictionary;
    language: Language;
    onlock: () => void;
  }

  const { backend, vault, t, language, onlock }: Props = $props();

  let path = $state('/');
  let entries = $state<Entry[]>([]);
  let selection = $state<Set<string>>(new Set());
  let filter = $state('');

  const segments = $derived(path.split('/').filter((part) => part.length > 0));

  const visible = $derived(
    filter.trim() === ''
      ? entries
      : entries.filter((entry) => entry.name.toLowerCase().includes(filter.trim().toLowerCase())),
  );

  const hasSelection = $derived(selection.size > 0);
  const onlyOneSelected = $derived(selection.size === 1);

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

  $effect(() => {
    const current = path;
    void backend.readDir(vault.id, current).then((list) => {
      entries = list;
      selection = new Set();
    });
  });

  function go(to: string) {
    path = to === '' ? '/' : to;
    filter = '';
  }

  function enter(entry: Entry) {
    if (entry.kind === 'directory') {
      go(`${path === '/' ? '' : path}/${entry.name}`);
    }
  }

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
        tip={t.tipVaultPath}
        variant="ghost"
        icon="lock"
        iconOnly
        label={vault.name}
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

      <Button tip={t.tipNewFolder} icon="plus">{t.newFolder}</Button>
      <Button tip={t.tipAddFiles} variant="primary" icon="file">{t.addFiles}</Button>

      <span class="divider"></span>

      <!-- Alone at the right, because it is the control someone may need fast. -->
      <Button tip={t.tipLockNow} icon="lock" onclick={onlock}>{t.lockNow}</Button>
    </div>
  </div>

  {#if hasSelection}
    <div class="selection-bar">
      <span class="count">{selection.size} {t.itemsSelected}</span>
      <Button tip={t.tipExtract} variant="ghost" icon="download">{t.extract}</Button>
      <Button tip={t.tipRename} variant="ghost" icon="pencil" disabled={!onlyOneSelected}>
        {t.rename}
      </Button>
      <Button tip={t.tipRemove} variant="danger" icon="trash">{t.remove}</Button>
    </div>
  {/if}

  <div
    class="listing"
    bind:this={viewport}
    onscroll={(event) => (scrollTop = event.currentTarget.scrollTop)}
  >
    {#if visible.length === 0}
      <div class="empty">
        <Icon name="folder" size={26} />
        <h2>{t.emptyFolder}</h2>
        <p class="muted">{t.emptyFolderBody}</p>
      </div>
    {:else}
      <div class="head">
        <span>{t.nameColumn}</span>
        <span class="right">{t.sizeColumn}</span>
        <span class="right">{t.modifiedColumn}</span>
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

  .listing {
    flex: 1;
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
</style>
