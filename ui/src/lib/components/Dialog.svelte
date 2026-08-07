<!--
  A question the interface has to stop and ask.

  There are three of them in the file browser — name a new folder, rename
  something, confirm a deletion — and they are one component because the
  differences between them are a label and a colour, while the things that must
  not differ are the ones nobody notices until they are wrong: Escape closes it,
  Enter confirms it, focus starts inside it and cannot leave, and the button
  that destroys something is never the one under the pointer by default.

  It is deliberately not a `<dialog>` element. The native one brings its own
  focus behaviour and its own backdrop, both of which then have to be worked
  around to match everything else here.
-->
<script lang="ts">
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';

  interface Props {
    title: string;
    /** The part that has to be read, when the title is not the whole story. */
    body?: string | undefined;
    /**
     * The name to start from, and the switch that decides whether this
     * dialogue asks for one at all. Absent means it only asks yes or no.
     */
    name?: string | undefined;
    confirmLabel: string;
    confirmTip: string;
    cancelLabel: string;
    /** Red, and never focused first. */
    destructive?: boolean;
    busy?: boolean;
    /** What went wrong with the last attempt, shown in place. */
    problem?: string | null;
    onconfirm: (name: string) => void;
    oncancel: () => void;
  }

  const {
    title,
    body,
    name,
    confirmLabel,
    confirmTip,
    cancelLabel,
    destructive = false,
    busy = false,
    problem = null,
    onconfirm,
    oncancel,
  }: Props = $props();

  const asksForName = $derived(name !== undefined);

  // Deliberately the initial value and not a derived one: this is the field the
  // user is about to edit, and it must not be pulled back to the prop while
  // they are typing. The caller mounts a fresh dialogue for each question.
  // svelte-ignore state_referenced_locally
  let value = $state(name ?? '');
  let panel = $state<HTMLElement | null>(null);

  const ready = $derived(!busy && (!asksForName || value.trim().length > 0));

  /**
   * Puts the cursor where the editing starts, once.
   *
   * An action rather than an effect, and the difference is not academic: an
   * effect that reads the field's value re-runs on every keystroke, so it would
   * re-select the whole name as the user typed it — a text box that fights back.
   *
   * The selection stops before the extension. `.pdf` is part of the name and
   * almost never the part being changed, so selecting it too would make the
   * ordinary edit begin by deleting it.
   */
  function startEditing(node: HTMLInputElement) {
    // Deferred by a microtask, and not for luck: `bind:value` writes the field
    // after the action has run, and writing a value moves the caret to the end,
    // so a selection made now would be undone a moment later.
    queueMicrotask(() => {
      const initial = name ?? '';
      const stop = initial.lastIndexOf('.');

      node.focus();
      node.setSelectionRange(0, stop > 0 ? stop : initial.length);
    });
  }

  /**
   * Focus for the dialogues with nothing to type into.
   *
   * It has to land inside the panel, or Escape and Tab still belong to the
   * screen behind, which is exactly the screen the dialogue is covering.
   */
  function takeFocus(node: HTMLElement) {
    if (!asksForName) node.focus();
  }

  function confirm() {
    if (ready) onconfirm(value.trim());
  }

  /**
   * Keeps the keyboard inside the dialogue.
   *
   * Without this, Tab walks out of a modal and into the file list behind it,
   * where a keyboard user is now operating controls they cannot see.
   */
  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault();
      oncancel();
      return;
    }
    if (event.key !== 'Tab' || panel === null) return;

    const focusable = panel.querySelectorAll<HTMLElement>('input, button');
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (first === undefined || last === undefined) return;

    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
</script>

<svelte:window {onkeydown} />

<!-- The backdrop closes on a click, which is the ordinary way out of a modal.
     `onclick` on the backdrop only: a click inside the panel must not reach it. -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div class="backdrop" onclick={oncancel}>
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="panel"
    bind:this={panel}
    use:takeFocus
    onclick={(event) => event.stopPropagation()}
    role="dialog"
    aria-modal="true"
    aria-label={title}
    tabindex="-1"
  >
    <h2>{title}</h2>
    {#if body}<p class="body">{body}</p>{/if}

    {#if asksForName}
      <input
        use:startEditing
        bind:value
        onkeydown={(event) => {
          if (event.key === 'Enter') {
            event.preventDefault();
            confirm();
          }
        }}
        autocomplete="off"
        spellcheck="false"
        disabled={busy}
        aria-label={title}
      />
    {/if}

    {#if problem !== null}
      <p class="problem" role="alert">
        <Icon name="warning" size={15} />
        {problem}
      </p>
    {/if}

    <div class="actions">
      <Button tip={cancelLabel} variant="ghost" disabled={busy} onclick={oncancel} tipPlacement="top">
        {cancelLabel}
      </Button>
      <Button
        tip={confirmTip}
        variant={destructive ? 'danger' : 'primary'}
        disabled={!ready}
        onclick={confirm}
        tipPlacement="top"
      >
        {confirmLabel}
      </Button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 60;
    display: grid;
    place-items: center;
    padding: 20px;
    background: rgb(0 0 0 / 38%);
  }

  .panel {
    width: min(420px, 100%);
    padding: 20px;
    background: var(--surface-raised);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: var(--shadow-lifted);
  }

  .panel:focus {
    outline: none;
  }

  h2 {
    margin: 0;
    font-size: 15px;
  }

  .body {
    margin: 8px 0 0;
    font-size: 13px;
    color: var(--text-muted);
  }

  input {
    width: 100%;
    height: 34px;
    margin-top: 14px;
    padding: 0 11px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    background: var(--surface);
    color: var(--text);
    font-size: 13.5px;
  }

  input:focus {
    outline: none;
    border-color: var(--accent);
  }

  .problem {
    display: flex;
    align-items: center;
    gap: 7px;
    margin: 12px 0 0;
    padding: 9px 11px;
    border-radius: var(--radius-sm);
    background: var(--danger-soft);
    color: var(--danger);
    font-size: 12.5px;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 18px;
  }
</style>
