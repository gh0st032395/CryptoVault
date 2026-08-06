<!--
  A button, always with an explanation attached.

  `tip` is required rather than optional. Making it mandatory is the cheapest
  way to keep the rule true as the interface grows: an optional one gets left
  off exactly on the control that most needed it.
-->
<script lang="ts">
  import Icon from './Icon.svelte';
  import Tooltip from './Tooltip.svelte';

  type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';

  interface Props {
    /** What this button does, in a sentence. Shown on hover and on focus. */
    tip: string;
    variant?: Variant;
    icon?: 'lock' | 'unlock' | 'folder' | 'file' | 'plus' | 'search' | 'download' | 'trash' | 'pencil' | 'settings' | 'chevron' | 'back' | 'warning' | 'check';
    disabled?: boolean;
    /** Renders as a square icon-only button, with the label as its aria-label. */
    iconOnly?: boolean;
    label?: string;
    tipPlacement?: 'top' | 'bottom';
    onclick?: () => void;
    children?: import('svelte').Snippet;
  }

  const {
    tip,
    variant = 'secondary',
    icon,
    disabled = false,
    iconOnly = false,
    label,
    tipPlacement = 'bottom',
    onclick,
    children,
  }: Props = $props();
</script>

<Tooltip text={tip} placement={tipPlacement}>
  <button
    class="btn {variant}"
    class:icon-only={iconOnly}
    {disabled}
    aria-label={iconOnly ? label : undefined}
    onclick={onclick}
    type="button"
  >
    {#if icon}<Icon name={icon} />{/if}
    {#if !iconOnly}<span>{@render children?.()}</span>{/if}
  </button>
</Tooltip>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    height: 34px;
    padding: 0 13px;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    font-size: 13.5px;
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
    transition:
      background var(--quick) ease,
      border-color var(--quick) ease,
      opacity var(--quick) ease;
  }

  .btn.icon-only {
    width: 34px;
    padding: 0;
    justify-content: center;
  }

  .btn:disabled {
    opacity: 0.42;
    cursor: not-allowed;
  }

  .primary {
    background: var(--accent);
    color: var(--accent-text);
  }
  .primary:hover:not(:disabled) {
    background: var(--accent-hover);
  }

  .secondary {
    background: var(--surface-raised);
    border-color: var(--border);
    color: var(--text);
  }
  .secondary:hover:not(:disabled) {
    border-color: var(--border-strong);
    background: var(--surface-sunken);
  }

  .ghost {
    color: var(--text-muted);
  }
  .ghost:hover:not(:disabled) {
    background: var(--surface-sunken);
    color: var(--text);
  }

  .danger {
    color: var(--danger);
  }
  .danger:hover:not(:disabled) {
    background: var(--danger-soft);
  }
</style>
