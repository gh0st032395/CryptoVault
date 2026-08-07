<!--
  A tooltip that explains what a control does.

  Every button in this application has one. The rule comes from a simple
  observation: an icon is only obvious to the person who chose it, and a vault
  has several controls whose consequences are not reversible.

  Two things make it a tooltip rather than a decoration:

  - It appears on **focus** as well as hover, so it exists for someone using a
    keyboard.
  - It is wired with `aria-describedby`, so a screen reader announces it rather
    than the user discovering that a description existed visually.

  The short delay before showing keeps it from flickering as the pointer crosses
  a toolbar; dismissing is immediate, because a tooltip that lingers is in the
  way.
-->
<script lang="ts">
  interface Props {
    /** What the control does, in a sentence. */
    text: string;
    /** Which side to prefer. Falls back to the other if there is no room. */
    placement?: 'top' | 'bottom';
    children: import('svelte').Snippet;
  }

  const { text, placement = 'top', children }: Props = $props();

  let visible = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  const id = `tip-${Math.random().toString(36).slice(2, 9)}`;

  function show() {
    timer = setTimeout(() => (visible = true), 350);
  }

  function hide() {
    clearTimeout(timer);
    visible = false;
  }
</script>

<!--
  The wrapper is a presentational hull around whatever it is describing: the
  interactive element is the child, and the keyboard path is the focus handlers
  below rather than the pointer ones. Giving this span a role would announce a
  control that is not here.
-->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<span
  class="wrap"
  onmouseenter={show}
  onmouseleave={hide}
  onfocusin={() => (visible = true)}
  onfocusout={hide}
>
  <span class="target" aria-describedby={visible ? id : undefined}>
    {@render children()}
  </span>

  {#if visible}
    <span class="tip {placement}" role="tooltip" {id}>{text}</span>
  {/if}
</span>

<style>
  .wrap {
    position: relative;
    display: inline-flex;
  }

  .target {
    display: inline-flex;
  }

  .tip {
    position: absolute;
    z-index: 40;
    left: 50%;
    transform: translateX(-50%);
    width: max-content;
    max-width: 264px;
    padding: 7px 10px;
    border-radius: var(--radius-sm);
    background: var(--text);
    color: var(--surface);
    font-size: 12px;
    line-height: 1.45;
    text-align: left;
    box-shadow: var(--shadow-lifted);
    pointer-events: none;
    animation: appear var(--quick) ease-out;
  }

  .tip.top {
    bottom: calc(100% + 7px);
  }

  .tip.bottom {
    top: calc(100% + 7px);
  }

  @keyframes appear {
    from {
      opacity: 0;
      transform: translateX(-50%) translateY(2px);
    }
  }
</style>
