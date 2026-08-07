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

  let wrap = $state<HTMLElement | null>(null);

  const id = `tip-${Math.random().toString(36).slice(2, 9)}`;

  /** How close a tooltip may come to the edge of the window. */
  const MARGIN = 8;

  /**
   * Slides the tooltip back inside the window if centring would hang it off.
   *
   * A tooltip is centred on what it describes, which is right until the thing
   * it describes is near an edge — and the controls nearest an edge are the
   * ones alone at the end of a toolbar or a row, which tend to be the ones
   * whose explanation matters most.
   *
   * This is an action rather than an effect because the measurement has to
   * happen when the node is in the document and laid out. An effect reading
   * `offsetWidth` can run a moment too early, get zero, conclude that a
   * 264-pixel tooltip fits anywhere, and never correct itself.
   */
  function keepOnScreen(node: HTMLElement) {
    const anchor = wrap?.getBoundingClientRect();
    if (anchor === undefined) return;

    const centre = anchor.left + anchor.width / 2;
    const half = node.offsetWidth / 2;

    let shift = 0;
    if (centre - half < MARGIN) {
      shift = MARGIN - (centre - half);
    } else if (centre + half > window.innerWidth - MARGIN) {
      shift = window.innerWidth - MARGIN - (centre + half);
    }

    node.style.setProperty('--shift', `${shift}px`);
  }

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
  bind:this={wrap}
  onmouseenter={show}
  onmouseleave={hide}
  onfocusin={() => (visible = true)}
  onfocusout={hide}
>
  <span class="target" aria-describedby={visible ? id : undefined}>
    {@render children()}
  </span>

  {#if visible}
    <span class="tip {placement}" use:keepOnScreen role="tooltip" {id}>{text}</span>
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
    transform: translateX(calc(-50% + var(--shift, 0px)));
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
      transform: translateX(calc(-50% + var(--shift, 0px))) translateY(2px);
    }
  }
</style>
