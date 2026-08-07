<!--
  Creating a vault.

  The one screen where the interface has to be uncomfortable. Everywhere else
  the job is to stay out of the way; here it is to make sure nobody types a
  password they will not remember and finds out in six months.

  So the warning is not a footnote in grey text at the bottom. It sits between
  the password fields and the button, in the path of the person about to press
  it, and it says the thing plainly: if you forget this, the vault is gone.
-->
<script lang="ts">
  import type { Backend } from '../backend';
  import { chooseFolder, isDesktop } from '../platform';
  import type { Dictionary } from '../i18n';
  import { passwordStrength } from '../theme';
  import Button from '../components/Button.svelte';
  import Icon from '../components/Icon.svelte';
  import Tooltip from '../components/Tooltip.svelte';

  interface Props {
    backend: Backend;
    t: Dictionary;
    oncreated: () => void;
    oncancel: () => void;
  }

  const { backend, t, oncreated, oncancel }: Props = $props();

  let name = $state('');
  let location = $state('');
  let password = $state('');
  let confirmation = $state('');
  let sealed = $state(false);
  let busy = $state(false);
  /** What went wrong, if anything did. */
  let problem = $state<string | null>(null);

  const strength = $derived(passwordStrength(password));
  const strengthLabel = $derived(
    [t.strengthWeak, t.strengthFair, t.strengthGood, t.strengthStrong][strength] ?? t.strengthWeak,
  );

  // Only complain once there is something to complain about: an error that
  // appears on the first keystroke of the second field is noise, not help.
  const mismatch = $derived(confirmation.length > 0 && password !== confirmation);
  const ready = $derived(
    name.trim().length > 0 &&
      location.length > 0 &&
      password.length > 0 &&
      password === confirmation &&
      !busy,
  );

  async function choose() {
    const chosen = await chooseFolder(t.vaultLocation);
    if (chosen !== null) {
      location = chosen;
      problem = null;
    }
  }

  async function submit(event: Event) {
    event.preventDefault();
    if (!ready) return;

    busy = true;
    problem = null;
    try {
      await backend.createVault(name.trim(), location, password, sealed);
      oncreated();
    } catch (error) {
      // A folder that already holds a vault, a disk with no room, a place the
      // user cannot write to. All ordinary, all invisible until now: without
      // this the button simply stopped spinning and nothing happened.
      problem = error instanceof Error ? error.message : String(error);
    } finally {
      busy = false;
    }
  }
</script>

<div class="screen">
  <form onsubmit={submit}>
    <header>
      <span class="mark"><Icon name="plus" size={17} /></span>
      <h1>{t.newVault}</h1>
    </header>

    <label class="field">
      <span class="label">{t.vaultName}</span>
      <input bind:value={name} autocomplete="off" disabled={busy} />
    </label>

    <div class="field">
      <span class="label">{t.vaultLocation}</span>
      <div class="row">
        <input
          class="grow"
          bind:value={location}
          placeholder={t.locationPlaceholder}
          autocomplete="off"
          disabled={busy}
        />
        <Button
          tip={t.tipVaultPath}
          disabled={busy || !isDesktop}
          onclick={choose}
          tipPlacement="top">{t.choose}</Button
        >
      </div>
      <!-- The vault is a folder of its own, and where it will be is worth
           showing before the button is pressed rather than after. -->
      {#if location.length > 0 && name.trim().length > 0}
        <span class="destination faint">{location}/{name.trim()}</span>
      {/if}
    </div>

    <label class="field">
      <span class="label">{t.password}</span>
      <input bind:value={password} type="password" autocomplete="new-password" disabled={busy} />
    </label>

    {#if password.length > 0}
      <div class="strength" aria-live="polite">
        <span class="bars">
          {#each [0, 1, 2, 3] as step (step)}
            <span class="bar" class:on={step <= strength} data-level={strength}></span>
          {/each}
        </span>
        <!-- The tooltip goes on the label, not the row: it explains what the
             word means, and an inline target is what the wrapper handles. -->
        <Tooltip text={t.tipStrength} placement="top">
          <span class="strength-label" data-level={strength}>{strengthLabel}</span>
        </Tooltip>
      </div>
    {/if}

    <label class="field">
      <span class="label">{t.confirmPassword}</span>
      <input
        bind:value={confirmation}
        type="password"
        autocomplete="new-password"
        class:wrong={mismatch}
        aria-invalid={mismatch}
        disabled={busy}
      />
      {#if mismatch}
        <span class="mismatch" role="alert">{t.passwordsDiffer}</span>
      {/if}
    </label>

    <label class="toggle">
      <input type="checkbox" bind:checked={sealed} disabled={busy} />
      <span>
        <Tooltip text={t.tipSealed} placement="top">
          <strong>{t.sealedVault}</strong>
        </Tooltip>
        <span class="muted">{t.sealedExplain}</span>
      </span>
    </label>

    <!--
      In the path of the person about to press the button, not tucked away
      underneath it. This is the one thing on the screen they must read.
    -->
    <div class="warning" role="note">
      <Icon name="warning" size={17} />
      <span>
        <strong>{t.createWarningTitle}</strong>
        <span>{t.createWarningBody}</span>
      </span>
    </div>

    {#if problem !== null}
      <p class="problem" role="alert">
        <Icon name="warning" size={15} />
        {problem}
      </p>
    {/if}

    <div class="actions">
      <Button tip={t.cancel} variant="ghost" onclick={oncancel} tipPlacement="top">
        {t.cancel}
      </Button>
      <button class="primary-action" type="submit" disabled={!ready}>
        {busy ? '…' : t.create}
      </button>
    </div>
  </form>
</div>

<style>
  .screen {
    max-width: 520px;
    margin: 0 auto;
    padding: 34px 24px 56px;
  }

  .destination {
    margin-top: 5px;
    font-family: var(--font-mono);
    font-size: 11.5px;
    overflow-wrap: anywhere;
  }

  .problem {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 10px 13px;
    border-radius: var(--radius-sm);
    background: var(--danger-soft);
    color: var(--danger);
    font-size: 12.5px;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 15px;
    padding: 22px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }

  header {
    display: flex;
    align-items: center;
    gap: 11px;
    margin-bottom: 2px;
  }

  .mark {
    display: grid;
    place-items: center;
    width: 32px;
    height: 32px;
    border-radius: 9px;
    background: var(--accent-soft);
    color: var(--accent);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }

  .label {
    font-size: 12px;
    color: var(--text-muted);
  }

  .row {
    display: flex;
    gap: 8px;
  }

  .grow {
    flex: 1;
  }

  input[type='password'],
  input:not([type]) {
    height: 34px;
    padding: 0 11px;
    border: 1px solid var(--border-strong);
    border-radius: var(--radius-sm);
    background: var(--surface-raised);
    transition: border-color var(--quick) ease;
  }

  input:focus {
    border-color: var(--accent);
  }

  input.wrong {
    border-color: var(--danger);
  }

  .mismatch {
    font-size: 12px;
    color: var(--danger);
  }

  .strength {
    display: flex;
    align-items: center;
    gap: 9px;
    width: 100%;
  }

  .bars {
    display: flex;
    gap: 4px;
    flex: 1;
  }

  .bar {
    height: 4px;
    flex: 1;
    border-radius: 2px;
    background: var(--border);
    transition: background var(--quick) ease;
  }

  /* Amber up to "fair", the accent from "good": the colour should not
     congratulate a password the meter cannot actually vouch for. */
  .bar.on[data-level='0'],
  .bar.on[data-level='1'] {
    background: var(--locked);
  }
  .bar.on[data-level='2'],
  .bar.on[data-level='3'] {
    background: var(--accent);
  }

  .strength-label {
    font-size: 12px;
    font-weight: 550;
    min-width: 62px;
    text-align: right;
  }
  .strength-label[data-level='0'],
  .strength-label[data-level='1'] {
    color: var(--locked);
  }
  .strength-label[data-level='2'],
  .strength-label[data-level='3'] {
    color: var(--accent);
  }

  .toggle {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 11px 12px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    cursor: pointer;
  }

  .toggle span {
    display: flex;
    flex-direction: column;
    font-size: 13px;
  }

  .toggle .muted {
    font-size: 12px;
  }

  .warning {
    display: flex;
    gap: 10px;
    padding: 12px 13px;
    border-radius: var(--radius-sm);
    background: var(--locked-soft);
    color: var(--locked);
    font-size: 12.5px;
    line-height: 1.5;
  }

  .warning span {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 3px;
  }

  .primary-action {
    height: 34px;
    padding: 0 20px;
    border: 0;
    border-radius: var(--radius-sm);
    background: var(--accent);
    color: var(--accent-text);
    font-size: 13.5px;
    font-weight: 550;
    cursor: pointer;
  }

  .primary-action:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
</style>
