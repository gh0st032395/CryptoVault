<!--
  The screen before a vault is open: the list of vaults, and unlocking one.

  The lock state is the loudest thing on the page, on purpose. It is the single
  fact a user needs at a glance, and getting it wrong — thinking a vault is shut
  when it is open — is the mistake with the worst consequences.
-->
<script lang="ts">
  import type { Backend, VaultSummary } from '../backend';
  import { basename, WrongPassword } from '../backend';
  import { chooseFolder, isDesktop } from '../platform';
  import type { Dictionary } from '../i18n';
  import Button from '../components/Button.svelte';
  import Icon from '../components/Icon.svelte';
  import Tooltip from '../components/Tooltip.svelte';

  interface Props {
    backend: Backend;
    t: Dictionary;
    onopened: (vault: VaultSummary) => void;
    oncreate: () => void;
  }

  const { backend, t, onopened, oncreate }: Props = $props();

  let vaults = $state<VaultSummary[]>([]);
  let selected = $state<VaultSummary | null>(null);
  let password = $state('');
  let busy = $state(false);
  let failed = $state(false);
  /** Anything that went wrong that is not a wrong password. */
  let problem = $state<string | null>(null);
  let confirming = $state<string | null>(null);
  let passwordField = $state<HTMLInputElement | null>(null);

  $effect(() => {
    void refresh();
  });

  async function refresh() {
    try {
      vaults = await backend.listVaults();
    } catch (error) {
      problem = message(error);
    }
  }

  /** What to put on screen for a failure that has no handling of its own. */
  function message(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }

  function select(vault: VaultSummary) {
    selected = vault;
    password = '';
    failed = false;
    problem = null;
    // The password field is the only thing to do on this screen once a vault is
    // chosen, so it takes focus rather than waiting to be clicked.
    queueMicrotask(() => passwordField?.focus());
  }

  async function submit(event: Event) {
    event.preventDefault();
    if (selected === null || busy) return;

    busy = true;
    failed = false;
    problem = null;
    try {
      await backend.unlock(selected.id, password);
      const opened = selected;
      password = '';
      onopened(opened);
    } catch (error) {
      // A wrong password is the expected failure and gets its own handling: a
      // message beside the field and the cursor put back. Everything else is a
      // real problem — a folder that has been moved or a disk that is not
      // there — and has to be readable rather than thrown into the console.
      failed = error instanceof WrongPassword;
      if (failed) {
        passwordField?.focus();
        passwordField?.select();
      } else {
        problem = message(error);
      }
    } finally {
      busy = false;
    }
  }

  /**
   * Adds a vault that already exists.
   *
   * The folder's own name becomes the vault's name. It is what the user called
   * the folder, so it is already the name they recognise it by, and asking them
   * to type it again would be asking a question with an obvious answer.
   */
  async function addExisting() {
    const path = await chooseFolder(t.addExisting);
    if (path === null) return;

    problem = null;
    try {
      await backend.registerVault(basename(path), path);
      await refresh();
    } catch (error) {
      problem = message(error);
    }
  }

  async function forget(id: string) {
    confirming = null;
    problem = null;
    try {
      await backend.forgetVault(id);
      if (selected?.id === id) selected = null;
      await refresh();
    } catch (error) {
      problem = message(error);
    }
  }
</script>

<div class="screen">
  <header>
    <h1>{t.yourVaults}</h1>
    <div class="actions">
      <!--
        In a browser there is no folder to point at, so the button says what it
        would do and cannot do it. Hiding it would be tidier and would also hide
        the fact that the demonstration is a demonstration.
      -->
      <Button tip={t.tipAddExisting} icon="folder" disabled={!isDesktop} onclick={addExisting}>
        {t.addExisting}
      </Button>
      <Button tip={t.tipCreateVault} variant="primary" icon="plus" onclick={oncreate}>
        {t.createVault}
      </Button>
    </div>
  </header>

  {#if problem !== null}
    <p class="problem" role="alert">
      <Icon name="warning" size={15} />
      {problem}
    </p>
  {/if}

  {#if vaults.length === 0}
    <div class="empty">
      <h2>{t.noVaultsYet}</h2>
      <p class="muted">{t.noVaultsBody}</p>
    </div>
  {:else}
    <ul class="vaults">
      {#each vaults as vault (vault.id)}
        <li>
          <div class="entry">
            <button
              class="vault"
              class:active={selected?.id === vault.id}
              onclick={() => select(vault)}
              type="button"
            >
              <span class="state" class:open={vault.unlocked}>
                <Icon name={vault.unlocked ? 'unlock' : 'lock'} size={17} />
              </span>

              <span class="identity">
                <span class="name">{vault.name}</span>
                <Tooltip text={t.tipVaultPath} placement="bottom">
                  <span class="path faint">{vault.path}</span>
                </Tooltip>
              </span>

              {#if vault.sealed}
                <Tooltip text={t.tipSealed} placement="bottom">
                  <span class="badge">{t.sealedVault}</span>
                </Tooltip>
              {/if}

              <span class="status" class:open={vault.unlocked}>
                {vault.unlocked ? t.unlocked : t.locked}
              </span>
            </button>

            <!--
              Outside the row's own button rather than inside it: a button
              within a button is not valid, and more to the point a control that
              removes something must not be a place the mouse lands on the way
              to opening it.
            -->
            <Tooltip text={t.tipForget} placement="bottom">
              <button
                class="forget"
                onclick={() => (confirming = vault.id)}
                aria-label={t.forget}
                type="button"
              >
                <Icon name="close" size={15} />
              </button>
            </Tooltip>
          </div>

          {#if confirming === vault.id}
            <div class="confirm" role="alertdialog" aria-label={t.forget}>
              <span class="words">{t.forgetConfirm}</span>
              <Button tip={t.cancel} variant="ghost" onclick={() => (confirming = null)}>
                {t.cancel}
              </Button>
              <Button tip={t.tipForget} variant="danger" onclick={() => forget(vault.id)}>
                {t.forget}
              </Button>
            </div>
          {/if}

          {#if selected?.id === vault.id && !vault.unlocked}
            <form class="unlock" onsubmit={submit}>
              <label class="field">
                <span class="label">{t.password}</span>
                <input
                  bind:this={passwordField}
                  bind:value={password}
                  type="password"
                  autocomplete="current-password"
                  class:wrong={failed}
                  aria-invalid={failed}
                  disabled={busy}
                />
              </label>

              <Tooltip text={t.tipUnlockSlow} placement="top">
                <button class="primary-action" type="submit" disabled={busy || password === ''}>
                  {busy ? t.unlocking : t.unlock}
                </button>
              </Tooltip>
            </form>

            {#if failed}
              <p class="error" role="alert">
                <Icon name="warning" size={15} />
                {t.wrongPassword}
              </p>
            {:else if busy}
              <p class="hint faint">{t.unlockHint}</p>
            {/if}
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .screen {
    max-width: 720px;
    margin: 0 auto;
    padding: 44px 24px;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 22px;
  }

  .actions {
    display: flex;
    gap: 8px;
  }

  .empty {
    padding: 56px 32px;
    text-align: center;
    background: var(--surface);
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius);
  }

  .empty p {
    max-width: 46ch;
    margin: 8px auto 0;
  }

  .vaults {
    display: flex;
    flex-direction: column;
    gap: 10px;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .vaults li {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    overflow: hidden;
  }

  .entry {
    display: flex;
    align-items: stretch;
  }

  .vault {
    display: flex;
    align-items: center;
    gap: 13px;
    flex: 1;
    min-width: 0;
    padding: 14px 16px;
    border: 0;
    background: transparent;
    text-align: left;
    cursor: pointer;
    transition: background var(--quick) ease;
  }

  /* Quiet until the pointer is on the row: removing a vault from the list is
     not something to advertise, and not something to hide either. */
  .forget {
    display: grid;
    place-items: center;
    width: 38px;
    flex: none;
    border: 0;
    background: transparent;
    color: var(--text-muted);
    opacity: 0;
    cursor: pointer;
    transition:
      opacity var(--quick) ease,
      color var(--quick) ease;
  }

  .entry:hover .forget,
  .forget:focus-visible {
    opacity: 1;
  }

  .forget:hover {
    color: var(--danger);
  }

  .confirm {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-top: 1px solid var(--border);
    background: var(--surface-sunken);
    font-size: 12.5px;
  }

  .confirm .words {
    flex: 1;
  }

  .problem {
    display: flex;
    align-items: center;
    gap: 7px;
    margin-bottom: 14px;
    padding: 10px 13px;
    border-radius: var(--radius-sm);
    background: var(--danger-soft);
    color: var(--danger);
    font-size: 12.5px;
  }

  .vault:hover,
  .vault.active {
    background: var(--surface-sunken);
  }

  /* The lock is the loudest thing here, because it is the fact that matters. */
  .state {
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    flex: none;
    border-radius: 9px;
    background: var(--locked-soft);
    color: var(--locked);
  }

  .state.open {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .identity {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
    flex: 1;
  }

  .name {
    font-weight: 550;
  }

  .path {
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .badge {
    padding: 3px 8px;
    border-radius: 20px;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 11.5px;
    font-weight: 550;
  }

  .status {
    font-size: 12.5px;
    font-weight: 550;
    color: var(--locked);
  }

  .status.open {
    color: var(--accent);
  }

  .unlock {
    display: flex;
    align-items: flex-end;
    gap: 10px;
    padding: 0 16px 14px;
    border-top: 1px solid var(--border);
    padding-top: 14px;
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    flex: 1;
  }

  .label {
    font-size: 12px;
    color: var(--text-muted);
  }

  input {
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

  .primary-action {
    height: 34px;
    padding: 0 18px;
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

  .error,
  .hint {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 0 16px 14px;
    font-size: 12.5px;
  }

  .error {
    color: var(--danger);
  }
</style>
