<!--
  The application shell: which screen is showing, and the preferences that
  outlive it.

  It also owns the auto-lock timer, because auto-lock is a property of the
  application rather than of any one screen — a vault must lock whether the user
  is looking at a folder, a dialogue, or nothing at all.
-->
<script lang="ts">
  import { DemoBackend, IS_DEMO, type Backend, type VaultSummary } from './lib/backend';
  import { detectLanguage, strings, type Language } from './lib/i18n';
  import {
    applyTheme,
    loadLanguage,
    loadPolicy,
    loadTheme,
    saveLanguage,
    savePolicy,
    saveTheme,
    type LockPolicy,
    type ThemeChoice,
  } from './lib/theme';
  import Browser from './lib/screens/Browser.svelte';
  import CreateVault from './lib/screens/CreateVault.svelte';
  import Welcome from './lib/screens/Welcome.svelte';
  import Button from './lib/components/Button.svelte';
  import Icon from './lib/components/Icon.svelte';
  import Tooltip from './lib/components/Tooltip.svelte';

  /**
   * How long a vault stays open with nobody touching it, and how long the
   * warning lasts once it appears.
   *
   * Fifteen minutes is the default from the plan. The countdown is a minute:
   * long enough to notice and stop it, short enough that walking away really
   * does lock the vault.
   */
  const IDLE_LIMIT_MS = 15 * 60 * 1000;
  const COUNTDOWN_SECONDS = 60;

  const backend: Backend = new DemoBackend();

  let language = $state<Language>(loadLanguage(detectLanguage()));
  let themeChoice = $state<ThemeChoice>(loadTheme());
  let policy = $state<LockPolicy>(loadPolicy());
  let open = $state<VaultSummary | null>(null);
  let settingsOpen = $state(false);
  let creating = $state(false);

  /** Seconds left before an idle vault locks itself, or null when not warning. */
  let countdown = $state<number | null>(null);

  const t = $derived(strings(language));

  $effect(() => {
    applyTheme(themeChoice);
  });

  // The interface follows the system while the choice is "system", rather than
  // only at startup — someone switching their machine to dark at dusk should
  // not have to restart the application.
  $effect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const react = () => applyTheme(themeChoice);
    media.addEventListener('change', react);
    return () => media.removeEventListener('change', react);
  });

  /**
   * Auto-lock.
   *
   * Three policies, chosen by the user. `warn` is the default from the plan:
   * a countdown that can be stopped, and a lock if nobody stops it.
   *
   * `manual` really does disable the timer. It is a legitimate thing to want
   * and it is also the exact failure auto-lock exists to prevent, so the
   * tooltip beside it says that plainly rather than presenting the three
   * options as interchangeable.
   */
  $effect(() => {
    if (open === null || policy === 'manual') return;

    let idleTimer: ReturnType<typeof setTimeout>;
    let tick: ReturnType<typeof setInterval> | undefined;

    const startCountdown = () => {
      if (policy === 'immediate') {
        void lock();
        return;
      }
      countdown = COUNTDOWN_SECONDS;
      tick = setInterval(() => {
        countdown = (countdown ?? 1) - 1;
        if ((countdown ?? 0) <= 0) {
          clearInterval(tick);
          void lock();
        }
      }, 1000);
    };

    const restart = () => {
      clearTimeout(idleTimer);
      clearInterval(tick);
      countdown = null;
      idleTimer = setTimeout(startCountdown, IDLE_LIMIT_MS);
    };

    const events = ['pointerdown', 'keydown', 'wheel'] as const;
    for (const event of events) window.addEventListener(event, restart, { passive: true });
    restart();

    return () => {
      clearTimeout(idleTimer);
      clearInterval(tick);
      countdown = null;
      for (const event of events) window.removeEventListener(event, restart);
    };
  });

  async function lock() {
    if (open === null) return;
    await backend.lock(open.id);
    open = null;
    countdown = null;
  }

  function setLanguage(next: Language) {
    language = next;
    saveLanguage(next);
  }

  function setTheme(next: ThemeChoice) {
    themeChoice = next;
    saveTheme(next);
  }

  function setPolicy(next: LockPolicy) {
    policy = next;
    savePolicy(next);
  }
</script>

<div class="app">
  <div class="chrome">
    <span class="brand">
      <span class="mark" class:open={open !== null}>
        <Icon name={open === null ? 'lock' : 'unlock'} size={15} />
      </span>
      {t.appName}
    </span>

    <div class="chrome-actions">
      {#if open !== null}
        <Tooltip text={t.tipLockNow} placement="bottom">
          <span class="state-pill">{t.unlocked} · {open.name}</span>
        </Tooltip>
      {/if}
      <Button
        tip={t.settings}
        variant="ghost"
        icon="settings"
        iconOnly
        label={t.settings}
        onclick={() => (settingsOpen = !settingsOpen)}
      />
    </div>
  </div>

  {#if settingsOpen}
    <div class="settings">
      <div class="group">
        <span class="group-label">{t.theme}</span>
        <div class="choices">
          {#each [['light', t.themeLight], ['dark', t.themeDark], ['system', t.themeSystem]] as const as [value, label] (value)}
            <Tooltip text={t.tipTheme} placement="bottom">
              <button
                class="choice"
                class:on={themeChoice === value}
                onclick={() => setTheme(value)}
                type="button">{label}</button
              >
            </Tooltip>
          {/each}
        </div>
      </div>

      <div class="group">
        <span class="group-label">{t.autoLock}</span>
        <div class="choices">
          {#each [['warn', t.policyWarn, t.tipPolicyWarn], ['immediate', t.policyImmediate, t.tipPolicyImmediate], ['manual', t.policyManual, t.tipPolicyManual]] as const as [value, label, tip] (value)}
            <Tooltip text={tip} placement="bottom">
              <button
                class="choice"
                class:on={policy === value}
                onclick={() => setPolicy(value)}
                type="button">{label}</button
              >
            </Tooltip>
          {/each}
        </div>
      </div>

      <div class="group">
        <span class="group-label">{t.language}</span>
        <div class="choices">
          {#each [['it', 'Italiano'], ['en', 'English']] as const as [value, label] (value)}
            <Tooltip text={t.tipLanguage} placement="bottom">
              <button
                class="choice"
                class:on={language === value}
                onclick={() => setLanguage(value)}
                type="button">{label}</button
              >
            </Tooltip>
          {/each}
        </div>
      </div>
    </div>
  {/if}

  {#if IS_DEMO}
    <div class="demo" role="status">
      <Icon name="warning" size={14} />
      {t.demoBanner}
      <code>{DemoBackend.password}</code>
    </div>
  {/if}

  <main>
    {#if creating}
      <CreateVault
        {backend}
        {t}
        oncreated={() => (creating = false)}
        oncancel={() => (creating = false)}
      />
    {:else if open === null}
      <Welcome
        {backend}
        {t}
        onopened={(vault) => (open = vault)}
        oncreate={() => (creating = true)}
      />
    {:else}
      <Browser {backend} vault={open} {t} {language} onlock={lock} />
    {/if}
  </main>

  {#if countdown !== null}
    <div class="countdown" role="alertdialog" aria-labelledby="countdown-title">
      <span class="ring">{countdown}</span>
      <span class="words">
        <strong id="countdown-title">{t.autoLockTitle} {countdown}s</strong>
        <span class="muted">{t.autoLockBody}</span>
      </span>
      <Button tip={t.tipLockNow} variant="ghost" onclick={lock} tipPlacement="top">
        {t.lockNowShort}
      </Button>
      <Button tip={t.tipUnlock} variant="primary" onclick={() => (countdown = null)} tipPlacement="top">
        {t.stayUnlocked}
      </Button>
    </div>
  {/if}
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .chrome {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 9px 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 9px;
    font-size: 13.5px;
    font-weight: 600;
    letter-spacing: -0.01em;
  }

  .mark {
    display: grid;
    place-items: center;
    width: 26px;
    height: 26px;
    border-radius: 8px;
    background: var(--locked-soft);
    color: var(--locked);
  }

  .mark.open {
    background: var(--accent-soft);
    color: var(--accent);
  }

  .chrome-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .state-pill {
    padding: 4px 10px;
    border-radius: 20px;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: 12px;
    font-weight: 550;
  }

  .settings {
    display: flex;
    flex-wrap: wrap;
    gap: 16px 26px;
    padding: 12px 14px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
  }

  .group {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .group-label {
    font-size: 12px;
    color: var(--text-muted);
  }

  .choices {
    display: flex;
    gap: 3px;
    padding: 3px;
    border-radius: 8px;
    background: var(--surface-sunken);
  }

  .choice {
    padding: 4px 11px;
    border: 0;
    border-radius: 6px;
    background: transparent;
    font-size: 12.5px;
    color: var(--text-muted);
    cursor: pointer;
  }

  .choice.on {
    background: var(--surface-raised);
    color: var(--text);
    font-weight: 550;
    box-shadow: var(--shadow);
  }

  .demo {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 7px 14px;
    background: var(--locked-soft);
    color: var(--locked);
    font-size: 12.5px;
  }

  .demo code {
    padding: 1px 6px;
    border-radius: 5px;
    background: rgb(0 0 0 / 7%);
    font-family: var(--font-mono);
    font-size: 11.5px;
  }

  main {
    flex: 1;
    min-height: 0;
    overflow: auto;
  }

  .countdown {
    position: fixed;
    right: 18px;
    bottom: 18px;
    z-index: 50;
    display: flex;
    align-items: center;
    gap: 12px;
    max-width: 440px;
    padding: 13px 15px;
    background: var(--surface-raised);
    border: 1px solid var(--border-strong);
    border-radius: var(--radius);
    box-shadow: var(--shadow-lifted);
  }

  .ring {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    flex: none;
    border-radius: 50%;
    border: 2px solid var(--locked);
    color: var(--locked);
    font-size: 13px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }

  .words {
    display: flex;
    flex-direction: column;
    gap: 1px;
    font-size: 12.5px;
  }
</style>
