<script lang="ts">
  import { onDestroy, onMount } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import Select from "../../components/ui/Select.svelte";
  import Switch from "../../components/ui/Switch.svelte";
  import { locale, t } from "../../data/locale.svelte";
  import { routing } from "../../data/routing.svelte";
  import { updater } from "../../data/updater.svelte";
  import { warmup } from "../../data/warmup.svelte";

  import { Download, Flame, RefreshCw } from "../../components/ui/icons";
  import { overlay, toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";

  const RELOAD_DELAY_MS = 8000;

  type SystemInfo = { started_at: string; uptime_seconds: number };
  type ClientRouting = { mode: "exclude"; source_networks: string[] };
  type DirectPriority = { mode: "absolute" | "byOrder" };

  let busy = $state(false);
  let startedAt = $state<Date | null>(null);
  let now = $state(Date.now());
  let timer: ReturnType<typeof setInterval> | null = null;
  let clientRoutingText = $state("");
  let clientRoutingLoaded = $state(false);
  let clientRoutingSaving = $state(false);
  let directPriority = $state<"absolute" | "byOrder">("absolute");
  // Последний РЕЖИМ, подтверждённый сервером. Отдельно от directPriority,
  // потому что directPriority связан с селектом двусторонне: bits-ui успевает
  // записать туда новый выбор ДО вызова onValueChange, и сравнение «пришёл ли
  // другой режим» по самому directPriority всегда даёт «тот же» — запрос не
  // уходил вовсе, а после перезагрузки страницы выбор откатывался (mt-ui).
  let directPriorityApplied = $state<"absolute" | "byOrder">("absolute");
  let directPriorityLoaded = $state(false);
  let directPrioritySaving = $state(false);

  let uptime = $derived.by(() => {
    if (!startedAt) return null;
    return Math.max(0, Math.floor((now - startedAt.getTime()) / 1000));
  });

  const UNITS_RU = { d: "д", h: "ч", m: "м", s: "с" };
  const UNITS_EN = { d: "d", h: "h", m: "m", s: "s" };
  let units = $derived(locale.state.value === "ru" ? UNITS_RU : UNITS_EN);

  function formatUptime(s: number | null): string {
    if (s == null) return "—";
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const parts: string[] = [];
    if (d) parts.push(`${d}${units.d}`);
    if (d || h) parts.push(`${h}${units.h}`);
    if (d || h || m) parts.push(`${m}${units.m}`);
    parts.push(`${sec}${units.s}`);
    return parts.join(" ");
  }

  async function loadInfo() {
    try {
      const info = await fetcher.get<SystemInfo>("/system/info");
      startedAt = new Date(info.started_at);
      now = Date.now();
    } catch {
      // toast уже показан фетчером
    }
  }

  const directPriorityOptions = $derived([
    { value: "absolute", label: t("Direct wins any overlap") },
    { value: "byOrder", label: t("Direct follows group order") },
  ]);

  async function loadDirectPriority() {
    try {
      const config = await fetcher.get<DirectPriority>("/system/direct-priority");
      directPriority = config.mode;
      directPriorityApplied = config.mode;
      directPriorityLoaded = true;
    } catch {
      directPriorityLoaded = false;
    }
  }

  // Переключение переподнимает правила роутинга — отсюда подтверждение и
  // блокировка селекта на время запроса: это не мгновенная настройка.
  async function onDirectPriorityChange(mode: string) {
    if (!directPriorityLoaded || directPrioritySaving) return;
    if (mode !== "absolute" && mode !== "byOrder") return;
    const previous = directPriorityApplied;
    if (mode === previous) return;
    if (!confirm(t("Switching re-applies routing rules and takes about 10 seconds. Continue?"))) {
      directPriority = previous;
      return;
    }
    directPrioritySaving = true;
    directPriority = mode;
    try {
      const config = await fetcher.put<DirectPriority>("/system/direct-priority", { mode });
      directPriority = config.mode;
      directPriorityApplied = config.mode;
      toast.success(t("Direct priority saved"));
    } catch {
      directPriority = previous;
    } finally {
      directPrioritySaving = false;
    }
  }

  async function loadClientRouting() {
    try {
      const config = await fetcher.get<ClientRouting>("/system/client-routing");
      clientRoutingText = config.source_networks.join("\n");
      clientRoutingLoaded = true;
    } catch {
      clientRoutingLoaded = false;
    }
  }

  async function saveClientRouting() {
    if (!clientRoutingLoaded || clientRoutingSaving) return;
    clientRoutingSaving = true;
    const sourceNetworks = clientRoutingText
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
    try {
      const config = await fetcher.put<ClientRouting>("/system/client-routing", {
        mode: "exclude",
        source_networks: sourceNetworks,
      });
      clientRoutingText = config.source_networks.join("\n");
      toast.success(t("Client bypass saved"));
    } finally {
      clientRoutingSaving = false;
    }
  }

  onMount(() => {
    loadInfo();
    loadClientRouting();
    loadDirectPriority();
    routing.load();
    timer = setInterval(() => (now = Date.now()), 1000);
  });

  async function onRoutingToggle(checked: boolean) {
    await routing.setEnabled(checked);
  }

  onDestroy(() => {
    if (timer) clearInterval(timer);
  });

  async function handleRestart() {
    if (busy) return;
    if (!confirm(t("Restart magitrickled service?"))) return;

    busy = true;
    overlay.show(t("Restarting service..."));
    try {
      await fetcher.post("/system/restart", {});
      toast.success(t("Service restart initiated"));
    } catch {
      overlay.hide();
      busy = false;
      return;
    }
    setTimeout(() => window.location.reload(), RELOAD_DELAY_MS);
  }
</script>

<div class="settings">
  <section class="card" class:card-off={routing.state.loaded && !routing.state.enabled}>
    <div class="row">
      <div class="info">
        <h3>
          {routing.state.enabled ? t("MagiTrickle is on") : t("MagiTrickle is paused")}
        </h3>
        <p class="hint">{t("MT toggle hint")}</p>
      </div>
      <Switch
        checked={routing.state.enabled}
        disabled={routing.state.busy || !routing.state.loaded}
        onCheckedChange={onRoutingToggle}
        aria-label={t("MagiTrickle on/off")}
      />
    </div>
  </section>

  <section class="card">
    <div class="client-routing">
      <div class="info">
        <h3>{t("Bypass MagiTrickle for clients")}</h3>
        <p class="hint">{t("Client bypass hint")}</p>
      </div>
      <textarea
        bind:value={clientRoutingText}
        disabled={!clientRoutingLoaded || clientRoutingSaving}
        placeholder={t("One IP address or CIDR per line")}
        aria-label={t("Client bypass networks")}
        spellcheck="false"
      ></textarea>
      <p class="warning">{t("Client bypass DHCP warning")}</p>
      <div class="client-routing-actions">
        <Button onclick={saveClientRouting} inactive={!clientRoutingLoaded || clientRoutingSaving}>
          {clientRoutingSaving ? t("saving changes...") : t("Save Changes")}
        </Button>
      </div>
    </div>
  </section>

  <section class="card">
    <div class="row">
      <div class="info">
        <h3>{t("Direct group priority")}</h3>
        <p class="hint">{t("Direct priority hint")}</p>
      </div>
      <div class="direct-priority-control">
        <!-- bind обязателен: bits-ui меняет выбор внутри себя сразу по клику,
             и без двусторонней связи возврат directPriority к прежнему значению
             (отмена подтверждения, ошибка PUT) не доедет обратно в компонент —
             селект покажет режим, который так и не применился. -->
        <Select
          options={directPriorityOptions}
          bind:selected={directPriority}
          onValueChange={onDirectPriorityChange}
          ariaLabel={t("Direct group priority")}
        />
        {#if directPrioritySaving}
          <p class="hint">{t("Re-applying routing rules...")}</p>
        {/if}
      </div>
    </div>
  </section>

  <section class="card">
    <div class="row">
      <div class="info">
        <h3>{t("Warm up ipset")}</h3>
        <p class="hint">{t("Warmup hint")}</p>
        {#if warmup.state.last}
          <p class="uptime">
            <span class="uptime-label">{t("Last warmup")}:</span>
            <span class="uptime-value">{warmup.state.last.queried}/{warmup.state.last.matched}</span
            >
            {#if warmup.state.last.errors > 0}
              <span class="uptime-since">({warmup.state.last.errors} {t("errors")})</span>
            {/if}
            {#if warmup.state.last.truncated}
              <span class="uptime-since">({t("truncated")})</span>
            {/if}
          </p>
        {/if}
      </div>
      <Button
        onclick={() => warmup.run()}
        inactive={warmup.state.busy || (routing.state.loaded && !routing.state.enabled)}
      >
        {#if warmup.state.busy}
          <span class="update-spinner"><RefreshCw size={18} /></span>
          {t("Warming up...")}
        {:else}
          <Flame size={18} />
          {t("Warm up")}
        {/if}
      </Button>
    </div>
  </section>

  <section class="card">
    <div class="row">
      <div class="info">
        <h3>{t("Restart service")}</h3>
        <p class="hint">{t("Restarts magitrickled. The page will reload automatically.")}</p>
        <p class="uptime">
          <span class="uptime-label">{t("Uptime")}:</span>
          <span class="uptime-value">{formatUptime(uptime)}</span>
          {#if startedAt}
            <span class="uptime-since">({t("since")} {startedAt.toLocaleString()})</span>
          {/if}
        </p>
      </div>
      <Button onclick={handleRestart} inactive={busy}>
        <RefreshCw size={18} />
        {t("Restart")}
      </Button>
    </div>
  </section>

  <section class="card">
    <div class="row">
      <div class="info">
        <h3>{t("Updates")}</h3>
        <p class="hint">
          {t("Check and install fork updates.")}
          {#if updater.newVersion && !updater.updating}
            <br />
            <span style="color: var(--green); font-weight: 500;">
              {t("New version available:")}
              {updater.newVersion}
            </span>
          {/if}
          {#if updater.updating}
            <br />
            <span class="update-progress">
              <span class="update-spinner"><RefreshCw size={14} /></span>
              {updater.phaseLabel()}
            </span>
          {/if}
          {#if updater.phase === "failed" && updater.updateError}
            <br />
            <span style="color: var(--red, #e5484d); font-weight: 500;">
              {t("Update failed")}: {updater.updateError}
            </span>
            <br />
            <button
              class="log-toggle"
              onclick={() => updater.loadLog()}
              disabled={updater.logLoading}
            >
              {updater.logLoading ? t("Loading...") : t("Show log")}
            </button>
          {/if}
        </p>
        {#if updater.phase === "failed" && updater.log}
          <pre class="update-log">{updater.log}</pre>
        {/if}
      </div>
      <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
        <Button
          onclick={() => updater.check()}
          inactive={updater.checking || updater.updating}
          variant={updater.newVersion ? "secondary" : "primary"}
        >
          <RefreshCw size={18} />
          {updater.checking ? t("Checking...") : t("Check for Updates")}
        </Button>

        {#if updater.newVersion}
          <Button onclick={() => updater.runUpdate()} inactive={updater.updating} variant="primary">
            {#if updater.updating}
              <span class="update-spinner"><RefreshCw size={18} /></span>
              {updater.phaseLabel()}
            {:else}
              <Download size={18} />
              {updater.phase === "failed" ? t("Retry Update") : t("Install Update")}
            {/if}
          </Button>
        {/if}
      </div>
    </div>
  </section>
</div>

<style>
  .direct-priority-control {
    min-width: 15rem;
  }

  .settings {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    max-width: 720px;
    margin: 0 auto;
  }

  .card {
    border: 1px solid var(--border-light);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    background: var(--bg-card, transparent);
    transition:
      border-color 0.2s,
      background 0.2s;
  }

  .card.card-off {
    border-color: var(--orange, #c79030);
    background: color-mix(in srgb, var(--orange, #c79030) 8%, transparent);
  }

  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
  }

  .info {
    flex: 1;
    min-width: 0;
  }

  .client-routing {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  textarea {
    box-sizing: border-box;
    width: 100%;
    min-height: 8rem;
    resize: vertical;
    border: 1px solid var(--border-light);
    border-radius: 6px;
    padding: 0.7rem 0.8rem;
    background: var(--bg-2, rgba(0, 0, 0, 0.2));
    color: var(--text);
    font: 0.9rem/1.45 monospace;
  }

  textarea:focus {
    outline: none;
    border-color: var(--accent, var(--green));
  }

  textarea:disabled {
    opacity: 0.6;
  }

  .warning {
    margin: 0;
    color: var(--orange, #c79030);
    font-size: 0.82rem;
    line-height: 1.4;
  }

  .client-routing-actions {
    display: flex;
    justify-content: flex-end;
  }

  h3 {
    margin: 0 0 0.25rem 0;
    font-size: 1.05rem;
    font-weight: 600;
  }

  .hint {
    margin: 0;
    color: var(--text-2);
    font-size: 0.9rem;
    line-height: 1.4;
  }

  .uptime {
    margin: 0.6rem 0 0 0;
    font-size: 0.85rem;
    color: var(--text-2);
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    align-items: baseline;
  }

  .uptime-label {
    color: var(--text-3, var(--text-2));
  }

  .uptime-value {
    font-variant-numeric: tabular-nums;
    color: var(--text);
    font-weight: 500;
  }

  .uptime-since {
    color: var(--text-3, var(--text-2));
    font-size: 0.8rem;
  }

  .update-progress {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    color: var(--accent, var(--green));
    font-weight: 500;
  }

  .update-spinner {
    display: inline-flex;
    animation: update-spin 1s linear infinite;
  }

  .log-toggle {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent, var(--green));
    font-size: 0.8rem;
    cursor: pointer;
    text-decoration: underline;
  }

  .log-toggle:disabled {
    cursor: default;
    opacity: 0.6;
  }

  .update-log {
    margin-top: 0.6rem;
    padding: 0.6rem 0.8rem;
    background: var(--bg-2, rgba(0, 0, 0, 0.25));
    border: 1px solid var(--border-light);
    border-radius: 6px;
    font-size: 0.75rem;
    line-height: 1.4;
    max-height: 220px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }

  @keyframes update-spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  @media (max-width: 540px) {
    .row {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
