<script lang="ts">
  import { onMount } from "svelte";

  import { aliases } from "../../data/aliases.svelte";
  import { interfaces, fetchInterfaces } from "../../data/interfaces.svelte";
  import { t } from "../../data/locale.svelte";
  import { toast } from "../../utils/events";
  import { fetcher } from "../../utils/fetcher";
  import type { Group } from "../../types";

  import Button from "../../components/ui/Button.svelte";
  import Tooltip from "../../components/ui/Tooltip.svelte";
  import { Save, Import, Export, Globe, Gauge } from "../../components/ui/icons";

  let { visible = false }: { visible?: boolean } = $props();

  let interfaceList = $state<{ id: string; alias: string; active?: boolean; ip?: string }[]>([]);
  let hasChanges = $state(false);
  let fileInput: HTMLInputElement;

  let externalIPs = $state<Record<string, string | "loading" | "error">>({});
  let globalLoading = $state(false);
  let hasInitialCheck = $state(false);

  // Группы загружаются отдельно для статистики (InterfacesView — изолированный модуль)
  let groups = $state<Group[]>([]);

  let stats = $derived.by(() => {
    const global = {
      groups: groups.length,
      activeGroups: groups.filter((g) => g.enable).length,
      rules: groups.reduce((acc, g) => acc + (g.rules?.length ?? 0), 0),
      activeRules: groups.reduce((acc, g) => {
        if (!g.enable) return acc;
        return acc + (g.rules?.filter((r) => r.enable).length ?? 0);
      }, 0),
      usedInterfaces: new Set(groups.filter((g) => g.interface).map((g) => g.interface)).size,
    };

    const perInterface: Record<
      string,
      { groups: number; activeGroups: number; rules: number; activeRules: number }
    > = {};

    for (const g of groups) {
      if (!g.interface) continue;
      if (!perInterface[g.interface]) {
        perInterface[g.interface] = { groups: 0, activeGroups: 0, rules: 0, activeRules: 0 };
      }
      perInterface[g.interface].groups++;
      if (g.enable) {
        perInterface[g.interface].activeGroups++;
        perInterface[g.interface].activeRules += g.rules?.filter((r) => r.enable).length ?? 0;
      }
      perInterface[g.interface].rules += g.rules?.length ?? 0;
    }

    return { global, perInterface };
  });

  onMount(async () => {
    await aliases.load();
    if (interfaces.full.length === 0) {
      await fetchInterfaces();
    }
    try {
      const res = await fetcher.get<{ groups: Group[] }>("/groups?with_rules=true");
      groups = res?.groups ?? [];
    } catch {
      groups = [];
    }
    refreshList();
  });

  $effect(() => {
    if (visible && !hasInitialCheck) {
      hasInitialCheck = true;
      checkExternalIPs();
    }
  });

  async function checkExternalIPs() {
    globalLoading = true;

    const activeInterfaces = interfaceList.filter(
      (i) => (i.active && i.ip) || (i.active && i.id === "blackhole") || i.id === "TPROXY",
    );
    for (const i of activeInterfaces) {
      externalIPs[i.id] = "loading";
    }

    const promises = activeInterfaces.map(async (i) => {
      try {
        const res = await fetcher.get<{ ip: string }>(`/system/interfaces/${i.id}/external-ip`);
        externalIPs[i.id] = res.ip || "error";
      } catch {
        externalIPs[i.id] = "error";
      }
    });

    try {
      await Promise.allSettled(promises);
      toast.success(t("External IPs updated"));
    } finally {
      globalLoading = false;
    }
  }

  function refreshList() {
    const systemIds = new Set(interfaces.full.map((i) => i.id));
    const aliasIds = Object.keys(aliases.all);

    const known = interfaces.full.map((item) => ({
      id: item.id,
      alias: aliases.all[item.id] ?? "",
      active: item.active,
      ip: item.ip,
    }));

    const extra = aliasIds
      .filter((id) => !systemIds.has(id))
      .sort()
      .map((id) => ({ id, alias: aliases.all[id] }));

    interfaceList = [...known, ...extra];
  }

  async function save() {
    const newAliases: Record<string, string> = {};
    for (const item of interfaceList) {
      if (item.alias.trim()) {
        newAliases[item.id] = item.alias.trim();
      }
    }
    const ok = await aliases.save(newAliases);
    if (ok) {
      toast.success(t("Aliases saved successfully"));
      hasChanges = false;
    } else {
      toast.error(t("Failed to save aliases"));
    }
  }

  function exportConfig() {
    const data = JSON.stringify(aliases.all, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "config_interfaces.mtrickle";
    a.click();
    URL.revokeObjectURL(url);
  }

  function triggerImport() {
    fileInput.click();
  }

  async function importConfig(e: Event) {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      const systemIds = new Set(interfaces.full.map((i) => i.id));
      const aliasIds = Object.keys(parsed);
      const known = interfaces.full.map((item) => ({
        id: item.id,
        alias: parsed[item.id] ?? "",
        active: item.active,
        ip: item.ip,
      }));
      const extra = aliasIds
        .filter((id) => !systemIds.has(id))
        .sort()
        .map((id) => ({ id, alias: parsed[id] }));
      interfaceList = [...known, ...extra];
      hasChanges = true;
      toast.success(t("Config imported"));
    } catch {
      toast.error(t("Invalid config file"));
    }
    (e.target as HTMLInputElement).value = "";
  }
</script>

<div class="interfaces-view">
  <div class="view-header">
    <h2>{t("Interfaces")}</h2>
    <div class="actions">
      <Tooltip value={t("Check External IPs")}>
        <Button small onclick={checkExternalIPs} disabled={globalLoading}>
          <Globe size={20} class={globalLoading ? "spin" : ""} />
        </Button>
      </Tooltip>
      <Tooltip value={t("Import Interface Config")}>
        <Button small onclick={triggerImport}>
          <Import size={20} />
        </Button>
      </Tooltip>
      <Tooltip value={t("Export Interface Config")}>
        <Button small onclick={exportConfig}>
          <Export size={20} />
        </Button>
      </Tooltip>
      {#if hasChanges}
        <Tooltip value={t("Save Changes")}>
          <Button small onclick={save}>
            <Save size={20} />
          </Button>
        </Tooltip>
      {/if}
    </div>
  </div>

  <div class="stats-header-row">
    <div class="header-left">
      <div class="stat-header-col">
        <span class="stat-label">{t("Interfaces / Used")}</span>
        <span class="stat-value">
          {interfaceList.length}
          <span class="stat-sep">/</span>
          <span class="stat-active">{stats.global.usedInterfaces}</span>
        </span>
      </div>
    </div>
    <div class="header-right">
      <div class="stat-header-col">
        <span class="stat-label">{t("Groups / Active")}</span>
        <span class="stat-value">
          {stats.global.groups}
          <span class="stat-sep">/</span>
          <span class="stat-active">{stats.global.activeGroups}</span>
        </span>
      </div>
      <div class="stat-header-col">
        <span class="stat-label">{t("Rules / Active")}</span>
        <span class="stat-value">
          {stats.global.rules}
          <span class="stat-sep">/</span>
          <span class="stat-active">{stats.global.activeRules}</span>
        </span>
      </div>
    </div>
  </div>

  <input
    type="file"
    bind:this={fileInput}
    onchange={importConfig}
    style="display: none"
    accept=".json,.mtrickle"
  />

  <div class="list">
    {#each interfaceList as item (item.id)}
      <div class="interface-row">
        <div class="interface-info-wrapper">
          <div class="status-wrapper">
            <div
              class="status-dot"
              class:active={item.active}
              title={item.active ? t("interface.active") : t("interface.inactive")}
            ></div>
          </div>

          <div class="interface-main-content">
            <div class="interface-id">{item.id === "TPROXY" ? "redir" : item.id}</div>
            <input
              type="text"
              placeholder={t("Alias (optional)")}
              bind:value={item.alias}
              oninput={() => (hasChanges = true)}
              class="alias-input"
            />

            <div class="interface-ip-group">
              {#if item.ip}
                <div class="interface-ip" title={t("interface.ip")}>{item.ip}</div>
              {:else if item.id === "blackhole"}
                <div class="interface-ip" title={t("interface.ip")}>0.0.0.0</div>
              {/if}

              {#if externalIPs[item.id] === "loading"}
                <div class="interface-external-ip loading">
                  🌐 <span class="shimmer">{t("checking...")}</span>
                </div>
              {:else if externalIPs[item.id] === "error"}
                <div
                  class="interface-external-ip error"
                  title={t("Failed to look up external IP for this interface")}
                >
                  🌐 {t("Failed to get IP")}
                </div>
              {:else if externalIPs[item.id]}
                <div class="interface-external-ip success">
                  🌐 {externalIPs[item.id]}
                </div>
              {/if}
            </div>
          </div>
        </div>

        <!-- speedtest button hidden until feature is implemented -->
        <div class="interface-actions-row" style="display: none">
          <Tooltip value={t("Speed Test")}>
            <Button small variant="ghost" disabled title={t("Speed Test")}>
              <Gauge size={18} />
            </Button>
          </Tooltip>
        </div>

        <div class="interface-stats">
          {#if stats.perInterface[item.id]}
            <div class="stat-cell" title={t("Groups bound to this interface")}>
              <span class="stat-label-mini">{t("Groups / Active")}:</span>
              <span class="stat-value-mini">
                {stats.perInterface[item.id].groups}
                <span class="stat-sep">/</span>
                <span class="stat-active">{stats.perInterface[item.id].activeGroups}</span>
              </span>
            </div>
            <div class="stat-cell" title={t("Total rules in these groups")}>
              <span class="stat-label-mini">{t("Rules / Active")}:</span>
              <span class="stat-value-mini">
                {stats.perInterface[item.id].rules}
                <span class="stat-sep">/</span>
                <span class="stat-active">{stats.perInterface[item.id].activeRules}</span>
              </span>
            </div>
          {:else}
            <span class="no-stats">{t("Unused")}</span>
          {/if}
        </div>
      </div>
    {/each}
  </div>
</div>

<style>
  .interfaces-view {
    padding: 1rem;
    max-width: 900px;
    margin: 0 auto;
    width: 100%;
  }

  .view-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .view-header h2 {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text);
  }

  .actions {
    display: flex;
    gap: 0.5rem;
  }

  .stats-header-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 1rem;
    margin-bottom: 1rem;
    gap: 1rem;
    color: var(--text-2);
  }

  .header-left {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 2rem;
    padding-left: 1rem;
  }

  .header-right {
    width: 300px;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.5rem;
    flex-shrink: 0;
    padding-left: 1rem;
  }

  .stat-header-col {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1.2;
  }

  .stat-label {
    font-weight: 500;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    opacity: 0.7;
    white-space: nowrap;
  }

  .stat-value {
    font-weight: 700;
    color: var(--text);
    font-size: 1rem;
  }

  .stat-sep {
    opacity: 0.4;
    font-weight: 400;
  }

  .stat-active {
    color: #10b981;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .interface-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    padding: 1rem;
    background-color: var(--bg-light);
    border-radius: 0.5rem;
    border: 1px solid var(--bg-light-extra);
    transition: border-color 0.2s;
  }

  .interface-row:hover {
    border-color: var(--accent);
  }

  .interface-info-wrapper {
    display: flex;
    width: 100%;
    gap: 1rem;
  }

  .status-wrapper {
    display: flex;
    align-items: center;
    width: 10px;
    justify-content: center;
  }

  .status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: var(--bg-light-extra);
    border: 1px solid var(--text-2);
    flex-shrink: 0;
  }

  .status-dot.active {
    background-color: #10b981;
    border-color: #059669;
    box-shadow: 0 0 5px rgba(16, 185, 129, 0.4);
  }

  .interface-main-content {
    display: grid;
    grid-template-columns: 150px 1fr;
    grid-template-areas:
      "id input"
      "ips input";
    align-items: center;
    gap: 0 1rem;
    flex: 1;
  }

  .interface-id {
    grid-area: id;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--accent);
    flex-shrink: 0;
  }

  .interface-ip-group {
    grid-area: ips;
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .interface-ip {
    font-size: 0.8rem;
    color: var(--text-2);
    font-family: monospace;
  }

  .interface-external-ip {
    font-size: 0.8rem;
    font-family: monospace;
    display: flex;
    align-items: center;
    gap: 0.3rem;
    padding-right: 1rem;
  }

  .interface-external-ip.success {
    color: #10b981;
  }

  .interface-external-ip.error {
    color: var(--red, #ef4444);
    font-size: 0.7rem;
  }

  .interface-external-ip.loading {
    color: var(--text-2);
  }

  .alias-input {
    grid-area: input;
    align-self: center;
    width: 100%;
    border: none;
    background-color: transparent;
    font-size: 1.3rem;
    font-weight: 600;
    font-family: var(--font);
    color: var(--text);
    border-bottom: 1px solid transparent;
    padding: 0.2rem 0.5rem;
    min-width: 0;
  }

  .alias-input:focus {
    outline: none;
    border-bottom: 1px solid var(--accent);
  }

  .alias-input::placeholder {
    font-weight: 400;
    font-size: 1rem;
    opacity: 0.5;
  }

  .interface-actions-row {
    margin-left: auto;
    padding-right: 1rem;
    flex-shrink: 0;
  }

  .interface-stats {
    display: grid;
    grid-template-columns: 1fr 1fr;
    width: 300px;
    gap: 0.5rem;
    align-items: center;
    padding: 0 0.5rem;
    border-left: 1px solid var(--bg-light-extra);
    flex-shrink: 0;
  }

  .stat-cell {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.1rem;
    background: color-mix(in oklab, var(--bg-dark) 50%, transparent);
    padding: 0.3rem 0.4rem;
    border-radius: 0.4rem;
    font-size: 0.85rem;
    border: 1px solid var(--bg-light-extra);
    white-space: nowrap;
    height: 100%;
    text-align: center;
  }

  .stat-label-mini {
    color: var(--text-2);
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-value-mini {
    font-weight: 600;
    color: var(--text);
    font-size: 0.95rem;
  }

  .no-stats {
    grid-column: 1 / -1;
    text-align: center;
    font-size: 0.85rem;
    color: var(--text-2);
    font-style: italic;
    padding: 0 0.5rem;
  }

  .shimmer {
    background: linear-gradient(90deg, var(--text-2) 25%, var(--text) 50%, var(--text-2) 75%);
    background-size: 200% 100%;
    background-clip: text;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: shimmer 1.5s infinite;
  }

  @keyframes shimmer {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
  }

  :global(.spin) {
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  @media (max-width: 950px) {
    .interfaces-view {
      padding: 0.5rem;
    }

    .stats-header-row {
      flex-direction: column;
      align-items: stretch;
      padding: 0;
      gap: 0;
    }

    .header-left,
    .header-right {
      width: 100%;
      padding: 0;
    }

    .header-right {
      display: flex;
      flex-direction: column;
    }

    .stat-header-col {
      flex-direction: row;
      justify-content: space-between;
      padding: 0.1rem 0;
    }

    .interface-row {
      flex-direction: column;
      align-items: stretch;
      position: relative;
      gap: 0.5rem;
      padding-right: 1rem;
    }

    .interface-info-wrapper {
      position: relative;
      padding-left: 1rem;
    }

    .status-wrapper {
      position: absolute;
      top: 0.25rem;
      left: 0;
      width: auto;
    }

    .interface-main-content {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      padding-right: 2.25rem;
    }

    .interface-ip-group {
      display: contents;
    }

    .interface-actions-row {
      position: absolute;
      top: 0.5rem;
      right: 0.5rem;
      padding: 0;
      margin: 0;
    }

    .alias-input {
      order: -1;
      width: 100%;
    }

    .interface-stats {
      width: 100%;
      border-left: none;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 0;
      margin-top: 0.5rem;
    }

    .stat-cell {
      flex-direction: row;
      justify-content: space-between;
      height: auto;
      text-align: left;
      padding: 0.25rem 0.5rem;
      border: none;
    }
  }
</style>
