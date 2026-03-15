<script lang="ts">
  import { Dialog } from "bits-ui";
  import { fade } from "svelte/transition";

  import Button from "../../../components/ui/Button.svelte";
  import { Add, Copy, Radio, Square } from "../../../components/ui/icons";
  import { t } from "../../../data/locale.svelte";
  import { fetcher } from "../../../utils/fetcher";
  import { toast } from "../../../utils/events";

  type CapturedDomain = {
    domain: string;
    count: number;
  };

  type CaptureStatus = {
    active: boolean;
    started_at?: string;
    count: number;
    domains?: CapturedDomain[];
  };

  type Props = {
    open: boolean;
    onclose: () => void;
    onadddomains?: (domains: string[]) => void;
  };

  let { open = $bindable(), onclose, onadddomains }: Props = $props();

  let active = $state(false);
  let domains = $state<CapturedDomain[]>([]);
  let liveCount = $state(0);
  let pollTimer = $state<ReturnType<typeof setInterval> | null>(null);
  let selectedDomains = $state<Set<string>>(new Set());

  async function fetchStatus(withDomains: boolean) {
    try {
      const status = await fetcher.get<CaptureStatus>(
        `/system/dns-capture/status?domains=${withDomains}`,
      );
      active = status.active;
      liveCount = status.count;
      if (withDomains && status.domains) {
        domains = status.domains;
      }
    } catch {
      // ignore
    }
  }

  async function startCapture() {
    try {
      const status = await fetcher.post<CaptureStatus>("/system/dns-capture/start", {});
      active = status.active;
      liveCount = 0;
      domains = [];
      selectedDomains = new Set();
      startPolling();
    } catch {
      toast.error(t("Request failed"));
    }
  }

  async function stopCapture() {
    stopPolling();
    try {
      const status = await fetcher.post<CaptureStatus>("/system/dns-capture/stop", {});
      active = status.active;
      liveCount = status.count;
      if (status.domains) {
        domains = status.domains;
      }
    } catch {
      toast.error(t("Request failed"));
    }
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(() => fetchStatus(false), 2000);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function toggleDomain(domain: string) {
    const next = new Set(selectedDomains);
    if (next.has(domain)) {
      next.delete(domain);
    } else {
      next.add(domain);
    }
    selectedDomains = next;
  }

  function selectAll() {
    selectedDomains = new Set(domains.map((d) => d.domain));
  }

  function selectNone() {
    selectedDomains = new Set();
  }

  async function copySelected() {
    const text = [...selectedDomains].join("\n");
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast.success(t("Entries copied"));
    } catch {
      toast.error(t("Failed to copy entries"));
    }
  }

  function addSelected() {
    if (selectedDomains.size === 0) return;
    onadddomains?.([...selectedDomains]);
  }

  function handleOpenChange(v: boolean) {
    if (!v) {
      stopPolling();
      onclose();
    }
  }

  $effect(() => {
    if (open) {
      fetchStatus(true).then(() => {
        if (active) startPolling();
      });
    } else {
      stopPolling();
    }
  });
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange}>
  <Dialog.Overlay />
  <Dialog.Content
    class="dialog"
    data-state={open ? "open" : "closed"}
    escapeKeydownBehavior="close"
    forceMount
    onOpenAutoFocus={(e) => e.preventDefault()}
    style="--generic-dialog-max-width: 500px"
  >
    {#snippet child({ props, open: isOpen })}
      {#if isOpen}
        <div {...props} class="modal" in:fade={{ duration: 120 }} out:fade={{ duration: 120 }}>
          <Dialog.Title class="title">{t("DNS Capture")}</Dialog.Title>
          <Dialog.Close class="close">
            <Add size={22} style="transform:rotate(45deg)" />
          </Dialog.Close>

          <div class="capture-body">
            <div class="capture-controls">
              {#if !active}
                <Button class="accent" onclick={startCapture}>
                  <Radio size={16} />
                  {t("Start Capture")}
                </Button>
              {:else}
                <Button class="danger" onclick={stopCapture}>
                  <Square size={16} />
                  {t("Stop Capture")}
                </Button>
                <span class="live-count">
                  {t("Captured")}: {liveCount}
                </span>
              {/if}
            </div>

            {#if domains.length > 0}
              <div class="domain-actions">
                <button class="link-btn" onclick={selectAll}>{t("All")}</button>
                <button class="link-btn" onclick={selectNone}>{t("Reset")}</button>
                <span class="domain-count">
                  {selectedDomains.size} / {domains.length}
                </span>
                <button
                  class="link-btn"
                  onclick={copySelected}
                  disabled={selectedDomains.size === 0}
                >
                  <Copy size={14} />
                  {t("Copy")}
                </button>
              </div>

              <div class="domain-list">
                {#each domains as { domain, count }}
                  <label class="domain-row" class:selected={selectedDomains.has(domain)}>
                    <input
                      type="checkbox"
                      checked={selectedDomains.has(domain)}
                      onchange={() => toggleDomain(domain)}
                    />
                    <span class="domain-name">{domain}</span>
                    <span class="domain-count-badge">{count}</span>
                  </label>
                {/each}
              </div>
            {:else if !active}
              <p class="hint">{t("DNS Capture Hint")}</p>
            {/if}
          </div>
        </div>
      {/if}
    {/snippet}
  </Dialog.Content>
</Dialog.Root>

<style>
  .capture-body {
    margin-top: 1rem;
  }

  .capture-controls {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .capture-controls :global(button) {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
  }

  .live-count {
    color: var(--text-2);
    font-size: 0.9rem;
  }

  .domain-actions {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.75rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }

  .link-btn {
    background: none;
    border: none;
    color: var(--blue-light-extra);
    cursor: pointer;
    font-size: 0.85rem;
    padding: 0.15rem 0.3rem;
    border-radius: 0.25rem;
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
  }

  .link-btn:hover {
    background: var(--bg-light);
  }

  .link-btn:disabled {
    opacity: 0.4;
    cursor: default;
  }

  .domain-count {
    color: var(--text-2);
    font-size: 0.85rem;
    margin-left: auto;
  }

  .domain-list {
    max-height: 50vh;
    overflow-y: auto;
    margin-top: 0.5rem;
    display: flex;
    flex-direction: column;
  }

  .domain-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.5rem;
    border-radius: 0.3rem;
    cursor: pointer;
    font-size: 0.9rem;
  }

  .domain-row:hover {
    background: var(--bg-light);
  }

  .domain-row.selected {
    background: color-mix(in oklab, var(--accent) 12%, transparent);
  }

  .domain-row input[type="checkbox"] {
    flex-shrink: 0;
  }

  .domain-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .domain-count-badge {
    flex-shrink: 0;
    color: var(--text-2);
    font-size: 0.8rem;
    background: var(--bg-light);
    padding: 0.1rem 0.4rem;
    border-radius: 0.25rem;
  }

  .hint {
    color: var(--text-2);
    font-size: 0.9rem;
    margin-top: 0.75rem;
  }
</style>
