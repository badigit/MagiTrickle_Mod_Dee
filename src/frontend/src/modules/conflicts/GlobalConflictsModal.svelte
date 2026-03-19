<script lang="ts">
  import { Dialog } from "bits-ui";
  import { getContext } from "svelte";
  import { fade } from "svelte/transition";

  import { Add } from "../../components/ui/icons";
  import { t } from "../../data/locale.svelte";
  import { CONFLICTS_STORE_CONTEXT, type ConflictsStore, type ConflictPair } from "./conflicts.svelte";
  import ConflictIcon from "./ConflictIcon.svelte";

  type Props = {
    open?: boolean;
    conflicts?: ConflictPair[];
    onclose?: () => void;
  };

  let { open = false, conflicts = [], onclose }: Props = $props();

  const conflictsStore = getContext<ConflictsStore>(CONFLICTS_STORE_CONTEXT);

  function jumpTo(groupId: string, ruleId: string) {
    onclose?.();
    // small delay so modal closes before scroll
    setTimeout(() => conflictsStore?.navigateToRule(groupId, ruleId), 80);
  }
</script>

<Dialog.Root
  {open}
  onOpenChange={(v) => {
    if (!v) onclose?.();
  }}
>
  <Dialog.Overlay />
  <Dialog.Content
    class="dialog"
    data-state={open ? "open" : "closed"}
    escapeKeydownBehavior="close"
    forceMount
    onOpenAutoFocus={(e) => e.preventDefault()}
  >
    {#snippet child({ props, open: isOpen })}
      {#if isOpen}
        <div {...props} class="modal" in:fade={{ duration: 120 }} out:fade={{ duration: 120 }}>
          <Dialog.Title class="title">
            <ConflictIcon size={18} />
            {t("Subnet Conflicts")}
            <span class="count-badge">{conflicts.length}</span>
          </Dialog.Title>
          <Dialog.Close class="close">
            <Add size={22} style="transform:rotate(45deg)" />
          </Dialog.Close>

          <div class="body">
            {#if conflicts.length === 0}
              <div class="empty">{t("No subnet conflicts found")}</div>
            {:else}
              <div class="conflict-list">
                {#each conflicts as conflict, i (i)}
                  <div class="conflict-item">
                    {#if conflict.readonlyA}
                      <div class="conflict-rule readonly">
                        <span class="group-label">{conflict.groupAName || t("(unnamed group)")} <span class="sub-tag">{t("subscription")}</span></span>
                        <span class="rule-pattern"><code>{conflict.patternA}</code><span class="rule-type">{conflict.ruleAType}</span></span>
                      </div>
                    {:else}
                      <button
                        class="conflict-rule clickable"
                        onclick={() => jumpTo(conflict.groupAId, conflict.ruleAId)}
                        title={t("Jump to rule")}
                      >
                        <span class="group-label">{conflict.groupAName || t("(unnamed group)")}</span>
                        <span class="rule-pattern"><code>{conflict.patternA}</code><span class="rule-type">{conflict.ruleAType}</span></span>
                      </button>
                    {/if}

                    <div class="conflict-arrow">
                      <ConflictIcon size={14} />
                    </div>

                    {#if conflict.readonlyB}
                      <div class="conflict-rule readonly">
                        <span class="group-label">{conflict.groupBName || t("(unnamed group)")} <span class="sub-tag">{t("subscription")}</span></span>
                        <span class="rule-pattern"><code>{conflict.patternB}</code><span class="rule-type">{conflict.ruleBType}</span></span>
                      </div>
                    {:else}
                      <button
                        class="conflict-rule clickable"
                        onclick={() => jumpTo(conflict.groupBId, conflict.ruleBId)}
                        title={t("Jump to rule")}
                      >
                        <span class="group-label">{conflict.groupBName || t("(unnamed group)")}</span>
                        <span class="rule-pattern"><code>{conflict.patternB}</code><span class="rule-type">{conflict.ruleBType}</span></span>
                      </button>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          </div>
        </div>
      {/if}
    {/snippet}
  </Dialog.Content>
</Dialog.Root>

<style>
  .modal {
    max-height: calc(100vh - 6rem);
    display: flex;
    flex-direction: column;
  }

  .body {
    margin-top: 1rem;
    overflow-y: auto;
    flex: 1;
  }

  .empty {
    color: var(--text-2);
    font-size: 0.95rem;
    padding: 0.5rem 0;
  }

  .conflict-list {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .conflict-item {
    display: grid;
    grid-template-columns: 1fr auto 1fr;
    align-items: center;
    gap: 0.5rem;
    border-radius: 0.4rem;
    border: 1px solid var(--bg-light-extra);
    overflow: hidden;
    font-size: 0.88rem;
  }

  .conflict-rule {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
    min-width: 0;
    overflow: hidden;
  }

  .conflict-rule.clickable {
    padding: 0.5rem 0.6rem;
    background: var(--bg-light);
    border: none;
    text-align: left;
    cursor: pointer;
    transition: background 0.12s;
    color: inherit;
    font: inherit;
  }

  .conflict-rule.clickable:hover {
    background: var(--bg-light-extra);
  }

  .conflict-rule.readonly {
    padding: 0.5rem 0.6rem;
    background: var(--bg-light);
    opacity: 0.7;
  }

  .sub-tag {
    font-size: 0.65rem;
    color: var(--text-2);
    opacity: 0.7;
  }

  .group-label {
    color: var(--text-2);
    font-size: 0.75rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    line-height: 1.2;
  }

  .rule-pattern {
    display: flex;
    align-items: baseline;
    gap: 0.25rem;
    white-space: nowrap;
    overflow: hidden;
    font-size: 0.85rem;
    line-height: 1.3;
  }

  code {
    font-family: monospace;
    font-size: 1em;
    color: var(--accent);
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .rule-type {
    font-size: 0.7rem;
    color: var(--text-2);
    flex-shrink: 0;
    opacity: 0.7;
  }

  .conflict-arrow {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    padding: 0 0.1rem;
  }

  .title {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .count-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: color-mix(in oklab, var(--yellow, #f59e0b) 20%, transparent);
    color: var(--yellow, #f59e0b);
    border-radius: 999px;
    font-size: 0.75rem;
    font-weight: 700;
    min-width: 1.4em;
    height: 1.4em;
    padding: 0 0.3em;
    margin-left: 0.15rem;
  }

  @media (max-width: 500px) {
    .conflict-item {
      grid-template-columns: 1fr;
    }

    .conflict-arrow {
      display: none;
    }
  }
</style>
