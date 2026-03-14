<script lang="ts">
  import { Popover } from "bits-ui";
  import { getContext } from "svelte";

  import { Delete } from "../../components/ui/icons";
  import { t } from "../../data/locale.svelte";
  import { GROUPS_STORE_CONTEXT, type GroupsStore } from "../groups/groups.svelte";
  import { CONFLICTS_STORE_CONTEXT, type ConflictsStore, type ConflictPair } from "./conflicts.svelte";
  import ConflictIcon from "./ConflictIcon.svelte";

  type Props = {
    ruleId: string;
    groupIndex: number;
    ruleIndex: number;
  };

  let { ruleId, groupIndex, ruleIndex }: Props = $props();

  const conflictsStore = getContext<ConflictsStore>(CONFLICTS_STORE_CONTEXT);
  const groupsStore = getContext<GroupsStore>(GROUPS_STORE_CONTEXT);

  let myConflicts = $derived(conflictsStore?.conflictsByRuleId.get(ruleId) ?? []);
  let hasConflicts = $derived(myConflicts.length > 0);

  let open = $state(false);

  function getOther(pair: ConflictPair) {
    if (pair.ruleAId === ruleId) {
      return { groupId: pair.groupBId, groupIndex: pair.groupBIndex, ruleId: pair.ruleBId, name: pair.ruleBName, groupName: pair.groupBName, pattern: pair.patternB, ruleType: pair.ruleBType, readonly: pair.readonlyB };
    }
    return { groupId: pair.groupAId, groupIndex: pair.groupAIndex, ruleId: pair.ruleAId, name: pair.ruleAName, groupName: pair.groupAName, pattern: pair.patternA, ruleType: pair.ruleAType, readonly: pair.readonlyA };
  }

  function jumpTo(pair: ConflictPair) {
    const other = getOther(pair);
    open = false;
    conflictsStore.navigateToRule(other.groupId, other.ruleId);
  }

  function deleteOther(pair: ConflictPair) {
    const other = getOther(pair);
    // Find current index by ID to avoid using stale index from conflict pair
    const group = groupsStore.data[other.groupIndex];
    if (!group) return;
    const currentIndex = group.rules.findIndex((r) => r.id === other.ruleId);
    if (currentIndex === -1) return;
    open = false;
    groupsStore.deleteRuleFromGroup(other.groupIndex, currentIndex);
  }
</script>

{#if hasConflicts}
  <Popover.Root bind:open>
    <Popover.Trigger
      class="conflict-trigger"
      title={`${t("Subnet conflicts")}: ${myConflicts.length}`}
    >
      <ConflictIcon size={16} />
      {#if myConflicts.length > 1}
        <span class="trigger-count">{myConflicts.length}</span>
      {/if}
    </Popover.Trigger>

    <Popover.Content class="conflict-popover" sideOffset={6} align="end">
      <div class="popover-inner">
        <div class="popover-header">
          <ConflictIcon size={14} />
          {t("Conflicting subnets")}
        </div>

        <div class="conflict-list">
          {#each myConflicts as pair (pair.ruleAId + pair.ruleBId)}
            {@const other = getOther(pair)}
            <div class="conflict-row">
              <div class="conflict-info">
                <span class="other-group">{other.groupName || t("(unnamed group)")}</span>
                <span class="other-rule">{other.name || t("(unnamed rule)")} — <code>{other.pattern}</code> <span class="other-type">{other.ruleType}</span></span>
              </div>
              <div class="conflict-row-actions">
                {#if !other.readonly}
                  <button class="action-btn jump" onclick={() => jumpTo(pair)} title={t("Jump to conflicting rule")}>
                    ↗
                  </button>
                  <button class="action-btn del" onclick={() => deleteOther(pair)} title={t("Delete conflicting rule")}>
                    <Delete size={13} />
                  </button>
                {:else}
                  <span class="readonly-badge">{t("subscription")}</span>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      </div>
    </Popover.Content>
  </Popover.Root>
{/if}

<style>
  :global(.conflict-trigger) {
    display: inline-flex;
    align-items: center;
    gap: 0.15rem;
    color: var(--yellow, #f59e0b);
    background: color-mix(in oklab, var(--yellow, #f59e0b) 12%, transparent);
    border: 1px solid color-mix(in oklab, var(--yellow, #f59e0b) 28%, transparent);
    border-radius: 0.35rem;
    padding: 0.2rem 0.3rem;
    cursor: pointer;
    font-size: 0.75rem;
    font-weight: 700;
    line-height: 1;
    transition: background 0.12s;
  }

  :global(.conflict-trigger:hover) {
    background: color-mix(in oklab, var(--yellow, #f59e0b) 22%, transparent);
  }

  .trigger-count {
    font-size: 0.7rem;
    font-weight: 700;
  }

  :global(.conflict-popover) {
    z-index: 50;
    background: var(--bg-dark);
    border: 1px solid var(--bg-light-extra);
    border-radius: 0.5rem;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    min-width: 240px;
    max-width: 320px;
  }

  .popover-inner {
    padding: 0.65rem 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .popover-header {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--yellow, #f59e0b);
    padding-bottom: 0.4rem;
    border-bottom: 1px solid var(--bg-light-extra);
  }

  .conflict-list {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .conflict-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    padding: 0.3rem 0.4rem;
    border-radius: 0.35rem;
    background: var(--bg-light);
    border: 1px solid var(--bg-light-extra);
  }

  .conflict-info {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    min-width: 0;
    overflow: hidden;
    flex: 1;
  }

  .other-group {
    font-size: 0.72rem;
    color: var(--text-2);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .other-rule {
    font-size: 0.82rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  code {
    font-family: monospace;
    font-size: 0.82em;
    color: var(--accent);
  }

  .other-type {
    font-size: 0.72rem;
    color: var(--text-2);
    opacity: 0.75;
  }

  .conflict-row-actions {
    display: flex;
    align-items: center;
    gap: 0.2rem;
    flex-shrink: 0;
  }

  .action-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 1px solid transparent;
    border-radius: 0.3rem;
    background: transparent;
    cursor: pointer;
    padding: 0.25rem 0.3rem;
    font-size: 0.8rem;
    line-height: 1;
    transition: background 0.1s;
  }

  .action-btn.jump {
    color: var(--accent);
    font-size: 1rem;
  }

  .action-btn.jump:hover {
    background: color-mix(in oklab, var(--accent) 15%, transparent);
    border-color: color-mix(in oklab, var(--accent) 30%, transparent);
  }

  .action-btn.del {
    color: var(--red, #ef4444);
  }

  .action-btn.del:hover {
    background: color-mix(in oklab, var(--red, #ef4444) 15%, transparent);
    border-color: color-mix(in oklab, var(--red, #ef4444) 30%, transparent);
  }

  .readonly-badge {
    font-size: 0.65rem;
    color: var(--text-2);
    opacity: 0.7;
    white-space: nowrap;
  }
</style>
