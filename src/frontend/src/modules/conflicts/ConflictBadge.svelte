<script lang="ts">
  import { getContext } from "svelte";

  import Tooltip from "../../components/ui/Tooltip.svelte";
  import { t } from "../../data/locale.svelte";
  import { CONFLICTS_STORE_CONTEXT, type ConflictsStore } from "./conflicts.svelte";
  import ConflictIcon from "./ConflictIcon.svelte";

  type Props = {
    groupIndex: number;
  };

  let { groupIndex }: Props = $props();

  const conflictsStore = getContext<ConflictsStore>(CONFLICTS_STORE_CONTEXT);

  let groupConflicts = $derived(
    conflictsStore?.conflicts.filter(
      (conflict) => conflict.groupAIndex === groupIndex || conflict.groupBIndex === groupIndex,
    ) ?? [],
  );
  let count = $derived(conflictsStore?.conflictCountByGroup.get(groupIndex) ?? 0);
  let hasConflicts = $derived(count > 0);

  function jumpToGroupConflict() {
    const first = groupConflicts[0];
    if (!first || !conflictsStore) return;

    if (first.groupAIndex === groupIndex) {
      conflictsStore.navigateToRule(first.groupAId, first.ruleAId);
      return;
    }

    conflictsStore.navigateToRule(first.groupBId, first.ruleBId);
  }
</script>

{#if hasConflicts}
  <Tooltip value={`${t("Conflicts")}: ${count}`}>
    <button type="button" class="conflict-badge" onclick={jumpToGroupConflict}>
      <ConflictIcon size={15} />
      <span class="badge-count">{count}</span>
    </button>
  </Tooltip>
{/if}

<style>
  .conflict-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.18rem;
    color: var(--yellow, #f59e0b);
    font-size: 0.82rem;
    font-weight: 700;
    cursor: pointer;
    padding: 0.1rem 0.3rem;
    border-radius: 0.35rem;
    background: color-mix(in oklab, var(--yellow, #f59e0b) 15%, transparent);
    border: 1px solid color-mix(in oklab, var(--yellow, #f59e0b) 30%, transparent);
    appearance: none;
    line-height: 1;
  }

  .conflict-badge:hover {
    background: color-mix(in oklab, var(--yellow, #f59e0b) 20%, transparent);
    border-color: color-mix(in oklab, var(--yellow, #f59e0b) 45%, transparent);
  }

  .conflict-badge:focus-visible {
    outline: 1px solid color-mix(in oklab, var(--yellow, #f59e0b) 60%, white);
    outline-offset: 1px;
  }

  .badge-count {
    line-height: 1;
  }
</style>
