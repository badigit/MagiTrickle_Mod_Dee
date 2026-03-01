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

  let count = $derived(conflictsStore?.conflictCountByGroup.get(groupIndex) ?? 0);
  let hasConflicts = $derived(count > 0);
</script>

{#if hasConflicts}
  <Tooltip value={`${t("Subnet conflicts")}: ${count}`}>
    <span class="conflict-badge">
      <ConflictIcon size={15} />
      <span class="badge-count">{count}</span>
    </span>
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
    cursor: default;
    padding: 0.1rem 0.3rem;
    border-radius: 0.35rem;
    background: color-mix(in oklab, var(--yellow, #f59e0b) 15%, transparent);
    border: 1px solid color-mix(in oklab, var(--yellow, #f59e0b) 30%, transparent);
  }

  .badge-count {
    line-height: 1;
  }
</style>
