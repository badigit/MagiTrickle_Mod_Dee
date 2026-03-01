<script lang="ts">
  import { getContext } from "svelte";

  import Button from "../../components/ui/Button.svelte";
  import Tooltip from "../../components/ui/Tooltip.svelte";
  import { t } from "../../data/locale.svelte";
  import { CONFLICTS_STORE_CONTEXT, type ConflictsStore } from "./conflicts.svelte";
  import ConflictIcon from "./ConflictIcon.svelte";
  import GlobalConflictsModal from "./GlobalConflictsModal.svelte";

  const conflictsStore = getContext<ConflictsStore>(CONFLICTS_STORE_CONTEXT);

  let modalOpen = $state(false);
</script>

{#if conflictsStore?.hasConflicts}
  <Tooltip value={t("Show Subnet Conflicts")}>
    <Button onclick={() => (modalOpen = true)} class="conflict-toolbar-btn">
      <ConflictIcon size={22} />
      <span class="toolbar-count">{conflictsStore.count}</span>
    </Button>
  </Tooltip>
{/if}

<GlobalConflictsModal
  open={modalOpen}
  conflicts={conflictsStore?.conflicts ?? []}
  onclose={() => (modalOpen = false)}
/>

<style>
  .toolbar-count {
    font-size: 0.8rem;
    font-weight: 700;
    color: var(--yellow, #f59e0b);
    margin-left: 0.1rem;
  }
</style>
