<script lang="ts">
  import { TriangleAlert } from "../../components/ui/icons";

  type Props = {
    size?: number;
    [key: string]: any;
  };

  let { size = 16, ...rest }: Props = $props();
</script>

<span class="conflict-icon" {...rest}>
  <TriangleAlert {size} />
</span>

<style>
  .conflict-icon {
    color: var(--yellow, #f59e0b);
    display: inline-flex;
    align-items: center;
  }
</style>
