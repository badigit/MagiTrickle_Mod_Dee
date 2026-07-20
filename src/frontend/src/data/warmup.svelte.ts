import { t } from "./locale.svelte";

import { toast } from "../utils/events";
import { fetcher } from "../utils/fetcher";

// Ответ POST /api/v1/warmup — см. app.WarmupResult в бэкенде.
type WarmupRes = {
  matched: number;
  queried: number;
  errors: number;
  truncated: boolean;
};

const state = $state({ busy: false, last: null as WarmupRes | null });

export const warmup = {
  get state() {
    return state;
  },

  async run(): Promise<void> {
    if (state.busy) return;
    state.busy = true;
    try {
      const res = await fetcher.post<WarmupRes>("/warmup", {});
      state.last = res;
      toast.success(`${t("Warmup complete")}: ${res.queried}/${res.matched}`);
    } catch {
      // toast уже показан фетчером
    } finally {
      state.busy = false;
    }
  },
};
