import { fetcher } from "../utils/fetcher";

type EnabledRes = { enabled: boolean };

const state = $state({ enabled: true, loaded: false, busy: false });

export const routing = {
  get state() {
    return state;
  },

  async load() {
    try {
      const res = await fetcher.get<EnabledRes>("/system/enabled");
      state.enabled = res.enabled;
      state.loaded = true;
    } catch {
      // toast уже показан фетчером
    }
  },

  async setEnabled(enabled: boolean): Promise<boolean> {
    if (state.busy) return state.enabled;
    state.busy = true;
    try {
      const res = await fetcher.post<EnabledRes>("/system/enabled", { enabled });
      state.enabled = res.enabled;
      return res.enabled;
    } catch {
      // откатить визуально на серверное состояние
      try {
        await routing.load();
      } catch {}
      return state.enabled;
    } finally {
      state.busy = false;
    }
  },
};
