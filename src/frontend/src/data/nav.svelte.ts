import { persistedState } from "../utils/persisted-state.svelte";

// Активная вкладка приложения. Хранится в localStorage (ключ active_tab) и
// служит единым источником истины для навигации — чтобы переключать вкладку
// можно было из любого места (например, из бейджа обновления в шапке), а не
// только кликом по самой вкладке.
const stored = persistedState<string>("active_tab", "groups");

class NavStore {
  get tab(): string {
    return stored.current;
  }
  set tab(value: string) {
    stored.current = value;
  }

  goto(tab: string) {
    stored.current = tab;
  }
}

export const nav = new NavStore();
