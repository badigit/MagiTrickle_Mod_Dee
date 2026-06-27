import { fetcher } from "../utils/fetcher";
import { toast } from "../utils/events";
import { t } from "./locale.svelte";

// Интервал автоматической (silent) проверки обновлений: не чаще раза в сутки,
// чтобы не упираться в rate limit GitHub API (60 запросов/час на IP).
const SILENT_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const LAST_CHECK_KEY = "updater:lastCheck";

class UpdaterStore {
    newVersion = $state("");
    checking = $state(false);

    async check(silent = false) {
        if (this.checking) return;

        // Тихую проверку выполняем не чаще раза в сутки.
        if (silent) {
            const last = Number(localStorage.getItem(LAST_CHECK_KEY) || 0);
            if (Number.isFinite(last) && Date.now() - last < SILENT_CHECK_INTERVAL_MS) {
                return;
            }
        }

        this.checking = true;
        try {
            const res = await fetcher.get<{ available_version: string }>("/system/update/check");
            // Отметку времени ставим только при успешном ответе, чтобы при сбое
            // повторить проверку при следующем заходе.
            localStorage.setItem(LAST_CHECK_KEY, String(Date.now()));
            if (res && res.available_version) {
                this.newVersion = res.available_version;
                if (!silent) {
                    toast.success(`${t("New version available:")} ${this.newVersion}`);
                }
            } else {
                this.newVersion = "";
                if (!silent) {
                    toast.info(t("You have the latest version"));
                }
            }
        } catch (e) {
            console.error("Update check failed", e);
            if (!silent) {
                toast.error(t("Failed to check for updates"));
            }
        } finally {
            this.checking = false;
        }
    }

    async runUpdate() {
        try {
            this.checking = true;
            // Бэкенд синхронно скачивает install-скрипт и вернёт ошибку, если
            // скачать не удалось (нет сети/загрузчика) — тогда сюда прилетит throw.
            await fetcher.post("/system/update/run", {});
            toast.success(t("Update started. The service will restart shortly..."));
            setTimeout(() => {
                window.location.reload();
            }, 10000);
        } catch (e) {
            this.checking = false;
            toast.error(t("Failed to start update"));
        }
    }
}

export const updater = new UpdaterStore();
