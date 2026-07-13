import { fetcher } from "../utils/fetcher";
import { toast } from "../utils/events";
import { t } from "./locale.svelte";

// Интервал автоматической (silent) проверки обновлений: не чаще раза в сутки,
// чтобы не упираться в rate limit GitHub API (60 запросов/час на IP).
const SILENT_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const LAST_CHECK_KEY = "updater:lastCheck";

// Поллинг статуса фонового обновления.
const STATUS_POLL_MS = 1500;
// Сколько ждать возвращения демона после рестарта, прежде чем сдаться.
const RESTART_WAIT_MS = 120_000;

type UpdateStatus = {
    state: "idle" | "running" | "failed";
    step?: "downloading_script" | "installing";
    error?: string;
};

// Фазы UI. Бэкенд отдаёт idle/running/failed; фаза restarting — фронтовая:
// демон перестал отвечать во время установки, значит его перезапускает opkg.
export type UpdatePhase =
    | "idle"
    | "starting"
    | "downloading_script"
    | "installing"
    | "restarting"
    | "failed";

class UpdaterStore {
    newVersion = $state("");
    checking = $state(false);
    phase = $state<UpdatePhase>("idle");
    updateError = $state("");
    log = $state("");
    logLoading = $state(false);

    get updating(): boolean {
        return this.phase !== "idle" && this.phase !== "failed";
    }

    // Подтягивает хвост лога обновления для диагностики (кнопка «Показать лог»).
    async loadLog() {
        this.logLoading = true;
        try {
            const res = await fetcher.get<{ log: string }>("/system/update/log");
            this.log = res?.log || t("Log is empty");
        } catch (e) {
            this.log = `${t("Failed to load log")}: ${e}`;
        } finally {
            this.logLoading = false;
        }
    }

    phaseLabel(): string {
        switch (this.phase) {
            case "starting":
                return t("Starting update...");
            case "downloading_script":
                return t("Downloading update...");
            case "installing":
                return t("Installing update...");
            case "restarting":
                return t("Restarting service...");
            default:
                return "";
        }
    }

    async check(silent = false) {
        if (this.checking || this.updating) return;

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

    private sleep(ms: number) {
        return new Promise((r) => setTimeout(r, ms));
    }

    // Ожидание возвращения демона после рестарта: любой успешный ответ API
    // означает, что новый процесс поднялся.
    private async waitForRestart(): Promise<boolean> {
        const deadline = Date.now() + RESTART_WAIT_MS;
        while (Date.now() < deadline) {
            await this.sleep(STATUS_POLL_MS);
            try {
                await fetcher.get<UpdateStatus>("/system/update/status");
                return true;
            } catch {
                // демон ещё перезапускается
            }
        }
        return false;
    }

    async runUpdate() {
        if (this.updating) return;
        this.phase = "starting";
        this.updateError = "";

        try {
            await fetcher.post("/system/update/run", {});
        } catch (e) {
            console.error("Update start failed", e);
            this.phase = "failed";
            this.updateError = String(e);
            toast.error(t("Failed to start update"));
            return;
        }

        // Поллим статус. Исчезновение ответа на шаге installing — это рестарт
        // демона установщиком, т.е. штатная часть успешного пути.
        let sawInstalling = false;
        for (;;) {
            await this.sleep(STATUS_POLL_MS);
            let st: UpdateStatus | null = null;
            try {
                st = await fetcher.get<UpdateStatus>("/system/update/status");
            } catch {
                if (sawInstalling) {
                    // Демон ушёл в рестарт — ждём возвращения нового процесса.
                    this.phase = "restarting";
                    const back = await this.waitForRestart();
                    if (back) {
                        toast.success(t("Update installed. Reloading..."));
                        await this.sleep(1000);
                        window.location.reload();
                    } else {
                        this.phase = "failed";
                        this.updateError = t("Service did not come back after update");
                        toast.error(this.updateError);
                    }
                    return;
                }
                // Сетевой сбой до стадии установки — продолжаем поллинг.
                continue;
            }

            switch (st.state) {
                case "running":
                    if (st.step === "installing") {
                        sawInstalling = true;
                        this.phase = "installing";
                    } else {
                        this.phase = "downloading_script";
                    }
                    break;
                case "failed":
                    this.phase = "failed";
                    this.updateError = st.error || t("Update failed");
                    toast.error(`${t("Update failed")}: ${this.updateError}`);
                    return;
                case "idle":
                    // Установщик отработал без рестарта демона (или рестарт ещё
                    // не долетел). После стадии installing считаем успехом.
                    if (sawInstalling) {
                        toast.success(t("Update installed. Reloading..."));
                        await this.sleep(1000);
                        window.location.reload();
                        return;
                    }
                    break;
            }
        }
    }
}

export const updater = new UpdaterStore();
