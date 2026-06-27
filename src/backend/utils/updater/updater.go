//go:build linux || darwin
// +build linux darwin

package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"magitrickle/constant"

	"github.com/rs/zerolog/log"
)

const (
	// forkRepo — GitHub-репозиторий форка, откуда берутся релизы и install-скрипт.
	forkRepo = "badigit/MagiTrickle_mod_badigit"
	// forkBranch — ветка, из которой тянется install.sh.
	forkBranch = "mod_badigit"

	latestReleaseURL = "https://api.github.com/repos/" + forkRepo + "/releases/latest"
	installScriptURL = "https://raw.githubusercontent.com/" + forkRepo + "/" + forkBranch + "/scripts/install.sh"

	updateScriptPath = "/tmp/magitrickle_update.sh"
	updateLogPath    = "/tmp/magitrickle_update.log"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// updateMu защищает от параллельного запуска нескольких обновлений.
var updateMu sync.Mutex
var updateRunning bool

// currentVersion определяет текущую установленную версию: из constant.Version,
// заданной при сборке, либо через opkg как fallback.
func currentVersion() string {
	v := constant.Version
	if v == "" || v == "unattached" {
		cmd := exec.Command("sh", "-c", "opkg list-installed magitrickle 2>/dev/null | awk '{print $3}'")
		if out, err := cmd.Output(); err == nil {
			v = strings.TrimSpace(string(out))
		}
	}
	if v == "" || v == "unattached" {
		log.Warn().Msg("Could not determine current version, using 0.0.0 for comparison")
		v = "0.0.0"
	}
	return v
}

// CheckForUpdates возвращает тег новой версии, если она строго новее текущей,
// иначе — пустую строку.
func CheckForUpdates() (string, error) {
	log.Info().Msg("Checking for updates from badigit fork...")

	curr := currentVersion()
	log.Info().Str("current_version", curr).Msg("Current version")

	client := http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("User-Agent", "magitrickle-updater")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode github api response: %w", err)
	}

	latest := release.TagName
	if latest == "" {
		return "", fmt.Errorf("empty tag_name in github api response")
	}
	log.Info().Str("latest_version", latest).Msg("Found latest version")

	if compareVersions(latest, curr) > 0 {
		log.Info().Msg("Update available!")
		return latest, nil
	}

	log.Info().Msg("No updates found (already on latest version)")
	return "", nil
}

// compareVersions сравнивает две версии вида "vX.Y.Z" / "X.Y.Z".
// Возвращает >0 если a новее b, <0 если старше, 0 если равны по числовым компонентам.
// Сравнение чисто числовое по компонентам — pre-release суффиксы игнорируются,
// чего достаточно для задачи "не предлагать откат на более старый релиз".
func compareVersions(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

// parseVersion разбивает версию на числовые компоненты. Любой нечисловой
// хвост компонента (например "3-rc1") обрезается до числа.
func parseVersion(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		num := strings.Builder{}
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			num.WriteRune(r)
		}
		n, _ := strconv.Atoi(num.String())
		out = append(out, n)
	}
	return out
}

// downloadFile синхронно скачивает url в dest, перебирая доступные загрузчики
// (curl → wget → uclient-fetch), как это делает install.sh. Возвращает ошибку,
// если ни один загрузчик не найден или скачивание провалилось.
func downloadFile(url, dest string) error {
	var cmd *exec.Cmd
	switch {
	case lookPath("curl"):
		cmd = exec.Command("curl", "-Lf", "--retry", "3", "--retry-delay", "2", "-o", dest, url)
	case lookPath("wget"):
		cmd = exec.Command("wget", "-qO", dest, url)
	case lookPath("uclient-fetch"):
		cmd = exec.Command("uclient-fetch", "-qO", dest, url)
	default:
		return fmt.Errorf("no download tool found (curl, wget, uclient-fetch)")
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("download failed: %w: %s", err, strings.TrimSpace(string(out)))
	}

	fi, err := os.Stat(dest)
	if err != nil {
		return fmt.Errorf("downloaded script missing: %w", err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("downloaded script is empty")
	}
	return nil
}

func lookPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// RunUpdate скачивает install-скрипт синхронно (чтобы вернуть реальную ошибку
// при проблемах сети/отсутствии загрузчика), а затем запускает его в фоне.
// Вывод установки пишется в updateLogPath для пост-фактум диагностики.
func RunUpdate() error {
	updateMu.Lock()
	if updateRunning {
		updateMu.Unlock()
		return fmt.Errorf("update already in progress")
	}
	updateRunning = true
	updateMu.Unlock()

	// Если что-то пошло не так до старта фонового процесса — снимаем флаг,
	// чтобы пользователь мог повторить попытку.
	started := false
	defer func() {
		if !started {
			updateMu.Lock()
			updateRunning = false
			updateMu.Unlock()
		}
	}()

	log.Info().Msg("Downloading update script...")
	if err := downloadFile(installScriptURL, updateScriptPath); err != nil {
		return fmt.Errorf("failed to download update script: %w", err)
	}

	log.Info().Msg("Starting background update process...")
	// Скрипт уже скачан и проверен; выполняем его в отдельной сессии, чтобы он
	// пережил перезапуск демона. Вывод — в лог-файл, не в /dev/null.
	runScript := fmt.Sprintf(`(sh %s > %s 2>&1; rm -f %s) &`, updateScriptPath, updateLogPath, updateScriptPath)
	cmd := exec.Command("sh", "-c", runScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start background update: %w", err)
	}
	started = true

	log.Info().Str("log", updateLogPath).Msg("Background update started successfully")
	return nil
}
