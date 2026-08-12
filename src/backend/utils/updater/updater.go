//go:build linux || darwin
// +build linux darwin

package updater

import (
	"encoding/json"
	"fmt"
	"io"
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
	// install.sh тянем сначала через api.github.com (contents API, raw media
	// type) — тот же хост, что и проверка версии, — а при сбое падаем на
	// raw.githubusercontent.com. Оба у типового роутера с туннелем идут через github-
	// группу; два независимых хоста повышают шанс пережить транзиент.
	installScriptURLAPI = "https://api.github.com/repos/" + forkRepo + "/contents/scripts/install.sh?ref=" + forkBranch
	installScriptURLRaw = "https://raw.githubusercontent.com/" + forkRepo + "/" + forkBranch + "/scripts/install.sh"

	updateScriptPath = "/tmp/magitrickle_update.sh"
	updateLogPath    = "/tmp/magitrickle_update.log"

	// installTimeout ограничивает весь фоновый прогон install.sh (скачивание
	// ipk + opkg install). По истечении процесс-группа убивается и статус
	// становится failed — обновление не должно висеть вечно.
	installTimeout = 10 * time.Minute

	// downloadAttempts — попыток на каждый URL при транзиентных ошибках
	// (сеть / 5xx: GitHub периодически отдаёт 502 через туннель).
	downloadAttempts = 3
)

type githubRelease struct {
	TagName string `json:"tag_name"`
}

// Состояния обновления для UI. Терминальный success фронт не увидит от этого
// процесса: успешная установка перезапускает демона, и новый процесс стартует
// с state=idle — фронт трактует «демон вернулся с новой версией» как успех.
const (
	StateIdle    = "idle"
	StateRunning = "running"
	StateFailed  = "failed"

	StepDownloadingScript = "downloading_script"
	StepInstalling        = "installing"
)

// Status — снимок состояния обновления для GET /system/update/status.
type Status struct {
	State string `json:"state"`
	Step  string `json:"step,omitempty"`
	Error string `json:"error,omitempty"`
}

// updateMu защищает статус и от параллельного запуска нескольких обновлений.
var updateMu sync.Mutex
var updateStatus = Status{State: StateIdle}

func setStatus(s Status) {
	updateMu.Lock()
	updateStatus = s
	updateMu.Unlock()
}

// GetStatus возвращает текущий снимок состояния обновления.
func GetStatus() Status {
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateStatus
}

// ulog дописывает строку с меткой времени в лог обновления. Это единственный
// доступный на проде след: демон обычно логирует в /dev/null (init.d), поэтому
// зеркалим ключевые шаги в файл, который читается через GET /update/log и
// хвост которого кладётся в error при провале.
func ulog(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	log.Info().Str("component", "updater").Msg(line)
	f, err := os.OpenFile(updateLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	ts := time.Now().Format("15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] %s\n", ts, line)
}

// GetLog возвращает хвост лога обновления для GET /update/log.
func GetLog() string {
	return tailFile(updateLogPath, 8192)
}

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

// compareVersions сравнивает две версии вида "X.Y.Z-badigit.N", опционально с
// dev-суффиксом "~git...". Возвращает >0 если a новее b, <0 если старше, 0 если
// равны. Сначала сравниваются числовые компоненты; при их равенстве версия С
// pre-release-суффиксом ("~...") считается СТАРШЕ чистого тега того же номера
// (semver-семантика: 0.5.2-badigit.15~git... < 0.5.2-badigit.15). Это позволяет
// апдейтеру предложить чистый релиз .15 dev-сборке .15~git, но не «откатывать»
// одинаковые чистые версии.
func compareVersions(a, b string) int {
	pa, preA := parseVersion(a)
	pb, preB := parseVersion(b)
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
	// Числа равны: pre-release ниже чистого релиза того же номера.
	if preA == preB {
		return 0
	}
	if preA {
		return -1 // a — dev-сборка, b — чистый релиз
	}
	return 1
}

// parseVersion разбивает версию на числовые компоненты и признак pre-release.
// Всё после первого "~" (opkg-конвенция dev-сборок, например "~git2026...hash")
// отсекается и помечает версию как pre-release. Оставшаяся часть режется по ".",
// из каждого компонента берутся ведущие цифры ("2-badigit" -> 2, "15" -> 15).
func parseVersion(v string) (nums []int, preRelease bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '~'); i >= 0 {
		v = v[:i]
		preRelease = true
	}
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
	return out, preRelease
}

// httpGetBody делает GET с таймаутом и возвращает тело, признак «стоит
// повторить» (сеть/5xx) и ошибку. 4xx считаются постоянными (нет смысла
// повторять тот же URL), сеть и 5xx — транзиентными.
func httpGetBody(url, accept string) (body []byte, retryable bool, err error) {
	client := http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "magitrickle-updater")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, true, err // сетевые/таймаут — транзиентны
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, resp.StatusCode >= 500,
			fmt.Errorf("status %d %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, true, fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return nil, true, fmt.Errorf("empty body")
	}
	return body, false, nil
}

// downloadInstallScript тянет install.sh, перебирая источники (api.github.com,
// затем raw.githubusercontent.com) с ретраями на транзиентных ошибках. Раньше
// был один exec curl без таймаута и без ретраев: единичный 502 от GitHub через
// туннельный путь ронял всё обновление.
func downloadInstallScript(dest string) error {
	sources := []struct{ name, url, accept string }{
		{"api.github.com", installScriptURLAPI, "application/vnd.github.raw"},
		{"raw.githubusercontent.com", installScriptURLRaw, ""},
	}

	var lastErr error
	for _, s := range sources {
		for attempt := 1; attempt <= downloadAttempts; attempt++ {
			body, retryable, err := httpGetBody(s.url, s.accept)
			if err == nil {
				if werr := os.WriteFile(dest, body, 0755); werr != nil {
					return fmt.Errorf("failed to write script: %w", werr)
				}
				ulog("install.sh скачан с %s (%d байт, попытка %d)", s.name, len(body), attempt)
				return nil
			}
			lastErr = fmt.Errorf("%s: %w", s.name, err)
			ulog("скачивание с %s не удалось (попытка %d/%d): %v", s.name, attempt, downloadAttempts, err)
			if !retryable {
				break // постоянная ошибка на этом источнике — сразу к следующему
			}
			if attempt < downloadAttempts {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
		}
	}
	return fmt.Errorf("все источники недоступны: %w", lastErr)
}

// tailFile возвращает последние n байт файла (для короткой диагностики в статусе).
func tailFile(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	if fi.Size() > n {
		_, _ = f.Seek(-n, io.SeekEnd)
	}
	data, _ := io.ReadAll(f)
	return strings.TrimSpace(string(data))
}

// RunUpdate стартует обновление асинхронно и сразу возвращает управление —
// прогресс отдаётся через GetStatus (GET /system/update/status). Скачивание
// install.sh и его выполнение идут в фоне с таймаутами; успешная установка
// перезапускает демона (статус нового процесса — idle, фронт сверяет версию),
// провал переводит статус в failed с хвостом лога установки.
func RunUpdate() error {
	updateMu.Lock()
	if updateStatus.State == StateRunning {
		updateMu.Unlock()
		return fmt.Errorf("update already in progress")
	}
	updateStatus = Status{State: StateRunning, Step: StepDownloadingScript}
	updateMu.Unlock()

	go func() {
		// Свежий лог на каждый запуск — весь трейл одной попытки в одном файле.
		_ = os.WriteFile(updateLogPath, []byte(fmt.Sprintf("=== MagiTrickle update %s ===\n", currentVersion())), 0644)
		ulog("скачиваю install.sh...")

		if err := downloadInstallScript(updateScriptPath); err != nil {
			ulog("ОШИБКА скачивания: %v", err)
			setStatus(Status{State: StateFailed, Step: StepDownloadingScript, Error: err.Error()})
			return
		}

		ulog("запускаю установку...")
		setStatus(Status{State: StateRunning, Step: StepInstalling})

		// Отдельная сессия: install.sh перезапускает демона и должен пережить
		// его остановку. Вывод дописываем (>>) к трейлу скачивания.
		runScript := fmt.Sprintf(`sh %s >> %s 2>&1; rm -f %s`, updateScriptPath, updateLogPath, updateScriptPath)
		cmd := exec.Command("sh", "-c", runScript)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			ulog("не удалось запустить install.sh: %v", err)
			setStatus(Status{State: StateFailed, Step: StepInstalling, Error: err.Error()})
			return
		}

		// Ждём завершения с таймаутом. Успех обычно означает, что этот процесс
		// демона будет убит рестартом раньше, чем Wait вернётся, — до кода ниже
		// дело доходит в основном на провале установки.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				ulog("install.sh завершился с ошибкой: %v", err)
				setStatus(Status{State: StateFailed, Step: StepInstalling, Error: tailFile(updateLogPath, 1024)})
				return
			}
			// Скрипт завершился успешно, а демон всё ещё жив — считаем idle:
			// либо установка не потребовала рестарта, либо рестарт вот-вот придёт.
			ulog("install.sh завершился успешно")
			setStatus(Status{State: StateIdle})
		case <-time.After(installTimeout):
			// Убиваем всю процесс-группу (setsid: pgid == pid ребёнка).
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			ulog("установка прервана по таймауту (%s)", installTimeout)
			setStatus(Status{
				State: StateFailed,
				Step:  StepInstalling,
				Error: "install timed out after " + installTimeout.String(),
			})
		}
	}()

	log.Info().Str("log", updateLogPath).Msg("Update started in background")
	return nil
}
