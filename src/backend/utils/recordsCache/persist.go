package recordsCache

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// snapshotVersion — версия формата снапшота. Меняем при несовместимом изменении
// схемы, чтобы старый файл был отброшен, а не распарсен криво.
const snapshotVersion = 1

type snapshotAddress struct {
	Address  string `json:"a"` // IP в строковом виде
	Deadline int64  `json:"d"` // unix-секунды абсолютного дедлайна
}

type snapshotAlias struct {
	Alias    string `json:"a"`
	Deadline int64  `json:"d"`
}

// Snapshot — сериализуемый слепок кэша. Дедлайны абсолютные (unix), чтобы при
// загрузке уважать остаток TTL и отбрасывать истёкшее.
type Snapshot struct {
	Version   int                          `json:"v"`
	Addresses map[string][]snapshotAddress `json:"addresses"`
	Aliases   map[string]snapshotAlias     `json:"aliases"`
}

// Snapshot собирает полный слепок под RLock. Маршалить/писать — уже вне лока.
func (r *Records) Snapshot() Snapshot {
	r.locker.RLock()
	defer r.locker.RUnlock()

	return r.snapshotLocked(nil)
}

// SnapshotFiltered собирает слепок только тех доменов, для которых keep вернул
// true, ПЛЮС транзитивных целей их CNAME-цепочек: адреса лежат в конце цепочки,
// и без них загруженный снапшот не отдал бы по сматченному имени ни одного IP
// (автопрогрев ipset оказался бы пустым). keep == nil → полный слепок.
//
// Смысл фильтра (mt-fnj): recordsCache хранит ВСЕ резолвы LAN, а на диск нужны
// только домены, релевантные правилам — остальное переживает рестарт впустую
// (на проде это было >95% снапшота). Отфильтрованное остаётся в памяти: оно
// нужно для post-resolve subnet-правил и для CNAME-склейки.
//
// keep вызывается ВНЕ внутреннего лока — намеренно. Предикат ходит в конфиг
// (searchDomain → cfgMu), а порядок «records.RLock → cfgMu» встречно
// пересекается с ImportConfig (держит cfgMu.Lock и синхронизирует группы через
// recordsCache) — при вклинившемся писателе кэша это классический дедлок.
// Поэтому: сначала список имён (лок взят и отпущен), затем фильтрация без лока,
// затем сборка под RLock. Кэш между шагами может измениться — для снапшота,
// который и так пишется раз в несколько минут, это несущественно.
func (r *Records) SnapshotFiltered(keep func(string) bool) Snapshot {
	if keep == nil {
		return r.Snapshot()
	}

	domains := r.ListKnownDomains()
	want := make(map[string]struct{})
	for _, domain := range domains {
		if keep(domain) {
			want[domain] = struct{}{}
		}
	}

	r.locker.RLock()
	defer r.locker.RUnlock()

	// Дотягиваем цепочки CNAME вперёд: name → aliases[name].Alias → ...
	for _, domain := range domains {
		if _, ok := want[domain]; !ok {
			continue
		}
		current := domain
		for {
			alias, ok := r.aliases[current]
			if !ok {
				break
			}
			if _, seen := want[alias.Alias]; seen {
				break // уже собран (в т.ч. защита от циклов)
			}
			want[alias.Alias] = struct{}{}
			current = alias.Alias
		}
	}

	return r.snapshotLocked(want)
}

// snapshotLocked собирает слепок; want == nil означает «всё». Вызывать под RLock.
func (r *Records) snapshotLocked(want map[string]struct{}) Snapshot {
	snap := Snapshot{
		Version:   snapshotVersion,
		Addresses: make(map[string][]snapshotAddress),
		Aliases:   make(map[string]snapshotAlias),
	}
	for name, addresses := range r.addresses {
		if want != nil {
			if _, ok := want[name]; !ok {
				continue
			}
		}
		out := make([]snapshotAddress, 0, len(addresses))
		for _, addr := range addresses {
			out = append(out, snapshotAddress{
				Address:  addr.Address.String(),
				Deadline: addr.Deadline.Unix(),
			})
		}
		if len(out) > 0 {
			snap.Addresses[name] = out
		}
	}
	for name, alias := range r.aliases {
		if want != nil {
			if _, ok := want[name]; !ok {
				continue
			}
		}
		snap.Aliases[name] = snapshotAlias{
			Alias:    alias.Alias,
			Deadline: alias.Deadline.Unix(),
		}
	}
	return snap
}

// LoadSnapshot наполняет кэш из слепка, отбрасывая истёкшие записи. Существующие
// записи не трогает (мержит поверх). dirty НЕ взводит: только что загруженное с
// диска ещё не требует записи (addAddressLocked/addAliasLocked флаг не трогают).
func (r *Records) LoadSnapshot(snap Snapshot) {
	now := time.Now()

	r.locker.Lock()
	defer r.locker.Unlock()

	for name, addresses := range snap.Addresses {
		for _, sa := range addresses {
			deadline := time.Unix(sa.Deadline, 0)
			if !now.Before(deadline) {
				continue // истекло
			}
			ip := net.ParseIP(sa.Address)
			if ip == nil {
				continue
			}
			// Нормализуем в 4 байта для IPv4, чтобы совпадать с DNS-путём
			// (processARecord кладёт aRecord.A длиной 4).
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			r.addAddressLocked(name, ip, deadline)
		}
	}
	for name, sa := range snap.Aliases {
		deadline := time.Unix(sa.Deadline, 0)
		if !now.Before(deadline) {
			continue
		}
		r.addAliasLocked(name, sa.Alias, deadline)
	}
}

// Save атомарно пишет снапшот в path (tmp+rename). Пишет только при dirty:
// повторный вызов без изменений — no-op (бережём флеш). keep фильтрует, что
// попадёт на диск (см. SnapshotFiltered); nil — сохранять всё. Возвращает true,
// если запись реально произошла.
func (r *Records) Save(path string, keep func(string) bool) (bool, error) {
	if !r.dirty.Load() {
		return false, nil
	}
	// Сбрасываем dirty ДО сбора слепка: конкурентная запись между Snapshot и
	// clear снова взведёт флаг и попадёт в следующий Save (в худшем случае —
	// лишний прогон, не потеря данных).
	r.dirty.Store(false)

	snap := r.SnapshotFiltered(keep)

	// Страховка: пустой слепок при непустом кэше — почти наверняка сбой предиката
	// (например, Save вызван после teardown групп, и searchDomain уже ничего не
	// матчит — так на проде 2026-07-26 был затёрт весь накопленный прогрев).
	// Такой снапшот бесполезен, а старый файл ценен: отказываемся писать и
	// возвращаем dirty, чтобы следующий Save попробовал снова.
	if len(snap.Addresses) == 0 && len(snap.Aliases) == 0 && r.hasRecords() {
		r.dirty.Store(true)
		log.Warn().Msg("records cache snapshot came out empty while cache is not — refusing to overwrite")
		return false, nil
	}

	data, err := json.Marshal(snap)
	if err != nil {
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to marshal records snapshot: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to create snapshot dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, snapshotTmpPattern+"*.tmp")
	if err != nil {
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to create temp snapshot: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op если rename удался

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to write temp snapshot: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to sync temp snapshot: %w", err)
	}
	if err := tmp.Close(); err != nil {
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to close temp snapshot: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		r.dirty.Store(true)
		return false, fmt.Errorf("failed to rename snapshot: %w", err)
	}
	return true, nil
}

// hasRecords сообщает, есть ли в кэше хоть что-то (без учёта истечения).
func (r *Records) hasRecords() bool {
	r.locker.RLock()
	defer r.locker.RUnlock()

	return len(r.addresses) > 0 || len(r.aliases) > 0
}

// snapshotTmpPattern — префикс временных файлов Save (tmp+rename).
const snapshotTmpPattern = ".records-cache-"

// cleanupOrphanTmp удаляет временные файлы, оставшиеся от прерванной записи
// (процесс убит между CreateTemp и Rename — defer os.Remove тогда не отработал).
// Вызывается из Load, т.е. один раз за жизнь процесса. Best-effort.
func cleanupOrphanTmp(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, snapshotTmpPattern) || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			log.Debug().Err(err).Str("file", name).Msg("failed to remove orphan snapshot tmp")
		}
	}
}

// Load читает снапшот из path и наполняет кэш. Отсутствие файла — не ошибка.
func (r *Records) Load(path string) error {
	cleanupOrphanTmp(filepath.Dir(path))

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read snapshot: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}
	if snap.Version != snapshotVersion {
		log.Warn().
			Int("got", snap.Version).
			Int("want", snapshotVersion).
			Msg("records cache snapshot version mismatch, ignoring")
		return nil
	}
	r.LoadSnapshot(snap)
	return nil
}

// StartPersist запускает периодическую атомарную запись снапшота (только при
// изменениях). Интервал большой (флеш-износ). keep ограничивает состав снапшота
// (см. SnapshotFiltered); nil — сохранять всё.
//
// На ctx.Done горутина просто выходит и НЕ пишет: финальный флеш делает
// синхронный Save в defer у вызывающего (start.go). Иначе получается гонка —
// наблюдалась на проде 2026-07-26: при SIGTERM эта горутина успевала сбросить
// dirty и начать запись, синхронный defer из-за сброшенного флага пропускал
// свой Save, а процесс завершался раньше, чем горутина доходила до rename. В
// итоге снапшот не обновлялся вовсе, оставался только осиротевший .tmp.
func (r *Records) StartPersist(ctx context.Context, interval time.Duration, path string, keep func(string) bool) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if _, err := r.Save(path, keep); err != nil {
					log.Warn().Err(err).Msg("failed to persist records cache")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
