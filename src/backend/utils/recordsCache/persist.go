package recordsCache

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Snapshot собирает слепок под RLock. Маршалить/писать — уже вне лока.
func (r *Records) Snapshot() Snapshot {
	r.locker.RLock()
	defer r.locker.RUnlock()

	snap := Snapshot{
		Version:   snapshotVersion,
		Addresses: make(map[string][]snapshotAddress, len(r.addresses)),
		Aliases:   make(map[string]snapshotAlias, len(r.aliases)),
	}
	for name, addresses := range r.addresses {
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
// повторный вызов без изменений — no-op (бережём флеш). Возвращает true, если
// запись реально произошла.
func (r *Records) Save(path string) (bool, error) {
	if !r.dirty.Load() {
		return false, nil
	}
	// Сбрасываем dirty ДО сбора слепка: конкурентная запись между Snapshot и
	// clear снова взведёт флаг и попадёт в следующий Save (в худшем случае —
	// лишний прогон, не потеря данных).
	r.dirty.Store(false)

	snap := r.Snapshot()
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

	tmp, err := os.CreateTemp(dir, ".records-cache-*.tmp")
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

// Load читает снапшот из path и наполняет кэш. Отсутствие файла — не ошибка.
func (r *Records) Load(path string) error {
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
// изменениях) и финальную запись на отмену ctx. Интервал большой (флеш-износ).
func (r *Records) StartPersist(ctx context.Context, interval time.Duration, path string) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if _, err := r.Save(path); err != nil {
					log.Warn().Err(err).Msg("failed to persist records cache")
				}
			case <-ctx.Done():
				if _, err := r.Save(path); err != nil {
					log.Warn().Err(err).Msg("failed to persist records cache on shutdown")
				}
				return
			}
		}
	}()
}
