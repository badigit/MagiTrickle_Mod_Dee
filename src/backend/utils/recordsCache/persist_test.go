package recordsCache

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistRoundtrip(t *testing.T) {
	r := New()
	r.AddAddress("example.com", []byte{1, 2, 3, 4}, 3600)
	r.AddAddress("example.com", []byte{5, 6, 7, 8}, 3600)
	r.AddAlias("cdn.example.com", "example.com", 3600)

	path := filepath.Join(t.TempDir(), "records-cache.snap")
	wrote, err := r.Save(path, nil)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if !wrote {
		t.Fatal("Save returned false, expected write (cache is dirty)")
	}

	// Загружаем в свежий кэш.
	r2 := New()
	if err := r2.Load(path); err != nil {
		t.Fatalf("Load error: %v", err)
	}

	addrs := r2.GetAddresses("example.com")
	if len(addrs) != 2 {
		t.Fatalf("addresses = %d, want 2", len(addrs))
	}

	// Алиас должен резолвиться в те же адреса.
	viaAlias := r2.GetAddresses("cdn.example.com")
	if len(viaAlias) != 2 {
		t.Fatalf("alias addresses = %d, want 2", len(viaAlias))
	}
	found := false
	for _, a := range viaAlias {
		if bytes.Equal(a.Address.To4(), []byte{1, 2, 3, 4}) {
			found = true
		}
	}
	if !found {
		t.Error("alias did not resolve to expected address")
	}
}

func TestPersistDropsExpired(t *testing.T) {
	r := New()
	r.AddAddress("live.com", []byte{1, 1, 1, 1}, 3600)
	r.AddAddress("dead.com", []byte{2, 2, 2, 2}, 1) // истечёт почти сразу

	snap := r.Snapshot()
	// Форсируем протухание dead.com: подменяем дедлайн на прошлое.
	for i := range snap.Addresses["dead.com"] {
		snap.Addresses["dead.com"][i].Deadline = 1 // 1970
	}

	r2 := New()
	r2.LoadSnapshot(snap)

	if r2.GetAddresses("dead.com") != nil {
		t.Error("expired address must be dropped on load")
	}
	if r2.GetAddresses("live.com") == nil {
		t.Error("live address must survive load")
	}
}

func TestSaveSkipsWhenNotDirty(t *testing.T) {
	r := New()
	path := filepath.Join(t.TempDir(), "records-cache.snap")

	// Свежий кэш без изменений — не пишем.
	wrote, err := r.Save(path, nil)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if wrote {
		t.Error("Save wrote a file for a clean cache, expected skip")
	}

	// После изменения — пишем.
	r.AddAddress("example.com", []byte{1, 2, 3, 4}, 3600)
	wrote, err = r.Save(path, nil)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if !wrote {
		t.Error("Save skipped a dirty cache, expected write")
	}

	// Повторный Save без изменений — снова skip.
	wrote, err = r.Save(path, nil)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if wrote {
		t.Error("Save wrote again without changes, expected skip")
	}
}

// TestSnapshotFilteredKeepsCNAMEChain — ключевой тест mt-fnj: сохраняем только
// домены, релевантные правилам, НО вместе с целями их CNAME-цепочек. Адреса
// лежат в конце цепочки: если сохранить только сматченное имя, после загрузки
// GetAddresses по нему не вернёт ни одного IP и автопрогрев ipset станет пустым.
func TestSnapshotFilteredKeepsCNAMEChain(t *testing.T) {
	r := New()
	// example.com (сматчен правилом) → CNAME cdn.example.net → адреса там.
	r.AddAlias("example.com", "cdn.example.net", 3600)
	r.AddAddress("cdn.example.net", []byte{1, 2, 3, 4}, 3600)
	// Посторонний домен с адресами — правилами не сматчен.
	r.AddAddress("ads.tracker.example", []byte{9, 9, 9, 9}, 3600)

	keep := func(domain string) bool { return domain == "example.com" }
	snap := r.SnapshotFiltered(keep)

	if _, ok := snap.Aliases["example.com"]; !ok {
		t.Error("matched domain alias must be kept")
	}
	if _, ok := snap.Addresses["cdn.example.net"]; !ok {
		t.Error("CNAME target addresses must be kept (chain would be broken otherwise)")
	}
	if _, ok := snap.Addresses["ads.tracker.example"]; ok {
		t.Error("unmatched domain must NOT be persisted")
	}

	// Загруженный снапшот обязан отдавать адреса по сматченному имени.
	r2 := New()
	r2.LoadSnapshot(snap)
	addrs := r2.GetAddresses("example.com")
	if len(addrs) != 1 {
		t.Fatalf("GetAddresses via CNAME after load = %d, want 1", len(addrs))
	}
	if !bytes.Equal(addrs[0].Address.To4(), []byte{1, 2, 3, 4}) {
		t.Errorf("wrong address after load: %v", addrs[0].Address)
	}
	if r2.GetAddresses("ads.tracker.example") != nil {
		t.Error("unmatched domain must not survive persist")
	}
}

// TestSnapshotFilteredNilKeepsAll — nil-предикат сохраняет всё (обратная
// совместимость с полным снапшотом).
func TestSnapshotFilteredNilKeepsAll(t *testing.T) {
	r := New()
	r.AddAddress("a.example", []byte{1, 1, 1, 1}, 3600)
	r.AddAddress("b.example", []byte{2, 2, 2, 2}, 3600)

	snap := r.SnapshotFiltered(nil)
	if len(snap.Addresses) != 2 {
		t.Errorf("nil keep must persist everything, got %d domains", len(snap.Addresses))
	}
}

// TestSaveFilteredShrinksFile — Save с предикатом пишет заметно меньше.
func TestSaveFilteredShrinksFile(t *testing.T) {
	r := New()
	r.AddAddress("keep.example", []byte{1, 1, 1, 1}, 3600)
	for i := 0; i < 200; i++ {
		r.AddAddress(fmt.Sprintf("junk%d.example", i), []byte{10, 0, 0, byte(i % 256)}, 3600)
	}

	dir := t.TempDir()
	fullPath := filepath.Join(dir, "full.snap")
	if _, err := r.Save(fullPath, nil); err != nil {
		t.Fatalf("Save(full) error: %v", err)
	}

	filteredPath := filepath.Join(dir, "filtered.snap")
	keep := func(domain string) bool { return domain == "keep.example" }
	// dirty сброшен предыдущим Save — трогаем кэш, чтобы вторая запись состоялась.
	r.AddAddress("keep.example", []byte{1, 1, 1, 2}, 3600)
	if _, err := r.Save(filteredPath, keep); err != nil {
		t.Fatalf("Save(filtered) error: %v", err)
	}

	full, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat full: %v", err)
	}
	filtered, err := os.Stat(filteredPath)
	if err != nil {
		t.Fatalf("stat filtered: %v", err)
	}
	if filtered.Size() >= full.Size()/10 {
		t.Errorf("filtered snapshot must be far smaller: full=%d filtered=%d", full.Size(), filtered.Size())
	}
}

// TestSaveRefusesToWipeSnapshot — страховка от «предикат внезапно отфильтровал
// всё». Реальный случай (прод, 2026-07-26): финальный Save при SIGTERM шёл ПОСЛЕ
// teardown групп, searchDomain уже ничего не матчил, и накопленный снапшот был
// перезаписан пустым (35 байт) — рестарт потерял весь прогрев. Пустой слепок при
// непустом кэше бесполезен, писать его нельзя ни при каком порядке вызовов.
func TestSaveRefusesToWipeSnapshot(t *testing.T) {
	r := New()
	r.AddAddress("example.com", []byte{1, 2, 3, 4}, 3600)

	path := filepath.Join(t.TempDir(), "records-cache.snap")
	keepAll := func(string) bool { return true }
	if _, err := r.Save(path, keepAll); err != nil {
		t.Fatalf("Save(all) error: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Предикат «всё выключено» — как после teardown групп.
	r.AddAddress("example.com", []byte{1, 2, 3, 5}, 3600) // взводим dirty
	keepNothing := func(string) bool { return false }
	wrote, err := r.Save(path, keepNothing)
	if err != nil {
		t.Fatalf("Save(nothing) error: %v", err)
	}
	if wrote {
		t.Error("Save must refuse to write an empty snapshot over a non-empty cache")
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if after.Size() != before.Size() {
		t.Errorf("existing snapshot must survive: before=%d after=%d", before.Size(), after.Size())
	}

	// Данные не потеряны: следующий Save с рабочим предикатом снова пишет.
	wrote, err = r.Save(path, keepAll)
	if err != nil {
		t.Fatalf("Save(all again) error: %v", err)
	}
	if !wrote {
		t.Error("dirty must survive a refused save, so the next one writes")
	}
}

// TestLoadCleansOrphanTmp — процесс, убитый между CreateTemp и Rename, оставляет
// .tmp-мусор (наблюдалось на проде при SIGTERM). Load должен его подобрать.
func TestLoadCleansOrphanTmp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records-cache.snap")

	orphan := filepath.Join(dir, snapshotTmpPattern+"123456.tmp")
	if err := os.WriteFile(orphan, []byte("{}"), 0600); err != nil {
		t.Fatalf("prepare orphan: %v", err)
	}
	foreign := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(foreign, []byte("app: {}"), 0600); err != nil {
		t.Fatalf("prepare foreign: %v", err)
	}

	r := New()
	if err := r.Load(path); err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Error("orphan tmp must be removed on Load")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("unrelated files must not be touched")
	}
}

func TestLoadMissingFileIsNotError(t *testing.T) {
	r := New()
	err := r.Load(filepath.Join(t.TempDir(), "does-not-exist.snap"))
	if err != nil {
		t.Errorf("Load of missing file must not error, got: %v", err)
	}
}
