package recordsCache

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestPersistRoundtrip(t *testing.T) {
	r := New()
	r.AddAddress("example.com", []byte{1, 2, 3, 4}, 3600)
	r.AddAddress("example.com", []byte{5, 6, 7, 8}, 3600)
	r.AddAlias("cdn.example.com", "example.com", 3600)

	path := filepath.Join(t.TempDir(), "records-cache.snap")
	wrote, err := r.Save(path)
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
	wrote, err := r.Save(path)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if wrote {
		t.Error("Save wrote a file for a clean cache, expected skip")
	}

	// После изменения — пишем.
	r.AddAddress("example.com", []byte{1, 2, 3, 4}, 3600)
	wrote, err = r.Save(path)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if !wrote {
		t.Error("Save skipped a dirty cache, expected write")
	}

	// Повторный Save без изменений — снова skip.
	wrote, err = r.Save(path)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if wrote {
		t.Error("Save wrote again without changes, expected skip")
	}
}

func TestLoadMissingFileIsNotError(t *testing.T) {
	r := New()
	err := r.Load(filepath.Join(t.TempDir(), "does-not-exist.snap"))
	if err != nil {
		t.Errorf("Load of missing file must not error, got: %v", err)
	}
}
