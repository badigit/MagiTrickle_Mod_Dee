//go:build testing

package iptables

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestExecTimeoutKillsHungCommand — главный сценарий mt-7sa: iptables-save или
// iptables-restore залип (на роутере типичная причина — чужой xtables.lock,
// который держит ndm). Без таймаута вызов не возвращается никогда: ретраи
// mt-pfo не спасают, потому что они срабатывают на ОШИБКУ, а зависание ошибки
// не даёт.
//
// Возврат за время порядка таймаута доказывает и то, что процесс убит:
// cmd.Run() ждёт завершения процесса, поэтому вернуться раньше он не может.
func TestExecTimeoutKillsHungCommand(t *testing.T) {
	withShortExecTimeout(t, 200*time.Millisecond)

	ipt := &realIPTables{
		saveCmd:  "sleep",
		saveArgs: []string{"30"},
		proto:    ProtocolIPv4,
	}

	start := time.Now()
	_, err := ipt.Save(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Save must fail when the command hangs past the timeout")
	}
	if !errors.Is(err, ErrExecTimeout) {
		t.Errorf("want ErrExecTimeout, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Save waited %v — the hung process was not killed", elapsed)
	}
}

// TestExecRestoreTimeout — то же для Restore: именно он пишет правила, и именно
// его зависание оставит роутер без маршрутизации.
func TestExecRestoreTimeout(t *testing.T) {
	withShortExecTimeout(t, 200*time.Millisecond)

	ipt := &realIPTables{
		restoreCmd:  "sleep",
		restoreArgs: []string{"30"},
		proto:       ProtocolIPv4,
	}

	start := time.Now()
	err := ipt.Restore(context.Background(), []byte("*mangle\nCOMMIT\n"))
	elapsed := time.Since(start)

	if !errors.Is(err, ErrExecTimeout) {
		t.Fatalf("want ErrExecTimeout, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Restore waited %v — the hung process was not killed", elapsed)
	}
}

// TestExecHonoursExternalCancel: внешняя отмена прекращает вызов, не дожидаясь
// собственного таймаута. Нужно для mt-yvf, где проход прерывается приходом
// нового события netfilter.d.
func TestExecHonoursExternalCancel(t *testing.T) {
	withShortExecTimeout(t, time.Hour)

	ipt := &realIPTables{
		saveCmd:  "sleep",
		saveArgs: []string{"30"},
		proto:    ProtocolIPv4,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := ipt.Save(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Save must fail when the caller cancels")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Save waited %v — external cancellation ignored", elapsed)
	}
}

// TestExecTimeoutIsRetryable: залипание из-за чужого xtables.lock — это та же
// проигранная гонка с ndm, её надо повторять, а не считать фатальной.
func TestExecTimeoutIsRetryable(t *testing.T) {
	err := wrapExecTimeout(context.DeadlineExceeded, "iptables-restore")
	if !IsRetryableError(err) {
		t.Errorf("exec timeout must be retryable, got IsRetryableError=false for %v", err)
	}
	if !IsRacedError(errors.New("iptables-restore: line 2 failed")) {
		t.Error("raced error classification regressed")
	}
	if IsRetryableError(errors.New("Permission denied (you must be root)")) {
		t.Error("a genuine error must not be retryable")
	}
}

// TestCommitContextAbortsHungRestore: залипший Restore не держит CommitContext
// дольше, чем разрешает вызывающий. Собственный потолок execTimeout живёт в
// realIPTables и на fake не распространяется — здесь проверяется именно
// проброс внешнего контекста до самой команды, без которого worker коммиттера
// (mt-yvf) нельзя было бы прервать.
func TestCommitContextAbortsHungRestore(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	fake.BlockRestore(30 * time.Second)

	ipt := NewIPTables(fake)
	if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}
	if err := ipt.Append("mangle", "PREROUTING", "-i", "eth0", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- ipt.CommitContext(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("CommitContext must report an error when Restore hangs")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("CommitContext returned after %v — context was not propagated to Restore", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CommitContext hung on a stuck Restore — context is not propagated")
	}
}

// TestCommitMuSerialisesCommits: два одновременных коммита не должны
// пересекаться внутри одного объекта IPTables. Одного -race мало — он не
// докажет, что не пересеклись вызовы внешней команды, поэтому считаем
// одновременные Restore напрямую.
func TestCommitMuSerialisesCommits(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	fake.BlockRestore(150 * time.Millisecond)

	ipt := NewIPTables(fake)
	if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}
	if err := ipt.Append("mangle", "PREROUTING", "-i", "eth0", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	// Оба Restore должны реально произойти. Без ошибок второй коммит увидел бы
	// уже применённое правило, вычислил пустую дельту и до Restore не дошёл —
	// тогда тест ничего бы не проверял.
	raced := errors.New("iptables-restore failed: exit status 1: iptables-restore: line 2 failed")
	fake.FailRestore(raced, raced)

	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_ = ipt.Commit()
			done <- struct{}{}
		}()
	}
	<-done
	<-done

	if peak := fake.PeakConcurrentRestores(); peak > 1 {
		t.Errorf("%d Restore calls overlapped — commitMu does not serialise commits", peak)
	}
	if calls := fake.RestoreCalls(); calls < 2 {
		t.Fatalf("Restore called %d times, want 2 — the test did not exercise both commits", calls)
	}
}

func withShortExecTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	saved := execTimeout
	execTimeout = d
	t.Cleanup(func() { execTimeout = saved })
}
