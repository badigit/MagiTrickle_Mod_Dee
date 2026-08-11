//go:build testing

package iptables

import (
	"context"
	"testing"
)

// convergenceFixture — цепочка MT_TEST с двумя правилами и джампом из
// PREROUTING: минимальная модель того, что демон держит для одной группы.
func convergenceFixture(t *testing.T) (*IPTables, *FakeIPTables) {
	t.Helper()

	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)

	ipt := NewIPTables(fake)
	if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}
	if err := ipt.RegisterChainOverride("mangle", "MT_TEST"); err != nil {
		t.Fatalf("RegisterChainOverride failed: %v", err)
	}
	if err := ipt.Append("mangle", "MT_TEST", "-p", "udp", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := ipt.Append("mangle", "MT_TEST", "-p", "tcp", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := ipt.Append("mangle", "PREROUTING", "!", "-i", "lo", "-j", "MT_TEST"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	return ipt, fake
}

// TestCommitIsIdempotent: повторный коммит при неизменной модели не должен
// порождать НИ ОДНОЙ команды. Это основание отказа от drop-then-stage: лишний
// проход коммиттера ничего не стоит и ничего не ломает.
func TestCommitIsIdempotent(t *testing.T) {
	ipt, fake := convergenceFixture(t)

	if err := ipt.Commit(); err != nil {
		t.Fatalf("первый Commit failed: %v", err)
	}
	callsAfterFirst := fake.RestoreCalls()

	if err := ipt.Commit(); err != nil {
		t.Fatalf("второй Commit failed: %v", err)
	}
	if got := fake.RestoreCalls(); got != callsAfterFirst {
		t.Errorf("второй Commit выполнил restore (%d -> %d), хотя модель не менялась", callsAfterFirst, got)
	}

	rules := fake.GetRules("mangle", "MT_TEST")
	if len(rules) != 2 {
		t.Errorf("правил в цепочке = %d, want 2 (дублей быть не должно): %v", len(rules), rules)
	}
	jumps := fake.GetRules("mangle", "PREROUTING")
	if len(jumps) != 1 {
		t.Errorf("джампов = %d, want 1 (дублей быть не должно): %v", len(jumps), jumps)
	}
}

// TestCommitRecoversAfterFullFlush: прошивка Keenetic переписывает таблицу
// целиком, снося наши цепочки. Повторный коммит обязан восстановить их из
// модели — без пересборки модели и без drop-then-stage.
func TestCommitRecoversAfterFullFlush(t *testing.T) {
	ipt, fake := convergenceFixture(t)

	if err := ipt.Commit(); err != nil {
		t.Fatalf("первый Commit failed: %v", err)
	}

	// прошивка стёрла всё
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	fake.DropChain("mangle", "MT_TEST")

	if err := ipt.CommitContext(context.Background()); err != nil {
		t.Fatalf("восстановительный Commit failed: %v", err)
	}

	if !fake.ChainExists("mangle", "MT_TEST") {
		t.Fatal("цепочка MT_TEST не восстановлена после полного flush")
	}
	if got := len(fake.GetRules("mangle", "MT_TEST")); got != 2 {
		t.Errorf("правил в восстановленной цепочке = %d, want 2", got)
	}
	if got := len(fake.GetRules("mangle", "PREROUTING")); got != 1 {
		t.Errorf("джампов после восстановления = %d, want 1", got)
	}
}
