//go:build testing

package iptables

import (
	"context"
	"sync/atomic"
	"testing"
)

// countingExecutable считает обращения к ядру. Save — это `iptables-save`,
// Restore — `iptables-restore`; именно они стоят десятки миллисекунд на роутере
// и определяют цену Commit().
type countingExecutable struct {
	inner    Executable
	saves    atomic.Int32
	restores atomic.Int32
}

func (c *countingExecutable) Save(ctx context.Context) ([]byte, error) {
	c.saves.Add(1)
	return c.inner.Save(ctx)
}

func (c *countingExecutable) Restore(ctx context.Context, data []byte) error {
	c.restores.Add(1)
	return c.inner.Restore(ctx, data)
}

func (c *countingExecutable) Proto() Protocol { return c.inner.Proto() }

func newCountingIPTables() (*IPTables, *countingExecutable) {
	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	counter := &countingExecutable{inner: fake}
	ipt := NewIPTables(counter)
	ipt.RegisterChainPatch("mangle", "PREROUTING")
	return ipt, counter
}

// simulateGroupTeardown повторяет то, что делает одна группа при Disable:
// снять свою цепочку и джамп на неё, затем закоммитить.
func simulateGroupTeardown(t *testing.T, ipt *IPTables, chain string) {
	t.Helper()
	if err := ipt.RegisterChainDelete("mangle", chain); err != nil {
		t.Fatalf("RegisterChainDelete: %v", err)
	}
	if err := ipt.Delete("mangle", "PREROUTING", "-j", chain); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := ipt.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// TestCommitPerGroupCostsOneSaveEach фиксирует ТЕКУЩЕЕ (дорогое) поведение:
// каждый Commit — отдельная пара save/restore. На проде это давало 76 обращений
// к ядру за teardown 38 групп (mt-jou).
func TestCommitPerGroupCostsOneSaveEach(t *testing.T) {
	ipt, counter := newCountingIPTables()

	for _, chain := range []string{"MT_a", "MT_b", "MT_c", "MT_d"} {
		simulateGroupTeardown(t, ipt, chain)
	}

	if got := counter.saves.Load(); got != 4 {
		t.Errorf("saves = %d, want 4 (по одному на группу — базовое поведение)", got)
	}
}

// TestDeferredCollapsesCommits — суть фикса mt-jou: под Deferred промежуточные
// Commit() не ходят в ядро, правила копятся в буфере, а реальное применение
// происходит один раз. Время teardown перестаёт линейно расти по числу групп.
func TestDeferredCollapsesCommits(t *testing.T) {
	ipt, counter := newCountingIPTables()

	// Сначала поднимаем цепочки как при enable — иначе удалять нечего и
	// финальный коммит не дойдёт до Restore (дельта пустая).
	for _, chain := range []string{"MT_a", "MT_b", "MT_c", "MT_d"} {
		if err := ipt.RegisterChainOverride("mangle", chain); err != nil {
			t.Fatalf("RegisterChainOverride: %v", err)
		}
		if err := ipt.Append("mangle", "PREROUTING", "-j", chain); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := ipt.Commit(); err != nil {
		t.Fatalf("Commit (setup): %v", err)
	}
	counter.saves.Store(0)
	counter.restores.Store(0)

	ipt.SetDeferred(true)
	for _, chain := range []string{"MT_a", "MT_b", "MT_c", "MT_d"} {
		simulateGroupTeardown(t, ipt, chain)
	}
	if got := counter.saves.Load(); got != 0 {
		t.Errorf("saves во время батча = %d, want 0 (коммиты должны копиться)", got)
	}

	ipt.SetDeferred(false)
	if err := ipt.Commit(); err != nil {
		t.Fatalf("финальный Commit: %v", err)
	}

	if got := counter.saves.Load(); got != 1 {
		t.Errorf("saves после батча = %d, want 1 (одно обращение к ядру на всё)", got)
	}
	if got := counter.restores.Load(); got != 1 {
		t.Errorf("restores = %d, want 1", got)
	}
}

// TestDeferredAppliesAllAccumulatedRules — батч не должен терять правила:
// финальный коммит обязан применить всё, что накопилось.
func TestDeferredAppliesAllAccumulatedRules(t *testing.T) {
	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt := NewIPTables(fake)
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	ipt.SetDeferred(true)
	for _, chain := range []string{"MT_x", "MT_y"} {
		if err := ipt.RegisterChainOverride("mangle", chain); err != nil {
			t.Fatalf("RegisterChainOverride: %v", err)
		}
		if err := ipt.Append("mangle", chain, "-j", "ACCEPT"); err != nil {
			t.Fatalf("Append: %v", err)
		}
		if err := ipt.Commit(); err != nil { // no-op под Deferred
			t.Fatalf("Commit: %v", err)
		}
	}
	ipt.SetDeferred(false)
	if err := ipt.Commit(); err != nil {
		t.Fatalf("финальный Commit: %v", err)
	}

	for _, chain := range []string{"MT_x", "MT_y"} {
		if !fake.ChainExists("mangle", chain) {
			t.Errorf("цепочка %s не применена — батч потерял правила", chain)
		}
	}
}

// TestDeferredIsIdempotent — повторные SetDeferred(false) и Commit без изменений
// не должны падать (teardown вызывается на нескольких путях, включая defer).
func TestDeferredIsIdempotent(t *testing.T) {
	ipt, _ := newCountingIPTables()

	ipt.SetDeferred(false)
	ipt.SetDeferred(true)
	ipt.SetDeferred(true)
	ipt.SetDeferred(false)
	ipt.SetDeferred(false)

	if err := ipt.Commit(); err != nil {
		t.Fatalf("Commit после повторных переключений: %v", err)
	}
}
