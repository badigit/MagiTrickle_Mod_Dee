//go:build testing

package netfilterTools

import (
	"testing"

	"magitrickle/utils/iptables"
)

// TestBatchedBringUpKeepsRules воспроизводит регрессию mt-of9: bring-up под
// батчем оставлял систему БЕЗ правил MT_ (наблюдалось на проде — 0 правил в
// mangle и nat при живых ipset-сетах, весь трафик мимо прокси).
//
// Моделируется реальный путь Group.enable(): сначала ClearIfDisabled() снимает
// возможные остатки прошлого запуска, затем insertIPTablesRules() поднимает
// цепочку и джампы. Вне батча это два коммита и всё работает; здесь обе
// операции идут в один буфер.
func TestBatchedBringUpKeepsRules(t *testing.T) {
	r, fake := newTProxyTestFixture(iptables.ProtocolIPv4)
	ipt := r.nh.IPTables4

	ipt.SetDeferred(true)

	// Так делает Group.enable(): подчистить, затем поднять.
	if err := r.ClearIfDisabled(); err != nil {
		t.Fatalf("ClearIfDisabled: %v", err)
	}
	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules: %v", err)
	}

	ipt.SetDeferred(false)
	if err := ipt.Commit(); err != nil {
		t.Fatalf("финальный Commit: %v", err)
	}

	if !fake.ChainExists("nat", "MT_TEST") {
		t.Error("цепочка nat/MT_TEST отсутствует — bring-up под батчем потерял правила")
	}
	if !fake.ChainExists("mangle", "MT_TEST") {
		t.Error("цепочка mangle/MT_TEST отсутствует — bring-up под батчем потерял правила")
	}

	for _, table := range []string{"nat", "mangle"} {
		rules := fake.GetRules(table, "PREROUTING")
		found := false
		for _, rule := range rules {
			for _, arg := range rule {
				if arg == "MT_TEST" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s/PREROUTING не содержит джампа на MT_TEST: %v", table, rules)
		}
	}

	natRules := fake.GetRules("nat", "MT_TEST")
	if len(natRules) == 0 {
		t.Error("nat/MT_TEST пуста — правило REDIRECT не применилось")
	}
}

// TestBatchedBringUpMatchesUnbatched — итоговое состояние под батчем обязано
// совпадать с небатченным путём; иначе батч меняет семантику, а не только
// число обращений к ядру.
func TestBatchedBringUpMatchesUnbatched(t *testing.T) {
	// эталон: как сейчас работает прод (каждая операция со своим коммитом)
	refR, refFake := newTProxyTestFixture(iptables.ProtocolIPv4)
	if err := refR.ClearIfDisabled(); err != nil {
		t.Fatalf("ref ClearIfDisabled: %v", err)
	}
	if err := refR.insertIPTablesRules(refR.nh.IPTables4); err != nil {
		t.Fatalf("ref insert: %v", err)
	}
	if err := refR.nh.IPTables4.Commit(); err != nil {
		t.Fatalf("ref Commit: %v", err)
	}

	// батч
	batchR, batchFake := newTProxyTestFixture(iptables.ProtocolIPv4)
	bipt := batchR.nh.IPTables4
	bipt.SetDeferred(true)
	if err := batchR.ClearIfDisabled(); err != nil {
		t.Fatalf("batch ClearIfDisabled: %v", err)
	}
	if err := batchR.insertIPTablesRules(bipt); err != nil {
		t.Fatalf("batch insert: %v", err)
	}
	bipt.SetDeferred(false)
	if err := bipt.Commit(); err != nil {
		t.Fatalf("batch Commit: %v", err)
	}

	for _, tc := range []struct{ table, chain string }{
		{"nat", "MT_TEST"}, {"mangle", "MT_TEST"},
		{"nat", "PREROUTING"}, {"mangle", "PREROUTING"},
	} {
		want := refFake.GetRules(tc.table, tc.chain)
		got := batchFake.GetRules(tc.table, tc.chain)
		if len(want) != len(got) {
			t.Errorf("%s/%s: батч дал %d правил, небатченный путь — %d\nwant: %v\ngot:  %v",
				tc.table, tc.chain, len(got), len(want), want, got)
		}
	}
}
