//go:build testing

package netfilterTools

import (
	"reflect"
	"testing"

	"magitrickle/utils/iptables"
)

// newDirectPriorityFixture — direct-группа поверх PREROUTING, где уже висит
// цепочка другой (ранее поднятой) группы. Порядок jump-правил в PREROUTING и
// есть предмет проверки: он решает, кто выигрывает overlap по IP.
func newDirectPriorityFixture(byOrder bool) (*IPSetToLink, *iptables.FakeIPTables, *iptables.IPTables) {
	fake := iptables.NewFakeIPTables(iptables.ProtocolIPv4)
	ipt := iptables.NewIPTables(fake)

	existing := [][]string{{"!", "-i", "lo", "-j", "MT_OTHER"}}
	fake.SetInitialRules("nat", "PREROUTING", existing)
	fake.SetInitialRules("mangle", "PREROUTING", existing)
	ipt.RegisterChainPatch("nat", "PREROUTING")
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	r := &IPSetToLink{
		chainName: "MT_DIRECT",
		ifaceName: Direct,
		ipset:     &IPSet{ipsetName: "mt_direct"},
		nh:        &Helper{IPTables4: ipt, DirectPriorityByOrder: byOrder},
	}
	return r, fake, ipt
}

// TestDirectPriorityAbsolute — дефолт (mt-n4b): direct перебивает всех. Его
// цепочка встаёт ПЕРВОЙ в PREROUTING, поэтому ACCEPT внутри неё срабатывает
// раньше, чем TPROXY/MARK любой другой группы, независимо от места группы в UI.
func TestDirectPriorityAbsolute(t *testing.T) {
	r, fake, ipt := newDirectPriorityFixture(false)

	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	want := [][]string{
		{"!", "-i", "lo", "-j", "MT_DIRECT"},
		{"!", "-i", "lo", "-j", "MT_OTHER"},
	}
	for _, table := range []string{"mangle", "nat"} {
		got := fake.GetRules(table, "PREROUTING")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s/PREROUTING order mismatch (direct must be first).\nWant: %v\nGot:  %v", table, want, got)
		}
	}
}

// TestDirectPriorityByOrder — режим 'как раньше': direct участвует в общей
// очереди и цепляется в конец, как любая другая группа. Тогда группа, поднятая
// раньше (выше в списке UI), выигрывает overlap, а широкая direct-группа внизу
// работает catch-all'ом. Терминирование остаётся ACCEPT'ом — RETURN сюда не
// возвращаем, это был баг mt-my3 с проваливанием обхода.
func TestDirectPriorityByOrder(t *testing.T) {
	r, fake, ipt := newDirectPriorityFixture(true)

	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	want := [][]string{
		{"!", "-i", "lo", "-j", "MT_OTHER"},
		{"!", "-i", "lo", "-j", "MT_DIRECT"},
	}
	for _, table := range []string{"mangle", "nat"} {
		got := fake.GetRules(table, "PREROUTING")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s/PREROUTING order mismatch (direct must be last).\nWant: %v\nGot:  %v", table, want, got)
		}
	}
}

// TestDirectPriorityByOrderKeepsAccept — режим не должен менять содержимое
// цепочки: терминирование обхода остаётся ACCEPT в обеих таблицах. Иначе
// вернулся бы mt-my3 (RETURN проваливает пакет дальше по цепочкам групп).
func TestDirectPriorityByOrderKeepsAccept(t *testing.T) {
	r, fake, ipt := newDirectPriorityFixture(true)

	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	want := [][]string{
		{"-m", "set", "--match-set", "client_bypass_4", "src", "-j", "RETURN"},
		{"-m", "set", "--match-set", "mt_direct_4", "dst", "-j", "ACCEPT"},
	}
	for _, table := range []string{"mangle", "nat"} {
		got := fake.GetRules(table, "MT_DIRECT")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s/MT_DIRECT rules mismatch.\nWant: %v\nGot:  %v", table, want, got)
		}
	}
}
