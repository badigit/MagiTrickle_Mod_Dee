//go:build testing

package netfilterTools

import (
	"magitrickle/utils/iptables"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
)

func newTProxyTestFixture(proto iptables.Protocol) (*IPSetToTProxy, *iptables.FakeIPTables) {
	fake := iptables.NewFakeIPTables(proto)
	ipt := iptables.NewIPTables(fake)

	fake.SetInitialRules("nat", "PREROUTING", nil)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt.RegisterChainPatch("nat", "PREROUTING")
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	r := &IPSetToTProxy{
		chainName: "MT_TEST",
		port:      5001,
		mark:      100,
		table:     100,
		ipset:     &IPSet{ipsetName: "mt_test"},
		nh:        &Helper{IPTables4: ipt},
	}
	return r, fake
}

func TestInsertIPTablesRulesIPv4(t *testing.T) {
	r, fake := newTProxyTestFixture(iptables.ProtocolIPv4)

	err := r.insertIPTablesRules(r.nh.IPTables4)
	if err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	err = r.nh.IPTables4.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// NAT chain: TCP REDIRECT
	if !fake.ChainExists("nat", "MT_TEST") {
		t.Fatal("chain MT_TEST should exist in nat table")
	}
	natRules := fake.GetRules("nat", "MT_TEST")
	expectedNat := [][]string{
		{"-p", "tcp", "-m", "set", "--match-set", "mt_test_4", "dst", "-j", "REDIRECT", "--to-port", "5001"},
	}
	if !reflect.DeepEqual(natRules, expectedNat) {
		t.Errorf("nat chain rules mismatch.\nExpected: %v\nGot:      %v", expectedNat, natRules)
	}

	// nat/PREROUTING must jump to our chain
	natPreRules := fake.GetRules("nat", "PREROUTING")
	expectedNatPre := [][]string{
		{"!", "-i", "lo", "-j", "MT_TEST"},
	}
	if !reflect.DeepEqual(natPreRules, expectedNatPre) {
		t.Errorf("nat/PREROUTING rules mismatch.\nExpected: %v\nGot:      %v", expectedNatPre, natPreRules)
	}

	// Mangle chain: UDP TPROXY only
	if !fake.ChainExists("mangle", "MT_TEST") {
		t.Fatal("chain MT_TEST should exist in mangle table")
	}
	mangleRules := fake.GetRules("mangle", "MT_TEST")
	expectedMangle := [][]string{
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_4", "dst", "-m", "socket", "-j", "MARK", "--set-xmark", "100/100"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_4", "dst", "-m", "socket", "-j", "ACCEPT"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_4", "dst", "-j", "TPROXY", "--on-port", "5001", "--tproxy-mark", "100/100"},
	}
	if !reflect.DeepEqual(mangleRules, expectedMangle) {
		t.Errorf("mangle chain rules mismatch.\nExpected: %v\nGot:      %v", expectedMangle, mangleRules)
	}

	// mangle/PREROUTING must jump to our chain
	manglePreRules := fake.GetRules("mangle", "PREROUTING")
	expectedManglePre := [][]string{
		{"!", "-i", "lo", "-j", "MT_TEST"},
	}
	if !reflect.DeepEqual(manglePreRules, expectedManglePre) {
		t.Errorf("mangle/PREROUTING rules mismatch.\nExpected: %v\nGot:      %v", expectedManglePre, manglePreRules)
	}
}

func TestInsertIPTablesRulesIPv6(t *testing.T) {
	fake := iptables.NewFakeIPTables(iptables.ProtocolIPv6)
	ipt := iptables.NewIPTables(fake)

	fake.SetInitialRules("nat", "PREROUTING", nil)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt.RegisterChainPatch("nat", "PREROUTING")
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	r := &IPSetToTProxy{
		chainName: "MT_V6",
		port:      5001,
		mark:      200,
		table:     200,
		ipset:     &IPSet{ipsetName: "mt_test"},
		nh:        &Helper{IPTables6: ipt},
	}

	err := r.insertIPTablesRules(ipt)
	if err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	err = ipt.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// NAT chain: TCP REDIRECT with _6 suffix
	natRules := fake.GetRules("nat", "MT_V6")
	expectedNat := [][]string{
		{"-p", "tcp", "-m", "set", "--match-set", "mt_test_6", "dst", "-j", "REDIRECT", "--to-port", "5001"},
	}
	if !reflect.DeepEqual(natRules, expectedNat) {
		t.Errorf("nat chain rules mismatch.\nExpected: %v\nGot:      %v", expectedNat, natRules)
	}

	// Mangle chain: UDP TPROXY with _6 suffix
	mangleRules := fake.GetRules("mangle", "MT_V6")
	expectedMangle := [][]string{
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_6", "dst", "-m", "socket", "-j", "MARK", "--set-xmark", "200/200"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_6", "dst", "-m", "socket", "-j", "ACCEPT"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_6", "dst", "-j", "TPROXY", "--on-port", "5001", "--tproxy-mark", "200/200"},
	}
	if !reflect.DeepEqual(mangleRules, expectedMangle) {
		t.Errorf("mangle chain rules mismatch.\nExpected: %v\nGot:      %v", expectedMangle, mangleRules)
	}
}

func TestDeleteIPTablesRules(t *testing.T) {
	r, fake := newTProxyTestFixture(iptables.ProtocolIPv4)

	// First insert rules
	err := r.insertIPTablesRules(r.nh.IPTables4)
	if err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}
	err = r.nh.IPTables4.Commit()
	if err != nil {
		t.Fatalf("first Commit failed: %v", err)
	}

	// Now delete
	err = r.deleteIPTablesRules(r.nh.IPTables4)
	if err != nil {
		t.Fatalf("deleteIPTablesRules failed: %v", err)
	}
	err = r.nh.IPTables4.Commit()
	if err != nil {
		t.Fatalf("second Commit failed: %v", err)
	}

	// Both chains should be removed
	if fake.ChainExists("nat", "MT_TEST") {
		t.Error("chain MT_TEST should be deleted from nat table after cleanup")
	}
	if fake.ChainExists("mangle", "MT_TEST") {
		t.Error("chain MT_TEST should be deleted from mangle table after cleanup")
	}

	// Neither PREROUTING should reference our chain
	for _, table := range []string{"nat", "mangle"} {
		preRules := fake.GetRules(table, "PREROUTING")
		for _, rule := range preRules {
			for _, arg := range rule {
				if arg == "MT_TEST" {
					t.Errorf("%s/PREROUTING still references MT_TEST after delete", table)
				}
			}
		}
	}
}

func TestInsertIPTablesRulesNilIPTables(t *testing.T) {
	r := &IPSetToTProxy{
		chainName: "MT_NIL",
		port:      5001,
	}

	// Should not panic or error with nil iptables
	err := r.insertIPTablesRules(nil)
	if err != nil {
		t.Errorf("insertIPTablesRules(nil) should return nil, got: %v", err)
	}

	err = r.deleteIPTablesRules(nil)
	if err != nil {
		t.Errorf("deleteIPTablesRules(nil) should return nil, got: %v", err)
	}
}

func TestLinkUpHookIsNoop(t *testing.T) {
	r := &IPSetToTProxy{}
	err := r.LinkUpHook(netlink.LinkUpdate{})
	if err != nil {
		t.Errorf("LinkUpHook should be no-op, got: %v", err)
	}
}

// TestPREROUTINGExcludesLoopback verifies that nat/PREROUTING and mangle/PREROUTING
// jumps to the MagiTrickle chain are guarded by `! -i lo` to prevent router-local
// traffic from being hijacked.
//
// Regression: a poisoned subscription (e.g. opencck.org whatsapp returning
// 126.0.0.0/7 which covers 127.0.0.0/8) put 127.0.0.1 into the ipset, which
// caused router's own DNS queries to 127.0.0.1:53 to be looped through TPROXY
// → mihomo → VPN, exhausting CPU.
func TestPREROUTINGExcludesLoopback(t *testing.T) {
	r, fake := newTProxyTestFixture(iptables.ProtocolIPv4)

	if err := r.insertIPTablesRules(r.nh.IPTables4); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}
	if err := r.nh.IPTables4.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	for _, table := range []string{"nat", "mangle"} {
		rules := fake.GetRules(table, "PREROUTING")
		if len(rules) != 1 {
			t.Fatalf("%s/PREROUTING: want 1 rule, got %d: %v", table, len(rules), rules)
		}
		got := rules[0]
		want := []string{"!", "-i", "lo", "-j", "MT_TEST"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s/PREROUTING jump must exclude loopback.\nWant: %v\nGot:  %v", table, want, got)
		}
	}
}

func TestIPSetToTProxyFactory(t *testing.T) {
	nh := &Helper{
		ChainPrefix: "MT_",
		IpsetPrefix: "mts_",
		StartIdx:    100,
	}

	ipset := &IPSet{ipsetName: "mts_test"}
	result := nh.IPSetToTProxy("group1", 5001, ipset, 86400)

	if result.chainName != "MT_group1" {
		t.Errorf("chainName = %q, want %q", result.chainName, "MT_group1")
	}
	if result.port != 5001 {
		t.Errorf("port = %d, want %d", result.port, 5001)
	}
	if result.ipset != ipset {
		t.Error("ipset should be the same pointer")
	}
	if result.nh != nh {
		t.Error("nh should be the same pointer")
	}
	if result.startIdx != 100 {
		t.Errorf("startIdx = %d, want %d", result.startIdx, 100)
	}
	if result.refreshTimeout != 86400 {
		t.Errorf("refreshTimeout = %d, want %d", result.refreshTimeout, 86400)
	}
}

// TestInsertIPTablesRulesRefresh проверяет, что при refreshTimeout > 0 в mangle-
// цепочку ПЕРВЫМ добавляется правило продления ipset для conntrack NEW (mt-9g7,
// часть C). Оно должно стоять до socket/TPROXY-правил и капать по --timeout.
func TestInsertIPTablesRulesRefresh(t *testing.T) {
	r, fake := newTProxyTestFixture(iptables.ProtocolIPv4)
	r.refreshTimeout = 86400

	if err := r.insertIPTablesRules(r.nh.IPTables4); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}
	if err := r.nh.IPTables4.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	mangleRules := fake.GetRules("mangle", "MT_TEST")
	expectedMangle := [][]string{
		{"-m", "conntrack", "--ctstate", "NEW", "-m", "set", "--match-set", "mt_test_4", "dst", "-m", "set", "!", "--match-set", "mt_test_s4", "dst", "-j", "SET", "--add-set", "mt_test_4", "dst", "--exist", "--timeout", "86400"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_4", "dst", "-m", "socket", "-j", "MARK", "--set-xmark", "100/100"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_4", "dst", "-m", "socket", "-j", "ACCEPT"},
		{"-p", "udp", "-m", "set", "--match-set", "mt_test_4", "dst", "-j", "TPROXY", "--on-port", "5001", "--tproxy-mark", "100/100"},
	}
	if !reflect.DeepEqual(mangleRules, expectedMangle) {
		t.Errorf("mangle chain rules mismatch.\nExpected: %v\nGot:      %v", expectedMangle, mangleRules)
	}

	// NAT-цепочка (TCP REDIRECT) не должна меняться правилом продления.
	natRules := fake.GetRules("nat", "MT_TEST")
	expectedNat := [][]string{
		{"-p", "tcp", "-m", "set", "--match-set", "mt_test_4", "dst", "-j", "REDIRECT", "--to-port", "5001"},
	}
	if !reflect.DeepEqual(natRules, expectedNat) {
		t.Errorf("nat chain rules mismatch.\nExpected: %v\nGot:      %v", expectedNat, natRules)
	}
}

// TestRefreshExcludesStaticSubnets — регресс на mt-bq8.
//
// Правило продления делает `-j SET --add-set <set> dst`, а SET-target берёт
// КОНКРЕТНЫЙ destination IP из пакета. Если пакет совпал с широкой статической
// подсетью (0.0.0.0/1 у route-all, 10.0.0.0/8 и т.п.), ядро материализует этот
// IP отдельной /32-записью в том же hash:net сете. Широкая подсеть при этом не
// меняется, а мусорные /32 копятся на КАЖДЫЙ новый destination — до maxelem
// (дефолт 65536), после чего IpsetAdd для новых DNS-записей начинает падать и
// трафик к новым доменам уходит direct мимо прокси.
//
// Лечение: негативный матч по зеркалу статических подсетей (<set>_s4/_s6).
// Адрес внутри статической подсети продлевать не нужно — она permanent
// (timeout=0) и покрывает его сама, поэтому пропуск такого пакета мимо
// SET-target ничего не ломает.
func TestRefreshExcludesStaticSubnets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		proto     iptables.Protocol
		chain     string
		mainSet   string
		staticSet string
	}{
		{"ipv4", iptables.ProtocolIPv4, "MT_TEST", "mt_test_4", "mt_test_s4"},
		{"ipv6", iptables.ProtocolIPv6, "MT_TEST", "mt_test_6", "mt_test_s6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := iptables.NewFakeIPTables(tc.proto)
			ipt := iptables.NewIPTables(fake)
			fake.SetInitialRules("nat", "PREROUTING", nil)
			fake.SetInitialRules("mangle", "PREROUTING", nil)
			ipt.RegisterChainPatch("nat", "PREROUTING")
			ipt.RegisterChainPatch("mangle", "PREROUTING")

			nh := &Helper{}
			if tc.proto == iptables.ProtocolIPv4 {
				nh.IPTables4 = ipt
			} else {
				nh.IPTables6 = ipt
			}
			r := &IPSetToTProxy{
				chainName:      tc.chain,
				port:           5001,
				mark:           100,
				table:          100,
				ipset:          &IPSet{ipsetName: "mt_test"},
				nh:             nh,
				refreshTimeout: 86400,
			}

			if err := r.insertIPTablesRules(ipt); err != nil {
				t.Fatalf("insertIPTablesRules failed: %v", err)
			}
			if err := ipt.Commit(); err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			rules := fake.GetRules("mangle", tc.chain)
			if len(rules) == 0 {
				t.Fatalf("mangle chain %s is empty", tc.chain)
			}
			got := rules[0]
			want := []string{
				"-m", "conntrack", "--ctstate", "NEW",
				"-m", "set", "--match-set", tc.mainSet, "dst",
				"-m", "set", "!", "--match-set", tc.staticSet, "dst",
				"-j", "SET", "--add-set", tc.mainSet, "dst", "--exist", "--timeout", "86400",
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("refresh rule must exclude static-subnet mirror.\nWant: %v\nGot:  %v", want, got)
			}
		})
	}
}

// TestInsertIPTablesRulesNoRefresh проверяет, что при refreshTimeout == 0
// правило продления НЕ добавляется (обратная совместимость).
func TestInsertIPTablesRulesNoRefresh(t *testing.T) {
	r, fake := newTProxyTestFixture(iptables.ProtocolIPv4)
	r.refreshTimeout = 0

	if err := r.insertIPTablesRules(r.nh.IPTables4); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}
	if err := r.nh.IPTables4.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	mangleRules := fake.GetRules("mangle", "MT_TEST")
	for _, rule := range mangleRules {
		for _, arg := range rule {
			if arg == "SET" {
				t.Errorf("mangle chain must not contain SET-refresh rule when refreshTimeout==0: %v", mangleRules)
			}
		}
	}
}
