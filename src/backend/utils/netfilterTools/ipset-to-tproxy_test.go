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
		{"-j", "MT_TEST"},
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
		{"-j", "MT_TEST"},
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

func TestLinkUpdateHookIsNoop(t *testing.T) {
	r := &IPSetToTProxy{}
	err := r.LinkUpdateHook(netlink.LinkUpdate{})
	if err != nil {
		t.Errorf("LinkUpdateHook should be no-op, got: %v", err)
	}
}

func TestIPSetToTProxyFactory(t *testing.T) {
	nh := &Helper{
		ChainPrefix: "MT_",
		IpsetPrefix: "mts_",
		StartIdx:    100,
	}

	ipset := &IPSet{ipsetName: "mts_test"}
	result := nh.IPSetToTProxy("group1", 5001, ipset)

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
}
