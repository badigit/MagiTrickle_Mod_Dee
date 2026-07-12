//go:build testing

package netfilterTools

import (
	"magitrickle/utils/iptables"
	"reflect"
	"testing"
)

func newDirectTestFixture(proto iptables.Protocol) (*IPSetToLink, *iptables.FakeIPTables, *iptables.IPTables) {
	fake := iptables.NewFakeIPTables(proto)
	ipt := iptables.NewIPTables(fake)

	fake.SetInitialRules("nat", "PREROUTING", nil)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt.RegisterChainPatch("nat", "PREROUTING")
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	r := &IPSetToLink{
		chainName: "MT_DIRECT",
		ifaceName: Direct,
		ipset:     &IPSet{ipsetName: "mt_direct"},
		nh:        &Helper{IPTables4: ipt},
	}
	return r, fake, ipt
}

// TestDirectInsertUsesAccept is a regression test for the direct-mode bypass.
//
// Bug (mt-my3): the direct chain held a single `match-set dst -j RETURN` rule.
// RETURN from a user chain is a fall-through — match or no match, the packet
// returns to PREROUTING and keeps traversing the remaining group chains, so an
// IP that also sits in another group's ipset (overlap, e.g. a Cloudflare domain
// in group A + Cloudflare ASN subnet in group B) still gets TPROXY'd and direct
// fails to override. The fix uses ACCEPT, which terminates table traversal and
// actually bypasses the remaining chains. Required in nat too, otherwise the
// TPROXY TCP REDIRECT in nat/PREROUTING still catches the traffic.
func TestDirectInsertUsesAccept(t *testing.T) {
	r, fake, ipt := newDirectTestFixture(iptables.ProtocolIPv4)

	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	for _, table := range []string{"mangle", "nat"} {
		if !fake.ChainExists(table, "MT_DIRECT") {
			t.Fatalf("chain MT_DIRECT should exist in %s table", table)
		}

		rules := fake.GetRules(table, "MT_DIRECT")
		want := [][]string{
			{"-m", "set", "--match-set", "mt_direct_4", "dst", "-j", "ACCEPT"},
		}
		if !reflect.DeepEqual(rules, want) {
			t.Errorf("%s/MT_DIRECT rules mismatch.\nWant: %v\nGot:  %v", table, want, rules)
		}

		// Explicit regression guard: the bypass target must never be RETURN.
		for _, rule := range rules {
			for _, arg := range rule {
				if arg == "RETURN" {
					t.Errorf("%s/MT_DIRECT must not use RETURN (fall-through no-op); got %v", table, rule)
				}
			}
		}

		// PREROUTING must jump to our chain, excluding loopback.
		preRules := fake.GetRules(table, "PREROUTING")
		wantPre := [][]string{
			{"!", "-i", "lo", "-j", "MT_DIRECT"},
		}
		if !reflect.DeepEqual(preRules, wantPre) {
			t.Errorf("%s/PREROUTING rules mismatch.\nWant: %v\nGot:  %v", table, wantPre, preRules)
		}
	}
}

// newInterfaceTestFixture wires the tables an interface-mode group touches
// (filter FORWARD, mangle PREROUTING, nat POSTROUTING) so insertIPTablesRules
// can run against the fake backend.
func newInterfaceTestFixture(proto iptables.Protocol, iface string) (*IPSetToLink, *iptables.FakeIPTables, *iptables.IPTables) {
	fake := iptables.NewFakeIPTables(proto)
	ipt := iptables.NewIPTables(fake)

	fake.SetInitialRules("filter", "FORWARD", nil)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	fake.SetInitialRules("nat", "POSTROUTING", nil)
	ipt.RegisterChainPatch("filter", "FORWARD")
	ipt.RegisterChainPatch("mangle", "PREROUTING")
	ipt.RegisterChainPatch("nat", "POSTROUTING")

	nh := &Helper{ChainPrefix: "MT_"}
	if proto == iptables.ProtocolIPv4 {
		nh.IPTables4 = ipt
	} else {
		nh.IPTables6 = ipt
	}

	r := &IPSetToLink{
		chainName: "MT_GRP",
		ifaceName: iface,
		mark:      100,
		table:     100,
		ipset:     &IPSet{ipsetName: "mt_grp"},
		nh:        nh,
	}
	return r, fake, ipt
}

// TestInterfaceGroupChainTerminatesWithAccept is a regression test for mt-sd3.
//
// The interface-mode mangle chain must end its matched branch with ACCEPT so the
// FIRST matching group wins (arbitration consistent with tproxy). Before the fix
// the chain only did MARK + save-mark and RETURNed, letting a later group chain
// overwrite the mark (last-wins, inconsistent with tproxy's first-wins).
func TestInterfaceGroupChainTerminatesWithAccept(t *testing.T) {
	r, fake, ipt := newInterfaceTestFixture(iptables.ProtocolIPv4, "nwg0")

	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	rules := fake.GetRules("mangle", "MT_GRP")
	want := [][]string{
		{"-m", "set", "--match-set", "mt_grp_4", "dst", "-j", "MARK", "--set-mark", "100"},
		{"-m", "set", "--match-set", "mt_grp_4", "dst", "-j", "CONNMARK", "--save-mark"},
		{"-m", "set", "--match-set", "mt_grp_4", "dst", "-j", "ACCEPT"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("mangle/MT_GRP rules mismatch.\nWant: %v\nGot:  %v", want, rules)
	}
}

// TestInterfacePreambleLifecycle exercises the ref-counted shared preamble
// (mt-sd3): installed once on the first interface group, kept while >=1 group is
// active, removed only when the last releases it.
func TestInterfacePreambleLifecycle(t *testing.T) {
	fake := iptables.NewFakeIPTables(iptables.ProtocolIPv4)
	ipt := iptables.NewIPTables(fake)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	nh := &Helper{ChainPrefix: "MT_", IPTables4: ipt}

	// First acquire installs the preamble.
	if err := nh.acquireInterfacePreamble(); err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	if !fake.ChainExists("mangle", "MT_PREAMBLE") {
		t.Fatal("MT_PREAMBLE should exist after first acquire")
	}
	wantChain := [][]string{
		{"-j", "CONNMARK", "--restore-mark"},
		{"-m", "mark", "!", "--mark", "0x0", "-j", "ACCEPT"},
	}
	if got := fake.GetRules("mangle", "MT_PREAMBLE"); !reflect.DeepEqual(got, wantChain) {
		t.Errorf("MT_PREAMBLE chain mismatch.\nWant: %v\nGot:  %v", wantChain, got)
	}
	wantJump := [][]string{{"!", "-i", "lo", "-j", "MT_PREAMBLE"}}
	if got := fake.GetRules("mangle", "PREROUTING"); !reflect.DeepEqual(got, wantJump) {
		t.Errorf("PREROUTING jump mismatch.\nWant: %v\nGot:  %v", wantJump, got)
	}

	// Second acquire is a no-op on iptables (refcount only).
	if err := nh.acquireInterfacePreamble(); err != nil {
		t.Fatalf("second acquire failed: %v", err)
	}
	if got := fake.GetRules("mangle", "PREROUTING"); len(got) != 1 {
		t.Errorf("PREROUTING should have exactly one preamble jump, got %v", got)
	}

	// First release keeps it (still one group active).
	if err := nh.releaseInterfacePreamble(); err != nil {
		t.Fatalf("first release failed: %v", err)
	}
	if !fake.ChainExists("mangle", "MT_PREAMBLE") {
		t.Fatal("MT_PREAMBLE must stay while one group still holds it")
	}

	// Last release removes chain and jump.
	if err := nh.releaseInterfacePreamble(); err != nil {
		t.Fatalf("last release failed: %v", err)
	}
	if fake.ChainExists("mangle", "MT_PREAMBLE") {
		t.Error("MT_PREAMBLE should be gone after last release")
	}
	if got := fake.GetRules("mangle", "PREROUTING"); len(got) != 0 {
		t.Errorf("PREROUTING preamble jump should be removed, got %v", got)
	}

	// Over-release is a no-op, not an underflow.
	if err := nh.releaseInterfacePreamble(); err != nil {
		t.Fatalf("over-release should be a no-op, got: %v", err)
	}
	if nh.preambleRefs != 0 {
		t.Errorf("preambleRefs should stay 0 after over-release, got %d", nh.preambleRefs)
	}
}

// TestInterfacePreambleOrderedBeforeGroupJump verifies the preamble jump is
// inserted before an already-appended group jump, so restore-mark/ACCEPT run
// ahead of the group chains regardless of install order.
func TestInterfacePreambleOrderedBeforeGroupJump(t *testing.T) {
	fake := iptables.NewFakeIPTables(iptables.ProtocolIPv4)
	ipt := iptables.NewIPTables(fake)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	// A group jump is appended first...
	if err := ipt.Append("mangle", "PREROUTING", "!", "-i", "lo", "-j", "MT_GRP"); err != nil {
		t.Fatalf("append group jump failed: %v", err)
	}
	if err := ipt.Commit(); err != nil {
		t.Fatalf("commit group jump failed: %v", err)
	}

	// ...then the preamble is installed.
	nh := &Helper{ChainPrefix: "MT_", IPTables4: ipt}
	if err := nh.acquireInterfacePreamble(); err != nil {
		t.Fatalf("acquire failed: %v", err)
	}

	got := fake.GetRules("mangle", "PREROUTING")
	want := [][]string{
		{"!", "-i", "lo", "-j", "MT_PREAMBLE"},
		{"!", "-i", "lo", "-j", "MT_GRP"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PREROUTING order mismatch — preamble must precede group jump.\nWant: %v\nGot:  %v", want, got)
	}
}

// TestDirectInsertIPv6 verifies the direct chain uses the _6 ipset suffix and
// ACCEPT for the IPv6 path.
func TestDirectInsertIPv6(t *testing.T) {
	fake := iptables.NewFakeIPTables(iptables.ProtocolIPv6)
	ipt := iptables.NewIPTables(fake)

	fake.SetInitialRules("nat", "PREROUTING", nil)
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	ipt.RegisterChainPatch("nat", "PREROUTING")
	ipt.RegisterChainPatch("mangle", "PREROUTING")

	r := &IPSetToLink{
		chainName: "MT_DIRECT6",
		ifaceName: Direct,
		ipset:     &IPSet{ipsetName: "mt_direct"},
		nh:        &Helper{IPTables6: ipt},
	}

	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}

	for _, table := range []string{"mangle", "nat"} {
		rules := fake.GetRules(table, "MT_DIRECT6")
		want := [][]string{
			{"-m", "set", "--match-set", "mt_direct_6", "dst", "-j", "ACCEPT"},
		}
		if !reflect.DeepEqual(rules, want) {
			t.Errorf("%s/MT_DIRECT6 rules mismatch.\nWant: %v\nGot:  %v", table, want, rules)
		}
	}
}
