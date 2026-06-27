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
