//go:build testing

package netfilterTools

import (
	"reflect"
	"testing"

	"magitrickle/utils/iptables"
)

func TestNormalizeSourceNetworks(t *testing.T) {
	values, networks, err := NormalizeSourceNetworks([]string{
		" 192.168.1.10 ",
		"192.168.1.10",
		"192.168.1.99/24",
		"2001:db8::1",
		"2001:db8::abcd/64",
		"",
	})
	if err != nil {
		t.Fatalf("NormalizeSourceNetworks failed: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.0/24", "2001:db8::1", "2001:db8::/64"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("canonical values mismatch: want %v, got %v", want, values)
	}
	if got := []uint8{networks[0].CIDR, networks[1].CIDR, networks[2].CIDR, networks[3].CIDR}; !reflect.DeepEqual(got, []uint8{32, 24, 128, 64}) {
		t.Fatalf("CIDRs mismatch: %v", got)
	}
}

func TestNormalizeSourceNetworksRejectsInvalidValue(t *testing.T) {
	if _, _, err := NormalizeSourceNetworks([]string{"device.lan"}); err == nil {
		t.Fatal("expected invalid address error")
	}
}

func TestPortRemapStartsWithClientBypassGuard(t *testing.T) {
	fake := iptables.NewFakeIPTables(iptables.ProtocolIPv4)
	ipt := iptables.NewIPTables(fake)
	fake.SetInitialRules("nat", "PREROUTING", nil)
	ipt.RegisterChainPatch("nat", "PREROUTING")
	r := &PortRemap{
		chainName: "MT_DNSOR",
		nh:        &Helper{IpsetPrefix: "mt_", IPTables4: ipt},
	}
	if err := r.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("insertIPTablesRules failed: %v", err)
	}
	want := []string{"-m", "set", "--match-set", "mt_client_bypass_4", "src", "-j", "RETURN"}
	if got := fake.GetRules("nat", "MT_DNSOR"); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("DNSOR bypass guard mismatch: want %v, got %v", want, got)
	}
}

func TestClientBypassSetNamesRejectLongPrefix(t *testing.T) {
	nh := &Helper{IpsetPrefix: "prefix_that_is_too_long_", IPTables4: iptables.NewIPTables(iptables.NewFakeIPTables(iptables.ProtocolIPv4))}
	if _, err := nh.clientBypassSpecs(); err == nil {
		t.Fatal("expected long ipset prefix error")
	}
}
