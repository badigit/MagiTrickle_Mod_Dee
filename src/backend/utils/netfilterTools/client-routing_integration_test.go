//go:build integration && linux

package netfilterTools

import (
	"os"
	"testing"

	"magitrickle/utils/iptables"

	"github.com/vishvananda/netlink"
)

func TestClientBypassKernelSwap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for kernel ipset operations")
	}

	nh := &Helper{
		IpsetPrefix: "mti_",
		IPTables4:   new(iptables.IPTables),
	}
	defer func() {
		if err := nh.DestroyClientBypass(); err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
	}()

	if _, err := nh.SetupClientBypass([]string{"10.77.0.1"}); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	assertKernelSetContains(t, "mti_client_bypass_4", "10.77.0.1")

	if _, err := nh.UpdateClientBypass([]string{"10.77.0.2/32"}); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	assertKernelSetContains(t, "mti_client_bypass_4", "10.77.0.2")
	if exists, err := netlink.IpsetTest("mti_client_bypass_4", &netlink.IPSetEntry{IP: []byte{10, 77, 0, 1}, CIDR: 32}); err == nil && exists {
		t.Fatal("old entry survived atomic replacement")
	}
}

func assertKernelSetContains(t *testing.T, name, address string) {
	t.Helper()
	ip := []byte{10, 77, 0, 1}
	if address == "10.77.0.2" {
		ip[3] = 2
	}
	exists, err := netlink.IpsetTest(name, &netlink.IPSetEntry{IP: ip, CIDR: 32})
	if err != nil || !exists {
		t.Fatalf("%s does not contain %s: %v", name, address, err)
	}
}
