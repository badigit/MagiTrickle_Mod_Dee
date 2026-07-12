package netfilterTools

import (
	"errors"
	"fmt"
	"sync"

	"magitrickle/utils/iptables"
)

// preambleChainSuffix names the shared interface-mode preamble chain
// (ChainPrefix + suffix, e.g. "MT_PREAMBLE"). Matching ChainPrefix means the
// startup iptables cleaner removes it automatically after a crash.
const preambleChainSuffix = "PREAMBLE"

type Helper struct {
	ChainPrefix string
	IpsetPrefix string
	IPTables4   *iptables.IPTables
	IPTables6   *iptables.IPTables

	StartIdx uint32

	// preambleMu guards the reference count for the shared interface-mode
	// mangle preamble. The preamble is a single chain shared by all
	// interface-mode groups, installed on the first group and removed on the
	// last, so its lifecycle can't be owned by any individual group.
	preambleMu   sync.Mutex
	preambleRefs int
}

// acquireInterfacePreamble ensures the shared mangle PREROUTING preamble is
// installed and bumps its reference count. The preamble runs before every
// interface-group chain:
//
//	-j CONNMARK --restore-mark      restore the per-connection routing mark
//	-m mark ! --mark 0 -j ACCEPT    connection already decided -> skip re-eval
//
// This makes the routing decision one-shot per connection: once a group chain
// has marked and save-marked a connection, subsequent packets are routed by the
// restored mark even after the destination IP has aged out of the ipset (DNS TTL
// expiry). That fixes the interface-mode long-session drop (every packet used to
// re-query the ipset; an expired IP left the packet unmarked -> default route ->
// RST). It also short-circuits decided connections so a later group cannot steal
// an already-established one.
//
// The restore-mark MUST be one shared rule, not per-group: a per-group
// restore-mark would leak a foreign group's restored mark into the next group's
// chain and corrupt arbitration.
func (nh *Helper) acquireInterfacePreamble() error {
	nh.preambleMu.Lock()
	defer nh.preambleMu.Unlock()

	if nh.preambleRefs == 0 {
		var errs []error
		for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
			errs = append(errs, nh.installInterfacePreamble(ipt))
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
	}
	nh.preambleRefs++
	return nil
}

// releaseInterfacePreamble drops one reference and removes the shared preamble
// when the last interface-mode group goes away.
func (nh *Helper) releaseInterfacePreamble() error {
	nh.preambleMu.Lock()
	defer nh.preambleMu.Unlock()

	if nh.preambleRefs == 0 {
		return nil
	}
	nh.preambleRefs--
	if nh.preambleRefs > 0 {
		return nil
	}

	var errs []error
	for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
		errs = append(errs, nh.removeInterfacePreamble(ipt))
	}
	return errors.Join(errs...)
}

func (nh *Helper) installInterfacePreamble(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	chain := nh.ChainPrefix + preambleChainSuffix

	if err := ipt.RegisterChainOverride("mangle", chain); err != nil {
		return fmt.Errorf("failed to create preamble chain: %w", err)
	}
	if err := ipt.Append("mangle", chain, "-j", "CONNMARK", "--restore-mark"); err != nil {
		return fmt.Errorf("failed to append restore-mark: %w", err)
	}
	if err := ipt.Append("mangle", chain, "-m", "mark", "!", "--mark", "0x0", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to append mark-accept: %w", err)
	}
	// Append, don't Insert@1: direct-mode chains Insert@1 and MUST stay above
	// the preamble (direct's contract is to override everything — adding an IP
	// to a direct group must divert even an established, connmark'ed
	// connection). Insert@1 here would race with direct for the top slot and
	// the winner would depend on group enable order. Appending is still ahead
	// of every interface-group jump because acquire runs in enable() before the
	// group appends its own jump. Exclude loopback, matching the group jumps.
	if err := ipt.Append("mangle", "PREROUTING", "!", "-i", "lo", "-j", chain); err != nil {
		return fmt.Errorf("failed to append preamble jump: %w", err)
	}
	if err := ipt.Commit(); err != nil {
		return fmt.Errorf("failed to commit preamble: %w", err)
	}
	return nil
}

func (nh *Helper) removeInterfacePreamble(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	chain := nh.ChainPrefix + preambleChainSuffix

	var errs []error
	if err := ipt.Delete("mangle", "PREROUTING", "!", "-i", "lo", "-j", chain); err != nil {
		errs = append(errs, fmt.Errorf("failed to unlink preamble jump: %w", err))
	}
	if err := ipt.RegisterChainDelete("mangle", chain); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete preamble chain: %w", err))
	}
	if err := ipt.Commit(); err != nil {
		errs = append(errs, fmt.Errorf("failed to commit preamble removal: %w", err))
	}
	return errors.Join(errs...)
}

func New(chainPrefix, ipsetPrefix string, disableIPv4, disableIPv6 bool, startIdx uint32) (*Helper, error) {
	var ipt4, ipt6 *iptables.IPTables

	if !disableIPv4 {
		ipt4 = iptables.NewIPTables(iptables.NewRealIPTables())
	}

	if !disableIPv6 {
		ipt6 = iptables.NewIPTables(iptables.NewRealIP6Tables())
	}

	return &Helper{
		ChainPrefix: chainPrefix,
		IpsetPrefix: ipsetPrefix,
		IPTables4:   ipt4,
		IPTables6:   ipt6,
		StartIdx:    startIdx,
	}, nil
}
