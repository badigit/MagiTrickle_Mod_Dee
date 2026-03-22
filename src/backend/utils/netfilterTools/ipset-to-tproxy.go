package netfilterTools

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"magitrickle/utils/iptables"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type IPSetToTProxy struct {
	enabled atomic.Bool
	locker  sync.Mutex

	chainName string
	port      uint16
	startIdx  uint32
	ipset     *IPSet
	nh        *Helper
	mark      uint32
	table     int
	ip4Rule   *netlink.Rule
	ip6Rule   *netlink.Rule
	ip4Route  *netlink.Route
	ip6Route  *netlink.Route
}

func (r *IPSetToTProxy) insertIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}

	ipsetName := r.ipset.ipsetName
	if ipt.Proto() == iptables.ProtocolIPv4 {
		ipsetName += "_4"
	} else {
		ipsetName += "_6"
	}

	portStr := strconv.Itoa(int(r.port))
	markStr := strconv.Itoa(int(r.mark))
	tproxyMark := markStr + "/" + markStr

	/*
		NAT PREROUTING — TCP REDIRECT
	*/

	err := ipt.RegisterChainOverride("nat", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create nat chain: %w", err)
	}

	err = ipt.Append("nat", r.chainName,
		"-p", "tcp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "REDIRECT", "--to-port", portStr,
	)
	if err != nil {
		return fmt.Errorf("failed to append TCP REDIRECT rule: %w", err)
	}

	err = ipt.Append("nat", "PREROUTING", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to nat/PREROUTING: %w", err)
	}

	/*
		Mangle PREROUTING — UDP TPROXY
	*/

	err = ipt.RegisterChainOverride("mangle", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create mangle chain: %w", err)
	}

	// DIVERT: established UDP TPROXY connections get marked and accepted
	err = ipt.Append("mangle", r.chainName,
		"-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-m", "socket",
		"-j", "MARK", "--set-xmark", tproxyMark,
	)
	if err != nil {
		return fmt.Errorf("failed to append UDP socket MARK rule: %w", err)
	}
	err = ipt.Append("mangle", r.chainName,
		"-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-m", "socket",
		"-j", "ACCEPT",
	)
	if err != nil {
		return fmt.Errorf("failed to append UDP socket ACCEPT rule: %w", err)
	}

	// TPROXY: new UDP connections matching the ipset
	err = ipt.Append("mangle", r.chainName,
		"-p", "udp",
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "TPROXY",
		"--on-port", portStr,
		"--tproxy-mark", tproxyMark,
	)
	if err != nil {
		return fmt.Errorf("failed to append UDP TPROXY rule: %w", err)
	}

	err = ipt.Append("mangle", "PREROUTING", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to mangle/PREROUTING: %w", err)
	}

	err = ipt.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit iptables rules: %w", err)
	}
	return nil
}

func (r *IPSetToTProxy) deleteIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	var errs []error

	/*
		NAT — TCP REDIRECT cleanup
	*/

	err := ipt.RegisterChainDelete("nat", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete nat chain: %w", err))
	}

	err = ipt.Delete("nat", "PREROUTING", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlink nat chain: %w", err))
	}

	/*
		Mangle — UDP TPROXY cleanup
	*/

	err = ipt.RegisterChainDelete("mangle", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete mangle chain: %w", err))
	}

	err = ipt.Delete("mangle", "PREROUTING", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlink mangle chain: %w", err))
	}

	err = ipt.Commit()
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
	}
	return errors.Join(errs...)
}

func (r *IPSetToTProxy) insertIPRule() error {
	if r.nh.IPTables4 != nil {
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = r.table
		rule.Family = nl.FAMILY_V4
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip4Rule = rule
	}

	if r.nh.IPTables6 != nil {
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = r.table
		rule.Family = nl.FAMILY_V6
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip6Rule = rule
	}

	return nil
}

func (r *IPSetToTProxy) deleteIPRule() error {
	var errs []error

	if r.ip4Rule != nil {
		err := netlink.RuleDel(r.ip4Rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip4Rule = nil
	}

	if r.ip6Rule != nil {
		err := netlink.RuleDel(r.ip6Rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip6Rule = nil
	}

	return errors.Join(errs...)
}

func (r *IPSetToTProxy) insertIPRoute() error {
	// TPROXY needs: ip route add local default dev lo table <table>
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("error while getting loopback interface: %w", err)
	}
	loIdx := lo.Attrs().Index

	if r.nh.IPTables4 != nil {
		route := &netlink.Route{
			LinkIndex: loIdx,
			Dst:       &net.IPNet{IP: []byte{0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0}},
			Table:     r.table,
			Type:      unix.RTN_LOCAL,
			Scope:     unix.RT_SCOPE_HOST,
		}
		err := netlink.RouteAdd(route)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("error while adding local route: %w", err)
		}
		r.ip4Route = route
	}

	if r.nh.IPTables6 != nil {
		route := &netlink.Route{
			LinkIndex: loIdx,
			Dst:       &net.IPNet{IP: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			Table:     r.table,
			Type:      unix.RTN_LOCAL,
			Scope:     unix.RT_SCOPE_HOST,
		}
		err := netlink.RouteAdd(route)
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("error while adding local route: %w", err)
		}
		r.ip6Route = route
	}

	return nil
}

func (r *IPSetToTProxy) deleteIPRoute() error {
	var errs []error

	if r.ip4Route != nil {
		err := netlink.RouteDel(r.ip4Route)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ip4Route = nil
	}

	if r.ip6Route != nil {
		err := netlink.RouteDel(r.ip6Route)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ip6Route = nil
	}

	return errors.Join(errs...)
}

func (r *IPSetToTProxy) getUnusedMarkAndTable() (idx uint32, err error) {
	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{0: {}, 253: {}, 254: {}, 255: {}}

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return 0, fmt.Errorf("error while getting rules: %w", err)
	}
	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
		tableMap[rule.Table] = struct{}{}
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, fmt.Errorf("error while getting routes: %w", err)
	}
	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	for idx = r.startIdx; idx < 0x7ffffffe; idx++ {
		_, tableExists := tableMap[int(idx)]
		_, markExists := markMap[idx]
		if !tableExists && !markExists {
			break
		}
	}

	return idx, nil
}

// checkTProxyAvailable verifies that required kernel modules are loaded.
func checkTProxyAvailable() error {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil // can't check, proceed optimistically
	}
	modules := string(data)
	hasTProxy := strings.Contains(modules, "xt_TPROXY") || strings.Contains(modules, "nft_tproxy")
	hasSocket := strings.Contains(modules, "xt_socket") || strings.Contains(modules, "nft_socket")
	if hasTProxy && hasSocket {
		return nil
	}
	var missing []string
	if !hasTProxy {
		missing = append(missing, "tproxy")
	}
	if !hasSocket {
		missing = append(missing, "socket")
	}
	return fmt.Errorf("TPROXY requires kernel modules %v not found; "+
		"install: opkg install kmod-ipt-tproxy kmod-ipt-socket "+
		"or: apk add kmod-nft-tproxy kmod-nft-socket iptables-mod-tproxy iptables-mod-socket",
		missing)
}

// ensureKernelModule tries to load a kernel module by name (best-effort).
func ensureKernelModule(name string) {
	matches, _ := filepath.Glob("/lib/modules/*/" + name + ".ko")
	if len(matches) == 0 {
		return
	}
	f, err := os.Open(matches[0])
	if err != nil {
		return
	}
	defer f.Close()
	err = unix.FinitModule(int(f.Fd()), "", 0)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		log.Debug().Err(err).Str("module", name).Msg("tproxy: failed to load kernel module")
	}
}

func (r *IPSetToTProxy) enable() error {
	if !r.enabled.CompareAndSwap(false, true) {
		return nil
	}

	ensureKernelModule("xt_TPROXY")
	ensureKernelModule("xt_socket")
	ensureKernelModule("nft_tproxy")
	ensureKernelModule("nft_socket")

	if err := checkTProxyAvailable(); err != nil {
		return err
	}

	idx, err := r.getUnusedMarkAndTable()
	if err != nil {
		return err
	}
	r.mark, r.table = idx, int(idx)

	err = r.insertIPRule()
	if err != nil {
		return err
	}

	err = r.insertIPRoute()
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables4)
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables6)
	if err != nil {
		return err
	}

	return nil
}

func (r *IPSetToTProxy) Enable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	err := r.enable()
	if err != nil {
		r.disable()
	} else {
		log.Debug().
			Int("table", r.table).
			Int("mark", int(r.mark)).
			Uint16("port", r.port).
			Msg("tproxy: using ip table, mark and port")
	}

	return err
}

func (r *IPSetToTProxy) disable() error {
	if !r.enabled.Load() {
		return nil
	}
	defer r.enabled.Store(false)

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

func (r *IPSetToTProxy) Disable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	return r.disable()
}

func (r *IPSetToTProxy) ClearIfDisabled() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if r.enabled.Load() {
		return nil
	}

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

// LinkUpdateHook is a no-op for TPROXY (does not depend on interface state).
func (r *IPSetToTProxy) LinkUpdateHook(_ netlink.LinkUpdate) error {
	return nil
}

func (nh *Helper) IPSetToTProxy(name string, port uint16, ipset *IPSet) *IPSetToTProxy {
	return &IPSetToTProxy{
		nh:        nh,
		chainName: nh.ChainPrefix + name,
		port:      port,
		ipset:     ipset,
		startIdx:  nh.StartIdx,
	}
}
