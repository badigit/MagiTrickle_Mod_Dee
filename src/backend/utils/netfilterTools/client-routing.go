package netfilterTools

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"magitrickle/utils/iptables"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const clientBypassSetSuffix = "client_bypass"

// SourceNetwork is a canonical IP or CIDR split by address family.
type SourceNetwork struct {
	Canonical string
	IP        net.IP
	CIDR      uint8
	IPv6      bool
}

// NormalizeSourceNetworks validates, canonicalizes and deduplicates client
// source networks. Plain addresses remain plain in the persisted/UI form while
// ipset receives explicit /32 or /128 prefixes.
func NormalizeSourceNetworks(values []string) ([]string, []SourceNetwork, error) {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	networks := make([]SourceNetwork, 0, len(values))

	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}

		var ip net.IP
		var bits int
		ipv6 := false
		canonical := ""
		if strings.Contains(value, "/") {
			_, parsedNet, err := net.ParseCIDR(value)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid source network %q", value)
			}
			ip = parsedNet.IP
			var totalBits int
			bits, totalBits = parsedNet.Mask.Size()
			ipv6 = totalBits == 128
			canonical = parsedNet.String()
		} else {
			ip = net.ParseIP(value)
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid source address %q", value)
			}
			canonical = ip.String()
			if ip.To4() != nil {
				bits = 32
			} else {
				bits = 128
				ipv6 = true
			}
		}

		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
		if ip4 := ip.To4(); !ipv6 && ip4 != nil {
			networks = append(networks, SourceNetwork{Canonical: canonical, IP: slices.Clone(ip4), CIDR: uint8(bits)})
		} else {
			networks = append(networks, SourceNetwork{Canonical: canonical, IP: slices.Clone(ip.To16()), CIDR: uint8(bits), IPv6: true})
		}
	}

	return normalized, networks, nil
}

func (nh *Helper) clientBypassSetName(ipt *iptables.IPTables) string {
	name := nh.IpsetPrefix + clientBypassSetSuffix
	if ipt.Proto() == iptables.ProtocolIPv4 {
		return name + "_4"
	}
	return name + "_6"
}

func (nh *Helper) appendClientBypassGuard(ipt *iptables.IPTables, table, chain string) error {
	if ipt == nil {
		return nil
	}
	return ipt.Append(table, chain,
		"-m", "set", "--match-set", nh.clientBypassSetName(ipt), "src",
		"-j", "RETURN",
	)
}

func createClientBypassSet(name string, family uint8) error {
	return netlink.IpsetCreate(name, "hash:net", netlink.IpsetCreateOptions{Family: family})
}

func destroyClientBypassSet(name string) error {
	err := netlink.IpsetDestroy(name)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func populateClientBypassSet(name string, ipv6 bool, networks []SourceNetwork) error {
	for _, network := range networks {
		if network.IPv6 != ipv6 {
			continue
		}
		if err := netlink.IpsetAdd(name, &netlink.IPSetEntry{
			IP:      slices.Clone(network.IP),
			CIDR:    network.CIDR,
			Replace: true,
		}); err != nil {
			return fmt.Errorf("failed to add %s to %s: %w", network.Canonical, name, err)
		}
	}
	return nil
}

type clientBypassSpec struct {
	active string
	shadow string
	family uint8
	ipv6   bool
}

func (nh *Helper) clientBypassSpecs() ([]clientBypassSpec, error) {
	specs := make([]clientBypassSpec, 0, 2)
	base := nh.IpsetPrefix + clientBypassSetSuffix
	if nh.IPTables4 != nil {
		specs = append(specs, clientBypassSpec{active: base + "_4", shadow: base + "_4_n", family: unix.AF_INET})
	}
	if nh.IPTables6 != nil {
		specs = append(specs, clientBypassSpec{active: base + "_6", shadow: base + "_6_n", family: unix.AF_INET6, ipv6: true})
	}
	for _, spec := range specs {
		// Linux IPSET_MAXNAMELEN includes the trailing NUL.
		if len(spec.shadow) >= 32 {
			return nil, fmt.Errorf("ipset tablePrefix is too long for client routing: %q", nh.IpsetPrefix)
		}
	}
	return specs, nil
}

// SetupClientBypass creates the permanent active sets before any iptables rule
// can reference them. Stale sets from an unclean shutdown are reconciled.
func (nh *Helper) SetupClientBypass(values []string) ([]string, error) {
	normalized, networks, err := NormalizeSourceNetworks(values)
	if err != nil {
		return nil, err
	}

	nh.clientBypassMu.Lock()
	defer nh.clientBypassMu.Unlock()
	base := nh.IpsetPrefix + clientBypassSetSuffix
	for _, name := range []string{base + "_4", base + "_6", base + "_4_n", base + "_6_n"} {
		if err := destroyClientBypassSet(name); err != nil {
			return nil, fmt.Errorf("failed to remove stale client bypass set %s: %w", name, err)
		}
	}

	specs, err := nh.clientBypassSpecs()
	if err != nil {
		return nil, err
	}
	created := make([]string, 0, len(specs))
	for _, spec := range specs {
		if err := createClientBypassSet(spec.active, spec.family); err != nil {
			for _, name := range created {
				_ = destroyClientBypassSet(name)
			}
			return nil, fmt.Errorf("failed to create client bypass set %s: %w", spec.active, err)
		}
		created = append(created, spec.active)
		if err := populateClientBypassSet(spec.active, spec.ipv6, networks); err != nil {
			for _, name := range created {
				_ = destroyClientBypassSet(name)
			}
			return nil, err
		}
	}
	nh.clientBypassReady = true
	return normalized, nil
}

// UpdateClientBypass replaces both families with shadow-set swaps. Rules keep
// referencing the stable active names throughout the update.
func (nh *Helper) UpdateClientBypass(values []string) ([]string, error) {
	normalized, networks, err := NormalizeSourceNetworks(values)
	if err != nil {
		return nil, err
	}

	nh.clientBypassMu.Lock()
	defer nh.clientBypassMu.Unlock()
	if !nh.clientBypassReady {
		return nil, errors.New("client bypass sets are not initialized")
	}

	specs, err := nh.clientBypassSpecs()
	if err != nil {
		return nil, err
	}
	for _, spec := range specs {
		if err := destroyClientBypassSet(spec.shadow); err != nil {
			return nil, fmt.Errorf("failed to remove stale shadow set %s: %w", spec.shadow, err)
		}
		if err := createClientBypassSet(spec.shadow, spec.family); err != nil {
			for _, cleanup := range specs {
				_ = destroyClientBypassSet(cleanup.shadow)
			}
			return nil, fmt.Errorf("failed to create shadow set %s: %w", spec.shadow, err)
		}
		if err := populateClientBypassSet(spec.shadow, spec.ipv6, networks); err != nil {
			for _, cleanup := range specs {
				_ = destroyClientBypassSet(cleanup.shadow)
			}
			return nil, err
		}
	}

	swapped := make([]clientBypassSpec, 0, len(specs))
	for _, spec := range specs {
		if err := netlink.IpsetSwap(spec.active, spec.shadow); err != nil {
			var rollbackErrs []error
			for i := len(swapped) - 1; i >= 0; i-- {
				if rollbackErr := netlink.IpsetSwap(swapped[i].active, swapped[i].shadow); rollbackErr != nil {
					rollbackErrs = append(rollbackErrs, fmt.Errorf("failed to roll back client bypass set %s: %w", swapped[i].active, rollbackErr))
				}
			}
			for _, cleanup := range specs {
				_ = destroyClientBypassSet(cleanup.shadow)
			}
			return nil, errors.Join(fmt.Errorf("failed to swap client bypass set %s: %w", spec.active, err), errors.Join(rollbackErrs...))
		}
		swapped = append(swapped, spec)
	}
	for _, spec := range specs {
		if err := destroyClientBypassSet(spec.shadow); err != nil {
			log.Warn().Err(err).Str("ipset", spec.shadow).Msg("failed to remove old client bypass shadow set")
		}
	}
	return normalized, nil
}

func (nh *Helper) DestroyClientBypass() error {
	nh.clientBypassMu.Lock()
	defer nh.clientBypassMu.Unlock()
	nh.clientBypassReady = false
	return errors.Join(
		destroyClientBypassSet(nh.IpsetPrefix+clientBypassSetSuffix+"_4"),
		destroyClientBypassSet(nh.IpsetPrefix+clientBypassSetSuffix+"_6"),
		destroyClientBypassSet(nh.IpsetPrefix+clientBypassSetSuffix+"_4_n"),
		destroyClientBypassSet(nh.IpsetPrefix+clientBypassSetSuffix+"_6_n"),
	)
}
