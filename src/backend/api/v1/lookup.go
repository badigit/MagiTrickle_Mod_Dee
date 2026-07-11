package v1

import (
	"net"
	"net/http"
	"strings"

	"magitrickle/api/utils"
	"magitrickle/api/v1/types"
	"magitrickle/models"
)

// Lookup выполняет batch-проверку доменов/IP/подсетей по правилам групп,
// подписок и (опционально) по ipset на роутере.
func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.LookupReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Queries) == 0 {
		utils.WriteJson(w, http.StatusOK, types.LookupRes{Results: []types.LookupResult{}})
		return
	}

	// Collect all rule sources: groups + subscriptions
	type ruleSource = lookupSource

	// Чтение под RLock: matchRule/итерация читают rule.Rule и *.Rules, которые
	// API-писатели мутируют in-place (mt-gjg/mt-jfc). WriteJson — вне лока.
	var results []types.LookupResult
	h.app.WithConfigRead(func() {
		var sources []ruleSource
		appGroups := h.app.Groups()
		for _, g := range appGroups {
			m := g.Model()
			if !m.Enable {
				continue
			}
			sources = append(sources, ruleSource{
				id:     m.ID.String(),
				name:   m.Name,
				source: "group",
				rules:  m.Rules,
			})
		}
		for _, s := range h.app.Subscriptions() {
			if !s.Enable {
				continue
			}
			sources = append(sources, ruleSource{
				id:     s.ID.String(),
				name:   s.Name,
				source: "subscription",
				rules:  s.Rules,
			})
		}

		// Preload ipset data if requested
		type ipsetEntry struct {
			groupID   string
			groupName string
			source    string
			setName   string
			network   net.IPNet
		}
		var ipsetEntries []ipsetEntry

		if req.CheckIpset {
			for _, g := range appGroups {
				m := g.Model()
				if !m.Enable {
					continue
				}
				gid := m.ID.String()

				if ipv4, err := g.ListIPv4Subnets(); err == nil {
					for subnet := range ipv4 {
						cidr := subnet.CIDR
						if cidr == 0 {
							cidr = 32
						}
						ipsetEntries = append(ipsetEntries, ipsetEntry{
							groupID:   gid,
							groupName: m.Name,
							source:    "group",
							network: net.IPNet{
								IP:   net.IP(subnet.Address[:]),
								Mask: net.CIDRMask(int(cidr), 32),
							},
						})
					}
				}
				if ipv6, err := g.ListIPv6Subnets(); err == nil {
					for subnet := range ipv6 {
						cidr := subnet.CIDR
						if cidr == 0 {
							cidr = 128
						}
						ipsetEntries = append(ipsetEntries, ipsetEntry{
							groupID:   gid,
							groupName: m.Name,
							source:    "group",
							network: net.IPNet{
								IP:   net.IP(subnet.Address[:]),
								Mask: net.CIDRMask(int(cidr), 128),
							},
						})
					}
				}
			}
		}

		results = make([]types.LookupResult, len(req.Queries))
		for qi, query := range req.Queries {
			result := types.LookupResult{
				Query:    query,
				RuleHits: []types.RuleHit{},
			}

			qLower := strings.ToLower(strings.TrimSpace(query))
			qIP, qNet := parseIPOrCIDR(qLower)

			// Check rules
			for _, src := range sources {
				for _, rule := range src.rules {
					if !rule.Enable {
						continue
					}
					if hit := matchRule(rule, qLower, qIP, qNet, src); hit != nil {
						result.RuleHits = append(result.RuleHits, *hit)
					}
				}
			}

			// Check ipset
			if req.CheckIpset && qIP != nil {
				result.IpsetHits = []types.IpsetHit{}
				seen := make(map[string]bool)
				for _, entry := range ipsetEntries {
					if entry.network.Contains(qIP) {
						if !seen[entry.groupID] {
							seen[entry.groupID] = true
							result.IpsetHits = append(result.IpsetHits, types.IpsetHit{
								GroupID:   entry.groupID,
								GroupName: entry.groupName,
								Source:    entry.source,
							})
						}
					}
				}
			}

			results[qi] = result
		}
	})

	utils.WriteJson(w, http.StatusOK, types.LookupRes{Results: results})
}

type lookupSource struct {
	id     string
	name   string
	source string // "group" or "subscription"
	rules  []*models.Rule
}

func parseIPOrCIDR(s string) (net.IP, *net.IPNet) {
	if strings.Contains(s, "/") {
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil
		}
		return ip, ipNet
	}
	ip := net.ParseIP(s)
	return ip, nil
}

func matchRule(rule *models.Rule, qLower string, qIP net.IP, qNet *net.IPNet, src lookupSource) *types.RuleHit {
	rLower := strings.ToLower(rule.Rule)
	hit := types.RuleHit{
		GroupID:   src.id,
		GroupName: src.name,
		Source:    src.source,
		RuleType:  rule.Type,
		Rule:      rule.Rule,
	}

	switch rule.Type {
	case models.RuleTypeDomain:
		if qLower == rLower {
			hit.Match = "exact"
			return &hit
		}

	case models.RuleTypeNamespace:
		if qLower == rLower {
			hit.Match = "exact"
			return &hit
		}
		if len(qLower) > len(rLower)+1 && qLower[len(qLower)-len(rLower)-1] == '.' && qLower[len(qLower)-len(rLower):] == rLower {
			hit.Match = "namespace"
			return &hit
		}

	case models.RuleTypeWildcard:
		if rule.IsMatch(qLower) {
			hit.Match = "wildcard"
			return &hit
		}

	case models.RuleTypeRegEx:
		if rule.IsMatch(qLower) {
			hit.Match = "regex"
			return &hit
		}

	case models.RuleTypeSubnet, models.RuleTypeSubnet6:
		_, rNet, err := net.ParseCIDR(rule.Rule)
		if err != nil {
			rIP := net.ParseIP(rule.Rule)
			if rIP == nil {
				return nil
			}
			bits := 32
			if rIP.To4() == nil {
				bits = 128
			}
			rNet = &net.IPNet{IP: rIP, Mask: net.CIDRMask(bits, bits)}
		}

		// Query is a single IP
		if qIP != nil && qNet == nil {
			if rNet.Contains(qIP) {
				hit.Match = "contains"
				return &hit
			}
		}
		// Query is a CIDR
		if qNet != nil {
			qOnes, _ := qNet.Mask.Size()
			rOnes, _ := rNet.Mask.Size()
			if rNet.Contains(qNet.IP) && qOnes >= rOnes {
				hit.Match = "subnet_of"
				return &hit
			}
			if qNet.Contains(rNet.IP) && rOnes >= qOnes {
				hit.Match = "supernet_of"
				return &hit
			}
		}
	}
	return nil
}
