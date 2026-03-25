package netfilterTools

import (
	"errors"
	"fmt"
	"strings"

	"magitrickle/utils/iptables"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func (nh *Helper) cleanIPTables(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	jumpToChainPrefix := "-j " + nh.ChainPrefix

	exists, err := ipt.GetCurrentRules()
	if err != nil {
		return fmt.Errorf("listing chains error: %w", err)
	}

	for table, chains := range exists {
		chainListToDelete := make([]string, 0)

		for chain, rules := range chains {
			if strings.HasPrefix(chain, nh.ChainPrefix) {
				chainListToDelete = append(chainListToDelete, chain)
				continue
			}

			for _, r := range rules {
				if !r.Contains(jumpToChainPrefix) {
					continue
				}

				err = ipt.Delete(table, chain, r.Args()...)
				if errors.Is(err, iptables.ErrChainNotInitialized) {
					err = ipt.RegisterChainPatch(table, chain)
					if err != nil {
						return fmt.Errorf("chain register error: %w", err)
					}
					err = ipt.Delete(table, chain, r.Args()...)
				}
				if err != nil {
					return fmt.Errorf("rule deletion error: %w", err)
				}
			}
		}

		for _, chain := range chainListToDelete {
			err = ipt.RegisterChainDelete(table, chain)
			if err != nil {
				return fmt.Errorf("deleting chain error: %w", err)
			}
		}
	}

	err = ipt.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit iptables rules: %w", err)
	}
	return nil
}

func (nh *Helper) CleanIPTables() error {
	var errs []error
	errs = append(errs, nh.cleanIPTables(nh.IPTables4))
	errs = append(errs, nh.cleanIPTables(nh.IPTables6))
	errs = append(errs, nh.cleanIPRulesAndRoutes())
	return errors.Join(errs...)
}

// cleanIPRulesAndRoutes удаляет ip rule и ip route, оставшиеся после аварийного
// завершения. Все mark'и и table ID MagiTrickle начинаются с StartIdx (0x4D616769).
func (nh *Helper) cleanIPRulesAndRoutes() error {
	// Собираем таблицы из ip rules с нашими mark'ами
	tables := make(map[int]struct{})

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list ip rules: %w", err)
	}
	for _, rule := range rules {
		if rule.Mark >= nh.StartIdx && rule.Mark < nh.StartIdx+0x10000 {
			tables[rule.Table] = struct{}{}
			if err := netlink.RuleDel(&rule); err != nil {
				log.Warn().Err(err).Uint32("mark", rule.Mark).Int("table", rule.Table).Msg("failed to delete stale ip rule")
			} else {
				log.Info().Uint32("mark", rule.Mark).Int("table", rule.Table).Msg("cleaned stale ip rule")
			}
		}
	}

	// Удаляем routes из найденных таблиц
	for table := range tables {
		filter := &netlink.Route{Table: table}
		routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
		if err != nil {
			log.Warn().Err(err).Int("table", table).Msg("failed to list routes in stale table")
			continue
		}
		for _, route := range routes {
			if err := netlink.RouteDel(&route); err != nil {
				log.Warn().Err(err).Int("table", table).Msg("failed to delete stale route")
			} else {
				log.Info().Int("table", table).Msg("cleaned stale route")
			}
		}
	}

	return nil
}
