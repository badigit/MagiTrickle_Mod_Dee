package magitrickle

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"magitrickle/app"
	"magitrickle/constant"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"
	"magitrickle/utils/trie"

	"github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var (
	ErrAlreadyRunning           = errors.New("already running")
	ErrGroupIDConflict          = errors.New("group id conflict")
	ErrRuleIDConflict           = errors.New("rule id conflict")
	ErrSubscriptionIDConflict   = errors.New("subscription id conflict")
	ErrConfigUnsupportedVersion = errors.New("config unsupported version")
)

// WildcardRule holds a compiled wildcard pattern and its group.
type WildcardRule struct {
	Rule  string
	Group *Group
}

// App – основная структура ядра приложения
type App struct {
	enabled       atomic.Bool // Start вызван
	routingActive atomic.Bool // routing+DNSOR подняты (false когда пользователь нажал паузу)
	startedAt     time.Time

	config models.AppConfig

	dnsMITM            *dnsMITMProxy.DNSMITMProxy
	nfHelper           *netfilterTools.Helper
	recordsCache       *recordsCache.Records
	groups             atomic.Pointer[[]*Group]
	subscriptionGroups atomic.Pointer[[]*Group]
	subscriptions      atomic.Pointer[[]*models.Subscription]
	dnsOverrider       *netfilterTools.PortRemap

	interfaceAliases map[string]string

	dnsCapture *DNSCapture

	domainTrie atomic.Value // holds *trie.Trie

	wildcardRules       []*WildcardRule
	wildcardRulesLocker sync.RWMutex

	// cfgMu сериализует все мутации конфига (группы/правила/подписки) и
	// защищает lock-free чтения датапаса. См. app_config_lock.go.
	cfgMu sync.RWMutex
}

// New создаёт новый экземпляр App
func New() *App {
	a := &App{
		startedAt:        time.Now(),
		config:           constant.DefaultAppConfig,
		interfaceAliases: make(map[string]string),
		dnsCapture:       NewDNSCapture(),
	}
	emptyGroups := make([]*Group, 0)
	a.groups.Store(&emptyGroups)
	emptySubscriptionGroups := make([]*Group, 0)
	a.subscriptionGroups.Store(&emptySubscriptionGroups)
	emptySubscriptions := make([]*models.Subscription, 0)
	a.subscriptions.Store(&emptySubscriptions)
	if err := a.LoadConfig(); err != nil {
		log.Error().Err(err).Msg("failed to load config file")
	}
	if err := a.LoadInterfaceConfig(); err != nil {
		log.Error().Err(err).Msg("failed to load interface aliases")
	}
	a.domainTrie.Store(trie.New())
	return a
}

// Trie returns the current domain trie.
func (a *App) Trie() *trie.Trie {
	return a.domainTrie.Load().(*trie.Trie)
}

// RebuildTrie rebuilds the domain trie and wildcard/regex rule lists
// from all enabled routing groups. Call after any group/rule change.
func (a *App) RebuildTrie() {
	newTrie := trie.New()
	var newWildcards []*WildcardRule

	for _, g := range a.routingGroups() {
		if !g.Enabled() || !g.Group.Enable {
			continue
		}
		for _, rule := range g.Rules {
			if !rule.IsEnabled() {
				continue
			}
			switch rule.Type {
			case models.RuleTypeDomain:
				newTrie.Insert(rule.Rule, g, true)
			case models.RuleTypeWildcard:
				if strings.Contains(rule.Rule, "*") || strings.Contains(rule.Rule, "?") {
					newWildcards = append(newWildcards, &WildcardRule{
						Rule:  rule.Rule,
						Group: g,
					})
				} else {
					// wildcard without glob chars is effectively a namespace
					cleanDomain := strings.TrimPrefix(rule.Rule, "*.")
					newTrie.Insert(cleanDomain, g, false)
				}
			case models.RuleTypeNamespace:
				newTrie.Insert(rule.Rule, g, false)
			case models.RuleTypeRegEx:
				// regex rules stay as fallback — compiled lazily in rule.IsMatch
				// we don't add them to trie; they are checked in searchFallback
			}
		}
	}
	a.domainTrie.Store(newTrie)

	a.wildcardRulesLocker.Lock()
	a.wildcardRules = newWildcards
	a.wildcardRulesLocker.Unlock()

	log.Debug().
		Int("wildcards", len(newWildcards)).
		Msg("trie rebuilt")
}

// searchDomain looks up a domain in the trie, then falls back to wildcard and regex rules.
// Держит cfgMu.RLock: step 3 (regex-fallback) читает g.Rules/rule.Rule, которые
// API-писатели мутируют in-place под cfgMu.Lock. НЕ вызывать под уже взятым cfgMu.
func (a *App) searchDomain(domain string) (*Group, bool) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()

	// 1. Trie lookup — O(domain parts)
	if data, found := a.Trie().Search(domain); found {
		if g, ok := data.(*Group); ok && g.Enabled() && g.Group.Enable {
			return g, true
		}
	}

	// 2. Wildcard fallback
	a.wildcardRulesLocker.RLock()
	wRules := a.wildcardRules
	a.wildcardRulesLocker.RUnlock()
	for _, wr := range wRules {
		if wildcard.Match(wr.Rule, domain) {
			if wr.Group.Enabled() && wr.Group.Group.Enable {
				return wr.Group, true
			}
		}
	}

	// 3. Regex fallback — iterate all groups, check only regex rules
	for _, g := range a.routingGroups() {
		if !g.Enabled() || !g.Group.Enable {
			continue
		}
		for _, rule := range g.Rules {
			if !rule.IsEnabled() || rule.Type != models.RuleTypeRegEx {
				continue
			}
			if rule.IsMatch(domain) {
				return g, true
			}
		}
	}

	return nil, false
}

// Config возвращает конфигурацию
func (a *App) Config() models.AppConfig {
	return a.config
}

// Groups возвращает список групп
func (a *App) Groups() []app.Group {
	gs := *a.groups.Load()
	groups := make([]app.Group, len(gs))
	for i, g := range gs {
		groups[i] = g
	}
	return groups
}

// ClearGroups отключает все группы и очищает список
func (a *App) ClearGroups() {
	for _, g := range *a.groups.Load() {
		_ = g.Disable()
	}
	emptyGroups := make([]*Group, 0)
	a.groups.Store(&emptyGroups)
}

// SyncAllGroups пересинхронизирует ipset'ы всех активных групп и перестраивает trie.
// Вызывается после изменения конфига групп, чтобы удалить stale IP
// из ipset'ов групп, из которых правила были убраны.
func (a *App) SyncAllGroups() {
	a.RebuildTrie()
	for _, group := range a.routingGroups() {
		if group.Enabled() {
			_ = group.Sync()
		}
	}
}

// AddGroup добавляет новую группу
func (a *App) AddGroup(groupModel *models.Group) error {
	groups := *a.groups.Load()
	for _, group := range groups {
		if groupModel.ID == group.ID {
			return ErrGroupIDConflict
		}
	}
	// Проверка уникальности rule.ID внутри группы.
	dup := make(map[[4]byte]struct{})
	for _, rule := range groupModel.Rules {
		if _, exists := dup[rule.ID]; exists {
			return ErrRuleIDConflict
		}
		dup[rule.ID] = struct{}{}
	}

	grp, err := NewGroup(groupModel, a)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	newGroups := make([]*Group, len(groups)+1)
	copy(newGroups, groups)
	newGroups[len(groups)] = grp
	a.groups.Store(&newGroups)

	log.Info().
		Str("id", grp.ID.String()).
		Str("name", grp.Name).
		Msg("added group")

	// если routing активен – включаем группу и синхронизируем ipset
	if a.routingActive.Load() {
		if err = grp.Enable(); err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
		if err = grp.Sync(); err != nil {
			return fmt.Errorf("failed to sync group: %w", err)
		}
	}
	return nil
}

// RemoveGroupByIndex удаляет группу по индексу
func (a *App) RemoveGroupByIndex(idx int) {
	groups := *a.groups.Load()
	newGroups := make([]*Group, 0, len(groups)-1)
	newGroups = append(newGroups, groups[:idx]...)
	newGroups = append(newGroups, groups[idx+1:]...)
	a.groups.Store(&newGroups)
}

// ListInterfaces возвращает список сетевых интерфейсов, удовлетворяющих заданным критериям
func (a *App) ListInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	if a.config.ShowAllInterfaces {
		return interfaces, nil
	}

	var filteredInterfaces []net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagPointToPoint == 0 || slices.Contains(constant.IgnoredInterfaces, iface.Name) {
			continue
		}
		filteredInterfaces = append(filteredInterfaces, iface)
	}
	return filteredInterfaces, nil
}

// OutgoingLinkIndexes returns the set of interface indexes that carry the
// router's own egress — i.e. have a default route pointing out through them in
// any routing table. That is precisely the precondition for the external-IP
// probe (BindToDevice + HTTP GET) to succeed.
//
// It exists to tell incoming/server tunnels apart from outgoing ones: an SSTP
// server endpoint like sstp0 (the router IS the server, clients dial in) has no
// default route via it and is excluded, so the UI must not auto-run a doomed
// external-IP test against it (mt-8fi). Outgoing tunnels (WAN, WG clients) and
// interface-mode group links do have a default route via them and are included.
func (a *App) OutgoingLinkIndexes() map[int]bool {
	out := make(map[int]bool)
	// Table 0 as the filter means "all tables": interface-mode groups install
	// their default route in a per-group table, so scanning only main misses them.
	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Warn().Err(err).Msg("failed to list routes for outgoing-interface detection")
		return out
	}
	mark := func(linkIndex int) {
		if linkIndex > 0 {
			out[linkIndex] = true
		}
	}
	for _, route := range routes {
		// Only a default route (zero-length destination) grants general egress.
		if route.Dst != nil {
			if ones, _ := route.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		// Skip non-unicast defaults (blackhole/unreachable/prohibit) — e.g. the
		// blackhole default that interface-mode installs as a leak guard.
		if route.Type != unix.RTN_UNICAST {
			continue
		}
		mark(route.LinkIndex)
		for _, nh := range route.MultiPath {
			mark(nh.LinkIndex)
		}
	}
	return out
}

// DnsOverrider возвращает dnsOverrider
func (a *App) DnsOverrider() *netfilterTools.PortRemap {
	return a.dnsOverrider
}

// InterfaceAliases returns a copy of configured interface aliases.
func (a *App) InterfaceAliases() map[string]string {
	aliases := make(map[string]string, len(a.interfaceAliases))
	for k, v := range a.interfaceAliases {
		aliases[k] = v
	}
	return aliases
}

// DNSCapture возвращает экземпляр DNSCapture.
func (a *App) DNSCapture() app.DNSCapturer {
	return a.dnsCapture
}

// SetInterfaceAliases replaces configured interface aliases.
func (a *App) SetInterfaceAliases(aliases map[string]string) {
	a.interfaceAliases = make(map[string]string, len(aliases))
	for k, v := range aliases {
		a.interfaceAliases[k] = v
	}
}

// StartedAt returns the moment when this process was created.
func (a *App) StartedAt() time.Time {
	return a.startedAt
}

// IsRoutingActive reports whether MagiTrickle is currently capturing/routing
// traffic (DnsOverrider + groups enabled).
func (a *App) IsRoutingActive() bool {
	return a.routingActive.Load()
}

// bringUpRouting enables DNS port-remap and all routing groups, syncs IPSet
// from the in-memory DNS cache. Idempotent: safe to call when already up.
func (a *App) bringUpRouting() error {
	if !a.routingActive.CompareAndSwap(false, true) {
		return nil
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Enable(); err != nil {
			a.routingActive.Store(false)
			return fmt.Errorf("failed to override DNS: %w", err)
		}
	}

	for _, group := range a.routingGroups() {
		if err := group.Enable(); err != nil {
			a.routingActive.Store(false)
			return fmt.Errorf("failed to enable group %s: %w", group.Name, err)
		}
		if err := group.Sync(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group sync after enable returned error")
		}
	}
	a.RebuildTrie()
	log.Info().Msg("routing brought up")
	return nil
}

// bringDownRouting tears down dnsOverrider and disables all routing groups.
// Idempotent: no-op when already down.
func (a *App) bringDownRouting() error {
	if !a.routingActive.CompareAndSwap(true, false) {
		return nil
	}

	for _, group := range a.routingGroups() {
		if err := group.Disable(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group disable failed")
		}
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Disable(); err != nil {
			log.Warn().Err(err).Msg("dnsOverrider disable failed")
		}
	}
	log.Info().Msg("routing brought down")
	return nil
}

// SetEnabled toggles routing on/off and persists the choice to config.
// When enabled=false, traffic flows as if MagiTrickle were not running.
func (a *App) SetEnabled(enabled bool) error {
	if a.config.Enabled == enabled && a.routingActive.Load() == enabled {
		return nil
	}

	if enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
	} else {
		_ = a.bringDownRouting()
	}

	a.config.Enabled = enabled
	if err := a.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to persist app.enabled")
		return err
	}
	return nil
}

// Restart spawns a detached shell that calls the platform restart command
// (init.d/procd or systemctl), then exits the current process so the
// supervisor brings magitrickled back up with fresh configuration.
//
// Teardown semantics: the restart command (e.g. `init.d ... restart`) stops
// this service first, which delivers SIGTERM. The normal shutdown path then
// runs gracefully — Start's deferred bringDownRouting + dnsMITM.Close tear down
// the iptables rules and the DNS override (see start.go). So in the normal case
// teardown DOES happen, via the signal, not here.
//
// The os.Exit(0) below is therefore NOT the primary exit — it is a watchdog
// fallback for the degraded case where the restart command fails to terminate
// us within 3s (signal ignored, shutdown hung). In that path teardown is
// intentionally skipped: leaving the iptables rules and DNS override in place
// avoids a routing-leak window, and the freshly started process reconciles any
// stale state on startup (each group's enable() calls ClearIfDisabled before
// re-adding its rules). Hence os.Exit(0), not teardown-then-exit.
func (a *App) Restart() {
	log.Info().Str("cmd", constant.RestartCommand).Msg("restart requested via API")

	cmd := exec.Command("sh", "-c", "sleep 1; "+constant.RestartCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("failed to start restart command")
		return
	}
	go func() { _ = cmd.Wait() }()

	// Watchdog fallback: force-exit if the restart command above did not take us
	// down via SIGTERM within 3s. Teardown is intentionally skipped here — see
	// the function doc for why leaving routing in place is the safe choice.
	go func() {
		time.Sleep(3 * time.Second)
		log.Info().Msg("exiting process to let supervisor restart it")
		os.Exit(0)
	}()
}
