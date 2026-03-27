package magitrickle

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"magitrickle/app"
	"magitrickle/constant"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"
	"magitrickle/utils/trie"

	"github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/rs/zerolog/log"
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
	enabled atomic.Bool

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
}

// New создаёт новый экземпляр App
func New() *App {
	a := &App{
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
func (a *App) searchDomain(domain string) (*Group, bool) {
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

	// если приложение уже запущено – включаем группу и выполняем синхронизацию
	if a.enabled.Load() {
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
