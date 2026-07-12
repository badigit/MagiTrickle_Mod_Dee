package magitrickle

import (
	"testing"

	"magitrickle/models"
	"magitrickle/utils/trie"
)

// Эти тесты замораживают продуктовую политику арбитража доменов (mt-7rd,
// Вариант 1): при пересечении правил ПОБЕЖДАЕТ ПЕРВАЯ ГРУППА в порядке
// routingGroups() — базовые группы раньше подписок, — а внутри домена работает
// фиксированный приоритет слоёв trie(exact/namespace) > wildcard > regex.
// Порядок одинаков для доменного арбитража (здесь) и IP-арбитража (порядок
// iptables-цепочек, first-wins во всех режимах после mt-sd3), давая единое
// правило: «выше в списке = побеждает». searchDomain — источник истины для
// того, В ЧЕЙ ipset попадёт IP резолвнутого домена.

func sdRule(t, rule string) *models.Rule {
	return &models.Rule{Type: t, Rule: rule, Enable: true}
}

func sdRuleDisabled(t, rule string) *models.Rule {
	return &models.Rule{Type: t, Rule: rule, Enable: false}
}

func sdGroup(name string, enable bool, rules ...*models.Rule) *Group {
	g := &Group{Group: &models.Group{Name: name, Enable: enable, Rules: rules}}
	g.enabled.Store(enable)
	return g
}

func newSearchApp(base, subs []*Group) *App {
	a := &App{}
	a.domainTrie.Store(trie.New())
	a.groups.Store(&base)
	a.subscriptionGroups.Store(&subs)
	a.RebuildTrie()
	return a
}

// TestSearchDomainArbitration покрывает кросс-групповой и кросс-слойный
// арбитраж searchDomain. want == "" означает «ни одна группа не выиграла».
func TestSearchDomainArbitration(t *testing.T) {
	cases := []struct {
		name  string
		base  []*Group
		subs  []*Group
		query string
		want  string
	}{
		{
			name: "trie exact бьёт wildcard другой группы",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeDomain, "example.com")),
				sdGroup("B", true, sdRule(models.RuleTypeWildcard, "*.com")),
			},
			query: "example.com",
			want:  "A",
		},
		{
			name: "два wildcard — первая группа по порядку конфига",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeWildcard, "*.example.org")),
				sdGroup("B", true, sdRule(models.RuleTypeWildcard, "*.example.org")),
			},
			query: "x.example.org",
			want:  "A",
		},
		{
			name: "regex-fallback отдаёт свою группу когда trie/wildcard молчат",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeDomain, "other.com")),
				sdGroup("B", true, sdRule(models.RuleTypeRegEx, `\.vpn$`)),
			},
			query: "host.vpn",
			want:  "B",
		},
		{
			name: "приоритет слоёв trie > wildcard > regex между разными группами",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeNamespace, "svc.net")),
				sdGroup("B", true, sdRule(models.RuleTypeWildcard, "*.net")),
				sdGroup("C", true, sdRule(models.RuleTypeRegEx, `net$`)),
			},
			query: "x.svc.net",
			want:  "A",
		},
		{
			name: "disabled-группа не участвует",
			base: []*Group{
				sdGroup("A", false, sdRule(models.RuleTypeDomain, "site.com")),
				sdGroup("B", true, sdRule(models.RuleTypeNamespace, "site.com")),
			},
			query: "site.com",
			want:  "B",
		},
		{
			name: "disabled-правило не участвует",
			base: []*Group{
				sdGroup("A", true,
					sdRuleDisabled(models.RuleTypeDomain, "foo.com"),
					sdRule(models.RuleTypeWildcard, "*.bar.com"),
				),
			},
			query: "foo.com",
			want:  "", // единственное подходящее правило выключено
		},
		{
			name:  "база раньше подписки при одинаковом wildcard",
			base:  []*Group{sdGroup("BASE", true, sdRule(models.RuleTypeWildcard, "*.example.com"))},
			subs:  []*Group{sdGroup("SUB", true, sdRule(models.RuleTypeWildcard, "*.example.com"))},
			query: "a.example.com",
			want:  "BASE",
		},
		{
			// mt-4ho: Domain-тип = точное совпадение, поддомены НЕ матчит.
			// Поэтому catch-all '*' из подписки честно выигрывает 2ip.ru — это
			// ожидаемое поведение exact-семантики, а не «подписка перебила группу».
			name:  "Domain(exact) 'ru' не ловит поддомен -> catch-all подписки выигрывает",
			base:  []*Group{sdGroup("G", true, sdRule(models.RuleTypeDomain, "ru"))},
			subs:  []*Group{sdGroup("SUB", true, sdRule(models.RuleTypeWildcard, "*"))},
			query: "2ip.ru",
			want:  "SUB",
		},
		{
			name:  "Domain(exact) 'ru' ловит ровно 'ru'",
			base:  []*Group{sdGroup("G", true, sdRule(models.RuleTypeDomain, "ru"))},
			subs:  []*Group{sdGroup("SUB", true, sdRule(models.RuleTypeWildcard, "*"))},
			query: "ru",
			want:  "G",
		},
		{
			// Путь исправления для mt-4ho: namespace-тип ловит поддомены.
			name:  "Namespace 'ru' ловит поддомен 2ip.ru",
			base:  []*Group{sdGroup("G", true, sdRule(models.RuleTypeNamespace, "ru"))},
			subs:  []*Group{sdGroup("SUB", true, sdRule(models.RuleTypeWildcard, "*"))},
			query: "2ip.ru",
			want:  "G",
		},
		{
			// Wildcard без глоб-символов трактуется RebuildTrie как namespace.
			name:  "Wildcard-без-глоба 'ru' == namespace, ловит 2ip.ru",
			base:  []*Group{sdGroup("G", true, sdRule(models.RuleTypeWildcard, "ru"))},
			subs:  []*Group{sdGroup("SUB", true, sdRule(models.RuleTypeWildcard, "*"))},
			query: "2ip.ru",
			want:  "G",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newSearchApp(tc.base, tc.subs)
			g, ok := a.searchDomain(tc.query)
			if tc.want == "" {
				if ok {
					t.Fatalf("searchDomain(%q): ожидали промах, получили группу %q", tc.query, g.Name)
				}
				return
			}
			if !ok {
				t.Fatalf("searchDomain(%q): ожидали группу %q, получили промах", tc.query, tc.want)
			}
			if g.Name != tc.want {
				t.Errorf("searchDomain(%q) = %q, ожидали %q", tc.query, g.Name, tc.want)
			}
		})
	}
}

// TestRoutingGroupsOrder закрепляет инвариант источника арбитража: базовые
// группы всегда идут ПЕРЕД подписочными в routingGroups(), что и делает базу
// приоритетнее подписок в searchDomain и в порядке iptables-цепочек.
func TestRoutingGroupsOrder(t *testing.T) {
	base := []*Group{sdGroup("base1", true), sdGroup("base2", true)}
	subs := []*Group{sdGroup("sub1", true)}
	a := newSearchApp(base, subs)

	got := a.routingGroups()
	want := []string{"base1", "base2", "sub1"}
	if len(got) != len(want) {
		t.Fatalf("routingGroups() длина = %d, ожидали %d", len(got), len(want))
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("routingGroups()[%d] = %q, ожидали %q (база должна быть раньше подписок)", i, got[i].Name, name)
		}
	}
}
