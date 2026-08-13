package magitrickle

import (
	"testing"

	"magitrickle/models"
)

// searchDomainExplain — единственный источник и решения, и его объяснения:
// /api/v1/lookup показывает пользователю победителя арбитража (mt-ztg), и если
// объяснение начнёт расходиться с фактическим роутингом, тула будет уверенно
// врать. Поэтому каждый кейс проверяет и группу, и слой, и паритет с
// searchDomain, который остаётся тонкой обёрткой.
func TestSearchDomainExplain(t *testing.T) {
	cases := []struct {
		name     string
		base     []*Group
		subs     []*Group
		query    string
		wantName string
		wantWhy  string
	}{
		{
			name: "точное правило: why=exact",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeDomain, "example.com")),
				sdGroup("B", true, sdRule(models.RuleTypeWildcard, "*.com")),
			},
			query:    "example.com",
			wantName: "A",
			wantWhy:  models.LookupWhyExact,
		},
		{
			name: "namespace ловит поддомен: why=namespace",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeNamespace, "example.com")),
			},
			query:    "cdn.example.com",
			wantName: "A",
			wantWhy:  models.LookupWhyNamespace,
		},
		{
			name: "wildcard-слой, когда trie промахнулся: why=wildcard",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeDomain, "other.com")),
				sdGroup("B", true, sdRule(models.RuleTypeWildcard, "*.example.com")),
			},
			query:    "cdn.example.com",
			wantName: "B",
			wantWhy:  models.LookupWhyWildcard,
		},
		{
			name: "regex-фолбэк последний: why=regex",
			base: []*Group{
				sdGroup("A", true, sdRule(models.RuleTypeRegEx, `\.tun$`)),
			},
			query:    "host.tun",
			wantName: "A",
			wantWhy:  models.LookupWhyRegex,
		},
		{
			name: "подписка проигрывает базовой группе при равном слое",
			base: []*Group{
				sdGroup("base", true, sdRule(models.RuleTypeNamespace, "example.com")),
			},
			subs: []*Group{
				sdGroup("sub", true, sdRule(models.RuleTypeNamespace, "example.com")),
			},
			query:    "cdn.example.com",
			wantName: "base",
			wantWhy:  models.LookupWhyNamespace,
		},
		{
			name: "catch-all подписки не бьёт точное правило группы",
			base: []*Group{
				sdGroup("base", true, sdRule(models.RuleTypeDomain, "example.com")),
			},
			subs: []*Group{
				sdGroup("sub", true, sdRule(models.RuleTypeWildcard, "*")),
			},
			query:    "example.com",
			wantName: "base",
			wantWhy:  models.LookupWhyExact,
		},
		{
			name: "выключенное правило не выигрывает",
			base: []*Group{
				sdGroup("A", true, sdRuleDisabled(models.RuleTypeDomain, "example.com")),
			},
			query:    "example.com",
			wantName: "",
			wantWhy:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newSearchApp(tc.base, tc.subs)

			g, why, found := a.searchDomainExplain(tc.query)

			if tc.wantName == "" {
				if found {
					t.Fatalf("ожидали промах, получили группу %q (why=%q)", g.Name, why)
				}
				return
			}
			if !found {
				t.Fatalf("ожидали победителя %q, получили промах", tc.wantName)
			}
			if g.Name != tc.wantName {
				t.Errorf("группа = %q, want %q", g.Name, tc.wantName)
			}
			if why != tc.wantWhy {
				t.Errorf("why = %q, want %q", why, tc.wantWhy)
			}

			// Паритет: объяснение обязано указывать на ту же группу, которую
			// реально выберет роутинг.
			sg, sFound := a.searchDomain(tc.query)
			if sFound != found {
				t.Errorf("паритет found: searchDomain = %v, explain = %v", sFound, found)
			}
			if sFound && sg != g {
				t.Errorf("паритет группы: searchDomain = %q, explain = %q", sg.Name, g.Name)
			}
		})
	}
}
