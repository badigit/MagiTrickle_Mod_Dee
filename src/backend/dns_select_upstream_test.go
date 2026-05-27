package magitrickle

import (
	"fmt"
	"testing"

	"magitrickle/models"
	"magitrickle/utils/trie"

	"github.com/miekg/dns"
)

// TestSelectUpstream проверяет что selectUpstream корректно отделяет
// in-group домены (primary) от out-of-group (fallback). Subnet-правила
// на этом уровне игнорируются — они обрабатываются post-resolve.
func TestSelectUpstream(t *testing.T) {
	a := &App{}
	a.domainTrie.Store(trie.New())

	// Минимальная группа с разными типами правил
	g := &Group{
		Group: &models.Group{
			Enable: true,
			Rules: []*models.Rule{
				{Type: models.RuleTypeDomain, Rule: "example.com", Enable: true},
				{Type: models.RuleTypeNamespace, Rule: "test.org", Enable: true},
				{Type: models.RuleTypeSubnet, Rule: "192.0.2.0/24", Enable: true}, // не должно матчиться по домену
			},
		},
	}
	g.enabled.Store(true)

	groups := []*Group{g}
	a.groups.Store(&groups)
	emptySubGroups := []*Group{}
	a.subscriptionGroups.Store(&emptySubGroups)

	a.RebuildTrie()

	tests := []struct {
		name     string
		question string // пустая строка = пустой Msg без Questions
		wantFB   bool
	}{
		{"empty msg → fallback", "", true},
		{"matched RuleTypeDomain", "example.com", false},
		{"matched namespace exact", "test.org", false},
		{"matched namespace child", "x.test.org", false},
		{"matched namespace deeper", "a.b.test.org", false},
		{"unmatched suffix", "atest.org", true}, // НЕ matched (не subdomain test.org)
		{"unmatched RU", "yandex.ru", true},
		{"unmatched subnet-only domain", "any.unmatched.org", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := dns.Msg{}
			if tt.question != "" {
				req.SetQuestion(dns.Fqdn(tt.question), dns.TypeA)
			}
			got := a.selectUpstream(req)
			if got != tt.wantFB {
				t.Errorf("selectUpstream(%q) = %v, want %v", tt.question, got, tt.wantFB)
			}
		})
	}
}

// makeBenchApp собирает App с N domain-правилами и M namespace-правилами
// для замера накладных расходов selectUpstream/searchDomain под реалистичной
// нагрузкой правил (≈400 правил, как у пользователя).
func makeBenchApp(domains, namespaces int) *App {
	a := &App{}
	a.domainTrie.Store(trie.New())

	var rules []*models.Rule
	for i := 0; i < domains; i++ {
		rules = append(rules, &models.Rule{
			Type:   models.RuleTypeDomain,
			Rule:   fmt.Sprintf("d%d.example.com", i),
			Enable: true,
		})
	}
	for i := 0; i < namespaces; i++ {
		rules = append(rules, &models.Rule{
			Type:   models.RuleTypeNamespace,
			Rule:   fmt.Sprintf("ns%d.example.org", i),
			Enable: true,
		})
	}
	g := &Group{Group: &models.Group{Enable: true, Rules: rules}}
	g.enabled.Store(true)
	groups := []*Group{g}
	a.groups.Store(&groups)
	emptySubGroups := []*Group{}
	a.subscriptionGroups.Store(&emptySubGroups)
	a.RebuildTrie()
	return a
}

// BenchmarkSelectUpstream_Hit — путь когда домен matched в trie (in-group).
func BenchmarkSelectUpstream_Hit(b *testing.B) {
	a := makeBenchApp(200, 200)
	req := dns.Msg{}
	req.SetQuestion(dns.Fqdn("ns42.example.org"), dns.TypeA)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.selectUpstream(req)
	}
}

// BenchmarkSelectUpstream_Miss — путь когда домен НЕ matched (out-of-group).
// Это худший случай: trie miss + wildcard scan (тут wildcards=0).
func BenchmarkSelectUpstream_Miss(b *testing.B) {
	a := makeBenchApp(200, 200)
	req := dns.Msg{}
	req.SetQuestion(dns.Fqdn("yandex.ru"), dns.TypeA)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.selectUpstream(req)
	}
}

// BenchmarkSelectUpstream_Empty — путь без вопросов (early return).
func BenchmarkSelectUpstream_Empty(b *testing.B) {
	a := makeBenchApp(200, 200)
	req := dns.Msg{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.selectUpstream(req)
	}
}
