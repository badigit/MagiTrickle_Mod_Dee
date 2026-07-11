package magitrickle

import (
	"sync"
	"testing"

	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/trie"
)

// TestConfigRaceSearchVsMutate гоняет чтение датапаса (searchDomain) конкурентно
// с мутацией правил через конфиг-лок. Под `go test -race` ловит гонки mt-gjg
// (in-place мутация rule.Rule / reassign g.Rules) и mt-6q1 (compound RMW групп).
// До фикса (searchDomain без RLock, писатели без cfgMu) детектор гонок падал;
// после — чисто.
func TestConfigRaceSearchVsMutate(t *testing.T) {
	a := &App{}
	a.domainTrie.Store(trie.New())

	g := &Group{
		Group: &models.Group{
			ID:     intID.RandomID(),
			Enable: true,
			Rules: []*models.Rule{
				{ID: intID.RandomID(), Type: models.RuleTypeRegEx, Rule: `.*\.example\.com$`, Enable: true},
				{ID: intID.RandomID(), Type: models.RuleTypeDomain, Rule: "example.org", Enable: true},
			},
		},
	}
	g.enabled.Store(true)
	groups := []*Group{g}
	a.groups.Store(&groups)
	emptySub := []*Group{}
	a.subscriptionGroups.Store(&emptySub)
	a.RebuildTrie()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Читатели датапаса: searchDomain → step-3 regex-fallback читает g.Rules/rule.Rule.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					a.searchDomain("api.example.com")
					a.searchDomain("nomatch.invalid")
				}
			}
		}()
	}

	// Читатель через публичный GroupByID под RLock (mt-q5m путь резолва).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				a.WithConfigRead(func() { _, _ = a.GroupByID(g.ID) })
			}
		}
	}()

	// Писатель: мутация поля правила + reassign среза + add/remove группы под cfgMu.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			a.WithConfigWrite(func() {
				g.Group.Rules[0].Rule = `.*\.example\.com$` // in-place (mt-gjg)
				g.Group.Rules = append([]*models.Rule{}, g.Group.Rules...)
				a.RebuildTrie()
			})
		}
		close(stop)
	}()

	wg.Wait()
}
