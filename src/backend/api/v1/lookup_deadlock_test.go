package v1

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"bytes"
	"encoding/json"

	"magitrickle/api/v1/types"
	"magitrickle/app"
	"magitrickle/models"
)

// cfgLockApp воспроизводит реальную дисциплину блокировок App: WithConfigRead —
// это RLock того же мьютекса, который берут DirectPriority и
// SearchDomainVerdict. Именно на этом сочетании возникает дедлок, если хендлер
// вызывает их изнутри WithConfigRead: sync.RWMutex не реентрантен, и писатель,
// вставший в очередь между внешним и внутренним RLock, блокирует оба навсегда.
type cfgLockApp struct {
	app.Main
	mu     sync.RWMutex
	groups []app.Group
	// writerWaiting сигналит тесту, что писатель встал в очередь за Lock.
	writerWaiting chan struct{}
	writerOnce    sync.Once
}

func (f *cfgLockApp) WithConfigRead(fn func()) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	// Пока внешний RLock удерживается, запускаем писателя — как это делает
	// живой роутер: обновление подписок или правка группы в соседнем запросе.
	f.writerOnce.Do(func() {
		go func() {
			close(f.writerWaiting)
			f.mu.Lock()
			f.mu.Unlock()
		}()
		<-f.writerWaiting
		time.Sleep(20 * time.Millisecond) // дать писателю встать в очередь
	})
	fn()
}

func (f *cfgLockApp) Groups() []app.Group                   { return f.groups }
func (f *cfgLockApp) RoutingGroups() []app.Group            { return f.groups }
func (f *cfgLockApp) Subscriptions() []*models.Subscription { return nil }
func (f *cfgLockApp) IsRoutingActive() bool                 { return true }

func (f *cfgLockApp) DirectPriority() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return models.DirectPriorityAbsolute
}

func (f *cfgLockApp) SearchDomainVerdict(domain string) (app.Group, string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.groups) == 0 {
		return nil, "", false
	}
	return f.groups[0], models.LookupWhyExact, true
}

// Lookup обязан считать winner вне конфиг-лока. Если расчёт снова уедет под
// WithConfigRead, этот тест не упадёт с ошибкой, а зависнет — поэтому ждём с
// дедлайном и валим по таймауту.
func TestLookupDoesNotDeadlockWithConcurrentWriter(t *testing.T) {
	fake := &cfgLockApp{
		groups:        []app.Group{lookupGroup("AI", &models.Rule{Type: models.RuleTypeDomain, Rule: "claude.ai", Enable: true})},
		writerWaiting: make(chan struct{}),
	}

	body, err := json.Marshal(types.LookupReq{Queries: []string{"claude.ai", "10.0.0.1"}, CheckIpset: true})
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan int, 1)
	go func() {
		res := httptest.NewRecorder()
		NewRouter(fake).ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/lookup", bytes.NewReader(body)))
		done <- res.Code
	}()

	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("status = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lookup завис: рекурсивный RLock под ожидающим писателем — тот самый дедлок, который вешает DNS роутера")
	}
}
