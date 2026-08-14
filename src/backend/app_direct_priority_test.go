package magitrickle

import (
	"errors"
	"strings"
	"testing"

	"magitrickle/models"
	"magitrickle/utils/trie"
)

// newDirectPriorityApp — App, у которого подъём и снятие роутинга подменены:
// настоящие трогают netfilter, которого в тестах нет, а проверять надо именно
// поведение переключателя вокруг них.
func newDirectPriorityApp(t *testing.T, mode string, routingUp bool) *App {
	t.Helper()
	a := &App{}
	a.config = models.AppConfig{}
	a.config.Netfilter.DirectPriority = mode
	a.config.Enabled = routingUp
	a.routingActive.Store(routingUp)
	a.domainTrie.Store(trie.New())
	empty := make([]*Group, 0)
	a.groups.Store(&empty)
	a.subscriptionGroups.Store(&empty)
	// Сохранение в тестах — no-op: проверяем поведение переключателя, а не
	// запись YAML, которой в тестовой среде некуда лечь.
	a.saveConfigFn = func() error { return nil }
	return a
}

// Заявленная транзакционность: если подъём после смены режима не удался,
// система обязана вернуться к прежнему режиму И к поднятому роутингу. Иначе
// одна неудачная попытка переключения оставляет роутер без правил.
func TestSetDirectPriorityRollsBackRoutingAfterFailedBringUp(t *testing.T) {
	a := newDirectPriorityApp(t, models.DirectPriorityAbsolute, true)

	var downCalls, upCalls int
	a.bringDownFn = func() error {
		downCalls++
		a.routingActive.Store(false)
		return nil
	}
	a.bringUpFn = func() error {
		upCalls++
		if upCalls == 1 {
			// Настоящий bringUpRouting при неудаче снимает всё и гасит флаг.
			a.routingActive.Store(false)
			return errors.New("boom")
		}
		a.routingActive.Store(true)
		return nil
	}

	err := a.SetDirectPriority(models.DirectPriorityByOrder)
	if err == nil {
		t.Fatal("ожидали ошибку переключения")
	}
	if !a.routingActive.Load() {
		t.Error("роутинг остался снятым — откат не поднял его обратно")
	}
	if got := a.DirectPriority(); got != models.DirectPriorityAbsolute {
		t.Errorf("режим = %q, want %q (откат к прежнему)", got, models.DirectPriorityAbsolute)
	}
	if upCalls != 2 {
		t.Errorf("bringUp вызван %d раз, ожидали 2 (попытка + откат)", upCalls)
	}
}

// После неудачной попытки конфиг и фактическое состояние расходятся, поэтому
// повторный запрос обязан чинить, а не отвечать «уже применено».
func TestSetDirectPriorityRetriesAfterInconsistentState(t *testing.T) {
	a := newDirectPriorityApp(t, models.DirectPriorityAbsolute, true)
	a.bringDownFn = func() error { a.routingActive.Store(false); return nil }
	a.bringUpFn = func() error { a.routingActive.Store(true); return nil }

	// Имитируем последствие сбоя: конфиг говорит absolute, роутинг снят.
	a.routingActive.Store(false)

	if err := a.SetDirectPriority(models.DirectPriorityAbsolute); err != nil {
		t.Fatalf("повторный запрос вернул ошибку: %v", err)
	}
	if !a.routingActive.Load() {
		t.Error("повторный запрос с тем же режимом не поднял роутинг: ранний выход соврал")
	}
}

// Если не удался даже откат, пользователь обязан узнать, что роутинг лежит.
func TestSetDirectPriorityReportsFailedRollback(t *testing.T) {
	a := newDirectPriorityApp(t, models.DirectPriorityAbsolute, true)
	a.bringDownFn = func() error { a.routingActive.Store(false); return nil }
	a.bringUpFn = func() error { a.routingActive.Store(false); return errors.New("boom") }

	err := a.SetDirectPriority(models.DirectPriorityByOrder)
	if err == nil {
		t.Fatal("ожидали ошибку")
	}
	if !strings.Contains(err.Error(), "routing is down") {
		t.Errorf("ошибка не сообщает о снятом роутинге: %v", err)
	}
}

// При снятом роутинге переключение — это правка конфига: поднимать нечего.
func TestSetDirectPriorityWithRoutingDownDoesNotBringUp(t *testing.T) {
	a := newDirectPriorityApp(t, models.DirectPriorityAbsolute, false)
	var upCalls int
	a.bringUpFn = func() error { upCalls++; return nil }
	a.bringDownFn = func() error { return nil }

	if err := a.SetDirectPriority(models.DirectPriorityByOrder); err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if upCalls != 0 {
		t.Errorf("bringUp вызван %d раз при снятом роутинге", upCalls)
	}
	if got := a.DirectPriority(); got != models.DirectPriorityByOrder {
		t.Errorf("режим = %q, want byOrder", got)
	}
}
