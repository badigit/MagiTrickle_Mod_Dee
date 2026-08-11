package magitrickle

import (
	"testing"

	"magitrickle/constant"
	"magitrickle/models"
)

// newShutdownTestApp — минимальный App без живых netfilter-объектов: групп нет,
// поэтому bringUpRouting дошёл бы до конца без обращения к ядру.
func newShutdownTestApp() *App {
	a := &App{config: constant.DefaultAppConfig}
	emptyGroups := make([]*Group, 0)
	a.groups.Store(&emptyGroups)
	emptySubscriptionGroups := make([]*Group, 0)
	a.subscriptionGroups.Store(&emptySubscriptionGroups)
	emptySubscriptions := make([]*models.Subscription, 0)
	a.subscriptions.Store(&emptySubscriptions)
	return a
}

// TestSetEnabledRejectedDuringShutdown — регресс mt-kd1: после начала shutdown
// демон обязан отказывать в поднятии роутинга. Окно возникало так: teardown в
// Start отпускает lifecycleMu, сняв правила, а HTTP- и unix-листенеры
// закрываются defer'ами, зарегистрированными ВЫШЕ, то есть по LIFO уже ПОСЛЕ.
// В зазоре SetEnabled(true) успевал поднять правила заново, второго teardown
// уже не было — и демон завершался с живыми DNS-remap и TPROXY, а трафик до
// перезапуска сервиса уходил в остановленный процесс.
//
// Закрытием листенеров это не лечится: http.Server.Close рвёт соединения, но
// не отменяет уже запущенный обработчик, поэтому гейт обязан стоять внутри
// SetEnabled, под тем же lifecycleMu, что держит teardown.
func TestSetEnabledRejectedDuringShutdown(t *testing.T) {
	a := newShutdownTestApp()
	a.shuttingDown = true

	err := a.SetEnabled(true)
	if err == nil {
		t.Error("SetEnabled(true) during shutdown must return an error, got nil")
	}
	if a.routingActive.Load() {
		t.Error("routing was brought up during shutdown — teardown has already run, nothing will take it down")
	}
}

// TestSetEnabledDisableAllowedDuringShutdown — гейт не должен мешать снятию:
// выключение во время shutdown безопасно (правила и так снимаются) и не обязано
// падать ошибкой, иначе обычный путь teardown начал бы шуметь в логах.
func TestSetEnabledDisableAllowedDuringShutdown(t *testing.T) {
	a := newShutdownTestApp()
	a.config.Enabled = false
	a.shuttingDown = true

	if err := a.SetEnabled(false); err != nil {
		t.Errorf("SetEnabled(false) during shutdown must be a no-op, got: %v", err)
	}
	if a.routingActive.Load() {
		t.Error("routingActive must stay false")
	}
}

// TestSetEnabledAllowedBeforeShutdown — контроль: без shutdown-флага гейт не
// срабатывает и поднятие проходит штатно.
func TestSetEnabledAllowedBeforeShutdown(t *testing.T) {
	a := newShutdownTestApp()

	if err := a.SetEnabled(true); err != nil {
		// SaveConfig пишет в путь, которого нет в тестовой среде — это ожидаемо
		// и не должно маскировать сам факт поднятия, проверяемый ниже.
		t.Logf("SetEnabled(true) returned: %v (ожидаемо: SaveConfig без /opt)", err)
	}
	if !a.routingActive.Load() {
		t.Error("routing must be brought up when not shutting down")
	}
}
