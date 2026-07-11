package magitrickle

import (
	appiface "magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/intID"
)

// cfgMu (в App) сериализует ЛЮБУЮ мутацию конфига (группы/правила/подписки) и
// защищает lock-free чтения датапаса (searchDomain/RebuildTrie читают g.Rules и
// rule.Rule in-place). Модель: писатели — WithConfigWrite (эксклюзив), датапас и
// API-читатели — WithConfigRead (шаринг). Мутация под эксклюзивом безопасна без
// COW: читатель не может идти конкурентно.
//
// ВАЖНО (перф): под write-локом держим ТОЛЬКО in-memory мутацию + снимок ответа.
// Блокирующий I/O (WriteJson клиенту, SaveConfig на флеш) — ВНЕ лока, иначе
// searchDomain (RLock) встаёт за писателем → стойл DNS. SaveConfig берёт RLock сам.

// WithConfigWrite выполняет fn под эксклюзивным конфиг-локом. Только in-memory
// мутация; без сетевого/дискового I/O внутри fn.
func (a *App) WithConfigWrite(fn func()) {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	fn()
}

// WithConfigRead выполняет fn под шаринг-локом. Для чтений, трогающих изменяемый
// контент правил/групп/подписок (g.Rules, rule.Rule, subscription.Rules).
func (a *App) WithConfigRead(fn func()) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	fn()
}

// GroupByID резолвит группу по ID из базовых групп. Вызывающий ОБЯЗАН держать
// cfgMu (read или write). Заменяет idx-через-HTTP-заголовок (TOCTOU-safe, если
// резолв и мутация — в одной критической секции). Возвращает (nil, false) без
// оборачивания nil-указателя в непустой интерфейс.
func (a *App) GroupByID(id intID.ID) (appiface.Group, bool) {
	for _, g := range *a.groups.Load() {
		if g.ID == id {
			return g, true
		}
	}
	return nil, false
}

// ruleByID ищет правило в модели группы по ID. Вызывающий держит cfgMu.
func ruleByID(g *models.Group, id intID.ID) (*models.Rule, int, bool) {
	for i, r := range g.Rules {
		if r.ID == id {
			return r, i, true
		}
	}
	return nil, -1, false
}
