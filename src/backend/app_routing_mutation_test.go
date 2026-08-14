package magitrickle

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"magitrickle/models"
	"magitrickle/utils/trie"
)

// Операции, меняющие ТОПОЛОГИЮ цепочек в ядре, обязаны идти по одной.
// Переключение режима делает teardown+bring-up всех групп, а перестройка
// подписок в это же время выключает старые группы, подменяет снимок и включает
// новые — цепочки получаются вперемешку: часть в старом режиме, часть в новом,
// часть остаётся при снятом роутинге. Гонки данных тут нет, поэтому
// race-детектор молчит, и поймать это можно только явной сериализацией.
func TestRoutingMutationsAreSerialized(t *testing.T) {
	a := &App{}
	a.config.Netfilter.DirectPriority = models.DirectPriorityAbsolute
	a.config.Enabled = true
	a.routingActive.Store(true)
	a.domainTrie.Store(trie.New())
	empty := make([]*Group, 0)
	a.groups.Store(&empty)
	a.subscriptionGroups.Store(&empty)
	a.saveConfigFn = func() error { return nil }

	var inMutation atomic.Bool
	var overlaps atomic.Int32

	// Обе стороны отмечают своё присутствие в критической секции: если они
	// пересекутся хоть раз, счётчик перестанет быть нулём.
	enter := func() {
		if !inMutation.CompareAndSwap(false, true) {
			overlaps.Add(1)
		}
		time.Sleep(2 * time.Millisecond)
	}
	leave := func() { inMutation.Store(false) }

	a.bringDownFn = func() error { enter(); defer leave(); a.routingActive.Store(false); return nil }
	a.bringUpFn = func() error { enter(); defer leave(); a.routingActive.Store(true); return nil }

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		mode := models.DirectPriorityByOrder
		if i%2 == 0 {
			mode = models.DirectPriorityAbsolute
		}
		go func() {
			defer wg.Done()
			_ = a.SetDirectPriority(mode)
		}()
		go func() {
			defer wg.Done()
			// Тот же класс операции: перестройка групп подписок трогает
			// цепочки в ядре и обязана ждать своей очереди.
			a.WithRoutingMutation(func() error {
				enter()
				defer leave()
				return nil
			})
		}()
	}
	wg.Wait()

	if got := overlaps.Load(); got != 0 {
		t.Fatalf("операции с цепочками пересеклись %d раз — сериализации нет", got)
	}
}
