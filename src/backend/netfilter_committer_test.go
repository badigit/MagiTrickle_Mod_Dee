//go:build testing

package magitrickle

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor ждёт выполнения условия. Применяется ТОЛЬКО для положительных
// ожиданий («проход должен произойти»): для отрицательных таймер дал бы
// ложно-зелёный результат, поэтому отсутствие прохода везде проверяется
// через итоговый счётчик после синхронной точки (setMode).
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("условие не выполнилось: %s", msg)
}

func newTestCommitter(t *testing.T, commit func(ctx context.Context, wake <-chan struct{}) error) *netfilterCommitter {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := startNetfilterCommitter(ctx, commit, time.Hour) // reconcile по умолчанию не мешает
	t.Cleanup(c.stop)
	return c
}

// TestCommitterRunsRequestedPass: в режиме ready сигнал приводит к проходу.
func TestCommitterRunsRequestedPass(t *testing.T) {
	var passes atomic.Int32
	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	c.setMode(committerReady)

	c.request()
	waitFor(t, func() bool { return passes.Load() == 1 }, "проход не выполнен")
}

// TestCommitterFoldsRequests: канал ёмкостью 1 даёт «не более одного
// ОТЛОЖЕННОГО прохода». Проверяем именно это: «ровно один проход на серию»
// зависит от планировщика и таким тестом не проверяется.
func TestCommitterFoldsRequests(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	var passes atomic.Int32

	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		entered <- struct{}{}
		<-release
		return nil
	})
	c.setMode(committerReady)

	c.request()
	<-entered // worker внутри первого прохода

	// пока worker занят, шлём ещё три события
	for i := 0; i < 3; i++ {
		c.request()
	}
	close(release)

	waitFor(t, func() bool { return passes.Load() == 2 }, "отложенный проход не выполнен")

	// синхронная точка: после setMode worker гарантированно обработал всё,
	// что успел взять из каналов до неё
	c.setMode(committerReady)
	if got := passes.Load(); got != 2 {
		t.Errorf("проходов = %d, want 2 (первый + один схлопнутый)", got)
	}
}

// TestCommitterDoesNotLoseEventDuringPass: событие, пришедшее ВО ВРЕМЯ прохода,
// не теряется — за текущим проходом следует ещё один.
func TestCommitterDoesNotLoseEventDuringPass(t *testing.T) {
	var passes atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var once sync.Once

	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		entered <- struct{}{}
		once.Do(func() { <-release })
		return nil
	})
	c.setMode(committerReady)

	c.request()
	<-entered
	c.request()
	close(release)

	waitFor(t, func() bool { return passes.Load() >= 2 }, "событие во время прохода потеряно")
}

// TestCommitterLatchesEventWhileStarting: событие в starting не исполняется,
// но и не теряется — оно срабатывает при переходе в ready.
func TestCommitterLatchesEventWhileStarting(t *testing.T) {
	var passes atomic.Int32
	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	// режим по умолчанию — starting

	c.request()
	c.setMode(committerReady)

	waitFor(t, func() bool { return passes.Load() == 1 }, "защёлкнутое событие не исполнено после ready")

	c.setMode(committerReady)
	if got := passes.Load(); got != 1 {
		t.Errorf("проходов = %d, want 1 (защёлка должна сработать ровно один раз)", got)
	}
}

// TestCommitterDiscardsEventWhilePaused: на паузе цепочки сняты намеренно,
// событие отбрасывается вместе с защёлкой. Копить его до Resume неверно:
// Resume пересобирает правила из модели, а не из накопленных событий.
func TestCommitterDiscardsEventWhilePaused(t *testing.T) {
	var passes atomic.Int32
	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	c.setMode(committerPaused)

	c.request()
	// Переход в paused дренирует очередь внутри обработчика команды, поэтому
	// после возврата setMode ожидающего события гарантированно нет. Одного
	// лишь подтверждения команды было бы мало: select между cmds и req
	// выбирает случайно, и событие пережило бы паузу.
	c.setMode(committerPaused)
	c.setMode(committerReady)

	// теперь убеждаемся, что worker жив и работает, но старое событие не всплыло
	c.request()
	waitFor(t, func() bool { return passes.Load() == 1 }, "worker не обработал новое событие")

	c.setMode(committerReady)
	if got := passes.Load(); got != 1 {
		t.Errorf("проходов = %d, want 1 (событие с паузы не должно всплывать)", got)
	}
}

// TestCommitterDropsLatchOnPause: защёлка, взведённая в starting, не должна
// пережить уход на паузу.
func TestCommitterDropsLatchOnPause(t *testing.T) {
	var passes atomic.Int32
	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})

	c.request()
	c.setMode(committerStarting) // подтверждение команды; событие уже защёлкнуто либо ещё в очереди
	c.setMode(committerPaused)   // сбрасывает и защёлку, и очередь
	c.setMode(committerReady)

	c.request()
	waitFor(t, func() bool { return passes.Load() == 1 }, "worker не обработал новое событие")

	c.setMode(committerReady)
	if got := passes.Load(); got != 1 {
		t.Errorf("проходов = %d, want 1 (защёлка должна сброситься на паузе)", got)
	}
}

// TestCommitterStopIsIdempotent: stop вызывается двумя путями — явно перед
// снятием правил и defer'ом на ранних выходах, поэтому повторный вызов обязан
// быть no-op, а не паникой или зависанием.
func TestCommitterStopIsIdempotent(t *testing.T) {
	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error { return nil })
	c.setMode(committerReady)

	c.stop()
	c.stop()
	c.stop()
}

// TestCommitterStopWaitsForWorker: после stop ни один проход не идёт — иначе
// teardown снимал бы цепочки, пока worker их восстанавливает.
func TestCommitterStopWaitsForWorker(t *testing.T) {
	inPass := make(chan struct{})
	finish := make(chan struct{})
	var running atomic.Bool

	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		running.Store(true)
		close(inPass)
		<-finish
		running.Store(false)
		return nil
	})
	c.setMode(committerReady)

	c.request()
	<-inPass

	stopped := make(chan struct{})
	go func() {
		c.stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		t.Fatal("stop вернулся, пока проход ещё идёт")
	case <-time.After(50 * time.Millisecond):
	}

	close(finish)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop не дождался worker'а")
	}
	if running.Load() {
		t.Error("проход всё ещё идёт после stop")
	}
}

// TestCommitterAfterStopIsInert: поздние вызовы от HTTP-обработчика безопасны —
// каналы не закрываются, а setMode не виснет на мёртвом worker'е.
func TestCommitterAfterStopIsInert(t *testing.T) {
	var passes atomic.Int32
	c := newTestCommitter(t, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	c.setMode(committerReady)
	c.stop()

	c.request()
	c.request()
	c.setMode(committerReady) // не должен зависнуть

	if got := passes.Load(); got != 0 {
		t.Errorf("проходов после stop = %d, want 0", got)
	}
}

// TestCommitterSchedulesReconcileAfterFailure: если проход провалился и новых
// событий нет, страховочный проход обязан состояться сам — иначе правила
// останутся снятыми до перезапуска демона.
func TestCommitterSchedulesReconcileAfterFailure(t *testing.T) {
	var passes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := startNetfilterCommitter(ctx, func(ctx context.Context, wake <-chan struct{}) error {
		if passes.Add(1) == 1 {
			return errors.New("проиграли гонку")
		}
		return nil
	}, 10*time.Millisecond)
	t.Cleanup(c.stop)
	c.setMode(committerReady)

	c.request()
	waitFor(t, func() bool { return passes.Load() >= 2 }, "страховочный проход не состоялся")
}

// TestCommitterReconcileDoesNotSurvivePause: взведённый страховочный таймер не
// должен выстрелить после ухода на паузу — иначе он вернёт правила, которые
// teardown только что снял.
//
// Это единственная отрицательная проверка, где ожидание неизбежно: срабатывание
// таймера наблюдаемо только по факту прохода, а его отсутствие — только по
// времени. Риск ложно-зелёного принят осознанно и уменьшен запасом: ждём втрое
// дольше задержки таймера. Наблюдаемого счётчика ради одного теста в
// продакшн-код не добавляем.
func TestCommitterReconcileDoesNotSurvivePause(t *testing.T) {
	var passes atomic.Int32
	failed := make(chan struct{})
	var once sync.Once

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := startNetfilterCommitter(ctx, func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		once.Do(func() { close(failed) })
		return errors.New("проиграли гонку")
	}, 50*time.Millisecond)
	t.Cleanup(c.stop)
	c.setMode(committerReady)

	c.request()
	<-failed                   // проход провалился, таймер взведён
	c.setMode(committerPaused) // синхронная точка: worker принял паузу

	before := passes.Load()
	time.Sleep(150 * time.Millisecond) // таймер успел бы выстрелить дважды
	if got := passes.Load(); got != before {
		t.Errorf("проходов %d -> %d: страховочный таймер пережил паузу", before, got)
	}
}
