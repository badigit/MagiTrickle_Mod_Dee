# Асинхронный коммиттер netfilter-правил — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-dim:subagent-driven-development (recommended) or superpowers-dim:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Обрабатывать события `netfilter.d` в отдельной горутине со схлопыванием, чтобы одна перезапись таблиц прошивкой Keenetic стоила одного прохода, а HTTP-хук отвечал мгновенно.

**Architecture:** Горутина-worker с каналом запросов ёмкостью 1 (схлопывание — следствие ёмкости). Цикл ретраев получает канал пробуждения: новое событие прерывает паузу между попытками и начинает проход заново. Состояние worker'а — явная машина (`starting`/`ready`/`paused`/`stopping`) под мьютексом переходов, потому что `routingActive` выставляется до включения групп и признаком готовности быть не может.

**Tech Stack:** Go 1.x, стандартная библиотека (`context`, `sync`, `time`), zerolog. Тесты — `go test -tags testing`, fake-реализация `Executable` уже есть.

## Global Constraints

- Спека: `.designs/bd-mt-yvf/spec.md`. При расхождении плана со спекой — прав спек, сообщить оркестратору.
- Сборка и тесты ТОЛЬКО через WSL, никогда напрямую на Windows:
  `wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing ./...'`
- Комментарии в коде и сообщения коммитов — по-русски. Без AI-атрибуции и `Co-Authored-By`.
- Коммитить после каждой задачи. Push — только по явной просьбе разработчика.
- `iptables-restore` НЕ убиваем по приходу события (замер прода: полный проход 34–79 мс). Прерываем только ожидание между попытками.
- Канал запросов НИКОГДА не закрывается: в него пишет HTTP-обработчик, запись в закрытый канал — паника.
- Контракт порядка локов (нарушение = дедлок): `мьютекс переходов → cfgMu → g.locker → locker компонента → preambleMu → commitMu → ipt.sync → chain.sync → exec`. Worker берёт только хвост, начиная с `commitMu`; `cfgMu` и `g.locker` он не берёт никогда.

## Что уже сделано (НЕ переделывать)

Реализовано в mt-7sa (`f8f989d`) и mt-pfo (`436df82`, `2d5efe4`):

- `commitMu sync.Mutex` в `IPTables` — сериализация коммитов, берётся в `CommitContext` (`utils/iptables/iptables.go:33,229`);
- `Executable.Save(ctx)`/`Restore(ctx, data)` с контекстом и потолком `execTimeout = 5s`, ошибка `ErrExecTimeout`;
- `CommitWithRetry(ctx)` с бюджетом `commitRetryBackoff = {0, 50ms, 200ms, 500ms}`, классификаторы `IsRacedError`, `IsRetryableError`;
- `NetfilterDHook` больше НЕ передаёт `r.Context()` — использует `context.Background()`.

## File Structure

| Файл | Ответственность |
|---|---|
| `src/backend/utils/iptables/commit-retry.go` (изменить) | Добавить `CommitWithRetryWake(ctx, wake)`; `CommitWithRetry(ctx)` становится обёрткой с `nil`-каналом |
| `src/backend/netfilter_committer.go` (создать) | Компонент `netfilterCommitter`: канал, worker, состояния, идемпотентная остановка, отложенный reconcile |
| `src/backend/netfilter_committer_test.go` (создать) | Тесты компонента на подставном коммите, без netfilter |
| `src/backend/app.go` (изменить) | Откат при неуспешном `bringUpRouting`; `lifecycleMu` вокруг переходов; проброс состояния в коммиттер |
| `src/backend/start.go` (изменить) | Создание коммиттера до `SetupUnixSocket`, порядок остановки, `forceCommitIPTablesWake` |
| `src/backend/api/v1/handlers.go` (изменить) | `NetfilterDHook` шлёт неблокирующий сигнал и отвечает 200 |
| `src/backend/app/magitrickle.go` (изменить) | Метод интерфейса для сигнала коммиттеру |

---

### Task 1: Пробуждаемый цикл ретраев

**Files:**
- Modify: `src/backend/utils/iptables/commit-retry.go:98-141`
- Test: `src/backend/utils/iptables/commit-retry_test.go`

**Interfaces:**
- Consumes: `ipt.CommitContext(ctx) error`, `commitRetryBackoff []time.Duration`, `protoName(Protocol) string` — всё уже существует.
- Produces: `func (ipt *IPTables) CommitWithRetryWake(ctx context.Context, wake <-chan struct{}) error`. При получении из `wake` во время паузы между попытками цикл начинается заново с полным бюджетом. `CommitWithRetry(ctx)` сохраняет прежнюю сигнатуру и поведение (эквивалент `wake = nil`).

- [ ] **Step 1: Написать падающие тесты**

Добавить в конец `src/backend/utils/iptables/commit-retry_test.go`:

```go
// TestCommitWithRetryWakeRestartsOnEvent: событие, пришедшее во время паузы
// между попытками, прекращает ожидание и начинает проход ЗАНОВО — с полным
// бюджетом попыток. Смысл: дельта от устаревшего снимка ляжет так же криво,
// поэтому продолжать старый проход бессмысленно.
func TestCommitWithRetryWakeRestartsOnEvent(t *testing.T) {
	ipt, fake := newRetryFixture(t)

	saved := commitRetryBackoff
	commitRetryBackoff = []time.Duration{0, time.Hour, time.Hour}
	t.Cleanup(func() { commitRetryBackoff = saved })

	// первая попытка проигрывает гонку, вторая (после рестарта) проходит
	fake.FailRestore(errors.New(racedStderr))

	wake := make(chan struct{}, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		wake <- struct{}{}
	}()

	start := time.Now()
	if err := ipt.CommitWithRetryWake(context.Background(), wake); err != nil {
		t.Fatalf("CommitWithRetryWake failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("ожидание не прервано событием, прошло %v", elapsed)
	}
	if got := fake.RestoreCalls(); got != 2 {
		t.Errorf("Restore calls = %d, want 2 (провал + проход после рестарта)", got)
	}
}

// TestCommitWithRetryWakeNilChannelBehavesAsBefore: nil-канал в select никогда
// не готов, поэтому старое поведение сохраняется дословно.
func TestCommitWithRetryWakeNilChannelBehavesAsBefore(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	fake.FailRestore(errors.New(racedStderr), errors.New(racedStderr))

	if err := ipt.CommitWithRetryWake(context.Background(), nil); err != nil {
		t.Fatalf("CommitWithRetryWake failed: %v", err)
	}
	if got := fake.RestoreCalls(); got != 3 {
		t.Errorf("Restore calls = %d, want 3", got)
	}
}

// TestCommitWithRetryWakeContextWinsOverWake: отменённый контекст важнее
// события — worker не должен писать в netfilter во время остановки.
func TestCommitWithRetryWakeContextWinsOverWake(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	wake := make(chan struct{}, 1)
	wake <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := ipt.CommitWithRetryWake(ctx, wake); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got: %v", err)
	}
	if got := fake.RestoreCalls(); got != 0 {
		t.Errorf("Restore calls = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Запустить тесты и убедиться, что они падают**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -run Wake ./utils/iptables/ 2>&1 | grep -v "^{"'
```

Ожидается: `undefined: ipt.CommitWithRetryWake` (ошибка компиляции).

- [ ] **Step 3: Реализовать**

В `src/backend/utils/iptables/commit-retry.go` заменить тело `CommitWithRetry` целиком (строки 98–141) на:

```go
func (ipt *IPTables) CommitWithRetry(ctx context.Context) error {
	return ipt.CommitWithRetryWake(ctx, nil)
}

// CommitWithRetryWake — то же, что CommitWithRetry, но пауза между попытками
// слушает ещё и канал wake. Событие из него означает «состояние ядра снова
// изменилось»: продолжать текущий проход бессмысленно, потому что дельта
// считалась от устаревшего снимка. Поэтому проход начинается ЗАНОВО с полным
// бюджетом попыток. Busy-loop это не создаёт — частота ограничена частотой
// событий netfilter.d.
//
// wake == nil допустим: nil-канал в select никогда не готов, поведение
// совпадает с прежним.
func (ipt *IPTables) CommitWithRetryWake(ctx context.Context, wake <-chan struct{}) error {
	for {
		lastErr, restarted := ipt.commitRetryPass(ctx, wake)
		if restarted {
			log.Debug().
				Str("type", protoName(ipt.Proto())).
				Msg("iptables commit restarted by a new netfilter event")
			continue
		}
		return lastErr
	}
}

// commitRetryPass — один проход по бюджету попыток. Возвращает (ошибка, true),
// если проход прерван событием из wake и его надо начать заново.
func (ipt *IPTables) commitRetryPass(ctx context.Context, wake <-chan struct{}) (error, bool) {
	var lastErr error

	for attempt, delay := range commitRetryBackoff {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err(), false
			case <-wake:
				return nil, true
			case <-time.After(delay):
			}
		} else if err := ctx.Err(); err != nil {
			return err, false
		}

		lastErr = ipt.CommitContext(ctx)
		if lastErr == nil {
			if attempt > 0 {
				log.Debug().
					Int("attempt", attempt+1).
					Str("type", protoName(ipt.Proto())).
					Msg("iptables commit succeeded after retry")
			}
			return nil, false
		}

		event := log.Warn()
		switch {
		case errors.Is(lastErr, ErrExecTimeout):
			// Не «сделали неверно», а «не сделали вовсе»: команда залипла и была
			// убита. Ретраим, но на виду — молчать об этом нельзя, иначе
			// диагностика «почему правила не вернулись» упрётся в тишину.
			event = log.Warn().Bool("exec_timeout", true)
		case IsRacedError(lastErr):
			// Ожидаемо: прошивка переписала таблицу под нами.
			event = log.Debug()
		}
		event.Err(lastErr).
			Int("attempt", attempt+1).
			Int("attempts", len(commitRetryBackoff)).
			Str("type", protoName(ipt.Proto())).
			Msg("iptables commit failed, retrying")
	}

	return fmt.Errorf("iptables commit failed after %d attempts: %w", len(commitRetryBackoff), lastErr), false
}
```

- [ ] **Step 4: Запустить весь пакет**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -race ./utils/iptables/ 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: `ok magitrickle/utils/iptables`. Старые тесты `commit-retry_test.go` должны пройти без правок — это проверка того, что обёртка не изменила поведение.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/utils/iptables/commit-retry.go src/backend/utils/iptables/commit-retry_test.go
git commit -m "feat(netfilter): цикл ретраев умеет прерываться новым событием (mt-yvf)

CommitWithRetryWake слушает канал пробуждения в паузе между попытками:
событие означает, что состояние ядра снова изменилось, и продолжать проход
со старой дельтой бессмысленно — он начинается заново с полным бюджетом.

CommitWithRetry остаётся обёрткой с nil-каналом, синхронные пути и их тесты
не тронуты: nil-канал в select никогда не готов."
```

---

### Task 2: Компонент коммиттера — канал, worker, идемпотентная остановка

**Files:**
- Create: `src/backend/netfilter_committer.go`
- Create: `src/backend/netfilter_committer_test.go`

**Interfaces:**
- Consumes: ничего из предыдущих задач (компонент изолирован, функция коммита внедряется).
- Produces:
  - тип `netfilterCommitter` с полями-методами ниже;
  - `func newNetfilterCommitter(commit func(ctx context.Context, wake <-chan struct{}) error) *netfilterCommitter`;
  - `func (c *netfilterCommitter) start(ctx context.Context)` — запускает worker;
  - `func (c *netfilterCommitter) request()` — неблокирующий сигнал;
  - `func (c *netfilterCommitter) stop()` — идемпотентная остановка с ожиданием worker'а;
  - константы состояний `committerStarting`, `committerReady`, `committerPaused`, `committerStopping` и метод `setState(committerState)`.

  В этой задаче реализуются ТОЛЬКО `committerReady` и `committerStopping`; остальные состояния объявляются и обрабатываются в Task 3.

- [ ] **Step 1: Написать падающие тесты**

Создать `src/backend/netfilter_committer_test.go`:

```go
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

// waitFor ждёт выполнения условия до таймаута. Нужен потому, что worker
// асинхронный: без ожидания тест проверял бы состояние раньше, чем worker
// успел сработать, и был бы флаки.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("условие не выполнилось за %v: %s", timeout, msg)
}

// TestCommitterRunsRequestedPass: сигнал приводит к проходу.
func TestCommitterRunsRequestedPass(t *testing.T) {
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	defer c.stop()

	c.request()
	waitFor(t, time.Second, func() bool { return passes.Load() == 1 }, "проход не выполнен")
}

// TestCommitterFoldsRequests: канал ёмкостью 1 гарантирует «не более одного
// ОТЛОЖЕННОГО прохода». Проверяем именно это, а не «ровно один проход»:
// последнее зависит от того, когда worker забрал сигнал, и такой тест был бы
// флаки.
func TestCommitterFoldsRequests(t *testing.T) {
	release := make(chan struct{})
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		<-release // держим worker внутри прохода
		return nil
	})
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)

	c.request()
	waitFor(t, time.Second, func() bool { return passes.Load() == 1 }, "первый проход не начался")

	// пока worker занят, шлём ещё три события — они должны схлопнуться в один
	for i := 0; i < 3; i++ {
		c.request()
	}
	close(release)

	waitFor(t, time.Second, func() bool { return passes.Load() == 2 }, "отложенный проход не выполнен")
	time.Sleep(50 * time.Millisecond)
	if got := passes.Load(); got != 2 {
		t.Errorf("проходов = %d, want 2 (первый + один схлопнутый отложенный)", got)
	}
	c.stop()
}

// TestCommitterDoesNotLoseEventDuringPass: событие, пришедшее ВО ВРЕМЯ прохода,
// не теряется — за текущим проходом гарантированно следует ещё один.
func TestCommitterDoesNotLoseEventDuringPass(t *testing.T) {
	var passes atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var once sync.Once

	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		entered <- struct{}{}
		once.Do(func() { <-release })
		return nil
	})
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	defer c.stop()

	c.request()
	<-entered // worker внутри первого прохода
	c.request()
	close(release)

	waitFor(t, time.Second, func() bool { return passes.Load() >= 2 }, "событие во время прохода потеряно")
}

// TestCommitterStopIsIdempotent: stop вызывается двумя путями (явно перед
// teardown и через defer на ранних выходах), поэтому повторный вызов обязан
// быть no-op, а не паникой или зависанием.
func TestCommitterStopIsIdempotent(t *testing.T) {
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error { return nil })
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)

	c.stop()
	c.stop()
	c.stop()
}

// TestCommitterStopWaitsForWorker: после stop ни один проход не должен идти —
// иначе teardown снимал бы цепочки, пока worker их восстанавливает.
func TestCommitterStopWaitsForWorker(t *testing.T) {
	inPass := make(chan struct{})
	finish := make(chan struct{})
	var running atomic.Bool

	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		running.Store(true)
		close(inPass)
		<-finish
		running.Store(false)
		return nil
	})
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)

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
	case <-time.After(time.Second):
		t.Fatal("stop не дождался worker'а")
	}
	if running.Load() {
		t.Error("проход всё ещё идёт после stop")
	}
}

// TestCommitterRequestAfterStopDoesNotPanic: канал не закрывается, поэтому
// поздний сигнал от HTTP-обработчика безопасен.
func TestCommitterRequestAfterStopDoesNotPanic(t *testing.T) {
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error { return nil })
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	c.stop()

	c.request()
	c.request()
}

// TestCommitterStopWithoutStart: defer на раннем выходе из Start может позвать
// stop до start — это не должно зависать.
func TestCommitterStopWithoutStart(t *testing.T) {
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error { return nil })
	done := make(chan struct{})
	go func() {
		c.stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop без start завис")
	}
}

// TestCommitterPassErrorDoesNotKillWorker: ошибка прохода не должна ронять
// worker — следующее событие обязано обработаться.
func TestCommitterPassErrorDoesNotKillWorker(t *testing.T) {
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return errors.New("boom")
	})
	c.setState(committerReady)
	c.reconcileDelay = time.Hour // отложенный reconcile здесь не проверяем

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	defer c.stop()

	c.request()
	waitFor(t, time.Second, func() bool { return passes.Load() == 1 }, "первый проход не выполнен")
	c.request()
	waitFor(t, time.Second, func() bool { return passes.Load() == 2 }, "worker умер после ошибки")
}
```

- [ ] **Step 2: Запустить тесты и убедиться, что они падают**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -run Committer . 2>&1 | grep -v "^{" | head -20'
```

Ожидается: `undefined: newNetfilterCommitter` (ошибка компиляции).

- [ ] **Step 3: Реализовать компонент**

Создать `src/backend/netfilter_committer.go`:

```go
package magitrickle

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// committerState — состояние коммиттера. Определяет, что делать с пришедшим
// событием netfilter.d. Признаком готовности НЕ может служить routingActive:
// он выставляется в начале bringUpRouting, до включения групп.
type committerState int32

const (
	// committerStarting — модель ещё собирается. Событие защёлкивается и
	// исполняется при переходе в ready. Отбрасывать нельзя: прошивка могла
	// снести уже поднятые группы, а включение последующих их не восстановит.
	committerStarting committerState = iota
	// committerReady — проходы выполняются.
	committerReady
	// committerPaused — роутинг снят намеренно (config.Enabled=false).
	// Событие подтверждается и отбрасывается.
	committerPaused
	// committerStopping — идёт остановка, события не принимаются.
	committerStopping
)

// defaultReconcileDelay — задержка страховочного прохода после того, как бюджет
// попыток исчерпан. Без него серия проигранных гонок и последующая тишина
// оставили бы правила снятыми до перезапуска демона.
const defaultReconcileDelay = 2 * time.Second

// netfilterCommitter владеет единственной горутиной, которая переустанавливает
// наши правила по событиям netfilter.d.
//
// Прошивка Keenetic переписывает таблицу целиком и шлёт событие на КАЖДУЮ
// таблицу, поэтому одна её перезапись даёт несколько событий подряд. Канал
// ёмкостью 1 схлопывает их: гарантия — не более одного ОТЛОЖЕННОГО прохода.
type netfilterCommitter struct {
	// req — канал запросов ёмкостью 1. НИКОГДА не закрывается: в него пишет
	// HTTP-обработчик, а запись в закрытый канал — паника.
	req chan struct{}

	// commit — сама работа. Внедряется, чтобы компонент тестировался без
	// netfilter. Второй аргумент — канал пробуждения для прерывания пауз
	// между попытками (см. CommitWithRetryWake).
	commit func(ctx context.Context, wake <-chan struct{}) error

	state   atomic.Int32
	latched atomic.Bool // событие, пришедшее в состоянии starting

	reconcileDelay time.Duration

	startOnce sync.Once
	stopOnce  sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
}

func newNetfilterCommitter(commit func(ctx context.Context, wake <-chan struct{}) error) *netfilterCommitter {
	c := &netfilterCommitter{
		req:            make(chan struct{}, 1),
		commit:         commit,
		reconcileDelay: defaultReconcileDelay,
		done:           make(chan struct{}),
	}
	c.state.Store(int32(committerStarting))
	return c
}

func (c *netfilterCommitter) setState(s committerState) {
	c.state.Store(int32(s))
}

func (c *netfilterCommitter) currentState() committerState {
	return committerState(c.state.Load())
}

// request — неблокирующий сигнал. Если запрос уже висит, новый растворяется:
// это и есть схлопывание.
func (c *netfilterCommitter) request() {
	select {
	case c.req <- struct{}{}:
	default:
	}
}

// start запускает worker. Повторный вызов — no-op.
func (c *netfilterCommitter) start(ctx context.Context) {
	c.startOnce.Do(func() {
		workerCtx, cancel := context.WithCancel(ctx)
		c.cancel = cancel
		go c.run(workerCtx)
	})
}

// stop переводит коммиттер в stopping, отменяет worker и ДОЖДАВШИСЬ его
// возвращается. Идемпотентен: вызывается и явно перед снятием правил, и
// defer'ом на ранних выходах из Start.
func (c *netfilterCommitter) stop() {
	c.stopOnce.Do(func() {
		c.setState(committerStopping)
		if c.cancel == nil {
			// start не вызывался: worker'а нет, ждать нечего.
			close(c.done)
			return
		}
		c.cancel()
		<-c.done
	})
}

func (c *netfilterCommitter) run(ctx context.Context) {
	defer close(c.done)

	// reconcile — страховочный таймер после исчерпания бюджета. Живёт ИМЕННО
	// здесь, как case этого select: отвязанный time.AfterFunc пережил бы
	// остановку и запустил бы запись во время teardown.
	var reconcile <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.req:
			reconcile = nil
		case <-reconcile:
			reconcile = nil
		}

		if c.currentState() == committerStopping {
			return
		}

		if err := c.commit(ctx, c.req); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Msg("netfilter commit pass failed, scheduling reconcile")
			reconcile = time.After(c.reconcileDelay)
		}
	}
}
```

- [ ] **Step 4: Запустить тесты**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -race -run Committer . 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: `ok magitrickle`.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/netfilter_committer.go src/backend/netfilter_committer_test.go
git commit -m "feat(netfilter): компонент асинхронного коммиттера правил (mt-yvf)

Горутина с каналом запросов ёмкостью 1. Схлопывание — следствие ёмкости:
прошивка шлёт событие на каждую таблицу, и серия событий от одной перезаписи
даёт не более одного отложенного прохода.

Остановка идемпотентна и дожидается worker'а: она вызывается двумя путями —
явно перед снятием правил и defer'ом на ранних выходах из Start. Канал
запросов не закрывается, поэтому поздний сигнал от HTTP-обработчика безопасен.

Страховочный таймер после исчерпания бюджета попыток живёт case'ом внутри
select worker'а: отвязанный AfterFunc пережил бы остановку и начал запись во
время teardown."
```

---

### Task 3: Машина состояний — защёлкивание на старте и отбрасывание на паузе

**Files:**
- Modify: `src/backend/netfilter_committer.go`
- Modify: `src/backend/netfilter_committer_test.go`

**Interfaces:**
- Consumes: `netfilterCommitter`, `setState`, `request`, `start`, `stop` из Task 2.
- Produces: `func (c *netfilterCommitter) setStateAndDrain(s committerState)` — смена состояния с немедленным исполнением защёлкнутого события при переходе в `ready`. Вызывающий из Task 5 использует именно её, а не `setState`.

- [ ] **Step 1: Написать падающие тесты**

Добавить в `src/backend/netfilter_committer_test.go`:

```go
// TestCommitterLatchesEventWhileStarting: событие в starting не исполняется,
// но и не теряется — оно должно сработать при переходе в ready.
func TestCommitterLatchesEventWhileStarting(t *testing.T) {
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	// состояние по умолчанию — starting

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	defer c.stop()

	c.request()
	time.Sleep(50 * time.Millisecond)
	if got := passes.Load(); got != 0 {
		t.Fatalf("проходов = %d, want 0 (в starting исполнять нельзя)", got)
	}

	c.setStateAndDrain(committerReady)
	waitFor(t, time.Second, func() bool { return passes.Load() == 1 }, "защёлкнутое событие не исполнено после ready")
}

// TestCommitterDiscardsEventWhilePaused: на паузе цепочки сняты намеренно,
// событие подтверждается и отбрасывается. Копить его до Resume неверно:
// Resume пересобирает правила из модели, а не из накопленных событий.
func TestCommitterDiscardsEventWhilePaused(t *testing.T) {
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	c.setState(committerPaused)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	defer c.stop()

	c.request()
	time.Sleep(50 * time.Millisecond)
	if got := passes.Load(); got != 0 {
		t.Fatalf("проходов = %d, want 0 (на паузе исполнять нечего)", got)
	}

	// переход в ready НЕ должен «доигрывать» событие с паузы
	c.setStateAndDrain(committerReady)
	time.Sleep(50 * time.Millisecond)
	if got := passes.Load(); got != 0 {
		t.Errorf("проходов = %d, want 0 (событие с паузы не должно всплывать)", got)
	}
}

// TestCommitterDropsLatchOnPause: защёлкнутое в starting событие не должно
// пережить уход на паузу.
func TestCommitterDropsLatchOnPause(t *testing.T) {
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)
	defer c.stop()

	c.request()
	time.Sleep(50 * time.Millisecond)

	c.setStateAndDrain(committerPaused)
	c.setStateAndDrain(committerReady)
	time.Sleep(50 * time.Millisecond)
	if got := passes.Load(); got != 0 {
		t.Errorf("проходов = %d, want 0 (защёлка должна сброситься на паузе)", got)
	}
}

// TestCommitterIgnoresEventWhileStopping: во время остановки события не
// принимаются вовсе.
func TestCommitterIgnoresEventWhileStopping(t *testing.T) {
	var passes atomic.Int32
	c := newNetfilterCommitter(func(ctx context.Context, wake <-chan struct{}) error {
		passes.Add(1)
		return nil
	})
	c.setState(committerReady)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.start(ctx)

	c.stop()
	c.request()
	time.Sleep(50 * time.Millisecond)
	if got := passes.Load(); got != 0 {
		t.Errorf("проходов = %d, want 0 (в stopping события не исполняются)", got)
	}
}
```

- [ ] **Step 2: Запустить и убедиться, что падают**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -run Committer . 2>&1 | grep -v "^{" | head -20'
```

Ожидается: `undefined: c.setStateAndDrain`.

- [ ] **Step 3: Реализовать обработку состояний**

В `src/backend/netfilter_committer.go` заменить блок проверки состояния внутри `run` (сразу после `select`) на:

```go
		switch c.currentState() {
		case committerStopping:
			return
		case committerStarting:
			// Модель ещё собирается: событие защёлкиваем и ждём готовности.
			c.latched.Store(true)
			continue
		case committerPaused:
			// Цепочки сняты намеренно, восстанавливать нечего. Защёлку тоже
			// сбрасываем: Resume пересоберёт правила из модели, а не из
			// накопленных событий.
			c.latched.Store(false)
			continue
		}
```

И добавить метод после `setState`:

```go
// setStateAndDrain меняет состояние и, если стало ready, немедленно исполняет
// событие, защёлкнутое во время starting.
//
// Уход на паузу сбрасывает защёлку: на паузе правила сняты намеренно, а Resume
// пересобирает их из модели.
func (c *netfilterCommitter) setStateAndDrain(s committerState) {
	if s == committerPaused {
		c.latched.Store(false)
	}
	c.setState(s)
	if s == committerReady && c.latched.Swap(false) {
		c.request()
	}
}
```

- [ ] **Step 4: Запустить тесты**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -race -run Committer . 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: `ok magitrickle`.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/netfilter_committer.go src/backend/netfilter_committer_test.go
git commit -m "feat(netfilter): состояния коммиттера — защёлка на старте, отбрасывание на паузе (mt-yvf)

Признаком готовности не может быть routingActive: он выставляется в начале
bringUpRouting, до включения групп. Поэтому состояние явное.

В starting событие защёлкивается: отбрасывать нельзя, прошивка могла снести
уже поднятые группы, а включение последующих их не восстановит. В paused
событие отбрасывается вместе с защёлкой — правила сняты намеренно, а Resume
пересобирает их из модели, а не из накопленных событий."
```

---

### Task 4: Откат неуспешного bringUpRouting и сериализация переходов

**Files:**
- Modify: `src/backend/app.go:388-433` (`bringUpRouting`, `bringDownRouting`), `src/backend/app.go:438-457` (`SetEnabled`)
- Test: `src/backend/app_lifecycle_test.go` (создать)

**Interfaces:**
- Consumes: ничего из предыдущих задач.
- Produces: `func (a *App) tearDownRouting()` — снятие роутинга без гейта `routingActive`; поле `lifecycleMu sync.Mutex` в `App`. `bringUpRouting` при ошибке оставляет систему в состоянии «ничего не включено».

- [ ] **Step 1: Написать падающий тест**

Создать `src/backend/app_lifecycle_test.go`:

```go
//go:build testing

package magitrickle

import (
	"sync"
	"testing"
)

// TestSetEnabledIsSerialized: SetEnabled зовётся прямо из HTTP-обработчика,
// поэтому двойной клик в UI даёт конкурентные вызовы. Без сериализации они
// гоняются за config.Enabled и routingActive, а с машиной состояний могли бы
// оставить коммиттер в ready при снятых цепочках.
//
// Тест проверяет сам факт взаимного исключения: критическая секция не
// выполняется двумя горутинами одновременно.
func TestSetEnabledIsSerialized(t *testing.T) {
	a := &App{}

	var mu sync.Mutex
	inside := 0
	maxInside := 0

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.lifecycleMu.Lock()
			defer a.lifecycleMu.Unlock()

			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()

			mu.Lock()
			inside--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if maxInside != 1 {
		t.Errorf("одновременно внутри критической секции = %d, want 1", maxInside)
	}
}
```

- [ ] **Step 2: Запустить и убедиться, что падает**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -run SetEnabledIsSerialized . 2>&1 | grep -v "^{" | head -10'
```

Ожидается: `a.lifecycleMu undefined`.

- [ ] **Step 3: Добавить поле и откат**

В `src/backend/app.go` в структуру `App` добавить поле (рядом с `cfgMu`):

```go
	// lifecycleMu сериализует переходы жизненного цикла роутинга: поднятие,
	// снятие и смену состояния коммиттера. SetEnabled вызывается прямо из
	// HTTP-обработчика, поэтому двойной клик в UI без этого лока гоняется за
	// config.Enabled и routingActive. Порядок: берётся ВЫШЕ cfgMu и commitMu.
	lifecycleMu sync.Mutex
```

Заменить `bringUpRouting` и `bringDownRouting` (строки 388–433) на:

```go
func (a *App) bringUpRouting() error {
	if !a.routingActive.CompareAndSwap(false, true) {
		return nil
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Enable(); err != nil {
			a.tearDownRouting()
			a.routingActive.Store(false)
			return fmt.Errorf("failed to override DNS: %w", err)
		}
	}

	for _, group := range a.routingGroups() {
		if err := group.Enable(); err != nil {
			// Откат обязателен: без него уже включённые группы остаются с
			// живыми цепочками при routingActive=false. Тогда следующий сброс
			// таблиц прошивкой снёс бы их, а коммиттер на паузе событие
			// отбросил бы — правила исчезли бы молча.
			a.tearDownRouting()
			a.routingActive.Store(false)
			return fmt.Errorf("failed to enable group %s: %w", group.Name, err)
		}
		if err := group.Sync(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group sync after enable returned error")
		}
	}
	a.RebuildTrie()
	log.Info().Msg("routing brought up")
	return nil
}

// bringDownRouting tears down dnsOverrider and disables all routing groups.
// Idempotent: no-op when already down.
func (a *App) bringDownRouting() error {
	if !a.routingActive.CompareAndSwap(true, false) {
		return nil
	}
	a.tearDownRouting()
	log.Info().Msg("routing brought down")
	return nil
}

// tearDownRouting снимает роутинг БЕЗ гейта routingActive. Вынесено из
// bringDownRouting, чтобы неуспешный bringUpRouting мог откатиться: там гейт
// уже занят текущим поднятием, и bringDownRouting оказался бы no-op.
func (a *App) tearDownRouting() {
	for _, group := range a.routingGroups() {
		if err := group.Disable(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group disable failed")
		}
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Disable(); err != nil {
			log.Warn().Err(err).Msg("dnsOverrider disable failed")
		}
	}
}
```

Заменить `SetEnabled` (строки 438–457) на:

```go
func (a *App) SetEnabled(enabled bool) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	if a.config.Enabled == enabled && a.routingActive.Load() == enabled {
		return nil
	}

	if enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
	} else {
		_ = a.bringDownRouting()
	}

	a.config.Enabled = enabled
	if err := a.SaveConfig(); err != nil {
		log.Error().Err(err).Msg("failed to persist app.enabled")
		return err
	}
	return nil
}
```

- [ ] **Step 4: Запустить весь пакет**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go build ./... && GOOS=linux go test -tags testing -race . 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: `ok magitrickle`.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/app.go src/backend/app_lifecycle_test.go
git commit -m "fix(routing): откат неуспешного bringUpRouting и сериализация переходов (mt-yvf)

bringUpRouting при ошибке на N-й группе оставлял включёнными группы до неё —
при routingActive=false. Следующий сброс таблиц прошивкой снёс бы их цепочки,
а коммиттер, находясь на паузе, событие отбросил бы: правила исчезли бы молча,
хотя группы считают себя включёнными. Теперь ошибка откатывает поднятие.

Откат идёт через tearDownRouting, вынесенный из bringDownRouting: у последнего
гейт routingActive уже занят текущим поднятием, и он оказался бы no-op.

lifecycleMu сериализует переходы: SetEnabled зовётся прямо из HTTP-обработчика,
и двойной клик в UI гонялся за config.Enabled и routingActive."
```

---

### Task 5: Встраивание коммиттера в жизненный цикл приложения

**Files:**
- Modify: `src/backend/start.go:88-180` (создание коммиттера, порядок остановки), `src/backend/start.go:253-275` (`ForceCommitIPTables`)
- Modify: `src/backend/app.go` (поле `committer`)

**Interfaces:**
- Consumes: `newNetfilterCommitter`, `start`, `stop`, `setStateAndDrain`, `request`, `committerReady`, `committerPaused` (Tasks 2–3); `CommitWithRetryWake` (Task 1); `lifecycleMu` (Task 4).
- Produces: `func (a *App) forceCommitIPTablesWake(ctx context.Context, wake <-chan struct{}) error`; `func (a *App) RequestNetfilterCommit()` — публичный метод для HTTP-обработчика (используется в Task 6); поле `a.committer *netfilterCommitter`.

- [ ] **Step 1: Добавить поле и метод коммита с пробуждением**

В `src/backend/app.go` в структуру `App` добавить:

```go
	// committer — единственный писатель правил по событиям netfilter.d.
	committer *netfilterCommitter
```

В `src/backend/start.go` заменить `ForceCommitIPTables` (строки 253+) на:

```go
func (a *App) ForceCommitIPTables(ctx context.Context) error {
	return a.forceCommitIPTablesWake(ctx, nil)
}

// forceCommitIPTablesWake — то же, но с каналом пробуждения: пришедшее во время
// пауз между попытками событие прерывает ожидание и начинает проход заново.
//
// v6 коммитится даже если упал v4: семейства независимы, и терять оба из-за
// одного не нужно.
func (a *App) forceCommitIPTablesWake(ctx context.Context, wake <-chan struct{}) error {
	if a.nfHelper == nil {
		return nil
	}

	var errs []error

	if a.nfHelper.IPTables4 != nil {
		if err := a.nfHelper.IPTables4.CommitWithRetryWake(ctx, wake); err != nil {
			errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
		}
	}

	if a.nfHelper.IPTables6 != nil {
		if err := a.nfHelper.IPTables6.CommitWithRetryWake(ctx, wake); err != nil {
			errs = append(errs, fmt.Errorf("failed to commit ip6tables rules: %w", err))
		}
	}

	return errors.Join(errs...)
}

// RequestNetfilterCommit просит коммиттер переустановить правила. Неблокирующий:
// вызывается из HTTP-обработчика хука netfilter.d.
func (a *App) RequestNetfilterCommit() {
	if a.committer != nil {
		a.committer.request()
	}
}
```

- [ ] **Step 2: Создать коммиттер до открытия сокета**

В `src/backend/start.go` вставить ПЕРЕД строкой `httpServer, err := api.SetupHTTP(a, errChan)` (около строки 129):

```go
	// Коммиттер создаётся ДО открытия сокетов: хук netfilter.d бьёт в unix-сокет,
	// и событие может прийти сразу после SetupUnixSocket. До готовности модели он
	// в состоянии starting — событие защёлкивается, но не исполняется.
	//
	// defer со stop регистрируется здесь же, чтобы worker не утёк на ранних
	// return err ниже (LinkByName, RebuildSubscriptionGroups, bringUpRouting).
	// stop идемпотентен, поэтому явный вызов перед снятием правил ниже не
	// конфликтует с этим defer.
	a.committer = newNetfilterCommitter(a.forceCommitIPTablesWake)
	a.committer.start(newCtx)
	defer a.committer.stop()
```

- [ ] **Step 3: Обеспечить порядок остановки**

В `src/backend/start.go` заменить строку `defer func() { _ = a.bringDownRouting() }()` (строка 173) на:

```go
	// Порядок обязателен: сперва остановить коммиттер и ДОЖДАТЬСЯ его, потом
	// снимать правила. Иначе teardown снимает цепочки, пока worker их
	// восстанавливает. Одним defer'ом это не решается: defer, зарегистрированный
	// при создании коммиттера выше, по LIFO выполнится ПОЗЖЕ этого — поэтому
	// stop вызывается явно здесь, а тот defer остаётся страховкой от ранних
	// выходов. Повторный stop — no-op.
	defer func() {
		a.committer.stop()
		_ = a.bringDownRouting()
	}()
```

- [ ] **Step 4: Перевести коммиттер в рабочее состояние после поднятия роутинга**

В `src/backend/start.go` заменить блок (около строки 166):

```go
	if a.config.Enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
	} else {
		log.Warn().Msg("MagiTrickle started with app.enabled=false — routing is paused")
	}
```

на:

```go
	if a.config.Enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
		// Модель собрана — коммиттер может писать. Событие, защёлкнутое во время
		// старта, исполнится немедленно.
		a.committer.setStateAndDrain(committerReady)
	} else {
		log.Warn().Msg("MagiTrickle started with app.enabled=false — routing is paused")
		a.committer.setStateAndDrain(committerPaused)
	}
```

- [ ] **Step 5: Синхронизировать состояние коммиттера с паузой и возобновлением**

В `src/backend/app.go` в `SetEnabled` (внутри `lifecycleMu`) заменить блок переключения на:

```go
	if enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
		if a.committer != nil {
			a.committer.setStateAndDrain(committerReady)
		}
	} else {
		if a.committer != nil {
			// Сначала паузим коммиттер, потом снимаем правила: иначе он успел бы
			// восстановить то, что снимает teardown.
			a.committer.setStateAndDrain(committerPaused)
		}
		_ = a.bringDownRouting()
	}
```

- [ ] **Step 6: Собрать и прогнать все тесты**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go build ./... && GOOS=linux go vet -tags testing ./... && GOOS=linux go test -tags testing -race ./... 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: все пакеты `ok`.

- [ ] **Step 7: Коммит**

```bash
git add src/backend/start.go src/backend/app.go
git commit -m "feat(netfilter): встроить коммиттер в жизненный цикл демона (mt-yvf)

Коммиттер создаётся до открытия unix-сокета: хук бьёт именно туда, и событие
может прийти раньше, чем собрана модель — до готовности оно защёлкивается.

Порядок остановки соблюдён явно: stop коммиттера и ожидание worker'а идут
ПЕРЕД снятием правил. Одним defer это не решается — зарегистрированный при
создании коммиттера выполнился бы по LIFO позже снятия, поэтому он остаётся
только страховкой от ранних выходов из Start, а рабочий путь зовёт stop явно.
Идемпотентность делает двойной вызов безопасным.

Пауза переводит коммиттер в paused ДО снятия правил, иначе он успел бы
восстановить то, что снимает teardown."
```

---

### Task 6: Тонкий хук

**Files:**
- Modify: `src/backend/api/v1/handlers.go:47-70` (`NetfilterDHook`)
- Modify: `src/backend/app/magitrickle.go` (интерфейс `Main`)

**Interfaces:**
- Consumes: `a.RequestNetfilterCommit()` (Task 5).
- Produces: метод `RequestNetfilterCommit()` в интерфейсе `app.Main`.

- [ ] **Step 1: Добавить метод в интерфейс**

В `src/backend/app/magitrickle.go` рядом с `ForceCommitIPTables(ctx context.Context) error` добавить:

```go
	RequestNetfilterCommit()
```

- [ ] **Step 2: Сделать обработчик неблокирующим**

В `src/backend/api/v1/handlers.go` заменить тело `NetfilterDHook` на:

```go
func (h *Handler) NetfilterDHook(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.NetfilterDHookReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Debug().
		Str("type", req.Type).
		Str("table", req.Table).
		Msg("received netfilter.d event")

	// Только сигнал, без ожидания. Прошивка шлёт событие на КАЖДУЮ таблицу,
	// поэтому одна её перезапись даёт несколько событий подряд — коммиттер
	// схлопывает их в один проход.
	//
	// Результат наружу не отдаём: вызывающему shell-скрипту с ним делать нечего,
	// а socat всё равно закрывает соединение сразу после отправки.
	h.app.RequestNetfilterCommit()
}
```

- [ ] **Step 3: Собрать и прогнать всё**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go build ./... && GOOS=linux go vet -tags testing ./... && GOOS=linux go test -tags testing -race ./... 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: все пакеты `ok`.

- [ ] **Step 4: Коммит**

```bash
git add src/backend/api/v1/handlers.go src/backend/app/magitrickle.go
git commit -m "feat(netfilter): хук netfilter.d только сигналит коммиттеру (mt-yvf)

Обработчик больше не ждёт применения правил: он шлёт неблокирующий сигнал и
отвечает сразу. Прошивка присылает событие на каждую таблицу, и схлопывание в
коммиттере превращает серию в один проход вместо трёх независимых.

Битый JSON по-прежнему даёт 400 — это ошибка вызывающего, а не результат
восстановления правил."
```

---

### Task 7: Проверка на живом роутере

**Files:** нет (полевая проверка).

**Interfaces:**
- Consumes: собранный пакет со всеми предыдущими задачами.

- [ ] **Step 1: Собрать пакет**

```bash
cd "<HOME>\GitHub\MagiTrickle\.claude\worktrees\happy-spence-498b01" && TAG=$(git describe --tags --abbrev=0) && COMMIT=$(git rev-parse --short HEAD) && PRERELEASE="${TAG%.*}.$((${TAG##*.}+1))" && DATE=$(date +%Y%m%d%H%M%S) && PKGVER="${PRERELEASE}~git${DATE}.${COMMIT}" && wsl -e bash -c "export PATH=\"\$HOME/.local/bin:\$PATH\" && eval \"\$(fnm env)\" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01 && export PKG_VERSION='$PKGVER' PKG_VERSION_PRERELEASE='$PRERELEASE' && make PLATFORM=entware TARGET=aarch64-3.10_kn GOOS=linux GOARCH=arm64 GOMIPS= 2>&1 | tail -3"
```

PKG_VERSION вычисляется на Windows-стороне: в worktree WSL-git не читает `.git` с Windows-путём и версия ломается.

- [ ] **Step 2: Задеплоить**

```bash
powershell -File scripts/update-router-package.ps1
```

Ожидается: `Deploy confirmed: magitrickled alive (pid=...) 45s after install.`

- [ ] **Step 3: Проверить восстановление после полного сноса**

Снести все наши цепочки и джампы в mangle и вызвать хук так, как это делает ndm:

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; for c in $(iptables -t mangle -S PREROUTING | grep -o "MT_[0-9a-f]*" | sort -u); do iptables -t mangle -D PREROUTING ! -i lo -j $c 2>/dev/null; done; for c in $(iptables -t mangle -S | grep "^-N MT_" | awk "{print \$2}"); do iptables -t mangle -F $c 2>/dev/null; iptables -t mangle -X $c 2>/dev/null; done; echo "снесено: $(iptables -t mangle -S | grep -c "^-N MT_")"; type=iptables table=mangle sh /opt/etc/ndm/netfilter.d/100-magitrickle; sleep 2; echo "восстановлено: цепочек=$(iptables -t mangle -S | grep -c "^-N MT_") джампов=$(iptables -t mangle -S PREROUTING | grep -c "j MT_")"'
```

Ожидается: после сноса `0`, после хука число цепочек и джампов совпадает с числом до сноса (на текущем проде — 38/38).

- [ ] **Step 4: Проверить, что хук отвечает мгновенно**

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; S=$(date +%s%N); type=iptables table=mangle sh /opt/etc/ndm/netfilter.d/100-magitrickle; E=$(date +%s%N); echo "хук вернулся за $(( (E-S)/1000000 )) мс"'
```

Ожидается: единицы миллисекунд — обработчик больше не ждёт применения правил. До изменения это же измерение давало 34–79 мс.

- [ ] **Step 5: Проверить, что демон пережил и правила целы**

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; echo "pid: $(pidof magitrickled)"; echo "mangle: цепочек=$(iptables -t mangle -S | grep -c "^-N MT_") джампов=$(iptables -t mangle -S PREROUTING | grep -c "j MT_")"; echo "nat: цепочек=$(iptables -t nat -S | grep -c "^-N MT_") джампов=$(iptables -t nat -S PREROUTING | grep -c "j MT_")"; curl -s -o /dev/null -w "проверка связи: %{http_code}\n" -m 8 https://1.1.1.1/'
```

Ожидается: демон жив, mangle и nat полные, связь есть.

- [ ] **Step 6: Записать результат в задачу**

```bash
bd comment mt-yvf "Полевая проверка на <ROUTER_IP>: <вставить фактические числа из шагов 3-5>"
```

---

## Self-Review

**Покрытие спеки:**

| Требование спеки | Задача |
|---|---|
| Компонент committer, горутина, канал ёмкостью 1 | Task 2 |
| Схлопывание («не более одного отложенного прохода») | Task 2 |
| Прерывание ожидания между попытками, сброс бюджета | Task 1 |
| Собственный контекст, не `r.Context()` | Task 5 (worker на `newCtx`), уже частично в `2d5efe4` |
| Машина состояний `starting`/`ready`/`paused`/`stopping` | Task 3 |
| Защёлкивание события в `starting` | Task 3 |
| Отбрасывание события в `paused` | Task 3 |
| Откат неуспешного `bringUpRouting` | Task 4 |
| Мьютекс переходов | Task 4 |
| Порядок остановки, идемпотентный stop, два пути вызова | Tasks 2 и 5 |
| Канал не закрывается | Task 2 |
| Отложенный reconcile внутри `select` | Task 2 |
| Тонкий хук | Task 6 |
| `commitMu`, таймаут exec | сделано в mt-7sa |
| Восстановление после полного flush | Task 7 |

**Не покрыто намеренно:** позиция джампов (mt-rrg, отдельная задача); `drop-then-stage` (спека обосновывает отказ); build tag платформы (не нужен); тесты конкуренции коммиттера с `PortRemap`/`Group.Enable` через блокирующий fake — вынесены за скоуп, так как требуют доступа к внутренностям `netfilterTools` из пакета `magitrickle`; сериализация обеспечивается `commitMu`, уже покрытым тестом в mt-7sa.

**Согласованность типов:** `commit func(ctx context.Context, wake <-chan struct{}) error` — сигнатура совпадает в Task 2 (поле), Task 5 (`forceCommitIPTablesWake`). `setStateAndDrain` вводится в Task 3 и используется в Task 5. `CommitWithRetryWake(ctx, wake)` вводится в Task 1 и используется в Task 5.
