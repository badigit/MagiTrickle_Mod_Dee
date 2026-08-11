# Асинхронный коммиттер netfilter-правил — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers-dim:subagent-driven-development (recommended) or superpowers-dim:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Обрабатывать события `netfilter.d` в отдельной горутине со схлопыванием, чтобы одна перезапись таблиц прошивкой Keenetic стоила одного прохода, а HTTP-хук отвечал мгновенно.

**Architecture:** Одна горутина владеет всем изменяемым состоянием коммиттера — текущим режимом, защёлкнутым событием и таймером страховочного прохода. Снаружи меняют режим командой через канал с подтверждением, а не записью в общую переменную: тогда гонок нет по построению, а не по договорённости. Схлопывание событий — следствие канала ёмкостью 1.

**Tech Stack:** Go, стандартная библиотека (`context`, `sync`, `time`), zerolog. Тесты — `go test -tags testing`, fake-реализация `Executable` уже есть.

## Global Constraints

- Спека: `.designs/bd-mt-yvf/spec.md`. При расхождении плана со спекой — прав спек, сообщить оркестратору.
- Сборка и тесты ТОЛЬКО через WSL, никогда напрямую на Windows:
  `wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing ./...'`
- Комментарии в коде и сообщения коммитов — по-русски. Без AI-атрибуции и `Co-Authored-By`.
- Коммитить после каждой задачи. Push — только по явной просьбе разработчика.
- `iptables-restore` НЕ убиваем по приходу события (замер прода: полный проход 34–79 мс). Прерываем только ожидание между попытками.
- Каналы коммиттера НИКОГДА не закрываются: в них пишет HTTP-обработчик, запись в закрытый канал — паника.
- Контракт порядка локов (нарушение = дедлок): `lifecycleMu → cfgMu → g.locker → locker компонента → preambleMu → commitMu → ipt.sync → chain.sync → exec`. Worker берёт только хвост, начиная с `commitMu`; `cfgMu` и `g.locker` он не берёт никогда.

## Что уже сделано (НЕ переделывать)

Реализовано в mt-7sa (`f8f989d`) и mt-pfo (`436df82`, `2d5efe4`):

- `commitMu sync.Mutex` в `IPTables` — сериализация коммитов, берётся в `CommitContext` (`utils/iptables/iptables.go:33,229`), покрыта тестом `TestCommitMuSerialisesCommits` (`utils/iptables/exec-timeout_test.go:154`);
- `Executable.Save(ctx)`/`Restore(ctx, data)` с контекстом и потолком `execTimeout = 5s`, ошибка `ErrExecTimeout`;
- `CommitWithRetry(ctx)` с бюджетом `commitRetryBackoff = {0, 50ms, 200ms, 500ms}`, классификаторы `IsRacedError`, `IsRetryableError`;
- `NetfilterDHook` больше НЕ передаёт `r.Context()` — использует `context.Background()`.

## File Structure

| Файл | Ответственность |
|---|---|
| `src/backend/utils/iptables/commit-retry.go` (изменить) | `CommitWithRetryWake(ctx, wake)`; `CommitWithRetry(ctx)` — обёртка с `nil`-каналом |
| `src/backend/utils/iptables/convergence_test.go` (создать) | Тесты сходимости модели: повторный коммит и восстановление после полного flush |
| `src/backend/netfilter_committer.go` (создать) | Компонент: worker-владелец состояния, каналы, идемпотентная остановка |
| `src/backend/netfilter_committer_test.go` (создать) | Тесты компонента на подставном коммите, без netfilter |
| `src/backend/app.go` (изменить) | Откат неуспешного `bringUpRouting`, `lifecycleMu`, синхронизация режима коммиттера |
| `src/backend/start.go` (изменить) | Запуск коммиттера до открытия сокета, порядок остановки, `forceCommitIPTablesWake` |
| `src/backend/api/v1/handlers.go` (изменить) | `NetfilterDHook` шлёт сигнал и отвечает сразу |
| `src/backend/app/magitrickle.go` (изменить) | Метод интерфейса для сигнала коммиттеру |

---

### Task 1: Пробуждаемый цикл ретраев и тесты сходимости

**Files:**
- Modify: `src/backend/utils/iptables/commit-retry.go:98-141`
- Test: `src/backend/utils/iptables/commit-retry_test.go`
- Create: `src/backend/utils/iptables/convergence_test.go`

**Interfaces:**
- Consumes: `ipt.CommitContext(ctx) error`, `commitRetryBackoff []time.Duration`, `protoName(Protocol) string`, `ErrExecTimeout`, `IsRacedError` — всё существует.
- Produces: `func (ipt *IPTables) CommitWithRetryWake(ctx context.Context, wake <-chan struct{}) error`. Событие из `wake` во время паузы между попытками начинает проход заново с полным бюджетом. `CommitWithRetry(ctx)` сохраняет прежнюю сигнатуру и поведение (эквивалент `wake = nil`).

- [ ] **Step 1: Написать падающие тесты пробуждения**

Добавить в конец `src/backend/utils/iptables/commit-retry_test.go`:

```go
// TestCommitWithRetryWakeRestartsOnEvent: событие, пришедшее во время паузы
// между попытками, прекращает ожидание и начинает проход ЗАНОВО — с полным
// бюджетом попыток. Смысл: дельта считалась от снимка, который уже устарел,
// поэтому продолжать старый проход бессмысленно.
func TestCommitWithRetryWakeRestartsOnEvent(t *testing.T) {
	ipt, fake := newRetryFixture(t)

	saved := commitRetryBackoff
	commitRetryBackoff = []time.Duration{0, time.Hour, time.Hour}
	t.Cleanup(func() { commitRetryBackoff = saved })

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
// не готов, поэтому прежнее поведение сохраняется дословно.
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
// события — во время остановки писать в netfilter нельзя.
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

- [ ] **Step 2: Написать тесты сходимости**

Спека требует их отдельно от пробуждения: они доказывают, почему коммиттеру не нужен `drop-then-stage`.

Создать `src/backend/utils/iptables/convergence_test.go`:

```go
//go:build testing

package iptables

import (
	"context"
	"testing"
)

// convergenceFixture — цепочка MT_TEST с двумя правилами и джампом из
// PREROUTING: минимальная модель того, что демон держит для одной группы.
func convergenceFixture(t *testing.T) (*IPTables, *FakeIPTables) {
	t.Helper()

	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)

	ipt := NewIPTables(fake)
	if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}
	if err := ipt.RegisterChainOverride("mangle", "MT_TEST"); err != nil {
		t.Fatalf("RegisterChainOverride failed: %v", err)
	}
	if err := ipt.Append("mangle", "MT_TEST", "-p", "udp", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := ipt.Append("mangle", "MT_TEST", "-p", "tcp", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if err := ipt.Append("mangle", "PREROUTING", "!", "-i", "lo", "-j", "MT_TEST"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	return ipt, fake
}

// TestCommitIsIdempotent: повторный коммит при неизменной модели не должен
// порождать НИ ОДНОЙ команды. Это основание отказа от drop-then-stage: лишний
// проход коммиттера ничего не стоит и ничего не ломает.
func TestCommitIsIdempotent(t *testing.T) {
	ipt, fake := convergenceFixture(t)

	if err := ipt.Commit(); err != nil {
		t.Fatalf("первый Commit failed: %v", err)
	}
	callsAfterFirst := fake.RestoreCalls()

	if err := ipt.Commit(); err != nil {
		t.Fatalf("второй Commit failed: %v", err)
	}
	if got := fake.RestoreCalls(); got != callsAfterFirst {
		t.Errorf("второй Commit выполнил restore (%d -> %d), хотя модель не менялась", callsAfterFirst, got)
	}

	rules := fake.GetRules("mangle", "MT_TEST")
	if len(rules) != 2 {
		t.Errorf("правил в цепочке = %d, want 2 (дублей быть не должно): %v", len(rules), rules)
	}
	jumps := fake.GetRules("mangle", "PREROUTING")
	if len(jumps) != 1 {
		t.Errorf("джампов = %d, want 1 (дублей быть не должно): %v", len(jumps), jumps)
	}
}

// TestCommitRecoversAfterFullFlush: прошивка Keenetic переписывает таблицу
// целиком, снося наши цепочки. Повторный коммит обязан восстановить их из
// модели — без пересборки модели и без drop-then-stage.
func TestCommitRecoversAfterFullFlush(t *testing.T) {
	ipt, fake := convergenceFixture(t)

	if err := ipt.Commit(); err != nil {
		t.Fatalf("первый Commit failed: %v", err)
	}

	// прошивка стёрла всё
	fake.SetInitialRules("mangle", "PREROUTING", nil)
	fake.DropChain("mangle", "MT_TEST")

	if err := ipt.CommitContext(context.Background()); err != nil {
		t.Fatalf("восстановительный Commit failed: %v", err)
	}

	if !fake.ChainExists("mangle", "MT_TEST") {
		t.Fatal("цепочка MT_TEST не восстановлена после полного flush")
	}
	if got := len(fake.GetRules("mangle", "MT_TEST")); got != 2 {
		t.Errorf("правил в восстановленной цепочке = %d, want 2", got)
	}
	if got := len(fake.GetRules("mangle", "PREROUTING")); got != 1 {
		t.Errorf("джампов после восстановления = %d, want 1", got)
	}
}
```

- [ ] **Step 3: Добавить в fake удаление цепочки**

Тест сходимости моделирует снос цепочки прошивкой, поэтому fake должен уметь её убирать. Добавить в `src/backend/utils/iptables/executable-fake.go` рядом с `ChainExists`:

```go
// DropChain удаляет цепочку целиком — так выглядит перезапись таблицы
// прошивкой Keenetic со стороны нашей модели.
func (ipt *FakeIPTables) DropChain(table, chain string) {
	if ipt.rules[table] == nil {
		return
	}
	delete(ipt.rules[table], chain)
}
```

- [ ] **Step 4: Запустить тесты и убедиться, что они падают**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -run "Wake|Converg|Idempotent|Flush" ./utils/iptables/ 2>&1 | grep -v "^{" | head -20'
```

Ожидается: `undefined: ipt.CommitWithRetryWake` (ошибка компиляции).

- [ ] **Step 5: Реализовать пробуждаемый цикл**

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
		err, restarted := ipt.commitRetryPass(ctx, wake)
		if !restarted {
			return err
		}
		log.Debug().
			Str("type", protoName(ipt.Proto())).
			Msg("iptables commit restarted by a new netfilter event")
	}
}

// commitRetryPass — один проход по бюджету попыток. Второе значение true
// означает, что проход прерван событием из wake и должен начаться заново.
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

- [ ] **Step 6: Запустить весь пакет с -race**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -race ./utils/iptables/ 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: `ok magitrickle/utils/iptables`. Старые тесты должны пройти без правок — это проверка того, что обёртка не изменила поведение.

- [ ] **Step 7: Коммит**

```bash
git add src/backend/utils/iptables/
git commit -m "feat(netfilter): цикл ретраев умеет прерываться новым событием (mt-yvf)

CommitWithRetryWake слушает канал пробуждения в паузе между попытками:
событие означает, что состояние ядра снова изменилось, и продолжать проход
со старой дельтой бессмысленно — он начинается заново с полным бюджетом.

CommitWithRetry остаётся обёрткой с nil-каналом, синхронные пути и их тесты
не тронуты: nil-канал в select никогда не готов.

Плюс тесты сходимости, на которых стоит отказ от drop-then-stage: повторный
коммит при неизменной модели не порождает команд и не плодит дублей, а после
полного сноса цепочки она восстанавливается из модели."
```

---

### Task 2: Компонент коммиттера

**Files:**
- Create: `src/backend/netfilter_committer.go`
- Create: `src/backend/netfilter_committer_test.go`

**Interfaces:**
- Consumes: ничего из предыдущих задач — функция коммита внедряется, поэтому компонент тестируется без netfilter.
- Produces:
  - `func startNetfilterCommitter(ctx context.Context, commit func(ctx context.Context, wake <-chan struct{}) error, reconcileDelay time.Duration) *netfilterCommitter` — создаёт И запускает worker (раздельных «создать» и «запустить» нет намеренно: так невозможно обратиться к незапущенному компоненту);
  - `func (c *netfilterCommitter) request()` — неблокирующий сигнал «нужен проход»;
  - `func (c *netfilterCommitter) setMode(m committerMode)` — синхронная смена режима, возвращается после того, как worker её принял;
  - `func (c *netfilterCommitter) stop()` — идемпотентная остановка с ожиданием worker'а;
  - режимы `committerStarting`, `committerReady`, `committerPaused`, `committerStopping`.

**Ключевое решение:** режим, защёлкнутое событие и таймер страховочного прохода — локальные переменные горутины `run`. Снаружи режим меняют командой через канал. Поэтому «проверили режим, а он сменился» и «таймер пережил паузу» невозможны по построению, а не по договорённости.

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
	<-failed                    // проход провалился, таймер взведён
	c.setMode(committerPaused)  // синхронная точка: worker принял паузу

	before := passes.Load()
	time.Sleep(150 * time.Millisecond) // таймер успел бы выстрелить дважды
	if got := passes.Load(); got != before {
		t.Errorf("проходов %d -> %d: страховочный таймер пережил паузу", before, got)
	}
}
```

- [ ] **Step 2: Запустить тесты и убедиться, что они падают**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -run Committer . 2>&1 | grep -v "^{" | head -20'
```

Ожидается: `undefined: startNetfilterCommitter` (ошибка компиляции).

- [ ] **Step 3: Реализовать компонент**

Создать `src/backend/netfilter_committer.go`:

```go
package magitrickle

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// committerMode — что коммиттер делает с пришедшим событием netfilter.d.
// Признаком готовности НЕ может служить routingActive: он выставляется в
// начале bringUpRouting, до включения групп.
type committerMode int

const (
	// committerStarting — модель ещё собирается. Событие защёлкивается и
	// исполняется при переходе в ready. Отбрасывать нельзя: прошивка могла
	// снести уже поднятые группы, а включение последующих их не восстановит.
	committerStarting committerMode = iota
	// committerReady — проходы выполняются.
	committerReady
	// committerPaused — роутинг снят намеренно (config.Enabled=false).
	// Событие отбрасывается вместе с защёлкой.
	committerPaused
	// committerStopping — идёт остановка, проходы больше не начинаются.
	committerStopping
)

// defaultReconcileDelay — задержка страховочного прохода после исчерпания
// бюджета попыток. Без него серия проигранных гонок и последующая тишина
// оставили бы правила снятыми до перезапуска демона.
const defaultReconcileDelay = 2 * time.Second

// netfilterCommitter владеет единственной горутиной, которая переустанавливает
// наши правила по событиям netfilter.d.
//
// Прошивка Keenetic переписывает таблицу целиком и шлёт событие на КАЖДУЮ
// таблицу, поэтому одна её перезапись даёт несколько событий подряд. Канал req
// ёмкостью 1 схлопывает их: гарантия — не более одного ОТЛОЖЕННОГО прохода.
//
// Весь изменяемый состав — режим, защёлка и страховочный таймер — живёт
// локальными переменными горутины run. Снаружи режим меняют командой через
// канал cmds, поэтому «проверили режим, а он сменился» и «таймер пережил
// паузу» невозможны по построению.
type netfilterCommitter struct {
	// req — «нужен проход», ёмкость 1. НИКОГДА не закрывается: в него пишет
	// HTTP-обработчик, а запись в закрытый канал — паника.
	req chan struct{}
	// wake — «прерви ожидание между попытками», ёмкость 1. Отдельный канал, а
	// не req: проход состоит из двух коммитов (IPv4 и IPv6), и общий канал
	// означал бы, что первый съест сигнал, предназначенный обоим.
	wake chan struct{}
	// cmds — смена режима с подтверждением.
	cmds chan committerCmd

	commit         func(ctx context.Context, wake <-chan struct{}) error
	reconcileDelay time.Duration

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     chan struct{}
}

type committerCmd struct {
	mode committerMode
	ack  chan struct{}
}

// startNetfilterCommitter создаёт и СРАЗУ запускает коммиттер. Раздельных
// «создать» и «запустить» нет намеренно: так к компоненту невозможно
// обратиться до старта worker'а.
func startNetfilterCommitter(
	ctx context.Context,
	commit func(ctx context.Context, wake <-chan struct{}) error,
	reconcileDelay time.Duration,
) *netfilterCommitter {
	workerCtx, cancel := context.WithCancel(ctx)
	c := &netfilterCommitter{
		req:            make(chan struct{}, 1),
		wake:           make(chan struct{}, 1),
		cmds:           make(chan committerCmd),
		commit:         commit,
		reconcileDelay: reconcileDelay,
		cancel:         cancel,
		done:           make(chan struct{}),
	}
	go c.run(workerCtx)
	return c
}

// request — неблокирующий сигнал. Если запрос уже висит, новый растворяется:
// это и есть схлопывание. Дополнительно будит цикл ретраев, если проход прямо
// сейчас пережидает паузу между попытками.
func (c *netfilterCommitter) request() {
	select {
	case c.req <- struct{}{}:
	default:
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// setMode меняет режим и возвращается ПОСЛЕ того, как worker команду принял.
// Синхронность важна: перевод в paused обязан гарантировать, что нового
// прохода уже не начнётся, иначе он вернул бы правила, которые снимает
// teardown.
//
// Ожидание ack тоже слушает done: worker мог получить отмену контекста и выйти,
// не подтвердив команду, — тогда ack не закроется никогда.
func (c *netfilterCommitter) setMode(m committerMode) {
	ack := make(chan struct{})
	select {
	case c.cmds <- committerCmd{mode: m, ack: ack}:
	case <-c.done:
		return
	}
	select {
	case <-ack:
	case <-c.done:
	}
}

// stop переводит коммиттер в stopping, отменяет worker и ДОЖДАВШИСЬ его
// возвращается. Идемпотентен: вызывается и явно перед снятием правил, и
// defer'ом на ранних выходах из Start.
func (c *netfilterCommitter) stop() {
	c.stopOnce.Do(func() {
		c.cancel()
		<-c.done
	})
}

func (c *netfilterCommitter) run(ctx context.Context) {
	defer close(c.done)

	mode := committerStarting
	latched := false
	// reconcile — страховочный таймер. Живёт ИМЕННО здесь: отвязанный
	// time.AfterFunc пережил бы и смену режима, и остановку.
	var reconcile <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			return

		case cmd := <-c.cmds:
			switch cmd.mode {
			case committerPaused, committerStopping:
				// Правила снимаются намеренно: ни защёлка, ни страховочный
				// проход, ни УЖЕ ЛЕЖАЩЕЕ В ОЧЕРЕДИ событие не должны их
				// вернуть. Очередь дренируем здесь: select выбирает между
				// cmds и req случайно, поэтому «команда принята» само по себе
				// не означает, что старое событие не всплывёт после resume.
				latched = false
				reconcile = nil
				select {
				case <-c.req:
				default:
				}
			case committerReady:
				if latched {
					latched = false
					c.request()
				}
			}
			mode = cmd.mode
			close(cmd.ack)
			continue

		case <-c.req:
			reconcile = nil

		case <-reconcile:
			reconcile = nil
		}

		// Отмена могла прийти одновременно с событием: select выбрал бы между
		// ними случайно, и проход начался бы уже после остановки.
		if ctx.Err() != nil {
			return
		}

		switch mode {
		case committerStopping:
			return
		case committerStarting:
			latched = true
			continue
		case committerPaused:
			continue
		}

		// Осушаем wake: сигнал, оставшийся от предыдущего события, не должен
		// прервать проход, который ещё не начался.
		select {
		case <-c.wake:
		default:
		}

		if err := c.commit(ctx, c.wake); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Dur("retry_in", c.reconcileDelay).
				Msg("netfilter commit pass failed, scheduling reconcile")
			reconcile = time.After(c.reconcileDelay)
		}
	}
}
```

- [ ] **Step 4: Запустить тесты с -race**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go test -tags testing -race -run Committer -count=3 . 2>&1 | grep -E "^(ok|FAIL|---)"'
```

`-count=3` — проверка на флаки. Ожидается: `ok magitrickle`.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/netfilter_committer.go src/backend/netfilter_committer_test.go
git commit -m "feat(netfilter): компонент асинхронного коммиттера правил (mt-yvf)

Горутина владеет всем изменяемым состоянием — режимом, защёлкой и страховочным
таймером. Снаружи режим меняют командой через канал с подтверждением, поэтому
«проверили режим, а он сменился» и «таймер пережил паузу» невозможны по
построению, а не по договорённости.

Схлопывание — следствие канала ёмкостью 1: прошивка шлёт событие на каждую
таблицу, и серия от одной перезаписи даёт не более одного отложенного прохода.

Пробуждение цикла ретраев идёт отдельным каналом, а не тем же, что события:
проход состоит из двух коммитов (IPv4 и IPv6), и общий канал означал бы, что
первый съедает сигнал, предназначенный обоим.

Создание совмещено с запуском: обратиться к незапущенному компоненту нельзя,
поэтому и ветки «остановлен до старта» не существует."
```

---

### Task 3: Откат неуспешного поднятия роутинга и сериализация переходов

**Files:**
- Modify: `src/backend/app.go:388-433` (`bringUpRouting`, `bringDownRouting`), `src/backend/app.go:438-457` (`SetEnabled`)

**Interfaces:**
- Consumes: ничего из предыдущих задач.
- Produces: `func (a *App) tearDownRouting() error` — снятие роутинга без гейта `routingActive`, возвращает объединённую ошибку; поле `lifecycleMu sync.Mutex` в `App`.

**Про тесты этой задачи — честно.** Юнит-тест на откат потребовал бы подменяемых `Group` и `netfilterTools.Helper`, которых в коде нет: `Group.Enable` идёт прямо в ipset и iptables. Вводить интерфейсы ради одного теста несоразмерно. Поэтому корректность отката проверяется чтением кода при ревью задачи и полевым сценарием в Task 6, а не юнит-тестом. Фиктивного теста, проверяющего собственноручно взятый мьютекс вместо поведения `SetEnabled`, здесь нет намеренно.

- [ ] **Step 1: Добавить поле мьютекса**

В `src/backend/app.go` в структуру `App` рядом с `cfgMu` добавить:

```go
	// lifecycleMu сериализует переходы жизненного цикла роутинга: поднятие,
	// снятие и смену режима коммиттера. SetEnabled вызывается прямо из
	// HTTP-обработчика, поэтому двойной клик в UI без этого лока гоняется за
	// config.Enabled и routingActive. Берётся ВЫШЕ cfgMu и commitMu.
	lifecycleMu sync.Mutex
```

- [ ] **Step 2: Вынести снятие роутинга и добавить откат**

Заменить `bringUpRouting` и `bringDownRouting` (строки 388–433) на:

```go
func (a *App) bringUpRouting() error {
	if !a.routingActive.CompareAndSwap(false, true) {
		return nil
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Enable(); err != nil {
			return errors.Join(fmt.Errorf("failed to override DNS: %w", err), a.rollbackFailedBringUp())
		}
	}

	for _, group := range a.routingGroups() {
		if err := group.Enable(); err != nil {
			return errors.Join(
				fmt.Errorf("failed to enable group %s: %w", group.Name, err),
				a.rollbackFailedBringUp(),
			)
		}
		if err := group.Sync(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group sync after enable returned error")
		}
	}
	a.RebuildTrie()
	log.Info().Msg("routing brought up")
	return nil
}

// rollbackFailedBringUp снимает то, что успело подняться до ошибки, и
// возвращает ошибку неполного отката.
//
// Без отката уже включённые группы остались бы с живыми цепочками при
// routingActive=false: следующая перезапись таблиц прошивкой снесла бы их, а
// коммиттер, находясь к тому моменту на паузе, событие отбросил бы — правила
// исчезли бы молча, хотя группы считают себя включёнными.
//
// Неполный откат НЕЛЬЗЯ выдавать за успех. Group.disable и PortRemap.disable
// сбрасывают свой флаг enabled через defer даже когда снятие не удалось,
// поэтому после ошибки объекты считают себя выключенными, а цепочки в ядре
// могут остаться. Единственный честный ответ вызывающему — вернуть ошибку:
// на старте она остановит запуск (состояние подчистит CleanIPTables при
// следующем), в SetEnabled — дойдёт до пользователя, а не притворится паузой.
func (a *App) rollbackFailedBringUp() error {
	err := a.tearDownRouting()
	a.routingActive.Store(false)
	if err != nil {
		log.Error().Err(err).Msg("rollback after failed routing bring-up was incomplete")
	}
	return err
}

// bringDownRouting tears down dnsOverrider and disables all routing groups.
// Idempotent: no-op when already down.
func (a *App) bringDownRouting() error {
	if !a.routingActive.CompareAndSwap(true, false) {
		return nil
	}
	err := a.tearDownRouting()
	if err != nil {
		log.Warn().Err(err).Msg("routing brought down incompletely: some rules may remain")
	} else {
		log.Info().Msg("routing brought down")
	}
	return err
}

// tearDownRouting снимает роутинг БЕЗ гейта routingActive и возвращает всё,
// что не удалось снять.
//
// Вынесено из bringDownRouting, чтобы неуспешный bringUpRouting мог
// откатиться: там гейт уже занят текущим поднятием, и bringDownRouting
// оказался бы no-op.
func (a *App) tearDownRouting() error {
	var errs []error

	for _, group := range a.routingGroups() {
		if err := group.Disable(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group disable failed")
			errs = append(errs, fmt.Errorf("group %s: %w", group.Name, err))
		}
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Disable(); err != nil {
			log.Warn().Err(err).Msg("dnsOverrider disable failed")
			errs = append(errs, fmt.Errorf("dnsOverrider: %w", err))
		}
	}

	return errors.Join(errs...)
}
```

- [ ] **Step 3: Сериализовать SetEnabled и не терять ошибку снятия**

Заменить `SetEnabled` (строки 438–457) на:

```go
func (a *App) SetEnabled(enabled bool) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	if a.config.Enabled == enabled && a.routingActive.Load() == enabled {
		return nil
	}

	var bringDownErr error
	if enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
	} else {
		bringDownErr = a.bringDownRouting()
	}

	// Намерение пользователя фиксируем ДАЖЕ при неудачном снятии: иначе после
	// перезапуска демон снова поднимет роутинг, который просили выключить.
	// Но саму ошибку не глотаем — иначе HTTP ответит 200 OK, хотя цепочки в
	// ядре могли остаться.
	a.config.Enabled = enabled
	saveErr := a.SaveConfig()
	if saveErr != nil {
		log.Error().Err(saveErr).Msg("failed to persist app.enabled")
	}
	return errors.Join(bringDownErr, saveErr)
}
```

- [ ] **Step 4: Проверить импорт и собрать**

Убедиться, что в `src/backend/app.go` импортирован `errors` (нужен для `errors.Join`). Затем:

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go build ./... && GOOS=linux go vet -tags testing ./... && GOOS=linux go test -tags testing -race ./... 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: сборка без ошибок, все пакеты `ok`.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/app.go
git commit -m "fix(routing): откат неуспешного поднятия и сериализация переходов (mt-yvf)

bringUpRouting при ошибке на N-й группе оставлял включёнными группы до неё —
при routingActive=false. Следующая перезапись таблиц прошивкой снесла бы их
цепочки, а коммиттер, находясь на паузе, событие отбросил бы: правила исчезли
бы молча, хотя группы считают себя включёнными. Теперь ошибка откатывает
поднятие.

Откат идёт через tearDownRouting, вынесенный из bringDownRouting: у последнего
гейт routingActive уже занят текущим поднятием, и он оказался бы no-op.
tearDownRouting возвращает ошибки снятия, а не проглатывает их: неполный
откат должен быть виден в логе, а не выглядеть успехом.

lifecycleMu сериализует переходы: SetEnabled зовётся прямо из HTTP-обработчика,
и двойной клик в UI гонялся за config.Enabled и routingActive."
```

---

### Task 4: Встраивание коммиттера в жизненный цикл

**Files:**
- Modify: `src/backend/app.go` (поле `committer`, синхронизация режима в `SetEnabled`)
- Modify: `src/backend/start.go:125-180`, `src/backend/start.go:253-275`

**Interfaces:**
- Consumes: `startNetfilterCommitter`, `setMode`, `request`, `stop`, режимы (Task 2); `CommitWithRetryWake` (Task 1); `lifecycleMu` (Task 3).
- Produces: `func (a *App) forceCommitIPTablesWake(ctx context.Context, wake <-chan struct{}) error`; `func (a *App) RequestNetfilterCommit()`; поле `a.committer *netfilterCommitter`.

- [ ] **Step 1: Добавить поле и метод коммита с пробуждением**

В `src/backend/app.go` в структуру `App` добавить:

```go
	// committer — асинхронный писатель правил по событиям netfilter.d.
	committer *netfilterCommitter
```

В `src/backend/start.go` заменить `ForceCommitIPTables` (строки 253+) на:

```go
func (a *App) ForceCommitIPTables(ctx context.Context) error {
	return a.forceCommitIPTablesWake(ctx, nil)
}

// forceCommitIPTablesWake — то же, но с каналом пробуждения: событие,
// пришедшее во время пауз между попытками, прерывает ожидание и начинает
// проход заново.
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

// RequestNetfilterCommit просит коммиттер переустановить правила.
// Неблокирующий: вызывается из HTTP-обработчика хука netfilter.d.
func (a *App) RequestNetfilterCommit() {
	if a.committer != nil {
		a.committer.request()
	}
}
```

- [ ] **Step 2: Запустить коммиттер до открытия сокета**

В `src/backend/start.go` вставить сразу ПОСЛЕ строки `newCtx, cancel := context.WithCancel(ctx)` и `errChan := make(chan error)` (то есть перед `api.SetupHTTP`):

```go
	// Коммиттер запускается ДО открытия сокетов: хук netfilter.d бьёт в
	// unix-сокет, и событие может прийти сразу после SetupUnixSocket. До
	// готовности модели он в режиме starting — событие защёлкивается, но не
	// исполняется.
	//
	// defer со stop регистрируется здесь же, чтобы worker не утёк на ранних
	// return err ниже (LinkByName, RebuildSubscriptionGroups, bringUpRouting).
	// stop идемпотентен, поэтому явный вызов перед снятием правил ниже не
	// конфликтует с этим defer.
	a.committer = startNetfilterCommitter(newCtx, a.forceCommitIPTablesWake, defaultReconcileDelay)
	defer a.committer.stop()
```

- [ ] **Step 3: Обеспечить порядок остановки**

Заменить строку `defer func() { _ = a.bringDownRouting() }()` (строка 173) на:

```go
	// Порядок обязателен: сперва остановить коммиттер и ДОЖДАТЬСЯ его, потом
	// снимать правила. Иначе teardown снимает цепочки, пока worker их
	// восстанавливает. Одним defer это не решается: defer, зарегистрированный
	// при запуске коммиттера выше, по LIFO выполнится ПОЗЖЕ этого — поэтому
	// stop вызывается явно здесь, а тот defer остаётся страховкой от ранних
	// выходов. Повторный stop — no-op.
	//
	// lifecycleMu здесь обязателен: HTTP- и unix-серверы закрываются defer'ами,
	// зарегистрированными ВЫШЕ, а значит по LIFO — уже ПОСЛЕ этого снятия.
	// Без лока запрос SetEnabled(true) мог бы поднять правила обратно, когда
	// коммиттер уже остановлен и восстанавливать их некому.
	defer func() {
		a.committer.stop()
		a.lifecycleMu.Lock()
		defer a.lifecycleMu.Unlock()
		_ = a.bringDownRouting()
	}()
```

- [ ] **Step 4: Перевести коммиттер в рабочий режим под тем же локом, что и поднятие**

Заменить блок (около строки 166):

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
	// lifecycleMu — тот же лок, что держит SetEnabled: сокет уже открыт, и
	// пользовательский запрос паузы может прийти прямо во время стартового
	// поднятия.
	a.lifecycleMu.Lock()
	if a.config.Enabled {
		if err := a.bringUpRouting(); err != nil {
			a.lifecycleMu.Unlock()
			return err
		}
		// Модель собрана — коммиттер может писать. Событие, защёлкнутое во
		// время старта, исполнится немедленно.
		a.committer.setMode(committerReady)
	} else {
		log.Warn().Msg("MagiTrickle started with app.enabled=false — routing is paused")
		a.committer.setMode(committerPaused)
	}
	a.lifecycleMu.Unlock()
```

- [ ] **Step 5: Синхронизировать режим с паузой и возобновлением**

В `src/backend/app.go` в `SetEnabled` (внутри `lifecycleMu`) заменить блок переключения на:

```go
	if enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
		if a.committer != nil {
			a.committer.setMode(committerReady)
		}
	} else {
		if a.committer != nil {
			// Сначала паузим коммиттер — setMode возвращается только после
			// того, как worker принял режим, поэтому нового прохода уже не
			// начнётся. Иначе он восстановил бы то, что снимает teardown.
			a.committer.setMode(committerPaused)
		}
		bringDownErr = a.bringDownRouting()
	}
```

**Внимание, зависимость от Task 3.** Ошибка снятия здесь ОБЯЗАНА сохраняться в
`bringDownErr` и уходить вызывающему через `errors.Join` ниже по функции — это
результат Task 3, где ревью нашло, что `_ = a.bringDownRouting()` отдаёт
пользователю 200 OK при неполном снятии правил. Не заменяйте эту строку на
`_ = ...`: получится молчаливый регресс.
```

- [ ] **Step 6: Собрать и прогнать всё**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go build ./... && GOOS=linux go vet -tags testing ./... && GOOS=linux go test -tags testing -race ./... 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: все пакеты `ok`.

- [ ] **Step 7: Коммит**

```bash
git add src/backend/start.go src/backend/app.go
git commit -m "feat(netfilter): встроить коммиттер в жизненный цикл демона (mt-yvf)

Коммиттер запускается до открытия unix-сокета: хук бьёт именно туда, и событие
может прийти раньше, чем собрана модель — до готовности оно защёлкивается.

Стартовое поднятие роутинга взято под lifecycleMu: сокет уже открыт, и запрос
паузы может прийти прямо во время него.

Порядок остановки соблюдён явно: stop коммиттера и ожидание worker'а идут
ПЕРЕД снятием правил. Одним defer это не решается — зарегистрированный при
запуске коммиттера выполнился бы по LIFO позже снятия, поэтому он остаётся
страховкой от ранних выходов из Start, а рабочий путь зовёт stop явно.

Пауза переводит коммиттер в paused ДО снятия правил, и setMode возвращается
только после того, как worker принял режим."
```

---

### Task 5: Тонкий хук

**Files:**
- Modify: `src/backend/api/v1/handlers.go:47-70` (`NetfilterDHook`)
- Modify: `src/backend/app/magitrickle.go` (интерфейс `Main`)

**Interfaces:**
- Consumes: `a.RequestNetfilterCommit()` (Task 4).
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
	// схлопывает их.
	//
	// Ответ 200 здесь означает «событие принято», а НЕ «правила восстановлены»:
	// вызывающему shell-скрипту всё равно нечего делать с результатом, а socat
	// закрывает соединение сразу после отправки.
	h.app.RequestNetfilterCommit()
}
```

- [ ] **Step 3: Убрать осиротевший импорт**

`context` в `src/backend/api/v1/handlers.go` использовался ТОЛЬКО в удалённой строке `ForceCommitIPTables(context.Background())`. Проверить и убрать из блока импортов, иначе сборка упадёт на `imported and not used`:

```bash
wsl -e bash -c 'cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && grep -n "context\." api/v1/handlers.go | head'
```

Если вывод пуст — удалить строку `"context"` из импортов `api/v1/handlers.go`.

- [ ] **Step 4: Собрать и прогнать всё**

```bash
wsl -e bash -c 'export PATH="$HOME/.local/bin:$PATH" && eval "$(fnm env)" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01/src/backend && GOOS=linux go build ./... && GOOS=linux go vet -tags testing ./... && GOOS=linux go test -tags testing -race ./... 2>&1 | grep -E "^(ok|FAIL|---)"'
```

Ожидается: все пакеты `ok`.

- [ ] **Step 5: Коммит**

```bash
git add src/backend/api/v1/handlers.go src/backend/app/magitrickle.go
git commit -m "feat(netfilter): хук netfilter.d только сигналит коммиттеру (mt-yvf)

Обработчик больше не ждёт применения правил: шлёт неблокирующий сигнал и
отвечает сразу. Прошивка присылает событие на каждую таблицу, и схлопывание в
коммиттере превращает серию в один проход вместо трёх независимых.

Битый JSON по-прежнему даёт 400 — это ошибка вызывающего, а не результат
восстановления правил."
```

---

### Task 6: Полевая проверка на роутере

**Files:** нет (проверка на живой системе).

**Interfaces:**
- Consumes: собранный пакет со всеми предыдущими задачами.

**Осторожно:** это рабочий роутер с 38 группами. Шаг 4 намеренно снимает правила, поэтому перед ним делается полный снимок, а после — сверка `diff` с ним. Если что-то пойдёт не так на любом шаге, правила возвращает:

```bash
ssh <ROUTER_SSH> '/opt/etc/init.d/S99magitrickle restart'
```

**Про имена цепочек.** Наивная маска `MT_[0-9a-f]*` НЕ годится: кроме групп `MT_<8 hex>` на роутере живут подписочные `MT_s<8 hex>`, `MT_DNSOR` (port remap) и потенциально `MT_PREAMBLE` (interface-режим). Проверено на проде 03.08.2026: mangle — 34 `MT_<hex>` и 4 `MT_s<hex>`, nat — те же плюс `MT_DNSOR`. Поэтому ниже имена берутся из вывода `iptables -S` целиком, а не по маске из hex.

**Про схлопывание.** Автоматически на роутере оно НЕ проверяется: демон логирует в `/dev/null`, наблюдаемого счётчика проходов нет. Схлопывание покрыто юнит-тестом `TestCommitterFoldsRequests` (Task 2), а здесь проверяется лишь то, что серия событий не ломает итоговое состояние.

- [ ] **Step 1: Собрать пакет**

Выполнять в **Git Bash**, не в PowerShell: подстановки `$(...)`, `${TAG%.*}` и `$((...))` — синтаксис POSIX-шелла.

```bash
cd "<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01" && TAG=$(git describe --tags --abbrev=0) && COMMIT=$(git rev-parse --short HEAD) && PRERELEASE="${TAG%.*}.$((${TAG##*.}+1))" && DATE=$(date +%Y%m%d%H%M%S) && PKGVER="${PRERELEASE}~git${DATE}.${COMMIT}" && echo "PKG_VERSION=$PKGVER" && wsl -e bash -c "export PATH=\"\$HOME/.local/bin:\$PATH\" && eval \"\$(fnm env)\" && cd /mnt/c/<HOME>/GitHub/MagiTrickle/.claude/worktrees/happy-spence-498b01 && export PKG_VERSION='$PKGVER' PKG_VERSION_PRERELEASE='$PRERELEASE' && make PLATFORM=entware TARGET=aarch64-3.10_kn GOOS=linux GOARCH=arm64 GOMIPS= 2>&1 | tail -3"
```

PKG_VERSION вычисляется на Windows-стороне: в worktree WSL-git не читает `.git` с Windows-путём и версия ломается.

- [ ] **Step 2: Задеплоить**

```bash
powershell -File scripts/update-router-package.ps1
```

Ожидается: `Deploy confirmed: magitrickled alive (pid=...) 45s after install.`

- [ ] **Step 3: Снять снимок состояния ДО проверки**

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; iptables-save > /opt/root/tmp/mt-v4-before.rules; ip6tables-save > /opt/root/tmp/mt-v6-before.rules; echo "v4 mangle: цепочек=$(iptables -t mangle -S | grep -c "^-N MT_") джампов=$(iptables -t mangle -S PREROUTING | grep -c "j MT_")"; echo "v4 nat: цепочек=$(iptables -t nat -S | grep -c "^-N MT_") джампов=$(iptables -t nat -S PREROUTING | grep -c "j MT_")"; echo "v6 mangle: цепочек=$(ip6tables -t mangle -S | grep -c "^-N MT_")"'
```

Снимки обоих семейств остаются на роутере до конца проверки — по ним идёт сверка и, при необходимости, ручное восстановление.

- [ ] **Step 4: Проверить восстановление после полного сноса mangle**

Скрипт снимает ВСЕ наши цепочки mangle (имена берутся из `iptables -S`, а не по маске hex — иначе подписочные `MT_s<hex>` уцелеют) и сразу вызывает хук. При любой ошибке между сносом и восстановлением `trap` перезапускает демон, чтобы роутер не остался без правил.

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin
set -e
trap "echo ОШИБКА: восстанавливаю демоном; /opt/etc/init.d/S99magitrickle restart" EXIT

for c in $(iptables -t mangle -S | awk "/^-N MT_/ {print \$2}"); do
  iptables -t mangle -D PREROUTING ! -i lo -j $c 2>/dev/null || true
  iptables -t mangle -F $c 2>/dev/null || true
  iptables -t mangle -X $c 2>/dev/null || true
done
echo "после сноса: цепочек=$(iptables -t mangle -S | grep -c "^-N MT_") джампов=$(iptables -t mangle -S PREROUTING | grep -c "j MT_")"

type=iptables table=mangle sh /opt/etc/ndm/netfilter.d/100-magitrickle
sleep 3
echo "после хука: цепочек=$(iptables -t mangle -S | grep -c "^-N MT_") джампов=$(iptables -t mangle -S PREROUTING | grep -c "j MT_")"

trap - EXIT'
```

Ожидается: после сноса — 0 цепочек и 0 джампов, после хука — числа из шага 3.

- [ ] **Step 5: Сверить правила со снимком построчно**

Счётчики совпасть могут, а правила — отличаться, поэтому сверка идёт `diff`-ом. Сравниваются только наши строки: счётчики пакетов и правила прошивки меняются сами по себе.

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; iptables-save | grep "MT_" | sed "s/\[[0-9]*:[0-9]*\]//" | sort > /opt/root/tmp/mt-v4-after.txt; grep "MT_" /opt/root/tmp/mt-v4-before.rules | sed "s/\[[0-9]*:[0-9]*\]//" | sort > /opt/root/tmp/mt-v4-ref.txt; if diff -u /opt/root/tmp/mt-v4-ref.txt /opt/root/tmp/mt-v4-after.txt; then echo "СОВПАДАЕТ: правила восстановлены точно"; else echo "РАСХОЖДЕНИЕ (см. diff выше)"; fi'
```

Ожидается: `СОВПАДАЕТ`. Если расхождение — разбираться, не продолжая; вернуть состояние можно `/opt/etc/init.d/S99magitrickle restart`.

- [ ] **Step 6: Проверить, что хук отвечает мгновенно**

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; S=$(date +%s%N); type=iptables table=mangle sh /opt/etc/ndm/netfilter.d/100-magitrickle; E=$(date +%s%N); echo "хук вернулся за $(( (E-S)/1000000 )) мс"'
```

Ожидается: единицы миллисекунд — обработчик больше не ждёт применения правил. До изменения это же измерение давало 34–79 мс.

- [ ] **Step 7: Проверить, что серия событий не ломает состояние**

Прошивка шлёт событие на каждую таблицу; воспроизводим серию. Само схлопывание отсюда не наблюдаемо (см. врезку выше) — проверяется устойчивость итога.

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; for t in mangle nat filter; do type=iptables table=$t sh /opt/etc/ndm/netfilter.d/100-magitrickle; done; sleep 3; iptables-save | grep "MT_" | sed "s/\[[0-9]*:[0-9]*\]//" | sort > /opt/root/tmp/mt-v4-series.txt; if diff -u /opt/root/tmp/mt-v4-ref.txt /opt/root/tmp/mt-v4-series.txt; then echo "СОВПАДАЕТ: серия событий состояние не изменила"; else echo "РАСХОЖДЕНИЕ (см. diff выше)"; fi'
```

Ожидается: `СОВПАДАЕТ` — дублей джампов и потерянных цепочек нет.

- [ ] **Step 8: Проверить IPv6 и итоговое здоровье, убрать временные файлы**

```bash
ssh <ROUTER_SSH> 'export PATH=$PATH:/opt/sbin:/opt/bin; echo "pid: $(pidof magitrickled)"; ip6tables-save | grep "MT_" | sed "s/\[[0-9]*:[0-9]*\]//" | sort > /opt/root/tmp/mt-v6-after.txt; grep "MT_" /opt/root/tmp/mt-v6-before.rules | sed "s/\[[0-9]*:[0-9]*\]//" | sort > /opt/root/tmp/mt-v6-ref.txt; if diff -u /opt/root/tmp/mt-v6-ref.txt /opt/root/tmp/mt-v6-after.txt; then echo "IPv6 СОВПАДАЕТ"; else echo "IPv6 РАСХОЖДЕНИЕ"; fi; curl -s -o /dev/null -w "проверка связи: %{http_code}\n" -m 8 https://1.1.1.1/; rm -f /opt/root/tmp/mt-v4-*.rules /opt/root/tmp/mt-v6-*.rules /opt/root/tmp/mt-v4-*.txt /opt/root/tmp/mt-v6-*.txt'
```

Ожидается: демон жив, IPv6 совпадает со снимком (изменённый путь коммитит оба семейства), связь есть.

- [ ] **Step 9: Записать результат в задачу**

```bash
bd comment mt-yvf "Полевая проверка на <ROUTER_IP>: <фактические числа и результаты diff из шагов 3-8>"
```

---

## Self-Review

**Покрытие спеки:**

| Требование спеки | Где |
|---|---|
| Компонент committer, горутина, канал ёмкостью 1 | Task 2 |
| Схлопывание («не более одного отложенного прохода») | Task 2, `TestCommitterFoldsRequests` |
| Событие во время прохода не теряется | Task 2, `TestCommitterDoesNotLoseEventDuringPass` |
| Прерывание ожидания между попытками, сброс бюджета | Task 1, `TestCommitWithRetryWakeRestartsOnEvent` |
| Собственный контекст, не `r.Context()` | Task 4 (worker на `newCtx`), сделано в `2d5efe4` |
| Машина состояний | Task 2 |
| Защёлкивание события в `starting` | Task 2, `TestCommitterLatchesEventWhileStarting` |
| Отбрасывание события в `paused` | Task 2, `TestCommitterDiscardsEventWhilePaused`, `TestCommitterDropsLatchOnPause` |
| Reconcile внутри `select`, сброс при `paused`/`stopping` | Task 2, `TestCommitterSchedulesReconcileAfterFailure`, `TestCommitterReconcileDoesNotSurvivePause` |
| Порядок остановки, идемпотентный stop | Task 2 (`TestCommitterStopIsIdempotent`, `TestCommitterStopWaitsForWorker`, `TestCommitterAfterStopIsInert`) + Task 4 |
| Канал не закрывается | Task 2, `TestCommitterAfterStopIsInert` |
| Откат неуспешного `bringUpRouting` | Task 3 — **кодом и ревью, без юнит-теста** (см. ниже) |
| Мьютекс переходов | Task 3 + Task 4 (стартовое поднятие под тем же локом) — **кодом и ревью** |
| Сериализация писателей | сделано в mt-7sa, тест `TestCommitMuSerialisesCommits` |
| Сходимость: повторный проход, восстановление после flush | Task 1, `TestCommitIsIdempotent`, `TestCommitRecoversAfterFullFlush` |
| Тонкий хук | Task 5 |
| Полевая проверка | Task 6 |

**Что покрыто НЕ тестами и почему.** Откат `bringUpRouting` и удержание `lifecycleMu` в `SetEnabled` юнит-тестами не покрыты: `Group.Enable` и `dnsOverrider` работают напрямую с ipset и iptables, подменяемых интерфейсов в коде нет, а `SetEnabled` вдобавок пишет конфиг на диск. Вводить интерфейсы ради двух тестов несоразмерно задаче. Эти места проверяются чтением кода при ревью задачи и полевым сценарием Task 6. Тест, который проверял бы собственноручно взятый мьютекс вместо поведения `SetEnabled`, здесь не пишется — он ничего не доказывает.

**Не покрыто намеренно:** позиция джампов (mt-rrg, отдельная задача); `drop-then-stage` (спека обосновывает отказ, тесты сходимости в Task 1 подтверждают основание); build tag платформы (не нужен — хук ставится только в сборки `entware_kn`).

**Согласованность типов:** `commit func(ctx context.Context, wake <-chan struct{}) error` — одинаково в Task 2 (поле, конструктор) и Task 4 (`forceCommitIPTablesWake`). `setMode`/`request`/`stop` вводятся в Task 2 и используются в Task 4. `CommitWithRetryWake(ctx, wake)` вводится в Task 1, используется в Task 4. `tearDownRouting() error` вводится в Task 3, используется только внутри `app.go`.
