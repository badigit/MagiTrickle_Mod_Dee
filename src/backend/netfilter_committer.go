package magitrickle

import (
	"context"
	"fmt"
	"runtime/debug"
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

// stop отменяет контекст worker'а и ДОЖДАВШИСЬ его завершения возвращается.
// В committerStopping НЕ переводит — setMode(committerStopping) нигде не
// вызывается, worker завершается по отмене контекста (см. run: ctx.Done()).
// Идемпотентен: вызывается и явно перед снятием правил, и defer'ом на ранних
// выходах из Start.
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
			case committerStarting:
				// Возврат в starting не предусмотрен переходами режима, но
				// если он всё же придёт — защёлку трогать не нужно: она уже
				// либо снята, либо копит событие для будущего ready.
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

		if err := c.runPass(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn().Err(err).Dur("retry_in", c.reconcileDelay).
				Msg("netfilter commit pass failed, scheduling reconcile")
			reconcile = time.After(c.reconcileDelay)
		}
	}
}

// runPass изолирует панику: worker живёт в собственной горутине, и без
// recover любая паника внутри коммита валит весь демон. Раньше её
// перехватывал net/http, потому что коммит шёл в HTTP-обработчике.
// Паника становится обычной ошибкой прохода — дальше её подхватит
// страховочный таймер.
func (c *netfilterCommitter) runPass(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in netfilter commit: %v", r)
			log.Error().Str("stack", string(debug.Stack())).Msg("recovered panic in netfilter committer")
		}
	}()
	return c.commit(ctx, c.wake)
}
