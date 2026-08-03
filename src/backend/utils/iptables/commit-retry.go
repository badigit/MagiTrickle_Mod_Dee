package iptables

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Прошивка Keenetic держит собственную реализацию userspace netfilter и при
// любом изменении конфигурации переписывает таблицу ЦЕЛИКОМ и атомарно, после
// чего дёргает хук netfilter.d. Наш коммит в это же окно проигрывает гонку:
// дельта посчитана от снимка, который уже неактуален, и iptables-restore
// ругается на отсутствующие цепочки/правила.
//
// Разработчик Keenetic (форум, тема 20631) прямо сказал, что синхронизации со
// стороны прошивки не будет и устойчивость — забота пакета: ошибки класса ENOENT
// наружу не кидать, а начинать заново.
//
// Здесь — минимальная часть этого контракта: повтор с перечитыванием состояния.
// Накопление событий, отмена текущей записи и полная пересборка вместо дельты —
// следующий шаг (mt-yvf), он трогает архитектуру.

// commitRetryBackoff — задержки ПЕРЕД каждой попыткой. Длина = бюджет попыток.
// Первая нулевая: гонку почти всегда выигрывает немедленный повтор, потому что
// прошивка уже дописала свою таблицу. Переменная (а не константа) — тесты
// подменяют её, чтобы не спать.
var commitRetryBackoff = []time.Duration{
	0,
	50 * time.Millisecond,
	200 * time.Millisecond,
	500 * time.Millisecond,
}

// Как отличить проигранную гонку от настоящей ошибки — снято живьём с роутера
// (Keenetic, iptables-restore v1.4.21, 02.08.2026):
//
//	цепочки нет (её снёс ndm):     exit 1, "iptables-restore: line 2 failed"
//	-D несуществующего правила:    exit 1, "iptables-restore: line 2 failed"
//	неизвестная опция:             exit 2, "unknown option ...\nError occurred at line: 2"
//	мусор в синтаксисе:            exit 2, "Bad argument `this'\nError occurred at line: 2"
//	нет такой таблицы:             exit 2, "unable to initialize table ..."
//	нет kmod под match:            exit 2, "Couldn't load match `x':No such file or directory"
//
// То есть «ядро отказалось применить правило» (гонка) — это ровно "line N failed",
// а всё, что ушло в разбор аргументов, — наша ошибка либо отсутствующий модуль.
// Отсюда узкий классификатор: широкое "no such file or directory" сюда НЕ входит,
// иначе отсутствующий kmod маскировался бы под гонку и молча ретраился.
var restoreLineFailedRe = regexp.MustCompile(`line \d+ failed`)

// racedMarkers — дополнительные формулировки: занятость таблиц (любая версия) и
// формат iptables 1.8.x, где причина пишется словами.
var racedMarkers = []string{
	"xtables lock",
	"resource temporarily unavailable",
	"no chain/target/match by that name",
	"does a matching rule exist in that chain",
}

// IsRacedError сообщает, похожа ли ошибка на проигранную гонку с чужой
// перезаписью таблиц. Такие ошибки ожидаемы на Keenetic и не заслуживают
// warn-уровня в логе.
func IsRacedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if restoreLineFailedRe.MatchString(msg) {
		return true
	}
	for _, marker := range racedMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// IsRetryableError — стоит ли повторять попытку. Помимо проигранной гонки сюда
// входит собственный таймаут внешней команды (mt-7sa): залипание почти всегда
// вызвано чужим xtables.lock, то есть это та же гонка, только проявившаяся
// зависанием, а не ошибкой.
func IsRetryableError(err error) bool {
	return IsRacedError(err) || errors.Is(err, ErrExecTimeout)
}

// CommitWithRetry применяет накопленные правила, повторяя попытку, если запись
// не удалась. Каждая попытка — это полноценный Commit, то есть состояние ядра
// перечитывается заново: повторять запись со старой дельтой бессмысленно, она
// ляжет так же криво.
//
// Возвращает ошибку последней попытки, если бюджет исчерпан, и ошибку контекста,
// если его отменили.
func (ipt *IPTables) CommitWithRetry(ctx context.Context) error {
	var lastErr error

	for attempt, delay := range commitRetryBackoff {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		} else if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = ipt.CommitContext(ctx)
		if lastErr == nil {
			if attempt > 0 {
				log.Debug().
					Int("attempt", attempt+1).
					Str("type", protoName(ipt.Proto())).
					Msg("iptables commit succeeded after retry")
			}
			return nil
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

	return fmt.Errorf("iptables commit failed after %d attempts: %w", len(commitRetryBackoff), lastErr)
}

func protoName(proto Protocol) string {
	if proto == ProtocolIPv6 {
		return "ip6tables"
	}
	return "iptables"
}
