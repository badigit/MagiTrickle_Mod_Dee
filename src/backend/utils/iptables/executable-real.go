package iptables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// ErrExecTimeout — iptables-save/restore не уложился в отведённое время и был
// убит. Отдельная ошибка, потому что это не «команда отработала неверно», а
// «команда не отработала вовсе»: причина почти всегда внешняя (чужой
// xtables.lock, который на роутере регулярно держит ndm), и лечится повтором.
var ErrExecTimeout = errors.New("iptables command timed out")

// execTimeout — потолок на один вызов iptables-save/restore. Нормальный проход
// на роутере занимает 34–42 мс (замер на проде: 38 групп, полное восстановление
// после flush), так что запас здесь стократный — таймаут ловит именно
// залипание, а не медленную работу. Переменная, а не константа: тесты
// подменяют её, чтобы не ждать.
var execTimeout = 5 * time.Second

type realIPTables struct {
	saveCmd     string
	saveArgs    []string
	restoreCmd  string
	restoreArgs []string
	proto       Protocol
}

func NewRealIPTables() *realIPTables {
	return &realIPTables{
		saveCmd:     "iptables-save",
		restoreCmd:  "iptables-restore",
		restoreArgs: []string{"--noflush"},
		proto:       ProtocolIPv4,
	}
}

func NewRealIP6Tables() *realIPTables {
	return &realIPTables{
		saveCmd:     "ip6tables-save",
		restoreCmd:  "ip6tables-restore",
		restoreArgs: []string{"--noflush"},
		proto:       ProtocolIPv6,
	}
}

func (ipt *realIPTables) Proto() Protocol {
	return ipt.proto
}

func (ipt *realIPTables) Save(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	// CommandContext убивает процесс при отмене, а cmd.Run ждёт его смерти —
	// поэтому возврат отсюда означает, что зависшего потомка не осталось.
	cmd := exec.CommandContext(ctx, ipt.saveCmd, ipt.saveArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, wrapExecTimeout(ctxErr, ipt.saveCmd)
		}
		return nil, fmt.Errorf(
			"%s failed: %w: %s",
			ipt.saveCmd, err, stderr.String(),
		)
	}

	return stdout.Bytes(), nil
}

func (ipt *realIPTables) Restore(ctx context.Context, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, ipt.restoreCmd, ipt.restoreArgs...)

	var stderr bytes.Buffer
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return wrapExecTimeout(ctxErr, ipt.restoreCmd)
		}
		return fmt.Errorf(
			"%s failed: %w: %s",
			ipt.restoreCmd, err, stderr.String(),
		)
	}

	return nil
}

// wrapExecTimeout отличает собственный потолок времени от отмены вызывающим:
// первое — аномалия, которую надо видеть в логе, второе — штатное прерывание
// (новое событие netfilter.d, остановка демона).
func wrapExecTimeout(ctxErr error, cmdName string) error {
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return fmt.Errorf("%s did not finish in %s: %w", cmdName, execTimeout, ErrExecTimeout)
	}
	return fmt.Errorf("%s cancelled: %w", cmdName, ctxErr)
}
