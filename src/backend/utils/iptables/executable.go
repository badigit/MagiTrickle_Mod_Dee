package iptables

import "context"

// Executable — исполнитель iptables-save/iptables-restore.
//
// Обе операции принимают контекст: без него зависший процесс (типичная причина
// на роутере — чужой xtables.lock, который держит ndm) не возвращается никогда,
// и ретраи не помогают — они срабатывают на ошибку, а зависание ошибки не даёт
// (mt-7sa).
type Executable interface {
	Save(ctx context.Context) ([]byte, error)
	Restore(ctx context.Context, data []byte) error
	Proto() Protocol
}
