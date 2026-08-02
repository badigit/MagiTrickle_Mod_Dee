//go:build testing

package iptables

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// racedStderr — текст, который iptables-restore v1.4.21 реально выдаёт на
// Keenetic, когда ndm снёс нашу цепочку между iptables-save и iptables-restore.
// Снято с роутера 02.08.2026; обёртка Restore добавляет свой префикс и exit status.
const racedStderr = "iptables-restore failed: exit status 1: iptables-restore: line 2 failed"

func newRetryFixture(t *testing.T) (*IPTables, *FakeIPTables) {
	t.Helper()

	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", nil)

	ipt := NewIPTables(fake)
	if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
		t.Fatalf("RegisterChainPatch failed: %v", err)
	}
	if err := ipt.Append("mangle", "PREROUTING", "-i", "eth0", "-j", "ACCEPT"); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	return ipt, fake
}

// withFastRetries убирает реальные задержки, чтобы тест не спал.
func withFastRetries(t *testing.T) {
	t.Helper()
	saved := commitRetryBackoff
	commitRetryBackoff = []time.Duration{0, 0, 0, 0}
	t.Cleanup(func() { commitRetryBackoff = saved })
}

// TestCommitWithRetryRecoversFromRace — главный сценарий mt-pfo: ndm переписал
// таблицу под нами, первые попытки проиграли гонку, следующая прошла. Наружу
// ошибки быть не должно, правила — на месте.
func TestCommitWithRetryRecoversFromRace(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	fake.FailRestore(errors.New(racedStderr), errors.New(racedStderr))

	if err := ipt.CommitWithRetry(context.Background()); err != nil {
		t.Fatalf("CommitWithRetry should recover from a raced write, got: %v", err)
	}

	if got := fake.RestoreCalls(); got != 3 {
		t.Errorf("Restore calls = %d, want 3 (two raced + one successful)", got)
	}

	rules := fake.GetRules("mangle", "PREROUTING")
	want := [][]string{{"-i", "eth0", "-j", "ACCEPT"}}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("rules after recovery mismatch.\nWant: %v\nGot:  %v", want, rules)
	}
}

// TestCommitWithRetryRereadsStateBetweenAttempts: дельта считается от снимка
// ядра, поэтому повтор ОБЯЗАН перечитать состояние — иначе вторая попытка
// понесёт ту же дельту, посчитанную от устаревшего снимка.
func TestCommitWithRetryRereadsStateBetweenAttempts(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	fake.FailRestore(errors.New(racedStderr))

	if err := ipt.CommitWithRetry(context.Background()); err != nil {
		t.Fatalf("CommitWithRetry failed: %v", err)
	}

	if got := fake.SaveCalls(); got < 2 {
		t.Errorf("Save calls = %d, want >= 2 (state must be re-read before the retry)", got)
	}
}

// TestCommitWithRetryGivesUp: если гонка не кончается, попытки не бесконечны —
// ошибка возвращается наверх после исчерпания бюджета.
func TestCommitWithRetryGivesUp(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	persistent := make([]error, len(commitRetryBackoff)+5)
	for i := range persistent {
		persistent[i] = errors.New(racedStderr)
	}
	fake.FailRestore(persistent...)

	err := ipt.CommitWithRetry(context.Background())
	if err == nil {
		t.Fatal("CommitWithRetry must return an error when every attempt loses the race")
	}
	if got, want := fake.RestoreCalls(), len(commitRetryBackoff); got != want {
		t.Errorf("Restore calls = %d, want %d (one per configured attempt)", got, want)
	}
}

// TestCommitWithRetryNonRacedErrorAlsoRetried: не-гоночная ошибка тоже достойна
// повтора (таблица могла быть занята), но классифицируется иначе — это влияет
// на уровень лога, а не на факт ретрая.
func TestCommitWithRetryNonRacedErrorAlsoRetried(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	fake.FailRestore(errors.New("iptables-restore: unknown option \"--nonexistent\""))

	if err := ipt.CommitWithRetry(context.Background()); err != nil {
		t.Fatalf("CommitWithRetry should retry non-raced errors too, got: %v", err)
	}
	if got := fake.RestoreCalls(); got != 2 {
		t.Errorf("Restore calls = %d, want 2", got)
	}
}

// TestCommitWithRetryAbortsOnCancelledContext: с уже отменённым контекстом
// писать в netfilter незачем — ни одной попытки быть не должно.
func TestCommitWithRetryAbortsOnCancelledContext(t *testing.T) {
	withFastRetries(t)
	ipt, fake := newRetryFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ipt.CommitWithRetry(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got: %v", err)
	}
	if got := fake.RestoreCalls(); got != 0 {
		t.Errorf("Restore calls = %d, want 0 (nothing should be written under a cancelled context)", got)
	}
}

// TestCommitWithRetryInterruptsBackoff: отмена во время паузы между попытками
// прекращает ожидание немедленно, а не досыпает бэкофф до конца. Нужно для
// mt-yvf, где приход нового события netfilter.d будет прерывать текущий проход.
func TestCommitWithRetryInterruptsBackoff(t *testing.T) {
	ipt, fake := newRetryFixture(t)

	saved := commitRetryBackoff
	commitRetryBackoff = []time.Duration{0, time.Hour, time.Hour}
	t.Cleanup(func() { commitRetryBackoff = saved })

	fake.FailRestore(errors.New(racedStderr))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// даём первой попытке провалиться и уйти в часовой бэкофф
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := ipt.CommitWithRetry(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("CommitWithRetry slept through the backoff (%v) instead of honouring cancellation", elapsed)
	}
	if got := fake.RestoreCalls(); got != 1 {
		t.Errorf("Restore calls = %d, want 1 (first attempt runs, the rest is cancelled)", got)
	}
}

// TestIsRacedError — классификатор stderr: что считаем проигранной гонкой с ndm,
// а что настоящей ошибкой.
//
// Все строки в кейсах "снято живьём" получены прогоном iptables-restore на
// роутере (Keenetic, v1.4.21, 02.08.2026). Различие оказалось системным: ядро
// отказалось применить правило -> exit 1 и "line N failed"; разбор аргументов
// не прошёл -> exit 2 и "Error occurred at line".
func TestIsRacedError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		raced bool
	}{
		// снято живьём: цепочки нет (ndm снёс между save и restore)
		{"chain gone", errors.New("iptables-restore failed: exit status 1: iptables-restore: line 2 failed"), true},
		// снято живьём: -D правила, которого уже нет
		{"stale delete", errors.New("iptables-restore failed: exit status 1: iptables-restore: line 7 failed"), true},
		{"xtables lock", errors.New("Another app is currently holding the xtables lock; still -w seconds"), true},
		{"resource unavailable", errors.New("iptables-restore: Resource temporarily unavailable"), true},
		// формат iptables 1.8.x (не Keenetic, но встречается на других платформах)
		{"no chain 1.8.x", errors.New("iptables-restore v1.8.7: No chain/target/match by that name"), true},
		{"bad rule 1.8.x", errors.New("Bad rule (does a matching rule exist in that chain?)"), true},

		// снято живьём: НЕ гонка — ошибки разбора аргументов и окружения
		{"unknown option", errors.New("iptables-restore v1.4.21: unknown option \"--bogus-option\"\nError occurred at line: 2"), false},
		{"bad argument", errors.New("Bad argument `this'\nError occurred at line: 2"), false},
		{"unknown table", errors.New("iptables-restore v1.4.21: iptables-restore: unable to initialize table 'nosuchtable'"), false},
		// ВАЖНО: отсутствующий kmod не должен маскироваться под гонку — иначе
		// реальная проблема окружения молча уходит в ретраи на debug-уровне
		{"missing kmod", errors.New("iptables-restore v1.4.21: Couldn't load match `nosuchmatch':No such file or directory"), false},
		{"permission", errors.New("Permission denied (you must be root)"), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRacedError(tc.err); got != tc.raced {
				t.Errorf("IsRacedError(%v) = %v, want %v", tc.err, got, tc.raced)
			}
		})
	}
}
