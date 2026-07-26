package magitrickle

import (
	"math"
	"testing"
	"time"
)

// TestIPSetTTLFromRecord_PreservesNormalBehaviour — САМЫЙ важный тест этой правки:
// для обычных значений результат обязан совпадать со старой формулой
// (recordTTL + additionalTTL). Нормализация — защита от краёв, а не смена политики.
func TestIPSetTTLFromRecord_PreservesNormalBehaviour(t *testing.T) {
	cases := []struct {
		recordTTL     uint32
		additionalTTL uint32
	}{
		{300, 86400},  // наш дефолт (clientTTLCap=300 отдаётся клиенту, тут — оригинал)
		{3600, 3600},  // старый дефолт форка
		{60, 86400},   // короткий CDN-TTL
		{86400, 3600}, // ровно на границе потолка записи
		{1, 0},        // additionalTTL выключён
	}
	for _, c := range cases {
		want := c.recordTTL + c.additionalTTL
		if got := ipsetTTLFromRecord(c.recordTTL, c.additionalTTL); got != want {
			t.Errorf("ipsetTTLFromRecord(%d, %d) = %d, want %d (unchanged behaviour)",
				c.recordTTL, c.additionalTTL, got, want)
		}
	}
}

// TestIPSetTTLFromRecord_NeverZero — 0 в ipset означает PERMANENT (так намеренно
// добавляются статические subnet-правила). Динамическая запись не должна получить
// 0 ни при каких входных данных, иначе она залипнет навсегда.
func TestIPSetTTLFromRecord_NeverZero(t *testing.T) {
	if got := ipsetTTLFromRecord(0, 0); got == 0 {
		t.Error("ipsetTTLFromRecord(0, 0) = 0 — would create a PERMANENT ipset entry")
	}
}

// TestIPSetTTLFromRecord_NoOverflow — переполнение uint32 давало КРОШЕЧНЫЙ timeout
// вместо огромного (запись выпадает из ipset → direct-утечка). Плюс обратная
// сторона: насыщение не должно давать «почти вечную» запись — TTL из ответа
// ограничен сутками, поэтому итог остаётся осмысленным.
func TestIPSetTTLFromRecord_NoOverflow(t *testing.T) {
	got := ipsetTTLFromRecord(math.MaxUint32, 86400)
	if got < 86400 {
		t.Errorf("ipsetTTLFromRecord(MaxUint32, 86400) = %d — overflowed to a tiny timeout", got)
	}
	if want := maxRecordTTL + uint32(86400); got != want {
		t.Errorf("ipsetTTLFromRecord(MaxUint32, 86400) = %d, want %d (record TTL clamped to a day)", got, want)
	}

	// Абсурдный additionalTTL не должен переполнить сумму.
	if got := ipsetTTLFromRecord(3600, math.MaxUint32); got != math.MaxUint32 {
		t.Errorf("saturating add expected, got %d", got)
	}
}

// TestIPSetTTLFromRecord_RespectsBigAdditionalTTL — политика пользователя важнее
// потолка: при additionalTTL=7 суток запись обязана жить ~7 суток (апстримный
// подход капал СУММУ и сломал бы это).
func TestIPSetTTLFromRecord_RespectsBigAdditionalTTL(t *testing.T) {
	week := uint32(604800)
	got := ipsetTTLFromRecord(300, week)
	if got != 300+week {
		t.Errorf("ipsetTTLFromRecord(300, week) = %d, want %d — additionalTTL policy must not be clamped", got, 300+week)
	}
}

// TestIPSetTTLFromDeadline — путь «остаток из recordsCache»: ceil до секунды,
// минимум 1 (0 = permanent!), истёкшее не добавляем.
func TestIPSetTTLFromDeadline(t *testing.T) {
	cases := []struct {
		name    string
		d       time.Duration
		wantTTL uint32
		wantOK  bool
	}{
		{"истекло ровно", 0, 0, false},
		{"истекло давно", -5 * time.Second, 0, false},
		{"полсекунды → 1, не 0", 500 * time.Millisecond, 1, true},
		{"999мс → 1", 999 * time.Millisecond, 1, true},
		{"ровно секунда", time.Second, 1, true},
		{"1.2с → 2 (ceil)", 1200 * time.Millisecond, 2, true},
		{"час", time.Hour, 3600, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ipsetTTLFromDeadline(c.d)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if ok && got != c.wantTTL {
				t.Errorf("ttl = %d, want %d", got, c.wantTTL)
			}
			if ok && got == 0 {
				t.Error("ttl = 0 would create a PERMANENT ipset entry")
			}
		})
	}
}

// TestIPSetTTLFromDeadline_AbsurdFuture — битый снапшот может принести дедлайн в
// далёком будущем (дедлайны там абсолютные). Не должно превращаться в переполнение
// или в вечную запись.
func TestIPSetTTLFromDeadline_AbsurdFuture(t *testing.T) {
	got, ok := ipsetTTLFromDeadline(1000 * 24 * time.Hour) // ~3 года
	if !ok {
		t.Fatal("far-future deadline must still be usable")
	}
	if got == 0 || got == math.MaxUint32 {
		t.Errorf("ttl = %d, want a sane clamped value", got)
	}
}
