package magitrickle

import (
	"math"
	"time"
)

// maxRecordTTL — потолок TTL из DNS-ответа, учитываемый при расчёте времени жизни
// ipset-записи (сутки). Смысл двойной:
//
//   - защита от переполнения: 'Hdr.Ttl + AdditionalTTL' по uint32 при абсурдном
//     TTL (битый или враждебный апстрим; RFC 2181 отводит на TTL 31 бит, но
//     miekg/dns значение не нормализует) давало КРОШЕЧНЫЙ timeout вместо
//     огромного — запись выпадала из ipset и трафик уходил direct;
//   - защита от обратной крайности: простое насыщение до MaxUint32 дало бы
//     запись на 136 лет, то есть практически неудаляемую.
//
// TTL записи больше суток для маршрутизации смысла не имеет: столько же живёт
// наш AdditionalTTL по умолчанию, а продление ipset по трафику (SET на conntrack
// NEW) обновляет запись у всего живого.
const maxRecordTTL uint32 = 86400

// maxDeadlineTTL — потолок для пути «остаток по дедлайну из recordsCache».
// Снапшот хранит АБСОЛЮТНЫЕ дедлайны, поэтому подменённый/битый файл может
// принести дату в далёком будущем; в ipset такое попадать не должно.
const maxDeadlineTTL uint32 = 7 * 86400

// saturatingAddUint32 складывает без переполнения (при выходе за границу — MaxUint32).
func saturatingAddUint32(a, b uint32) uint32 {
	if a > math.MaxUint32-b {
		return math.MaxUint32
	}
	return a + b
}

// ipsetTTLFromRecord считает время жизни ipset-записи по TTL из DNS-ответа.
// Для нормальных значений результат тот же, что и у прежней формулы
// (recordTTL + additionalTTL) — нормализуются только края.
//
// Политика пользователя (additionalTTL) НЕ ограничивается: потолок применяется к
// TTL из ответа, а не к сумме. Апстримный вариант (MR !157) капает сумму и при
// большом additionalTTL молча урезал бы заданное время жизни.
//
// Никогда не возвращает 0: в ipset timeout 0 означает PERMANENT-запись — так
// намеренно добавляются статические subnet-правила (nil-timeout, см.
// zeroTimeout в netfilterTools). Динамическая запись, случайно получившая 0,
// залипла бы навсегда, и sync её не понизил бы (дифф пропускает oldTTL == nil).
func ipsetTTLFromRecord(recordTTL, additionalTTL uint32) uint32 {
	if recordTTL > maxRecordTTL {
		recordTTL = maxRecordTTL
	}
	ttl := saturatingAddUint32(recordTTL, additionalTTL)
	if ttl == 0 {
		return 1
	}
	return ttl
}

// ipsetTTLFromDeadline переводит остаток времени до дедлайна в ipset-timeout.
// Возвращает false, если запись уже истекла (её просто не добавляют).
//
// Округление ВВЕРХ и минимум 1 — принципиально: усечение вниз превращало
// остаток меньше секунды в 0, то есть в permanent-запись (см. ipsetTTLFromRecord).
func ipsetTTLFromDeadline(d time.Duration) (uint32, bool) {
	if d <= 0 {
		return 0, false
	}

	sec := uint64((d + time.Second - 1) / time.Second) // ceil
	if sec == 0 {
		sec = 1
	}
	if sec > uint64(maxDeadlineTTL) {
		sec = uint64(maxDeadlineTTL)
	}
	return uint32(sec), true
}
