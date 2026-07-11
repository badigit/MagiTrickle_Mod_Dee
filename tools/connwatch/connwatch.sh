#!/bin/sh
# connwatch.sh — ad-hoc per-client журнал соединений + вердикт покрытия MagiTrickle.
# Запускается НА РОУТЕРЕ (<ROUTER_IP>, Keenetic/Entware, BusyBox sh). Read-only:
# только слушает conntrack-события и спрашивает MT API, ничего не меняет в роутинге.
#
# Что делает за сеанс:
#   1) Включает MT DNS-capture с фильтром по IP клиента (домены, что резолвил телефон).
#   2) Слушает conntrack NEW от клиента. Для каждого нового публичного dst IP
#      спрашивает MT /lookup (check_ipset=true) и пишет вердикт:
#        covered   — IP сейчас в ipset какой-то группы => поедет через её роутинг;
#        rule-only — есть совпадение с правилом группы, но IP ещё НЕ в ipset
#                    (не резолвился через MT / попал только как подсеть) — пограничный;
#        uncovered — ни правила, ни ipset => идёт DIRECT, мимо групп.
#   3) Пишет журнал TSV + живой лог в stdout. Домены забираются на стопе из MT.
#
# Файлы: /opt/var/log/connwatch/<client>-<ts>/journal.tsv
#
# Использование:
#   connwatch.sh -s <CLIENT_IP>            # до kill (запускать через nohup ... &)
#   connwatch.sh -s <CLIENT_IP> -d 120     # авто-стоп через 120с
#
# Деплой (Windows OpenSSH, scp -O байт-в-байт):
#   scp -O -P 222 tools/connwatch/connwatch.sh root@<ROUTER_IP>:/opt/bin/
#   ssh -p 222 root@<ROUTER_IP> 'chmod +x /opt/bin/connwatch.sh'
# Зависимости: conntrack, curl, jq (уже стоят на проде).

set -u

CLIENT=""
DUR=0
API="http://127.0.0.1:8080/api/v1"

while [ $# -gt 0 ]; do
  case "$1" in
    -s) CLIENT="$2"; shift 2 ;;
    -d) DUR="$2"; shift 2 ;;
    -a) API="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -z "$CLIENT" ] && { echo "need -s CLIENT_IP" >&2; exit 2; }

TS=$(date +%Y%m%d-%H%M%S)
OUT="/opt/var/log/connwatch/$CLIENT-$TS"
mkdir -p "$OUT"
JOURNAL="$OUT/journal.tsv"
printf 'ts\tproto\tdst_ip\tdport\tverdict\tgroups\tipset\tmark\n' > "$JOURNAL"

echo "[connwatch] client=$CLIENT out=$OUT dur=${DUR:-inf}"

# на выходе (kill/TERM/по таймеру) гасим фоновый conntrack и стопим DNS-capture
cleanup() {
  for p in $(pgrep -f "conntrack -E -e NEW -s $CLIENT" 2>/dev/null); do
    kill "$p" 2>/dev/null
  done
  curl -s --max-time 4 -X POST "$API/system/dns-capture/stop" >/dev/null 2>&1
  echo "[connwatch] stopped, journal -> $JOURNAL"
  exit 0
}
trap cleanup INT TERM

# приватные/сервисные диапазоны — пропускаем (нас интересует только выход в интернет)
is_public() {
  case "$1" in
    10.*|127.*|169.254.*|192.168.*|\
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|\
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|\
    0.0.0.0|224.*|239.*|255.*|*:*) return 1 ;;
    *) return 0 ;;
  esac
}

classify() {
  proto="$1"; dst="$2"; dport="$3"; mark="$4"
  is_public "$dst" || return 0

  resp=$(curl -s --max-time 4 -X POST "$API/lookup" \
    -H 'Content-Type: application/json' \
    -d "{\"queries\":[\"$dst\"],\"check_ipset\":true}" 2>/dev/null)

  groups=$(printf '%s' "$resp" | jq -r '[.results[0].rule_hits[].group_name] | unique | join(",")' 2>/dev/null)
  nhits=$(printf '%s' "$resp" | jq -r '.results[0].rule_hits | length' 2>/dev/null)
  inipset=$(printf '%s' "$resp" | jq -r '((.results[0].ipset_hits // []) | length) > 0' 2>/dev/null)

  if [ "$inipset" = "true" ]; then
    ipset=yes; verdict=covered
  elif [ "${nhits:-0}" -gt 0 ] 2>/dev/null; then
    ipset=no; verdict=rule-only
  else
    ipset=no; verdict=uncovered
  fi

  ts=$(date '+%H:%M:%S')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$ts" "$proto" "$dst" "$dport" "$verdict" "${groups:-}" "$ipset" "$mark" >> "$JOURNAL"
  printf '[%s] %-3s %s:%s  %-9s groups=%s ipset=%s mark=%s\n' \
    "$ts" "$proto" "$dst" "$dport" "$verdict" "${groups:--}" "$ipset" "$mark"
}

# 1) MT DNS-capture с фильтром по клиенту
curl -s --max-time 4 -X POST "$API/system/dns-capture/start" \
  -H 'Content-Type: application/json' -d "{\"filter_ip\":\"$CLIENT\"}" >/dev/null 2>&1
echo "[connwatch] MT DNS-capture started (filter=$CLIENT)"

# 2) conntrack NEW -> awk вытаскивает первый (orig) dst/dport + mark, дедупит,
#    shell классифицирует через MT /lookup
CT="conntrack -E -e NEW -s $CLIENT"
[ "$DUR" -gt 0 ] 2>/dev/null && CT="conntrack -E -e NEW -s $CLIENT" # timeout ниже

run_stream() {
  $CT 2>/dev/null | awk '
    {
      proto=""; dst=""; dport=""; mark="0"
      for (i=1; i<=NF; i++) {
        if (proto=="" && $i ~ /^(tcp|udp)$/) proto=$i
        if (dst==""   && $i ~ /^dst=/)   { split($i,a,"="); dst=a[2] }
        if (dport=="" && $i ~ /^dport=/) { split($i,a,"="); dport=a[2] }
        if ($i ~ /^mark=/) { split($i,a,"="); mark=a[2] }
      }
      if (dst!="" && dport!="") {
        key=proto"|"dst"|"dport
        if (!(key in seen)) { seen[key]=1; print proto, dst, dport, mark; fflush() }
      }
    }' | while read -r proto dst dport mark; do
      classify "$proto" "$dst" "$dport" "$mark"
    done
}

if [ "$DUR" -gt 0 ] 2>/dev/null; then
  ( run_stream ) &
  SP=$!
  sleep "$DUR"
  kill "$SP" 2>/dev/null
  cleanup
else
  run_stream
fi

cleanup
