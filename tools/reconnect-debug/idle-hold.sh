#!/bin/sh
# idle-hold.sh — матрица выживания idle TCP-соединений: после паузы T жив ли конн.
# Пути: tunnel = mihomo HTTP CONNECT (:7891 на home) → полная цепочка до echo-сервера;
#       direct = роутер → echo-сервер напрямую (мимо mihomo).
# Требует echo-сервер (echo9099.py) на $DST:$PORT. Сигнатура убийцы idle-коннов:
# HELLO=YES PROBE=NO при T >= порога — на этом T соединение молча умерло за паузу.
DST=${DST:-45.145.163.163}; PORT=${PORT:-9099}
PROXY=${PROXY:-127.0.0.1}; PP=${PP:-7891}
OUT=${OUT:-/opt/var/log/reconnect-watchdog/idle-hold.tsv}
TS=${TS:-"60 180 300 420 600 900 1260"}
[ -f "$OUT" ] || printf 'epoch\tiso\tpath\tidle_s\thello\tprobe\tverdict\n' >> "$OUT"
one() { # $1=path $2=idle_seconds
  T=$2
  case "$1" in
    tunnel) ADDR="PROXY:${PROXY}:${DST}:${PORT},proxyport=${PP}" ;;
    direct) ADDR="TCP:${DST}:${PORT}" ;;
  esac
  s=$(date +%s)
  r=$( { echo "HELLO-$1-$T"; sleep "$T"; echo "PROBE-$1-$T"; sleep 6; } | socat -T $((T+30)) - "$ADDR" 2>/dev/null )
  h=NO; p=NO
  echo "$r" | grep -q "HELLO-$1-$T" && h=YES
  echo "$r" | grep -q "PROBE-$1-$T" && p=YES
  v=DEAD; [ "$p" = YES ] && v=ALIVE; [ "$h" = NO ] && v=CONNFAIL
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$s" "$(date -d @$s '+%F %T' 2>/dev/null || echo -)" "$1" "$T" "$h" "$p" "$v" >> "$OUT"
}
for T in $TS; do
  one tunnel "$T" &
  one direct "$T" &
done
wait
echo "done -> $OUT"
