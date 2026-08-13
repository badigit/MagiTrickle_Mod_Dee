#!/bin/sh
# rst-correlate.sh — последний RST-burst (post-handshake upstream stall) ↔ mihomo error-лог +
# mihomo-poll в момент. Отвечает: стойло ТИХОЕ (gRPC-стрим завис, mihomo молчит = throttle/перегруз
# узла) или mihomo пишет явную ошибку (dial/EOF/reset/deadline)?  Аргумент 1 (опц.) = N-я с конца.
D=/opt/var/log/reconnect-watchdog
N="${1:-1}"
L=$(tail -n "$N" "$D/rst-bursts.tsv" | head -1)
EP=$(echo "$L" | cut -f1); CNT=$(echo "$L" | cut -f3); DSTS=$(echo "$L" | cut -f4)
[ -z "$EP" ] && { echo "нет RST-burst событий"; exit 0; }

echo "=== RST-BURST (#$N с конца) ==="
echo "epoch=$EP  time=$(date -d @"$EP" '+%F %T' 2>/dev/null)  count=$CNT  dsts=$DSTS"

echo "=== mihomo error-лог ±20с вокруг берста ==="
ML=$(for H in $(date -d @$((EP-20)) +%Y%m%d-%H) $(date -d @$((EP+20)) +%Y%m%d-%H); do
       [ -f "$D/mlog-$H.log" ] && awk -v e="$EP" '{t=$1+0} t>=e-20 && t<=e+20' "$D/mlog-$H.log"
     done | sort -u)
[ -z "$ML" ] && echo "(пусто)" || echo "$ML"

echo "=== mihomo-poll ±20с (conn_total + traffic — стойло/flap туннеля) ==="
awk -F'\t' -v e="$EP" '{t=$1+0} t>=e-20 && t<=e+20 {print strftime("%T",$1)"  conn="$3"  "$2}' "$D/mihomo-poll.tsv" 2>/dev/null

echo "=== ВЕРДИКТ ==="
if [ -z "$ML" ]; then
  echo ">>> mlog ПУСТ → стойло ТИХОЕ: gRPC-стрим завис, mihomo не логирует ошибку."
  echo ">>> = узел принимает, но не отдаёт данные (throttle/перегрузка на стороне узла), не dial-fail."
else
  echo ">>> есть текст ошибки mihomo (см. выше) → явная upstream-проблема узла/цепочки."
fi
