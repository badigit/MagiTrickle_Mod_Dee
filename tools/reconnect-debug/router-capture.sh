#!/bin/sh
# router-capture.sh — корреляционный захват для дебага реконнектов "второй раз работает".
# Запускается НА РОУТЕРЕ (<ROUTER_IP>, Keenetic/Entware, BusyBox sh). Read-only по системе
# (только слушает события + дампит сеты), ничего не меняет в конфигах MT/mihomo.
#
# Что снимает за окно -d секунд в /opt/var/log/reconnect-debug/<ts>/:
#   conntrack.log    — conntrack -E (NEW/DESTROY) с timestamp + reply-tuple + флаги.
#                      TCP-в-прокси здесь = REDIRECT --to-ports 5001 (DNAT), НЕ fwmark
#                      (все :443 потоки mark=0 — на mark НЕ полагаемся).
#                      reply sport=5001 => поток ПРОКСИРУЕТСЯ (через mihomo redir).
#                      reply sport=443  => поток идёт DIRECT (мимо прокси).
#                      Это ГЛАВНЫЙ локализатор: ушёл ли ПЕРВЫЙ SYN в REDIRECT.
#   syn-wan.pcap     — tcpdump SYN/SYN-ACK/RST на WAN-интерфейсе (где умирает первый SYN).
#   syn-lan.pcap     — то же на LAN — видно, что вообще отправил клиент.
#   mihomo-poll.tsv  — раз в 1с: inner-stats {joined,left,alive} + traffic + кол-во conn
#                      (ловит H4: flap туннеля mihomo, независимо от MagiTrickle).
#   ipset.log        — (опц., если -I <setname>) дамп членства ipset раз в 0.5с
#                      (прямое доказательство гонки: IP появился в сете ПОСЛЕ первого SYN).
#                      Имена: ipset list -n | grep '^mt_' (per-group, _4=IPv4 _6=IPv6).
#   meta.txt         — старт wall-clock (для корреляции с часами ПК), параметры, окружение.
#
# Использование:
#   router-capture.sh [-d SEC] [-s SRC_IP] [-w WAN_IF] [-l LAN_IF] [-N TABLE SET] [-m]
#     -d SEC      длительность окна (по умолч. 120; 0 = до Ctrl+C)
#     -s SRC_IP   фильтр conntrack/tcpdump по источнику (IP ПК-зонда) — режет шум
#     -w WAN_IF   WAN-интерфейс (по умолч. — iface default-маршрута)
#     -l LAN_IF   LAN-интерфейс (по умолч. br0)
#     -I SET      доп. поллить членство ipset SET раз в 0.5с (напр. mt_03f344d8_4)
#     -m          включить стрим mihomo debug-лога (шумно)
#
# Деплой (с Windows OpenSSH, scp -O байт-в-байт):
#   scp -O -P 222 tools/reconnect-debug/router-capture.sh root@<ROUTER_IP>:/opt/bin/
#   ssh -p 222 root@<ROUTER_IP> 'chmod +x /opt/bin/router-capture.sh'
# Зависимости на роутере: conntrack, tcpdump, jq, curl (opkg install conntrack jq).

set -u

DUR=120
SRC=""
WAN=""
LAN="br0"
IPSET_NAME=""
MIHOMO_DEBUG=0

while [ $# -gt 0 ]; do
  case "$1" in
    -d) DUR="$2"; shift 2 ;;
    -s) SRC="$2"; shift 2 ;;
    -w) WAN="$2"; shift 2 ;;
    -l) LAN="$2"; shift 2 ;;
    -I) IPSET_NAME="$2"; shift 2 ;;
    -m) MIHOMO_DEBUG=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -z "$WAN" ] && WAN=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
[ -z "$WAN" ] && WAN="eth3"

TS=$(date +%Y%m%d-%H%M%S)
OUT="/opt/var/log/reconnect-debug/$TS"
mkdir -p "$OUT"

# GNU tar (busybox tar не умеет create)
TAR=/opt/bin/tar
[ -x "$TAR" ] || TAR=tar

# --- meta ---
{
  echo "label: reconnect-capture"
  echo "start_wall: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "start_epoch: $(date +%s)"
  echo "duration_s: $DUR"
  echo "src_filter: ${SRC:-<none>}"
  echo "wan_if: $WAN"
  echo "lan_if: $LAN"
  echo "ipset_poll: ${IPSET_NAME:-<none>}"
  echo "uptime: $(uptime 2>/dev/null)"
  echo "magitrickle_ver: $(curl -s http://127.0.0.1:8080/api/v1/system/version 2>/dev/null)"
  echo "mihomo_ver: $(curl -s http://127.0.0.1:9090/version 2>/dev/null)"
  echo "# Для корреляции с ПК: на ПК во время старта зафиксируй (Get-Date).ToUniversalTime()"
} > "$OUT/meta.txt"

PIDS=""
cleanup() {
  echo ""
  echo "[capture] stopping, pids: $PIDS"
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  sleep 1
  echo "[capture] archiving -> $OUT.tar.gz"
  "$TAR" -czf "$OUT.tar.gz" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null
  echo "[capture] done: $OUT.tar.gz"
  echo "[capture] забрать на ПК: scp -O -P 222 root@<ROUTER_IP>:$OUT.tar.gz ."
  exit 0
}
trap cleanup INT TERM

echo "[capture] out=$OUT  dur=${DUR}s  wan=$WAN lan=$LAN src=${SRC:-all}"

# 1) conntrack events (главный локализатор: mark + RST/флаги по каждому потоку)
CT_FILTER=""
[ -n "$SRC" ] && CT_FILTER="-s $SRC"
conntrack -E -o timestamp,extended -e NEW,DESTROY $CT_FILTER > "$OUT/conntrack.log" 2>&1 &
PIDS="$PIDS $!"

# 2) tcpdump SYN/SYN-ACK/RST (флаги-онли => крошечные pcap)
BPF="(tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0"
[ -n "$SRC" ] && BPF="host $SRC and $BPF"
tcpdump -i "$WAN" -nn -s 96 -w "$OUT/syn-wan.pcap" "$BPF" >/dev/null 2>&1 &
PIDS="$PIDS $!"
tcpdump -i "$LAN" -nn -s 96 -w "$OUT/syn-lan.pcap" "$BPF" >/dev/null 2>&1 &
PIDS="$PIDS $!"

# 3) mihomo poll (H4: flap туннеля)
(
  echo "epoch	inner_stats	traffic	conn_total"
  while :; do
    IS=$(curl -s --max-time 2 http://127.0.0.1:9090/connections/inner-stats 2>/dev/null)
    TR=$(curl -s --max-time 2 http://127.0.0.1:9090/traffic 2>/dev/null | head -c 120)
    CN=$(curl -s --max-time 2 http://127.0.0.1:9090/connections 2>/dev/null | jq -r '.connections|length' 2>/dev/null)
    printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "${IS:-NA}" "${TR:-NA}" "${CN:-NA}"
    sleep 1
  done
) > "$OUT/mihomo-poll.tsv" 2>/dev/null &
PIDS="$PIDS $!"

# 4) ipset membership poll (опц.) — прямое доказательство гонки DNS->ipset
if [ -n "$IPSET_NAME" ]; then
  (
    while :; do
      printf '=== %s ===\n' "$(date +%s)"
      ipset list "$IPSET_NAME" 2>/dev/null | sed -n '/Members/,$p'
      sleep 0.5
    done
  ) > "$OUT/ipset.log" 2>/dev/null &
  PIDS="$PIDS $!"
fi

# 5) mihomo debug-лог (опц.)
if [ "$MIHOMO_DEBUG" = "1" ]; then
  curl -s "http://127.0.0.1:9090/logs?level=debug" > "$OUT/mihomo-debug.log" 2>&1 &
  PIDS="$PIDS $!"
fi

# ждём окно
if [ "$DUR" = "0" ]; then
  echo "[capture] до Ctrl+C..."
  while :; do sleep 3600; done
else
  sleep "$DUR"
  cleanup
fi
