#!/bin/sh
# connwatch-stop.sh — остановить активный connwatch для клиента (шлёт TERM ->
# триггерит cleanup: гасит conntrack + стопит MT DNS-capture). Запуск НА РОУТЕРЕ.
#   connwatch-stop.sh -s <CLIENT_IP>
set -u
CLIENT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) CLIENT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -z "$CLIENT" ] && { echo "need -s CLIENT_IP" >&2; exit 2; }

n=0
for p in $(pgrep -f "connwatch.sh -s $CLIENT" 2>/dev/null); do
  kill "$p" 2>/dev/null && n=$((n+1))
done
# на всякий случай добить осиротевший conntrack этого клиента
for p in $(pgrep -f "conntrack -E -e NEW -s $CLIENT" 2>/dev/null); do
  kill "$p" 2>/dev/null
done
# и остановить DNS-capture (если trap не успел)
curl -s --max-time 4 -X POST "http://127.0.0.1:8080/api/v1/system/dns-capture/stop" >/dev/null 2>&1
echo "[connwatch-stop] terminated processes: $n"
