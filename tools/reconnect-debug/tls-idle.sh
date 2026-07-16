#!/bin/sh
# tls-idle.sh — порог смерти idle TLS-соединений: handshake → тишина T → GET → жив?
# Пути: tunnel = socat OPENSSL поверх локального PROXY-моста в mihomo (:7891);
#       direct = socat OPENSSL напрямую (контроль серверной idle-политики).
# Требует socat >= 1.7.4 (snihost). Вердикт: ALIVE = HTTP-ответ пришёл после паузы;
# DEAD = ответа нет (сервер-FIN и silent-drop не различаем — их различает
# дельта tunnel vs direct: сервер один и тот же).
HOSTN=${HOSTN:-api.anthropic.com}
HIP=${HIP:-160.79.104.10}
BRIDGE=${BRIDGE:-12345}
PP=${PP:-7891}
OUT=${OUT:-/opt/var/log/reconnect-watchdog/tls-idle.tsv}
TS=${TS:-"30 60 120 180 300 420 600"}
[ -f "$OUT" ] || printf 'epoch\tiso\tpath\tidle_s\tverdict\thttp\tdur_s\n' >> "$OUT"

# мост в туннель (fork: одно соединение на каждого клиента)
pkill -f "TCP-LISTEN:${BRIDGE}" 2>/dev/null; sleep 1
(socat "TCP-LISTEN:${BRIDGE},reuseaddr,fork" "PROXY:127.0.0.1:${HOSTN}:443,proxyport=${PP}" >/dev/null 2>&1 &)
sleep 1

one() { # $1=path $2=idle_seconds
  # Паттерн пула Claude Code: запрос → ответ → idle T → второй запрос по тому же конну.
  # (Голый handshake+тишина не годится: edge режет беззапросные конны slowloris-защитой ~10с.)
  T=$2
  case "$1" in
    tunnel) ADDR="OPENSSL:127.0.0.1:${BRIDGE},snihost=${HOSTN},verify=0" ;;
    direct) ADDR="OPENSSL:${HIP}:443,snihost=${HOSTN},verify=0" ;;
  esac
  s=$(date +%s)
  r=$( { printf 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n' "$HOSTN"; sleep "$T"; \
         printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$HOSTN"; sleep 10; } \
       | socat -t 10 - "$ADDR" 2>/dev/null )
  e=$(date +%s)
  n=$(echo "$r" | grep -c '^HTTP/')
  case "$n" in
    2) v=ALIVE ;;
    1) v=DEAD-AFTER-IDLE ;;
    *) v=CONNFAIL ;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$s" "$(date -d @$s '+%F %T' 2>/dev/null || echo -)" "$1" "$T" "$v" "$n" "$((e-s))" >> "$OUT"
}

for T in $TS; do
  one tunnel "$T" &
  one direct "$T" &
done
wait
echo "done -> $OUT"
