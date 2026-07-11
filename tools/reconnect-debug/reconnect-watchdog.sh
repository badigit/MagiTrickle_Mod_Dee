#!/bin/sh
# reconnect-watchdog.sh — ЛЁГКИЙ always-on роллинг-захват на роутере для отлова
# перемежающегося реконнекта (когда событие случится — улика уже будет в логе).
#
# Пишет в /opt/var/log/reconnect-watchdog/:
#   ct-YYYYMMDD-HH.log  — conntrack -E (NEW/DESTROY) с timestamp+reply-tuple, РОТАЦИЯ почасовая,
#                         хранится последние KEEP часов. Локализатор: reply sport=5001=проксируется,
#                         sport=443=direct. Мёртвый проксируемый поток = вина mihomo; ушёл direct = вина MT.
#   mihomo-poll.tsv     — раз в 5с: inner-stats + conn_total (ловит flap туннеля), трим до 100k строк.
#   watchdog.log        — старт/стоп/ошибки.
#
# Запуск (детач через subshell, nohup в BusyBox нет):
#   (/opt/bin/reconnect-watchdog.sh -s <CLIENT_IP> </dev/null >/tmp/rw.log 2>&1 &)
# Стоп:  pkill -f reconnect-watchdog.sh ; pkill -f 'conntrack -E'
# Зависимости: conntrack, jq, curl.
#
#   -s SRC   фильтр conntrack по источнику (IP клиента); пусто = весь трафик
#   -k N     сколько часовых ct-файлов хранить (по умолч. 12)
#   -d DIR   каталог вывода

set -u
SRC=""; KEEP=12; DIR="/opt/var/log/reconnect-watchdog"; REDIR_PORT="${REDIR_PORT:-5001}"
while [ $# -gt 0 ]; do case "$1" in
  -s) SRC="$2"; shift 2;; -k) KEEP="$2"; shift 2;; -d) DIR="$2"; shift 2;;
  *) echo "unknown arg: $1" >&2; exit 2;; esac; done
mkdir -p "$DIR"

# single-instance обеспечивает лаунчер (PC-watchdog проверяет ps|grep перед стартом).
# Внутренний pgrep-guard убран: он ложно ловил процесс-лаунчер 'sh -c (...reconnect-watchdog.sh&)'
# как "другой инстанс" и демон сразу выходил.

echo "$(date '+%F %T %z') START src=${SRC:-all} keep=${KEEP}h pid=$$" >> "$DIR/watchdog.log"

SRCF=""; [ -n "$SRC" ] && SRCF="-s $SRC"
# regex-escaped SRC для RST-парсера; пусто = matched любой клиент
if [ -n "$SRC" ]; then SRC_RE=$(printf '%s' "$SRC" | sed 's/\./\\./g'); else SRC_RE='[0-9.]*'; fi
HAVE_TD=0; command -v tcpdump >/dev/null 2>&1 && HAVE_TD=1
TDHOST=""; [ -n "$SRC" ] && TDHOST="and host $SRC"
MPID=""; CTPID=""; DPID=""; TDPID=""; RBPID=""; MLPID=""
cleanup() {
  echo "$(date '+%F %T %z') STOP pid=$$" >> "$DIR/watchdog.log"
  [ -n "$MPID" ] && kill "$MPID" 2>/dev/null
  [ -n "$CTPID" ] && kill "$CTPID" 2>/dev/null
  [ -n "$DPID" ] && kill "$DPID" 2>/dev/null
  [ -n "$TDPID" ] && kill "$TDPID" 2>/dev/null
  [ -n "$RBPID" ] && kill "$RBPID" 2>/dev/null
  [ -n "$MLPID" ] && kill "$MLPID" 2>/dev/null
  exit 0
}
trap cleanup INT TERM

# mihomo-poll (раз в 5с)
( while :; do
    IS=$(curl -s --max-time 2 http://127.0.0.1:9090/connections/inner-stats 2>/dev/null)
    CN=$(curl -s --max-time 2 http://127.0.0.1:9090/connections 2>/dev/null | jq -r '.connections|length' 2>/dev/null)
    printf '%s\t%s\t%s\n' "$(date +%s)" "${IS:-NA}" "${CN:-NA}" >> "$DIR/mihomo-poll.tsv"
    sleep 5
  done ) &
MPID=$!

# dead-proxied детектор (раз в 60с): «мёртвый проксируемый SYN» = REDIRECT в mihomo:5001,
# ответа ноль. Сигнатура реальных событий: DESTROY tcp ... reply sport=5001 ... packets=0.
# Ловит ВСЕ реальные обрывы по всем приложениям (не по 3 доменам зонда). Дедуп по epoch+sport.
DEAD="$DIR/dead-proxied.tsv"; KEYS="$DIR/.dead-keys"
[ -f "$DEAD" ] || printf 'router_epoch\tiso_local\tdst\torig_sport\tfwd_pkts\traw\n' > "$DEAD"
touch "$KEYS" 2>/dev/null
( while :; do
    for cf in $(ls -1t "$DIR"/ct-*.log 2>/dev/null | head -2); do
      grep -E "DESTROY.*[[:space:]]tcp[[:space:]].*sport=${REDIR_PORT} dport=[0-9]+ packets=0" "$cf" 2>/dev/null
    done | while IFS= read -r line; do
      ep=$(echo "$line" | sed -n 's/^\[\([0-9]*\)\..*/\1/p'); [ -z "$ep" ] && continue
      # анкер на dport=443 — только forward-тапл его имеет (reply: dport=<orig_sport>).
      # без анкера жадный .* хватает reply-тапл (src=роутер dst=клиент sport=REDIR_PORT).
      osp=$(echo "$line" | sed -n 's/.*dst=[0-9.]* sport=\([0-9]*\) dport=443.*/\1/p')
      key="$ep-$osp"
      grep -q "^$key$" "$KEYS" 2>/dev/null && continue
      echo "$key" >> "$KEYS"
      dst=$(echo "$line" | sed -n 's/.*dst=\([0-9.]*\) sport=[0-9]* dport=443.*/\1/p')
      fwd=$(echo "$line" | sed -n 's/.*dport=443 packets=\([0-9]*\).*/\1/p')
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ep" "$(date -d @"$ep" '+%F %T' 2>/dev/null || echo -)" "$dst" "$osp" "$fwd" "$line" >> "$DEAD"
    done
    if [ "$(wc -l < "$KEYS" 2>/dev/null || echo 0)" -gt 5000 ]; then tail -n 2000 "$KEYS" > "$KEYS.t" && mv "$KEYS.t" "$KEYS"; fi
    sleep 60
  done ) &
DPID=$!

# RST-burst детектор (раз в 60с): залп client [R.] к :443 в ≤3с = приложение абортит зависшие
# UPSTREAM-соединения (post-handshake stall — SYN-ACK был, данные встали). ЭТОТ режим = реальные
# user-visible "request failed / retry". Читает syn-pcap. Дедуп по epoch старта берста.
RSTLOG="$DIR/rst-bursts.tsv"; RKEYS="$DIR/.rst-keys"
[ -f "$RSTLOG" ] || printf 'router_epoch\tiso_local\tcount\tdsts\n' > "$RSTLOG"
touch "$RKEYS" 2>/dev/null
( while :; do
    NOW=$(date +%s); FROM=$((NOW-180))
    for sf in $(ls -1t "$DIR"/syn-*.log 2>/dev/null | head -2); do
      awk -v f="$FROM" '($1+0)>=f' "$sf" 2>/dev/null
    done | sed -n "s/^\([0-9]*\)\.[0-9]* IP ${SRC_RE}\.[0-9]* > \([0-9.]*\)\.443: Flags \[R\.\].*/\1 \2/p" | sort -n | \
    awk '
      NR==1 { bs=$1; c=1; be=$1; d=$2","; next }
      { if ($1-be>3){ if(c>=4) print bs"\t"c"\t"d; bs=$1; c=1; d="" } else c++; be=$1; if(index(d,$2",")==0) d=d $2"," }
      END { if(c>=4) print bs"\t"c"\t"d }
    ' | while IFS="$(printf '\t')" read -r ep cnt dsts; do
        [ -z "$ep" ] && continue
        grep -q "^$ep\$" "$RKEYS" 2>/dev/null && continue
        echo "$ep" >> "$RKEYS"
        printf '%s\t%s\t%s\t%s\n' "$ep" "$(date -d @"$ep" '+%F %T' 2>/dev/null || echo -)" "$cnt" "$dsts" >> "$RSTLOG"
      done
    [ "$(wc -l < "$RKEYS" 2>/dev/null || echo 0)" -gt 3000 ] && { tail -n 1000 "$RKEYS" > "$RKEYS.t" && mv "$RKEYS.t" "$RKEYS"; }
    sleep 60
  done ) &
RBPID=$!

# conntrack роллинг почасово + прун
while :; do
  H=$(date +%Y%m%d-%H)
  conntrack -E -o timestamp,extended -e NEW,DESTROY $SRCF >> "$DIR/ct-$H.log" 2>>"$DIR/watchdog.log" &
  CTPID=$!
  # rolling pcap SYN/SYN-ACK/RST на :443 (флаги-only, -tt=epoch, -s96=заголовки).
  # Ядро SYN-ACK'ает автономно при живом LISTEN (ListenOverflows=0) → «SYN есть, SYN-ACK нет»
  # локализует дроп ПОСЛЕ DNAT (не mihomo-slow-accept). Для разбора dead-proxied событий.
  if [ "$HAVE_TD" = 1 ]; then
    tcpdump -i br0 -n -tt -s 96 -l "tcp port 443 $TDHOST and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0" >> "$DIR/syn-$H.log" 2>>"$DIR/watchdog.log" &
    TDPID=$!
  fi
  # mihomo error-лог: стрим /logs?level=debug, фильтр на ошибки, timestamped (epoch) — текст
  # upstream-сбоя (dial/EOF/reset/deadline). --max-time=почасовой самостоп (совпадает с ротацией).
  curl -s -N --max-time 3600 "http://127.0.0.1:9090/logs?level=debug" 2>>"$DIR/watchdog.log" \
    | awk 'tolower($0) ~ /error|fail|timeout|reset|eof|deadline|refus|dial|handshake/ { print systime()" "$0; fflush() }' >> "$DIR/mlog-$H.log" &
  MLPID=$!
  # прун старых часовых файлов
  ls -1t "$DIR"/ct-*.log 2>/dev/null | tail -n +$((KEEP+1)) | xargs rm -f 2>/dev/null
  ls -1t "$DIR"/syn-*.log 2>/dev/null | tail -n +$((KEEP+1)) | xargs rm -f 2>/dev/null
  ls -1t "$DIR"/mlog-*.log 2>/dev/null | tail -n +$((KEEP+1)) | xargs rm -f 2>/dev/null
  # трим mihomo-poll
  if [ "$(wc -l < "$DIR/mihomo-poll.tsv" 2>/dev/null || echo 0)" -gt 120000 ]; then
    tail -n 80000 "$DIR/mihomo-poll.tsv" > "$DIR/.mp.tmp" && mv "$DIR/.mp.tmp" "$DIR/mihomo-poll.tsv"
  fi
  sleep 3600
  kill "$CTPID" 2>/dev/null; [ -n "$TDPID" ] && kill "$TDPID" 2>/dev/null; [ -n "$MLPID" ] && kill "$MLPID" 2>/dev/null
  for cp in $(ps w | grep '[c]url.*9090/logs' | awk '{print $1}'); do kill $cp 2>/dev/null; done
  wait "$CTPID" 2>/dev/null
done
