#!/bin/sh
# synth-stall.sh — синтетический репро стойлов долгоживущих активных потоков.
# Идея: держим медленные (--limit-rate) HTTPS-скачивания параллельно двумя путями —
#   tunnel : socks5h через mihomo :7890 (полный путь роутер→entry→exit→мир)
#   direct : с роутера напрямую, мимо туннеля (контроль «RU-деградации»)
# Оба пути гоняются ОДНОВРЕМЕННО (одно окно, одни внешние условия) → честный A/B.
#
# Сенсор стойла: --speed-limit 1 --speed-time ${STALLSEC} → rc=28 раньше MAXT = STALL.
# Здоровый поток при --limit-rate живёт до MAXT (тоже rc=28, но secs≈MAXT) = SURVIVED.
#
# Запуск:  synth-stall.sh [cycles]        (деф. 6 циклов ≈ cycles*MAXT секунд)
# Лог:     $OUT (TSV; verdict: SURVIVED|STALL|DONE|ERR-<rc>)
# Стоп:    pkill -f synth-stall.sh
OUT=${OUT:-/opt/var/log/reconnect-watchdog/synth-stall.tsv}
CONC=${CONC:-3}        # параллельных потоков на путь (эмуляция мультиплекса Claude Code)
LIMIT=${LIMIT:-32k}    # само-троттлинг → поток долгоживущий и активный
MAXT=${MAXT:-300}      # сек на попытку (окно выживания)
STALLSEC=${STALLSEC:-15}
SOCKS=${SOCKS:-socks5h://127.0.0.1:7890}
CYCLES=${1:-6}
# зарубежные отдачи, доступные с RU-IP и напрямую, и через туннель (проверено 2026-07-16;
# hetzner/scaleway блочат RU-IP → для direct-контроля непригодны).
# env-override: URLS="..." synth-stall.sh; для upload-режима MODE=up URLS="https://speed.cloudflare.com/__up ..."
URLS=${URLS:-"https://speed.cloudflare.com/__down?bytes=100000000 https://proof.ovh.net/files/100Mb.dat https://speed.cloudflare.com/__down?bytes=200000000"}

[ -f "$OUT" ] || printf 'epoch_start\tiso\tpath\turl\trc\tverdict\tbytes\tsecs\n' > "$OUT"

attempt() { # $1=path-label  $2=url  ($PROXYARG задаёт транспорт; MODE=up → upload)
  s=$(date +%s)
  if [ "${MODE:-down}" = up ]; then
    # upload-направление: тело $UPFILE → discard-endpoint; сенсор тот же
    o=$(curl $PROXYARG -sL -o /dev/null --max-time "$MAXT" \
          --limit-rate "$LIMIT" --speed-limit 1 --speed-time "$STALLSEC" \
          -X POST --data-binary "@${UPFILE:-/tmp/synth-up.bin}" \
          -w '%{size_upload}\t%{time_total}' "$2" 2>/dev/null)
  else
    o=$(curl $PROXYARG -sL -o /dev/null --max-time "$MAXT" \
          --limit-rate "$LIMIT" --speed-limit 1 --speed-time "$STALLSEC" \
          -w '%{size_download}\t%{time_total}' "$2" 2>/dev/null)
  fi
  rc=$?
  bytes=${o%%	*}; secs=${o##*	}; secs=${secs%%.*}
  [ -z "$secs" ] && secs=0
  if [ $rc -eq 0 ]; then v=DONE
  elif [ $rc -eq 28 ] && [ "$secs" -ge $((MAXT-3)) ]; then v=SURVIVED
  elif [ $rc -eq 28 ]; then v=STALL
  else v=ERR-$rc; fi
  printf '%s\t%s\t%s-%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$s" "$(date -d @$s '+%F %T' 2>/dev/null || echo -)" "$1" "${MODE:-down}" "$2" "$rc" "$v" "${bytes:-0}" "$secs" >> "$OUT"
}

cycle=0
while [ $cycle -lt "$CYCLES" ]; do
  cycle=$((cycle+1))
  echo "cycle $cycle/$CYCLES $(date '+%T')"
  i=0
  for u in $URLS; do
    i=$((i+1)); [ $i -gt "$CONC" ] && break
    PROXYARG="-x $SOCKS"; attempt tunnel "$u" &
    PROXYARG="";          attempt direct "$u" &
  done
  wait
done
echo "done -> $OUT"
