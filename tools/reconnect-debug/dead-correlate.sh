#!/bin/sh
# dead-correlate.sh — берёт ПОСЛЕДНЕЕ dead-proxied событие и сверяет с SYN-pcap:
# вышел ли SYN-ACK на мёртвый SYN? Это разводит «SYN дошёл до сокета, но handshake не
# завершился» vs «SYN дропнут после DNAT до сокета» (ядро SYN-ACK'ает автономно при живом
# LISTEN, ListenOverflows=0 → отсутствие [S.] = SYN не дошёл/дропнут, НЕ mihomo-slow-accept).
#
# Матчинг по dst И orig_sport = точный мёртвый поток. Аргумент 1 (опц.) = N-я с конца строка.
D=/opt/var/log/reconnect-watchdog
N="${1:-1}"
L=$(tail -n "$N" "$D/dead-proxied.tsv" | head -1)
EP=$(echo "$L" | cut -f1); DST=$(echo "$L" | cut -f3); SP=$(echo "$L" | cut -f4); FWD=$(echo "$L" | cut -f5)
[ -z "$EP" ] && { echo "нет событий"; exit 0; }

echo "=== DEAD EVENT (#$N с конца) ==="
echo "epoch=$EP  time=$(date -d @"$EP" '+%F %T' 2>/dev/null)  dst=$DST  sport=$SP  fwd_pkts=$FWD"

# собрать SYN-строки ±8с по exact-flow (dst + .sport) из часовых syn-логов вокруг события
LINES=$(for H in $(date -d @$((EP-8)) +%Y%m%d-%H) $(date -d @$((EP+8)) +%Y%m%d-%H); do
  [ -f "$D/syn-$H.log" ] && awk -v e="$EP" -v d="$DST" -v sp=".$SP " '{t=$1+0} t>=e-8 && t<=e+8 && index($0,d) && index($0,sp)' "$D/syn-$H.log"
done | sort -u)

echo "=== SYN-pcap для этого потока (dst=$DST sport=$SP, ±8с) ==="
if [ -z "$LINES" ]; then echo "(нет строк — событие раньше старта pcap, либо pcap не покрыл)"; fi
echo "$LINES"

nS=$(echo "$LINES"  | grep -c 'Flags \[S\]')
nSA=$(echo "$LINES" | grep -c 'Flags \[S\.\]')
nR=$(echo "$LINES"  | grep -c 'Flags \[R')
echo "=== ВЕРДИКТ ==="
echo "SYN(out)=$nS  SYN-ACK(back)=$nSA  RST=$nR"
if [ "$nS" -gt 0 ] && [ "$nSA" -eq 0 ] && [ "$nR" -eq 0 ]; then
  echo ">>> SYN(ы) вышли, НИ SYN-ACK НИ RST не вернулись → SYN-ACK не сгенерирован."
  echo ">>> При живом LISTEN и ListenOverflows=0 это = SYN дропнут ПОСЛЕ DNAT до сокета (не медленный accept)."
elif [ "$nSA" -gt 0 ]; then
  echo ">>> SYN-ACK ЕСТЬ → handshake на роутере завершался; смерть позже (mihomo relay/upstream)."
elif [ "$nR" -gt 0 ]; then
  echo ">>> RST → активный отказ (refuse), не тихий дроп."
else
  echo ">>> нет пакетных данных для вердикта."
fi
