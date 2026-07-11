#!/bin/sh
# connwatch-report.sh — сводка по последнему сеансу connwatch для клиента.
# Запускается НА РОУТЕРЕ. Агрегирует journal.tsv + забирает домены из MT DNS-capture.
#   connwatch-report.sh -s <CLIENT_IP>
set -u
CLIENT=""
API="http://127.0.0.1:8080/api/v1"
while [ $# -gt 0 ]; do
  case "$1" in
    -s) CLIENT="$2"; shift 2 ;;
    -a) API="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -z "$CLIENT" ] && { echo "need -s CLIENT_IP" >&2; exit 2; }

DIR=$(ls -d /opt/var/log/connwatch/$CLIENT-* 2>/dev/null | sort | tail -1)
[ -z "$DIR" ] && { echo "нет сеансов для $CLIENT"; exit 1; }
J="$DIR/journal.tsv"
echo "=== connwatch report: $CLIENT ==="
echo "journal: $J"
echo

TOTAL=$(($(wc -l < "$J") - 1))
echo "потоков в журнале: $TOTAL"
echo
echo "--- по вердикту ---"
tail -n +2 "$J" | awk -F'\t' '{c[$5]++} END{for(v in c) printf "  %-10s %d\n", v, c[v]}'
echo
echo "--- COVERED (поехало через группу) ---"
tail -n +2 "$J" | awk -F'\t' '$5=="covered"{print "  "$3":"$4" -> "$6}' | sort -u
echo
echo "--- RULE-ONLY (правило есть, но IP не в ipset — вероятно мимо DNS MT) ---"
tail -n +2 "$J" | awk -F'\t' '$5=="rule-only"{print "  "$3":"$4" -> "$6}' | sort -u
echo
echo "--- UNCOVERED (нет ни правила, ни ipset — direct, мимо групп) ---"
tail -n +2 "$J" | awk -F'\t' '$5=="uncovered"{print "  "$3":"$4}' | sort -u
echo
echo "--- DNS-запросы клиента (домен: count), из MT DNS-capture ---"
curl -s --max-time 5 "$API/system/dns-capture/status?domains=true" \
  | jq -r '.domains[]? | "  \(.count)\t\(.domain)"' 2>/dev/null | sort -rn | head -60
