#!/bin/sh
# connwatch-snapshot.sh — разовый снимок ВСЕХ текущих потоков клиента из conntrack -L
# (в отличие от connwatch.sh, который ловит только NEW). Для каждого публичного dst:
#   - фактический путь по reply-кортежу: PROXIED (reply sport=5001 / src=роутер) vs DIRECT;
#   - вердикт покрытия из MT /lookup (covered/rule-only/uncovered) + группа + домен.
# Запуск НА РОУТЕРЕ:  connwatch-snapshot.sh -s <CLIENT_IP>
set -u
CLIENT=""
API="http://127.0.0.1:8080/api/v1"
REDIR_PORT="5001"   # порт mihomo redir (reply sport => поток проксируется)
while [ $# -gt 0 ]; do
  case "$1" in
    -s) CLIENT="$2"; shift 2 ;;
    -p) REDIR_PORT="$2"; shift 2 ;;
    -a) API="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -z "$CLIENT" ] && { echo "need -s CLIENT_IP" >&2; exit 2; }

is_public() {
  case "$1" in
    10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|\
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|\
    0.0.0.0|224.*|239.*|255.*|*:*) return 1 ;;
    *) return 0 ;;
  esac
}

# conntrack -L -s CLIENT -> awk выдаёт: proto dst dport path
#   orig dst = реальный сервер (первый dst=)
#   Классификация пути по reply-кортежу (второй набор src=/dst=):
#     reply sport=REDIR_PORT           -> PROXY-redir  (REDIRECT/DNAT, TCP)
#     reply dst=CLIENT (нет SNAT)      -> PROXY-tproxy (TPROXY не NAT-ит: зеркальный
#                                         reply у ПУБЛИЧНОГО dst = локальный перехват)
#     reply dst=<WAN IP> (SNAT)        -> DIRECT       (реально ушёл в WAN)
TMP=/tmp/connwatch_snap.$$
conntrack -L -s "$CLIENT" 2>/dev/null | awk -v rp="$REDIR_PORT" -v cl="$CLIENT" '
  {
    proto=$1; dst=""; dport=""; sawdst=0; rsport=""; rdst=""
    for (i=1;i<=NF;i++) {
      if ($i ~ /^dst=/)   { split($i,a,"="); if (!sawdst) { dst=a[2]; sawdst=1 } else if (rdst=="") rdst=a[2] }
      else if (dport=="" && $i ~ /^dport=/) { split($i,a,"="); dport=a[2] }
      else if (sawdst && rsport=="" && $i ~ /^sport=/) { split($i,a,"="); rsport=a[2] }
    }
    if (dst!="") {
      path="DIRECT"
      if (rsport==rp) path="PROXY-redir"
      else if (rdst==cl) path="PROXY-tproxy"
      key=proto"|"dst"|"dport
      if (!(seen[key]++)) printf "%s\t%s\t%s\t%s\n", proto, dst, dport, path
    }
  }' > "$TMP"

printf 'proto\tdst_ip\tdport\tpath\tverdict\tgroups\n'
while IFS='	' read -r proto dst dport path; do
  is_public "$dst" || continue
  resp=$(curl -s --max-time 4 -X POST "$API/lookup" -H 'Content-Type: application/json' \
    -d "{\"queries\":[\"$dst\"],\"check_ipset\":true}" 2>/dev/null)
  groups=$(printf '%s' "$resp" | jq -r '[.results[0].rule_hits[].group_name]|unique|join(",")' 2>/dev/null)
  nh=$(printf '%s' "$resp" | jq -r '.results[0].rule_hits|length' 2>/dev/null)
  ips=$(printf '%s' "$resp" | jq -r '((.results[0].ipset_hits // [])|length)>0' 2>/dev/null)
  if [ "$ips" = "true" ]; then verdict=covered
  elif [ "${nh:-0}" -gt 0 ] 2>/dev/null; then verdict=rule-only
  else verdict=uncovered; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$proto" "$dst" "$dport" "$path" "$verdict" "${groups:--}"
done < "$TMP"
rm -f "$TMP"
