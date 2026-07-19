#!/usr/bin/env bash
# router-snapshot: одним ssh-pipe собирает состояние <ROUTER_IP>.
# Требует /opt/bin/tar (GNU) на роутере — `opkg install tar`.
# Использование: bash snapshot.sh [label]
set -euo pipefail

LABEL="${1:-}"
TS=$(date +%Y%m%d-%H%M%S)
NAME="${LABEL:+${LABEL}-}${TS}"
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
OUT="$ROOT/.tmp/snapshots/$NAME"
mkdir -p "$OUT"

ssh -p 222 root@<ROUTER_IP> "TS=$TS LABEL='$LABEL' sh -s" <<'REMOTE_SH' | tar -xzf - -C "$OUT"
set -e
D="/tmp/snap-$TS"
mkdir -p "$D"
cat /proc/sys/net/netfilter/nf_conntrack_count > "$D/conntrack-count" 2>/dev/null || true
cat /proc/sys/net/netfilter/nf_conntrack_max  > "$D/conntrack-max"   2>/dev/null || true
conntrack -L                       > "$D/conntrack.txt"          2>/dev/null || true
netstat -tlnp                      > "$D/listeners-tcp.txt"      2>/dev/null || true
netstat -ulnp                      > "$D/listeners-udp.txt"      2>/dev/null || true
ss -tnp                            > "$D/ss-tcp.txt"             2>/dev/null || true
curl -sf --max-time 5 http://127.0.0.1:9090/connections > "$D/mihomo-connections.json" 2>/dev/null || echo '{"connections":[]}' > "$D/mihomo-connections.json"
curl -sf --max-time 3 http://127.0.0.1:9090/version     > "$D/mihomo-version.json"     2>/dev/null || true
curl -sf --max-time 3 http://127.0.0.1:8080/api/v1/system/version > "$D/magitrickle-version.json" 2>/dev/null || true
[ -r /opt/etc/mihomo/config.yaml ]              && cp /opt/etc/mihomo/config.yaml              "$D/mihomo-config.yaml"
[ -r /opt/var/lib/magitrickle/config.yaml ]     && cp /opt/var/lib/magitrickle/config.yaml     "$D/magitrickle-config.yaml"
ps w                               > "$D/ps.txt"                  2>/dev/null || true
{
  echo "label=$LABEL"
  echo "timestamp=$TS"
  echo "remote_uptime=$(uptime)"
} > "$D/meta.txt"
/opt/bin/tar -czf - -C "$D" .
rm -rf "$D"
REMOTE_SH

echo "snapshot: $OUT"
echo "analyze:  python3 .claude/skills/router-snapshot/scripts/analyze.py \"$OUT\""
