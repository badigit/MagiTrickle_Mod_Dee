#!/usr/bin/env bash
set -euo pipefail

# Speed test through different proxy paths
# Run from an external device (e.g. WSL) that routes through the router

ROUTER_IP="${ROUTER_IP:-<ROUTER_IP>}"
MT_PORT="${MT_PORT:-8080}"
MT_DNS_PORT="${MT_DNS_PORT:-3553}"
SOCKS_PORT="${SOCKS_PORT:-7890}"
DOWNLOAD_SIZE="${DOWNLOAD_SIZE:-10Mb}"  # OVH file: 1Mb, 10Mb, 100Mb
RUNS="${RUNS:-5}"
T2S_IFACE="${T2S_IFACE:-t2s4}"

DOWNLOAD_URL="http://proof.ovh.net/files/${DOWNLOAD_SIZE}.dat"
TEST_DOMAIN="proof.ovh.net"
MT_API="http://${ROUTER_IP}:${MT_PORT}/api/v1"

TMP_GROUP_IDS=()

cleanup() {
  for gid in "${TMP_GROUP_IDS[@]}"; do
    echo "[*] Removing temporary group ${gid}..."
    curl -s -X DELETE "${MT_API}/groups/?id=${gid}" >/dev/null 2>&1
  done
  if [ ${#TMP_GROUP_IDS[@]} -gt 0 ]; then
    echo "    Cleanup done."
  fi
}
trap cleanup EXIT

create_tmp_group() {
  local iface=$1
  local label=$2
  local response
  response=$(curl -s -X POST "${MT_API}/groups/" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"_speedtest_${label}\",\"interface\":\"${iface}\",\"enable\":true,\"rules\":[{\"name\":\"speedtest\",\"type\":\"namespace\",\"rule\":\"${TEST_DOMAIN}\",\"enable\":true}]}")
  local gid
  gid=$(echo "$response" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  if [ -z "$gid" ]; then
    echo "ERROR: Failed to create group: ${response}" >&2
    return 1
  fi
  TMP_GROUP_IDS+=("$gid")
  echo "$gid"
}

delete_tmp_group() {
  local gid=$1
  curl -s -X DELETE "${MT_API}/groups/?id=${gid}" >/dev/null 2>&1
  TMP_GROUP_IDS=("${TMP_GROUP_IDS[@]/$gid/}")
}

resolve_domain() {
  dig +short "$TEST_DOMAIN" "@${ROUTER_IP}" -p "$MT_DNS_PORT" | grep -E '^[0-9]' | head -1
}

human_speed() {
  local bps=$1
  if (( $(echo "$bps > 1000000" | bc -l) )); then
    echo "$(echo "scale=1; $bps / 1048576" | bc) MB/s ($(echo "scale=0; $bps * 8 / 1000000" | bc) Mbit/s)"
  else
    echo "$(echo "scale=1; $bps / 1024" | bc) KB/s"
  fi
}

run_test() {
  local label=$1; shift
  local sum=0
  local min=999999999 max=0
  for i in $(seq 1 "$RUNS"); do
    local speed
    speed=$(curl -sL "$@" -o /dev/null -w "%{speed_download}" --max-time 30 "$DOWNLOAD_URL")
    sum=$(echo "$sum + $speed" | bc)
    if (( $(echo "$speed > $max" | bc -l) )); then max=$speed; fi
    if (( $(echo "$speed < $min" | bc -l) )); then min=$speed; fi
    echo "    run $i: $(human_speed "$speed")"
  done
  local avg
  avg=$(echo "scale=0; $sum / $RUNS" | bc)
  echo "    ─────────────────────────"
  echo "    AVG: $(human_speed "$avg")  min: $(human_speed "$min")  max: $(human_speed "$max")"
  echo ""
}

echo "=========================================="
echo " MagiTrickle Speed Test (download)"
echo "=========================================="
echo " Router:    ${ROUTER_IP}"
echo " File:      ${DOWNLOAD_SIZE} from OVH"
echo " Runs:      ${RUNS}"
echo "=========================================="
echo ""

# --- 1. DIRECT (no proxy) ---
echo "=== 1. DIRECT (no proxy) ==="
run_test "DIRECT"

# --- 2. TPROXY/redir ---
echo "[*] Setting up TPROXY route for ${TEST_DOMAIN}..."
GID_TPROXY=$(create_tmp_group "TPROXY" "tproxy")
echo "    Group: ${GID_TPROXY}"
RESOLVED_IP=$(resolve_domain)
echo "    Resolved: ${RESOLVED_IP}"
sleep 1

echo "=== 2. TPROXY/redir (REDIRECT → mihomo redir-port) ==="
run_test "TPROXY" --resolve "${TEST_DOMAIN}:80:${RESOLVED_IP}"

echo "[*] Removing TPROXY group..."
delete_tmp_group "$GID_TPROXY"

# --- 3. t2s4 (hev-socks5-tunnel) ---
echo "[*] Setting up ${T2S_IFACE} route for ${TEST_DOMAIN}..."
GID_T2S=$(create_tmp_group "$T2S_IFACE" "t2s")
echo "    Group: ${GID_T2S}"
RESOLVED_IP=$(resolve_domain)
echo "    Resolved: ${RESOLVED_IP}"
sleep 1

echo "=== 3. ${T2S_IFACE} / hev-socks5-tunnel (tun → SOCKS5 → mihomo) ==="
run_test "T2S" --resolve "${TEST_DOMAIN}:80:${RESOLVED_IP}"

echo "[*] Removing ${T2S_IFACE} group..."
delete_tmp_group "$GID_T2S"

# --- 4. SOCKS5 direct ---
echo "=== 4. SOCKS5 direct (→ mihomo:${SOCKS_PORT}, no tun) ==="
run_test "SOCKS5" --proxy "socks5h://${ROUTER_IP}:${SOCKS_PORT}"

echo "=========================================="
echo " Done!"
echo "=========================================="
