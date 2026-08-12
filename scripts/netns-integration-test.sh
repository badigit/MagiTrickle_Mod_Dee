#!/usr/bin/env bash
# Интеграционный прогон rule-gen против НАСТОЯЩЕГО netfilter в изолированных
# network namespace'ах. Роутер не задействован: всё живёт внутри WSL/Linux-хоста
# и удаляется по завершении.
#
# Схема:
#   [client ns] 10.88.0.1 --veth-- 10.88.0.2 [router ns] --> 10.77.0.5 (никуда)
#
# Тест запускается ВНУТРИ router-ns, поэтому и вызовы iptables, и netlink-сокеты
# ipset'а из кода попадают в этот namespace автоматически - подменять в коде
# ничего не нужно. Трафик генерируется из client-ns, решение netfilter читается
# по счётчикам правил.
set -euo pipefail

ROUTER_NS=mt-itest-router
CLIENT_NS=mt-itest-client
CLIENT_IP=10.88.0.1
ROUTER_IP=10.88.0.2
TARGET_IP=10.77.0.5

cleanup() {
  ip netns del "$ROUTER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "нужен root (netns/iptables/ipset): sudo $0" >&2
  exit 2
fi

for b in ip iptables ipset go; do
  command -v "$b" >/dev/null || { echo "нет бинаря: $b" >&2; exit 2; }
done

for m in ip_set xt_set xt_TPROXY xt_connmark; do
  modprobe "$m" 2>/dev/null || true
done

cleanup
ip netns add "$ROUTER_NS"
ip netns add "$CLIENT_NS"

ip link add vc type veth peer name vr
ip link set vc netns "$CLIENT_NS"
ip link set vr netns "$ROUTER_NS"

ip netns exec "$CLIENT_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP/24" dev vc
ip netns exec "$CLIENT_NS" ip link set vc up
ip netns exec "$CLIENT_NS" ip route add default via "$ROUTER_IP"

ip netns exec "$ROUTER_NS" ip link set lo up
ip netns exec "$ROUTER_NS" ip addr add "$ROUTER_IP/24" dev vr
ip netns exec "$ROUTER_NS" ip link set vr up
ip netns exec "$ROUTER_NS" sysctl -qw net.ipv4.ip_forward=1

cd "$(dirname "${BASH_SOURCE[0]}")/../src/backend"

MT_ITEST_CLIENT_NS="$CLIENT_NS" MT_ITEST_TARGET_IP="$TARGET_IP"   ip netns exec "$ROUTER_NS" go test -tags "testing netns" -count=1 -v ./utils/netfilterTools/ -run NetnsDirectPriority "$@"
