#!/usr/bin/env bash
# Интеграционный тест interface-режима MagiTrickle на network namespaces.
#
# Гоняет РЕАЛЬНЫЙ magitrickled в изолированной сетевой песочнице и проверяет
# поведение маршрутизации, которое unit-тесты (состав iptables-правил) поймать
# не могут:
#
#   T1  forward+reply path: клиент получает ответ через групповой интерфейс
#       (ловит reply-path баг преамбулы: безусловный restore-mark уводил
#       ответы обратно в туннель вместо LAN-клиента)
#   T2  долгая сессия переживает вычистку IP из ipset (имитация DNS TTL):
#       CONNMARK restore-mark держит established-соединение на маршруте группы
#   T3  негативный контроль: НОВОЕ соединение после вычистки идёт по main
#       (в "wan", где адрес недостижим) — подтверждает, что T2 прошёл именно
#       благодаря connmark, а не остаточному состоянию ipset
#   T4  арбитраж first-wins: при одном IP в ipset двух interface-групп
#       выигрывает ПЕРВАЯ группа по порядку конфига (инвариант mt-7rd)
#
# Топология (все netns свои, хост не затрагивается; iptables/ipset/routes
# демона живут внутри netns "router" и умирают вместе с ним):
#
#   [client] --veth-- [router: magitrickled] --veth-- [vpn: echo/http server]
#      10.90.1.2        .1.1   default→wan    .3.1        203.0.113.10 (lo)
#                        \-------veth-------- [wan: unreachable 203.0.113.10]
#                         .2.1               .2.2
#
# Требования: root, Linux >= 5.x (WSL2 ok), iproute2, iptables, ipset, python3,
# curl, go (для сборки, либо готовый бинарь через MT_BIN).
#
# Запуск из корня репо:  sudo tests/integration/interface_mode_netns.sh
# Готовый бинарь:        MT_BIN=/path/magitrickled sudo -E tests/integration/...

set -u

# --- параметры ---
R=mtitr   # router ns
C=mtitc   # client ns
V=mtitv   # vpn ns
W=mtitw   # wan ns
TEST_IP=203.0.113.10
HTTP_PORT=8080
ECHO_PORT=9090
DAEMON_WAIT=20

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
TMP=$(mktemp -d /tmp/mt-itest.XXXXXX)
LOG="$TMP/daemon.log"
FAILS=0
DAEMON_PID=""

say()  { echo "[itest] $*"; }
pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILS=$((FAILS + 1)); }

SRV_PID=""
cleanup() {
    set +e
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null
        for _ in $(seq 1 20); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.2; done
        kill -9 "$DAEMON_PID" 2>/dev/null
    fi
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    for ns in "$C" "$V" "$W" "$R"; do ip netns del "$ns" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "нужен root (sudo)"; exit 1; }

# --- бинарь ---
if [ -n "${MT_BIN:-}" ]; then
    BIN=$MT_BIN
else
    say "сборка magitrickled..."
    BIN=$TMP/magitrickled
    (cd "$REPO_ROOT/src/backend" && go build -o "$BIN" ./cmd/magitrickled) || {
        echo "сборка провалилась"; exit 1; }
fi
[ -x "$BIN" ] || { echo "бинарь $BIN не найден/не исполняем"; exit 1; }

# --- топология ---
say "создаю netns-топологию..."
for ns in "$R" "$C" "$V" "$W"; do ip netns add "$ns"; done

link() { # link <ifA> <nsA> <ipA> <ifB> <nsB> <ipB>
    ip link add "$1" netns "$2" type veth peer name "$4" netns "$5"
    ip -n "$2" addr add "$3" dev "$1"; ip -n "$5" addr add "$6" dev "$4"
    ip -n "$2" link set "$1" up;       ip -n "$5" link set "$4" up
}
link c1 "$R" 10.90.1.1/24  c0 "$C" 10.90.1.2/24
link w1 "$R" 10.90.2.1/24  w0 "$W" 10.90.2.2/24
link v1 "$R" 10.90.3.1/24  v0 "$V" 10.90.3.2/24
for ns in "$R" "$C" "$V" "$W"; do ip -n "$ns" link set lo up; done

ip netns exec "$R" sysctl -qw net.ipv4.ip_forward=1
ip -n "$R" route add default via 10.90.2.2            # main: всё в "wan"
ip -n "$C" route add default via 10.90.1.1
ip -n "$V" route add default via 10.90.3.1
ip -n "$V" addr add "$TEST_IP/32" dev lo              # тестовый IP живёт в "vpn"
ip -n "$W" route add unreachable "$TEST_IP/32"        # в "wan" он недостижим
# хинт для getGwFromIface: у v1 должен существовать маршрут со шлюзом,
# иначе default-маршрут таблицы группы останется без next-hop (veth = broadcast)
ip -n "$R" route add 198.51.100.0/24 via 10.90.3.2 dev v1

# --- серверы в "vpn" ---
ip netns exec "$V" python3 -c "
import http.server, threading, socketserver, socket

class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            data = self.rfile.readline()
            if not data: break
            self.wfile.write(data); self.wfile.flush()

socketserver.TCPServer.allow_reuse_address = True
e = socketserver.ThreadingTCPServer(('$TEST_IP', $ECHO_PORT), Echo)
threading.Thread(target=e.serve_forever, daemon=True).start()
h = http.server.ThreadingHTTPServer(('$TEST_IP', $HTTP_PORT), http.server.SimpleHTTPRequestHandler)
h.serve_forever()
" >"$TMP/server.log" 2>&1 &
SRV_PID=$!

# Активное ожидание готовности ОБОИХ портов изнутри "vpn" (минуя MagiTrickle):
# sleep-константа здесь была источником ложных RST-провалов T1.
say "жду готовности серверов в vpn-ns..."
srv_ready=0
for _ in $(seq 1 50); do
    if ip netns exec "$V" curl -fsS -m 1 -o /dev/null "http://$TEST_IP:$HTTP_PORT/" 2>/dev/null \
       && ip netns exec "$V" bash -c "exec 3<>/dev/tcp/$TEST_IP/$ECHO_PORT" 2>/dev/null; then
        srv_ready=1; break
    fi
    kill -0 "$SRV_PID" 2>/dev/null || break
    sleep 0.2
done
if [ "$srv_ready" != 1 ]; then
    echo "тест-инфра: серверы в vpn-ns не поднялись"; cat "$TMP/server.log"
    ip netns exec "$V" ss -tln
    exit 1
fi

# --- конфиг и запуск демона ---
write_config() { # write_config <groups-yaml>
    mkdir -p "$TMP/state"
    cat > "$TMP/state/config.yaml" <<EOF
configVersion: 0.1.3
app:
  enabled: true
  httpWeb:
    enabled: false
  dnsProxy:
    host: {address: 127.0.0.1, port: 5300}
    upstream: {address: 127.0.0.1, port: 5301}
    disableRemap53: true
  netfilter:
    disableIPv6: true
  link: []
  logLevel: debug
groups:
$1
EOF
}

start_daemon() {
    : > "$LOG"
    # ip netns exec даёт приватный mount ns — bind /var/lib/magitrickle
    # виден только демону, хостовая ФС не затрагивается
    ip netns exec "$R" bash -c "
        mkdir -p /var/lib/magitrickle /var/run
        mount --bind '$TMP/state' /var/lib/magitrickle
        exec '$BIN'" >"$LOG" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 $((DAEMON_WAIT * 5))); do
        grep -q "routing brought up" "$LOG" && return 0
        kill -0 "$DAEMON_PID" 2>/dev/null || break
        sleep 0.2
    done
    echo "=== daemon log ==="; tail -30 "$LOG"
    return 1
}

stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill "$DAEMON_PID" 2>/dev/null
    for _ in $(seq 1 25); do kill -0 "$DAEMON_PID" 2>/dev/null || { DAEMON_PID=""; return 0; }; sleep 0.2; done
    kill -9 "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
}

GROUP_V='  - id: "01020304"
    name: iface-vpn
    color: "#ff0000"
    interface: v1
    enable: true
    rules:
      - {id: "0a0b0c0d", name: test-ip, type: subnet, rule: '"$TEST_IP"'/32, enable: true}'
GROUP_W='  - id: "05060708"
    name: iface-wan
    color: "#00ff00"
    interface: w1
    enable: true
    rules:
      - {id: "0e0f1011", name: test-ip, type: subnet, rule: '"$TEST_IP"'/32, enable: true}'

write_config "$GROUP_V"
say "старт magitrickled (группа iface-vpn -> v1)..."
start_daemon || { fail "демон не поднялся"; exit 1; }

ipset_name=$(ip netns exec "$R" ipset list -n | grep '^mt_' | head -1)
say "ipset группы: $ipset_name"

dump_router_state() {
    echo "--- mangle ---";  ip netns exec "$R" iptables-save -t mangle
    echo "--- nat ---";     ip netns exec "$R" iptables-save -t nat
    echo "--- ip rule ---"; ip netns exec "$R" ip rule
    for t in $(ip netns exec "$R" ip rule | grep -o "lookup [0-9]*" | awk "{print \$2}" | sort -u); do
        echo "--- table $t ---"; ip netns exec "$R" ip route show table "$t"
    done
    echo "--- ipset ---";   ip netns exec "$R" ipset list
    echo "--- vpn-ns listeners ---"; ip netns exec "$V" ss -tln
}

# --- T1: forward + reply path ---
if ip netns exec "$C" curl -fsS -m 5 -o /dev/null "http://$TEST_IP:$HTTP_PORT/"; then
    pass "T1 forward+reply: клиент получил HTTP-ответ через групповой интерфейс"
else
    say "T1: первый запрос упал — диагностика и повтор через 1с..."
    dump_router_state
    sleep 1
    if ip netns exec "$C" curl -fsS -m 5 -o /dev/null "http://$TEST_IP:$HTTP_PORT/"; then
        fail "T1 forward+reply: прошёл только ПОВТОРНЫЙ запрос — гонка готовности маршрута после старта"
    else
        fail "T1 forward+reply: ответ не пришёл (reply-path сломан или маршрут не встал)"
    fi
fi

# --- T2: established переживает вычистку ipset (имитация DNS TTL) ---
M1="$TMP/phase1done"; M2="$TMP/continue"
rm -f "$M1" "$M2"
ip netns exec "$C" python3 -c "
import socket, time, os, sys
s = socket.create_connection(('$TEST_IP', $ECHO_PORT), timeout=5)
s.settimeout(5)
s.sendall(b'ping1\n')
assert s.recv(64) == b'ping1\n'
open('$M1', 'w').close()                    # фаза 1 ок — сигнал скрипту
for _ in range(100):                        # ждём отмашки после flush
    if os.path.exists('$M2'): break
    time.sleep(0.2)
else:
    sys.exit(3)
s.sendall(b'ping2\n')                       # обмен по ТОМУ ЖЕ соединению
assert s.recv(64) == b'ping2\n'
s.close()
" &
T2_PID=$!
for _ in $(seq 1 50); do [ -f "$M1" ] && break; sleep 0.2; done
if [ ! -f "$M1" ]; then
    fail "T2: фаза 1 (до вычистки) не прошла"
    kill $T2_PID 2>/dev/null
else
    ip netns exec "$R" ipset flush "$ipset_name"
    say "ipset '$ipset_name' вычищен (имитация истечения DNS TTL)"
    touch "$M2"
    if wait $T2_PID; then
        pass "T2 долгая сессия: обмен после вычистки ipset прошёл (restore-mark держит)"
    else
        fail "T2 долгая сессия: соединение умерло после вычистки ipset"
    fi
fi

# --- T3: новое соединение после вычистки идёт по main (в wan -> недостижимо) ---
if ip netns exec "$C" curl -fsS -m 3 -o /dev/null "http://$TEST_IP:$HTTP_PORT/" 2>/dev/null; then
    fail "T3 негатив: новое соединение прошло, хотя ipset пуст (маршрут group залип?)"
else
    pass "T3 негатив: новое соединение по main недостижимо — T2 держался именно на connmark"
fi

# --- T4: арбитраж first-wins между двумя interface-группами ---
say "рестарт с двумя группами: iface-vpn ПЕРВАЯ, iface-wan вторая..."
stop_daemon
write_config "$GROUP_V
$GROUP_W"
start_daemon || { fail "демон не поднялся (2 группы)"; exit 1; }
if ip netns exec "$C" curl -fsS -m 5 -o /dev/null "http://$TEST_IP:$HTTP_PORT/"; then
    pass "T4a арбитраж: первая группа (vpn) выиграла overlap — ответ получен"
else
    fail "T4a арбитраж: первая группа не выиграла (трафик ушёл не в vpn)"
fi

say "рестарт с обратным порядком: iface-wan ПЕРВАЯ..."
stop_daemon
write_config "$GROUP_W
$GROUP_V"
start_daemon || { fail "демон не поднялся (обратный порядок)"; exit 1; }
if ip netns exec "$C" curl -fsS -m 3 -o /dev/null "http://$TEST_IP:$HTTP_PORT/" 2>/dev/null; then
    fail "T4b арбитраж: ответ пришёл, хотя первой стоит wan-группа (unreachable)"
else
    pass "T4b арбитраж: первая группа (wan) выиграла overlap — адрес недостижим, как и должно"
fi

echo
if [ "$FAILS" -eq 0 ]; then
    say "ИТОГ: все проверки прошли ✔"
else
    say "ИТОГ: провалов: $FAILS ✖"
    echo "=== хвост лога демона ==="; tail -40 "$LOG"
fi
exit "$FAILS"
