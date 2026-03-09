"""
Integration test for MagiTrickle TCP REDIRECT + UDP TPROXY routing.

Verifies that traffic from a LAN client is correctly intercepted and proxied
by MagiTrickle + mihomo on the router. Tests three tunnel paths:

  [2] MagiTrickle — traffic bound to LAN interface, routed through router
      - TCP via iptables nat/REDIRECT (test: TLS handshake to resolved IPs)
      - QUIC/HTTP3 via iptables mangle/TPROXY (test: curl --http3-only)
      - NTP/UDP via iptables mangle/TPROXY (test: raw NTP packet)

  [3] SOCKS5 — direct proxy connection to mihomo SOCKS port
      - TCP, NTP via UDP ASSOCIATE
      - QUIC over SOCKS5 — expected to fail (curl limitation)

  [4] DIRECT — system default route, baseline

Also checks: DNS resolution via MagiTrickle, exit IP via cloudflare trace,
mihomo routing table, and connection health (alive vs dead/zombie).

Usage:
    python3 scripts/test-redir-tproxy.py

Environment:
    - WSL or Windows on the same LAN as the router
    - Router at ROUTER_IP with MagiTrickle + mihomo (redir-port)
    - On WSL: script binds curl to eth1 to use LAN interface
    - curl with nghttp3 recommended for QUIC tests (auto-detected)
"""

import socket
import ssl
import struct
import subprocess
import time
import json
import urllib.request
import sys

ROUTER_IP = "<ROUTER_IP>"
MAGITRICKLE_DNS_PORT = 3553
SOCKS5_PORT = 7890
MIHOMO_API = f"http://{ROUTER_IP}:9090"
MIHOMO_AUTH = "Bearer 1"
LOCAL_IP = "<ROUTER_IP>"
LOCAL_CURL_IFACE = "eth1" if sys.platform != "win32" else LOCAL_IP

TCP_DOMAINS = ["google.com", "discord.com", "api.anthropic.com"]
QUIC_DOMAINS = ["www.google.com", "discord.com", "www.cloudflare.com"]
NTP_SERVERS = ["time.google.com", "pool.ntp.org"]
CF_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
CURL_TIMEOUT = 5


# ======== DNS ========

def resolve_via_magitrickle(domain: str) -> str | None:
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((LOCAL_IP, 0))
        sock.settimeout(3)
        sock.sendto(query, (ROUTER_IP, MAGITRICKLE_DNS_PORT))
        data, _ = sock.recvfrom(512)
    except socket.timeout:
        return None
    finally:
        sock.close()
    pos = 12
    while pos < len(data) and data[pos] != 0:
        pos += data[pos] + 1
    pos += 5
    if len(data) <= pos + 12:
        return None
    if data[pos] & 0xC0 == 0xC0:
        pos += 2
    else:
        while pos < len(data) and data[pos] != 0:
            pos += data[pos] + 1
        pos += 1
    rtype = struct.unpack("!H", data[pos:pos+2])[0]
    pos += 8
    rdlen = struct.unpack("!H", data[pos:pos+2])[0]
    pos += 2
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(data[pos:pos+4])
    return None


# ======== curl helpers ========

def detect_curl() -> tuple[list[str], bool]:
    for cmd in [["curl"], ["curl.exe"]]:
        try:
            r = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return cmd, ("nghttp3" in r.stdout or "http3" in r.stdout.lower())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return ["curl"], False


def curl_test(url, extra_args=None, timeout=CURL_TIMEOUT):
    curl_cmd, _ = detect_curl()
    args = curl_cmd + [
        "-s", "--connect-timeout", str(timeout), "--max-time", str(timeout),
        "-o", "/dev/null",
        "-w", '{"http_code":%{http_code},"time":"%{time_total}","size":%{size_download}}',
    ]
    if extra_args:
        args.extend(extra_args)
    args.append(url)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 5)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip())
        return {"http_code": 0, "error": r.stderr.strip()[:120] or f"exit={r.returncode}"}
    except Exception as e:
        return {"http_code": 0, "error": str(e)[:120]}


def curl_trace(url, extra_args=None, timeout=CURL_TIMEOUT):
    curl_cmd, _ = detect_curl()
    args = curl_cmd + ["-s", "--connect-timeout", str(timeout), "--max-time", str(timeout)]
    if extra_args:
        args.extend(extra_args)
    args.append(url)
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 5)
        return r.stdout if r.returncode == 0 else f"error: {r.stderr.strip()[:120]}"
    except Exception as e:
        return f"error: {e}"


# ======== test functions ========

def test_tcp_socket(domain, ip):
    """TCP via Python socket, bound to LOCAL_IP (goes through router -> MT REDIRECT)."""
    result = {"domain": domain, "proto": "TCP", "status": "FAIL", "detail": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((LOCAL_IP, 0))
        sock.settimeout(CURL_TIMEOUT)
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            ssock.send(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
            resp = ssock.recv(1024).decode(errors="replace")
            result["status"] = "OK"
            result["detail"] = resp.split("\r\n")[0] if resp else ""
    except Exception as e:
        result["detail"] = str(e)[:100]
    finally:
        sock.close()
    return result


def test_quic_curl(domain, ip=None, extra_curl_args=None):
    """QUIC/HTTP3 via curl --http3-only."""
    result = {"domain": domain, "proto": "QUIC", "status": "FAIL", "detail": ""}
    args = ["--http3-only"]
    if extra_curl_args:
        args.extend(extra_curl_args)
    if ip:
        args.extend(["--resolve", f"{domain}:443:{ip}"])
    r = curl_test(f"https://{domain}/", extra_args=args, timeout=CURL_TIMEOUT)
    if r.get("http_code", 0) > 0:
        result["status"] = "OK"
        result["detail"] = f"HTTP/3 {r['http_code']} {r.get('time','')}s {r.get('size',0)}B"
    else:
        result["detail"] = r.get("error", "?")[:100]
    return result


def test_ntp_socket(server, ip, bind_ip=None):
    """UDP NTP via raw socket."""
    result = {"domain": server, "proto": "NTP", "status": "FAIL", "detail": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if bind_ip:
            sock.bind((bind_ip, 0))
        sock.settimeout(CURL_TIMEOUT)
        sock.sendto(b"\xe3" + b"\x00" * 47, (ip, 123))
        data, _ = sock.recvfrom(256)
        if len(data) >= 48:
            result["status"] = "OK"
            result["detail"] = f"got {len(data)}B"
        else:
            result["detail"] = f"short: {len(data)}B"
    except socket.timeout:
        result["detail"] = "timeout"
    except Exception as e:
        result["detail"] = str(e)[:100]
    finally:
        sock.close()
    return result


# ======== SOCKS5 ========

def socks5_connect(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CURL_TIMEOUT)
    sock.connect((ROUTER_IP, SOCKS5_PORT))
    sock.send(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise ConnectionError("SOCKS5 auth failed")
    d = host.encode()
    sock.send(b"\x05\x01\x00\x03" + bytes([len(d)]) + d + struct.pack("!H", port))
    resp = sock.recv(10)
    if len(resp) < 2 or resp[1] != 0:
        raise ConnectionError("SOCKS5 connect failed")
    return sock


def socks5_udp_associate():
    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.settimeout(CURL_TIMEOUT)
    ctrl.connect((ROUTER_IP, SOCKS5_PORT))
    ctrl.send(b"\x05\x01\x00")
    if ctrl.recv(2) != b"\x05\x00":
        raise ConnectionError("SOCKS5 auth failed")
    ctrl.send(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = ctrl.recv(32)
    if len(resp) < 10 or resp[1] != 0:
        raise ConnectionError("SOCKS5 UDP ASSOCIATE failed")
    relay_ip = socket.inet_ntoa(resp[4:8]) if resp[3] == 0x01 else ROUTER_IP
    relay_port = struct.unpack("!H", resp[8:10])[0]
    if relay_ip == "0.0.0.0":
        relay_ip = ROUTER_IP
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(CURL_TIMEOUT)
    return ctrl, udp, relay_ip, relay_port


def socks5_udp_send(udp_sock, rh, rp, dest_host, dest_port, payload):
    d = dest_host.encode()
    header = b"\x00\x00\x00\x03" + bytes([len(d)]) + d + struct.pack("!H", dest_port)
    udp_sock.sendto(header + payload, (rh, rp))
    data, _ = udp_sock.recvfrom(4096)
    if len(data) < 10:
        return b""
    atyp = data[3]
    start = {0x01: 10, 0x04: 22}.get(atyp, 10)
    if atyp == 0x03:
        start = 5 + data[4] + 2
    return data[start:]


def test_socks5_tcp(domain):
    result = {"domain": domain, "proto": "TCP", "status": "FAIL", "detail": ""}
    try:
        sock = socks5_connect(domain, 443)
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            ssock.send(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
            resp = ssock.recv(1024).decode(errors="replace")
            result["status"] = "OK"
            result["detail"] = resp.split("\r\n")[0] if resp else ""
    except Exception as e:
        result["detail"] = str(e)[:100]
    return result


def test_socks5_ntp(server):
    result = {"domain": server, "proto": "NTP", "status": "FAIL", "detail": ""}
    ctrl = udp = None
    try:
        ctrl, udp, rh, rp = socks5_udp_associate()
        resp = socks5_udp_send(udp, rh, rp, server, 123, b"\xe3" + b"\x00" * 47)
        if len(resp) >= 48:
            result["status"] = "OK"
            result["detail"] = f"got {len(resp)}B"
        else:
            result["detail"] = f"short: {len(resp)}B"
    except socket.timeout:
        result["detail"] = "timeout"
    except Exception as e:
        result["detail"] = str(e)[:100]
    finally:
        if udp: udp.close()
        if ctrl: ctrl.close()
    return result


def test_socks5_quic(domain):
    """QUIC over SOCKS5 -- curl does NOT support this, expected to fail."""
    result = {"domain": domain, "proto": "QUIC *", "status": "FAIL", "detail": ""}
    r = curl_test(f"https://{domain}/", extra_args=[
        "--http3-only", "--proxy", f"socks5h://{ROUTER_IP}:{SOCKS5_PORT}",
    ], timeout=3)
    if r.get("http_code", 0) > 0:
        result["status"] = "OK"
        result["detail"] = f"HTTP/3 {r['http_code']}"
    else:
        err = r.get("error", "?")
        if "not supported over a SOCKS" in err:
            result["detail"] = "curl: HTTP/3 not supported over SOCKS"
        else:
            result["detail"] = err[:100]
    return result


# ======== DIRECT (system default route) ========

def test_direct_tcp(domain):
    result = {"domain": domain, "proto": "TCP", "status": "FAIL", "detail": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(CURL_TIMEOUT)
        sock.connect((domain, 443))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            ssock.send(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
            resp = ssock.recv(1024).decode(errors="replace")
            result["status"] = "OK"
            result["detail"] = resp.split("\r\n")[0] if resp else ""
    except Exception as e:
        result["detail"] = str(e)[:100]
    finally:
        sock.close()
    return result


def test_direct_ntp(server):
    result = {"domain": server, "proto": "NTP", "status": "FAIL", "detail": ""}
    try:
        ip = socket.gethostbyname(server)
    except socket.gaierror as e:
        result["detail"] = f"DNS: {e}"
        return result
    return test_ntp_socket(server, ip)


def test_direct_quic(domain):
    result = {"domain": domain, "proto": "QUIC", "status": "FAIL", "detail": ""}
    r = curl_test(f"https://{domain}/", extra_args=["--http3-only"], timeout=CURL_TIMEOUT)
    if r.get("http_code", 0) > 0:
        result["status"] = "OK"
        result["detail"] = f"HTTP/3 {r['http_code']} {r.get('time','')}s {r.get('size',0)}B"
    else:
        result["detail"] = r.get("error", "?")[:100]
    return result


# ======== mihomo ========

def get_mihomo_connections():
    req = urllib.request.Request(f"{MIHOMO_API}/connections", headers={"Authorization": MIHOMO_AUTH})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("connections", [])
    except Exception:
        return []


def check_mihomo_routing(domains):
    conns = get_mihomo_connections()
    result = {}
    for domain in domains:
        matches = [c for c in conns if domain in (c["metadata"].get("host") or "")]
        if matches:
            types = set()
            for c in matches:
                m = c["metadata"]
                st = "alive" if c["download"] > 0 else "dead"
                types.add(f"{m.get('type','?')}/{m.get('network','?')}({st})")
            result[domain] = ", ".join(sorted(types))
        else:
            result[domain] = "DIRECT (not in mihomo)"
    return result


# ======== output ========

def print_result(r):
    icon = "+" if r["status"] == "OK" else "-"
    proto = r["proto"]
    # asterisk means "expected to fail"
    print(f"    [{icon}] {proto:8s} {r['domain']:28s} {r['status']:4s}  {r['detail']}")


def run_section(label, tests):
    """Run a list of (test_fn, args) and return results."""
    results = []
    print(f"\n  {label}")
    for fn, args, kwargs in tests:
        r = fn(*args, **kwargs)
        results.append(r)
        print_result(r)
    return results


def main():
    curl_cmd, has_h3 = detect_curl()
    print("MagiTrickle REDIRECT+TPROXY Test")
    print(f"Router: {ROUTER_IP}  Local: {LOCAL_IP}  SOCKS5: :{SOCKS5_PORT}  curl HTTP/3: {'yes' if has_h3 else 'no'}")
    print("=" * 80)

    # [1] DNS
    print(f"\n[1] DNS via MagiTrickle (:{MAGITRICKLE_DNS_PORT})")
    all_domains = sorted(set(TCP_DOMAINS) | set(QUIC_DOMAINS) | set(NTP_SERVERS))
    resolved = {}
    for domain in all_domains:
        ip = resolve_via_magitrickle(domain)
        if ip:
            resolved[domain] = ip
            print(f"    {domain:35s} -> {ip}")
        else:
            print(f"    {domain:35s} -> FAILED")
    if not resolved:
        print("\n  No DNS resolutions. Is MagiTrickle running?")
        sys.exit(1)

    all_results = []

    # [2] MagiTrickle path (TCP=REDIRECT via nat, UDP=TPROXY via mangle)
    print(f"\n[2] MagiTrickle (TCP REDIRECT + UDP TPROXY)")

    mt_tcp = []
    for d in TCP_DOMAINS:
        if d in resolved:
            mt_tcp.append((test_tcp_socket, (d, resolved[d]), {}))
    all_results += run_section("TCP (nat REDIRECT)", mt_tcp)

    if has_h3:
        mt_quic = []
        for d in QUIC_DOMAINS:
            if d in resolved:
                mt_quic.append((test_quic_curl, (d,), {"ip": resolved[d], "extra_curl_args": ["--interface", LOCAL_CURL_IFACE]}))
        all_results += run_section("QUIC/HTTP3 (mangle TPROXY)", mt_quic)
    else:
        print(f"\n  QUIC/HTTP3 (mangle TPROXY)")
        print(f"    (skipped -- curl has no HTTP/3)")

    mt_ntp = []
    for s in NTP_SERVERS:
        if s in resolved:
            mt_ntp.append((test_ntp_socket, (s, resolved[s]), {"bind_ip": LOCAL_IP}))
    all_results += run_section("NTP (mangle TPROXY)", mt_ntp)

    # [3] SOCKS5 proxy path
    print(f"\n[3] SOCKS5 ({ROUTER_IP}:{SOCKS5_PORT})")

    s_tcp = [(test_socks5_tcp, (d,), {}) for d in TCP_DOMAINS[:2]]
    all_results += run_section("TCP", s_tcp)

    s_ntp = [(test_socks5_ntp, (s,), {}) for s in NTP_SERVERS]
    all_results += run_section("NTP (UDP ASSOCIATE)", s_ntp)

    if has_h3:
        s_quic = [(test_socks5_quic, (d,), {}) for d in QUIC_DOMAINS[:2]]
        all_results += run_section("QUIC * (curl does NOT support HTTP/3 over SOCKS)", s_quic)
    else:
        print(f"\n  QUIC (skipped -- no HTTP/3)")

    # [4] DIRECT (system default route)
    print(f"\n[4] DIRECT (system default route)")

    d_tcp = [(test_direct_tcp, (d,), {}) for d in TCP_DOMAINS[:2]]
    all_results += run_section("TCP", d_tcp)

    d_ntp = [(test_direct_ntp, (s,), {}) for s in NTP_SERVERS]
    all_results += run_section("NTP", d_ntp)

    if has_h3:
        d_quic = [(test_direct_quic, (d,), {}) for d in QUIC_DOMAINS[:2]]
        all_results += run_section("QUIC", d_quic)
    else:
        print(f"\n  QUIC (skipped -- no HTTP/3)")

    # [5] Exit IP (cloudflare trace)
    print(f"\n[5] Exit IP (cloudflare trace)")
    traces = [
        ("MagiTrickle", ["--interface", LOCAL_CURL_IFACE] + (
            ["--resolve", f"www.cloudflare.com:443:{resolved['www.cloudflare.com']}"]
            if "www.cloudflare.com" in resolved else []
        )),
        ("SOCKS5", ["--proxy", f"socks5h://{ROUTER_IP}:{SOCKS5_PORT}"]),
        ("DIRECT", []),
    ]
    for label, args in traces:
        body = curl_trace(CF_TRACE, extra_args=args, timeout=CURL_TIMEOUT)
        ip = colo = http_ver = "?"
        for line in body.splitlines():
            if line.startswith("ip="): ip = line[3:]
            elif line.startswith("colo="): colo = line[5:]
            elif line.startswith("http="): http_ver = line[5:]
        print(f"    {label:14s}  ip={ip:20s} colo={colo:5s} {http_ver}")

    # [6] mihomo routing
    print(f"\n[6] mihomo routing")
    time.sleep(0.5)
    tested = list(set(TCP_DOMAINS + QUIC_DOMAINS + NTP_SERVERS))
    routing = check_mihomo_routing(tested)
    for d in sorted(routing):
        via = routing[d]
        tag = "MT" if "DIRECT" not in via else "!!"
        print(f"    [{tag}] {d:35s} {via}")

    # [7] mihomo connections from our IP
    print(f"\n[7] mihomo connections from {LOCAL_IP}")
    conns = get_mihomo_connections()
    my = [c for c in conns if c["metadata"].get("sourceIP") == LOCAL_IP]
    for net in ["tcp", "udp"]:
        nc = [c for c in my if c["metadata"].get("network") == net]
        alive = sum(1 for c in nc if c["download"] > 0)
        dead = sum(1 for c in nc if c["upload"] > 0 and c["download"] == 0)
        print(f"    {net.upper()}: {len(nc)} total, {alive} alive, {dead} dead")
        for c in nc[:6]:
            m = c["metadata"]
            host = m.get("host") or m.get("destinationIP")
            dl, ul = c["download"], c["upload"]
            st = "ALIVE" if dl > 0 else "DEAD"
            print(f"      [{st:5s}] {m.get('type','?'):6s} {host}:{m.get('destinationPort')} ul={ul} dl={dl}")

    # Summary
    print(f"\n{'=' * 80}")
    print("Summary by path:")
    # Group results by section: determine section from test order
    sections = {
        "MagiTrickle": [], "SOCKS5": [], "DIRECT": [],
    }
    idx = 0
    # MT: tcp + quic + ntp
    mt_count = len(mt_tcp) + (len(mt_quic) if has_h3 else 0) + len(mt_ntp)
    for r in all_results[idx:idx+mt_count]:
        sections["MagiTrickle"].append(r)
    idx += mt_count
    # SOCKS: tcp + ntp + quic
    s_count = len(s_tcp) + len(s_ntp) + (len(s_quic) if has_h3 else 0)
    for r in all_results[idx:idx+s_count]:
        sections["SOCKS5"].append(r)
    idx += s_count
    # DIRECT: tcp + ntp + quic
    d_count = len(d_tcp) + len(d_ntp) + (len(d_quic) if has_h3 else 0)
    for r in all_results[idx:idx+d_count]:
        sections["DIRECT"].append(r)

    total_ok = total_all = 0
    for section, results in sections.items():
        ok = sum(1 for r in results if r["status"] == "OK")
        n = len(results)
        total_ok += ok
        total_all += n
        by_proto = {}
        for r in results:
            p = r["proto"].rstrip(" *")
            by_proto.setdefault(p, {"ok": 0, "n": 0})
            by_proto[p]["n"] += 1
            if r["status"] == "OK":
                by_proto[p]["ok"] += 1
        proto_str = "  ".join(f"{p}={v['ok']}/{v['n']}" for p, v in by_proto.items())
        print(f"  {section:14s} {ok}/{n} OK   ({proto_str})")

    mt_routed = sum(1 for v in routing.values() if "DIRECT" not in v)
    print(f"  {'MT routed':14s} {mt_routed}/{len(routing)}")
    print(f"\n  Total: {total_ok}/{total_all} passed")


if __name__ == "__main__":
    main()
