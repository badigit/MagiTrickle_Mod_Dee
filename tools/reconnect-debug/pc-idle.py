#!/usr/bin/env python3
# pc-idle.py — с ПК: доносит ли цепочка серверный FIN idle keep-alive конна.
# Путь: ПК → mihomo HTTP CONNECT (<ROUTER_IP>:7891) → выбранный узел → api.anthropic.com.
# Паттерн: GET → ответ → тихое ожидание T с прослушкой сокета → GET#2.
# Вердикты: FIN-DURING-IDLE (server close ДОШЁЛ — цепочка честная),
#           SILENT-TIMEOUT / RST-ON-PROBE (FIN потерян — зомби),
#           ALIVE (T < серверного лимита 400с).
# Матрица узлов: состав группы спрашивается у самого mihomo, скрипт переключает
# узлы по одному и валидирует. Имя группы — MIHOMO_GROUP из env или .router.env;
# ни имени группы, ни списка узлов в репозитории нет.
import json
import os
import pathlib
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request


def _router_env(key, default=None):
    """Адрес роутера в репозитории не хранится: env или .router.env в корне репо
    (см. .router.env.example, сам файл — в .gitignore)."""
    val = os.environ.get(key)
    if val:
        return val
    cfg = pathlib.Path(__file__).resolve().parents[2] / ".router.env"
    if cfg.exists():
        for line in cfg.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == key:
                return v.strip().strip('"').strip("'")
    return default


ROUTER = _router_env("ROUTER_IP") or sys.exit("не задан ROUTER_IP: env или .router.env")
GROUP = _router_env("MIHOMO_GROUP") or sys.exit("не задан MIHOMO_GROUP (имя proxy-группы mihomo): env или .router.env")
PROXY_PORT = 7891
API = f"http://{ROUTER}:9090"
HOST = "api.anthropic.com"
T = int(sys.argv[1]) if len(sys.argv) > 1 else 430
# Состав узлов в репозитории не хранится — он спрашивается у самого mihomo.
SERVICE_NODES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}


def api_group() -> dict:
    url = f"{API}/proxies/{urllib.parse.quote(GROUP)}"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.load(r)


def api_put_node(name: str) -> None:
    req = urllib.request.Request(
        f"{API}/proxies/{urllib.parse.quote(GROUP)}",
        data=json.dumps({"name": name}).encode(),
        method="PUT",
    )
    urllib.request.urlopen(req, timeout=5).read()


def api_now() -> str:
    return api_group()["now"]


def discover_nodes() -> list:
    """Матрица узлов: env NODES (через ';') либо состав группы из mihomo."""
    env_nodes = _router_env("NODES")
    if env_nodes:
        return [n.strip() for n in env_nodes.split(";") if n.strip()]
    return [n for n in api_group().get("all", []) if n not in SERVICE_NODES]


def http_get(s) -> str:
    s.sendall(b"GET / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n\r\n")
    s.settimeout(15)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            raise ConnectionError("EOF")
        buf += d
    return buf.split(b"\r\n", 1)[0].decode(errors="replace")


def probe(node: str, T: int) -> tuple[str, str]:
    raw = socket.create_connection((ROUTER, PROXY_PORT), timeout=10)
    raw.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        d = raw.recv(4096)
        if not d:
            return "CONNFAIL", "proxy-eof"
        resp += d
    if b" 200 " not in resp.split(b"\r\n", 1)[0]:
        return "CONNFAIL", resp.split(b"\r\n", 1)[0].decode(errors="replace")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST)
    st1 = http_get(s)
    if " 404" not in st1 and " 200" not in st1:
        return "BADFIRST", st1
    t0 = time.time()
    verdict = detail = None
    s.settimeout(T)
    try:
        while time.time() - t0 < T:
            s.settimeout(max(1.0, T - (time.time() - t0)))
            d = s.recv(4096)
            if not d:
                verdict, detail = "FIN-DURING-IDLE", f"after={int(time.time()-t0)}s"
                break
    except socket.timeout:
        pass
    except ConnectionResetError:
        verdict, detail = "RST-DURING-IDLE", f"after={int(time.time()-t0)}s"
    except ConnectionAbortedError:
        verdict, detail = "ABORT-DURING-IDLE", f"after={int(time.time()-t0)}s"
    if verdict is None:
        try:
            st2 = http_get(s)
            verdict, detail = "ALIVE", st2
        except socket.timeout:
            verdict, detail = "SILENT-TIMEOUT", "-"
        except ConnectionResetError:
            verdict, detail = "RST-ON-PROBE", "-"
        except (ConnectionError, ConnectionAbortedError, OSError) as e:
            verdict, detail = "DEAD-ON-PROBE", type(e).__name__
    try:
        s.close()
    except OSError:
        pass
    return verdict, detail


def main() -> None:
    print(f"T={T}s host={HOST} via {ROUTER}:{PROXY_PORT} group={GROUP}")
    nodes = discover_nodes()
    if not nodes:
        sys.exit(f"в группе {GROUP} нет узлов (проверь MIHOMO_GROUP)")
    # восстанавливаем то, что было выбрано до прогона, а не первый узел списка
    restore = api_now()
    for node in nodes:
        api_put_node(node)
        time.sleep(1)
        now = api_now()
        if now != node:
            print(f"{node}\tSWITCH-FAILED (now={now})")
            continue
        t0 = time.strftime("%F %T")
        v, d = probe(node, T)
        print(f"{t0}\t{node}\tT={T}\t{v}\t{d}", flush=True)
    api_put_node(restore)
    print("restored:", api_now())


if __name__ == "__main__":
    main()
