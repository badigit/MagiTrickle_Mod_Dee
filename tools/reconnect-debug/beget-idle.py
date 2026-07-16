#!/usr/bin/env python3
# exit-node-idle.py — idle-порог keep-alive TLS-коннов с exit-ноды (сегмент D изолированно).
# Пути: direct (дефолтный egress ноды) и warp (SO_BINDTODEVICE=warp).
# Паттерн: GET -> ответ -> idle T -> GET#2 -> вердикт.
# Отличает: ALIVE / FIN-DURING-IDLE / RST-ON-PROBE / SILENT-TIMEOUT / CONNFAIL.
import socket, ssl, sys, time, threading

HOST = "api.anthropic.com"
TS = [300, 420, 600]
PATHS = ["direct", "warp"]
OUT = "/tmp/exit-node-idle.tsv"
lock = threading.Lock()

def req(s):
    s.sendall(b"GET / HTTP/1.1\r\nHost: " + HOST.encode() + b"\r\n\r\n")
    s.settimeout(15)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            raise ConnectionError("EOF")
        buf += d
    # дочитать маленькое chunked-тело не обязательно: следующий парс ищет новый статус-лайн
    return buf.split(b"\r\n", 1)[0].decode(errors="replace")

def one(path, T):
    t0 = int(time.time())
    verdict, detail = "?", "-"
    try:
        raw = socket.create_connection((HOST, 443), timeout=15)
        if path == "warp":
            # пересоздаём с bind-to-device (нужен коннект заново)
            raw.close()
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.setsockopt(socket.SOL_SOCKET, 25, b"warp")  # SO_BINDTODEVICE
            raw.settimeout(15)
            raw.connect((HOST, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=HOST)
        st1 = req(s)
        # idle: молчим T, но слушаем FIN/RST (recv с таймаутом)
        s.settimeout(T)
        t_idle0 = time.time()
        try:
            d = s.recv(4096)
            # данные -> дочитываем хвост тела и продолжаем ждать остаток паузы
            while time.time() - t_idle0 < T:
                s.settimeout(max(1, T - (time.time() - t_idle0)))
                d = s.recv(4096)
                if not d:
                    verdict = "FIN-DURING-IDLE"
                    detail = f"after={int(time.time()-t_idle0)}s"
                    break
        except socket.timeout:
            pass  # тишина всю паузу — норма
        except ConnectionResetError:
            verdict = "RST-DURING-IDLE"
            detail = f"after={int(time.time()-t_idle0)}s"
        if verdict == "?":
            try:
                st2 = req(s)
                verdict, detail = "ALIVE", st2.split()[1] if len(st2.split()) > 1 else st2
            except socket.timeout:
                verdict = "SILENT-TIMEOUT"
            except ConnectionResetError:
                verdict = "RST-ON-PROBE"
            except ConnectionError:
                verdict = "FIN-ON-PROBE"
        try:
            s.close()
        except Exception:
            pass
    except Exception as e:
        verdict, detail = "CONNFAIL", type(e).__name__
    with lock:
        with open(OUT, "a") as f:
            f.write(f"{t0}\t{time.strftime('%F %T', time.localtime(t0))}\t{path}\t{T}\t{verdict}\t{detail}\n")

def main():
    with open(OUT, "a") as f:
        f.write("epoch\tiso\tpath\tidle_s\tverdict\tdetail\n")
    th = []
    for T in TS:
        for p in PATHS:
            t = threading.Thread(target=one, args=(p, T))
            t.start()
            th.append(t)
    for t in th:
        t.join()
    print("done ->", OUT)

if __name__ == "__main__":
    main()
