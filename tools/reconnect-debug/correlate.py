#!/usr/bin/env python3
"""
correlate.py — оффлайн-корреляция улик дебага реконнектов.

Соединяет probe-*.tsv (с ПК) и conntrack.log (с роутера, из router-capture.sh)
и классифицирует каждое событие "первый-фейл/второй-ок" по гипотезам H1-H4.

Запуск на ПК (python3; на роутере python нет):
  python3 correlate.py probe-YYYYMMDD-HHMMSS.tsv path/to/<capture>/conntrack.log [--port 443] [--redir 5001]

ЛОКАЛИЗАТОР (роутер на legacy iptables, TCP-в-прокси через REDIRECT --to-ports 5001):
  Проксируемый TCP-поток => в conntrack reply-tuple sport == REDIR (5001), reply src = роутер.
  Direct (мимо прокси)   => reply-tuple sport == orig dport (443), reply src = реальный dst.
  (fwmark здесь НЕ используется для TCP — все :443 потоки mark=0; не полагаемся на mark.)

Классификация события (таргет, где ok пришёл НЕ с 1й попытки, либо все фейл):
  H1 (DNS-resolve)      — resolved IP отличается между провальной и успешной попыткой.
  H2/H3 (ipset/route)   — IP тот же; 1й поток DIRECT (reply sport=443, мимо REDIRECT),
                          2й поток PROXIED (reply sport=5001). Гонка DNS→ipset / disposition.
  H4 (mihomo tunnel)    — оба потока PROXIED (sport=5001), но 1й UNREPLIED/быстрый DESTROY.
  UNRESOLVED            — нет conntrack-улик в окне.
"""
import sys, re, argparse
from collections import defaultdict

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("probe_tsv")
    ap.add_argument("conntrack_log")
    ap.add_argument("--port", type=int, default=443, help="orig dport таргета")
    ap.add_argument("--redir", type=int, default=5001, help="REDIRECT --to-ports (mihomo redir)")
    ap.add_argument("--window", type=float, default=3.0, help="окно сопоставления, сек")
    return ap.parse_args()

def read_probe(path):
    offset = 0.0
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#"):
                m = re.search(r"router_offset_s:\s*(-?\d+(\.\d+)?)", line)
                if m:
                    offset = float(m.group(1))
                continue
            if line.startswith("iso_utc") or not line.strip():
                continue
            c = line.split("\t")
            if len(c) < 10:
                continue
            rows.append({
                "iso": c[0], "epoch_ms": int(c[1]), "target": c[2],
                "attempt": int(c[3]), "resolved_ips": c[4], "resolve_ms": c[5],
                "connect_ip": c[6], "result": c[7], "connect_ms": c[8], "verdict": c[9],
            })
    return offset, rows

CT_RE = re.compile(r"\[(\d+\.\d+)\]\s+\[\s*(NEW|DESTROY|UPDATE)\s*\]")
def read_conntrack(path, redir):
    """Каждое событие: orig dst/dport, reply sport (=> proxied?), state, UNREPLIED."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = CT_RE.search(line)
            if not m:
                continue
            ts = float(m.group(1)); kind = m.group(2)
            dsts   = re.findall(r"\bdst=(\d+\.\d+\.\d+\.\d+)", line)
            sports = re.findall(r"\bsport=(\d+)", line)
            dports = re.findall(r"\bdport=(\d+)", line)
            orig_dst   = dsts[0] if dsts else None
            orig_dport = int(dports[0]) if dports else None
            reply_sport = int(sports[1]) if len(sports) > 1 else None
            proxied = (reply_sport == redir) if reply_sport is not None else None
            state = re.search(r"\b(SYN_SENT|SYN_RECV|ESTABLISHED|FIN_WAIT|CLOSE|TIME_WAIT|CLOSE_WAIT|LAST_ACK)\b", line)
            events.append({
                "ts": ts, "kind": kind, "dst": orig_dst, "dport": orig_dport,
                "reply_sport": reply_sport, "proxied": proxied,
                "state": state.group(1) if state else "",
                "unreplied": "[UNREPLIED]" in line,
                "raw": line.rstrip("\n"),
            })
    return events

def find_flow(events, dst, dport, t_router, window):
    best = None; bestd = window + 1
    for e in events:
        if e["kind"] != "NEW" or e["dst"] != dst:
            continue
        if dport is not None and e["dport"] not in (dport, None):
            continue
        d = abs(e["ts"] - t_router)
        if d <= window and d < bestd:
            best = e; bestd = d
    return best

def destroy_for(events, dst, dport, t_router, window):
    for e in events:
        if e["kind"] == "DESTROY" and e["dst"] == dst and abs(e["ts"] - t_router) <= window:
            if dport is None or e["dport"] in (dport, None):
                return e
    return None

def main():
    a = parse_args()
    offset, prows = read_probe(a.probe_tsv)
    events = read_conntrack(a.conntrack_log, a.redir)
    print(f"# offset(router-pc)={offset:.2f}s  probe_rows={len(prows)}  ct_events={len(events)}  redir_port={a.redir}")

    # группируем попытки по таргет-итерации (attempt сбрасывается в 1)
    groups = []
    cur = None
    for r in prows:
        if r["attempt"] == 1:
            cur = {"target": r["target"], "attempts": []}
            groups.append(cur)
        if cur is not None:
            cur["attempts"].append(r)

    counts = defaultdict(int)
    print(f"\n{'target':22} {'verdict':18} {'class':22} detail")
    print("-" * 104)
    for g in groups:
        atts = g["attempts"]
        succ = next((x for x in atts if x["result"] == "success"), None)
        first = atts[0]
        if succ and succ["attempt"] == 1:
            counts["OK-1st"] += 1
            continue
        verdict = succ["verdict"] if succ else "FAIL-all"

        klass, detail = "UNRESOLVED", ""
        if succ and first["connect_ip"] and succ["connect_ip"] and first["connect_ip"] != succ["connect_ip"]:
            klass = "H1 DNS-resolve"
            detail = f"ip1={first['connect_ip']} -> ip2={succ['connect_ip']}"
        else:
            ip = first["connect_ip"] or (succ["connect_ip"] if succ else "")
            t1 = first["epoch_ms"]/1000.0 + offset
            f1 = find_flow(events, ip, a.port, t1, a.window) if ip else None
            f2 = None
            if succ:
                t2 = succ["epoch_ms"]/1000.0 + offset
                f2 = find_flow(events, ip, a.port, t2, a.window)
            p1 = f1["proxied"] if f1 else None
            p2 = f2["proxied"] if f2 else None
            if f1 is not None and p1 is False and (p2 is True or succ is None):
                klass = "H2/H3 ipset/route"
                detail = f"1st DIRECT(reply sport={f1['reply_sport']}) 2nd PROXIED(sport={f2['reply_sport'] if f2 else '?'})"
            elif f1 is not None and p1 is True:
                dq = destroy_for(events, ip, a.port, t1, a.window)
                if f1["unreplied"] or dq:
                    klass = "H4 mihomo-tunnel"
                    detail = f"1st PROXIED(sport=5001) но {'UNREPLIED' if f1['unreplied'] else 'DESTROY'} (flap?)"
                else:
                    klass = "H4? marked-ok"
                    detail = "1st PROXIED, причина фейла не в маршруте"
            else:
                detail = f"f1={'y' if f1 else 'n'} f2={'y' if f2 else 'n'} ip={ip} p1={p1} p2={p2}"

        counts[klass.split()[0]] += 1
        print(f"{g['target']:22} {verdict:18} {klass:22} {detail}")

    print("\n# Сводка:")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {k:22} {v}")

if __name__ == "__main__":
    main()
