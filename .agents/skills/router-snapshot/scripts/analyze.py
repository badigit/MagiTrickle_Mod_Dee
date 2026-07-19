#!/usr/bin/env python3
"""Анализ снимка router-snapshot.

  python3 analyze.py <snapshot_dir>                   # сводка по одному
  python3 analyze.py <snapshot_dir_a> <snapshot_dir_b>  # diff (B относительно A)
"""
from __future__ import annotations
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Чтобы не падать на эмодзи в chains/специальных-прокси под cp1251 stdout.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

AGE_BUCKETS = [
    (0,        60,    "<1m"),
    (60,       300,   "1-5m"),
    (300,      3600,  "5-60m"),
    (3600,     21600, "1-6h"),
    (21600,    43200, "6-12h"),
    (43200,    86400, "12-24h"),
    (86400,    172800,"24-48h"),
    (172800,   1e12,  ">48h"),
]


def load_conns(snap: Path) -> list[dict]:
    p = snap / "mihomo-connections.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("connections", []) or []
    except json.JSONDecodeError:
        return []


def parse_start(s: str) -> datetime | None:
    if not s:
        return None
    s = re.sub(r"\.\d+", "", s).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def conntrack_count(snap: Path) -> tuple[int, int]:
    cur = (snap / "conntrack-count").read_text().strip() if (snap / "conntrack-count").exists() else "?"
    mx  = (snap / "conntrack-max").read_text().strip()   if (snap / "conntrack-max").exists()   else "?"
    return cur, mx


def listeners(snap: Path) -> set[tuple[str, str]]:
    """Set of (proto, port) from netstat output."""
    out = set()
    for fn, proto in (("listeners-tcp.txt", "tcp"), ("listeners-udp.txt", "udp")):
        f = snap / fn
        if not f.exists():
            continue
        for line in f.read_text(errors="replace").splitlines():
            m = re.search(r":(\d+)\s+\S+\s+LISTEN", line) if proto == "tcp" else re.search(r":(\d+)\s+\S+\s*$", line)
            if m:
                out.add((proto, m.group(1)))
    return out


def summarize(snap: Path) -> dict:
    conns = load_conns(snap)
    by_type = Counter(c["metadata"].get("type", "?") for c in conns)
    by_net  = Counter(c["metadata"].get("network", "?") for c in conns)
    by_dport = Counter(c["metadata"].get("destinationPort", "?") for c in conns)

    inner_853 = [c for c in conns if c["metadata"].get("type") == "Inner"
                 and c["metadata"].get("destinationPort") in ("853", "443")]
    now = datetime.now(timezone.utc)
    ages: list[float] = []
    for c in inner_853:
        st = parse_start(c.get("start", ""))
        if st:
            ages.append((now - st).total_seconds())

    bucket_counts: list[tuple[str, int]] = []
    for lo, hi, label in AGE_BUCKETS:
        bucket_counts.append((label, sum(1 for a in ages if lo <= a < hi)))

    cur, mx = conntrack_count(snap)
    return {
        "snap": snap,
        "conntrack": (cur, mx),
        "total_conns": len(conns),
        "by_type": by_type,
        "by_net": by_net,
        "by_dport": by_dport,
        "inner_dns_count": len(inner_853),
        "inner_dns_age": bucket_counts,
        "listeners": listeners(snap),
    }


def fmt_counter(c: Counter, top: int = 8) -> str:
    return "  ".join(f"{k}={v}" for k, v in c.most_common(top))


def print_summary(s: dict) -> None:
    print(f"=== {s['snap']} ===")
    print(f"conntrack:        {s['conntrack'][0]}/{s['conntrack'][1]}")
    print(f"mihomo /connections total: {s['total_conns']}")
    print(f"  by type:    {fmt_counter(s['by_type'])}")
    print(f"  by network: {fmt_counter(s['by_net'])}")
    print(f"  top dport:  {fmt_counter(s['by_dport'], 10)}")
    print(f"  Inner DNS (853+443) age buckets ({s['inner_dns_count']} total):")
    for label, n in s["inner_dns_age"]:
        if n:
            print(f"    {label:8s} {n}")


def diff(a: dict, b: dict) -> None:
    print(f"=== diff: {a['snap'].name}  →  {b['snap'].name} ===")
    ca, mxa = a["conntrack"]; cb, mxb = b["conntrack"]
    try:
        delta = int(cb) - int(ca)
        print(f"conntrack: {ca} → {cb}  (Δ{delta:+d})")
    except ValueError:
        print(f"conntrack: {ca} → {cb}")
    print(f"mihomo total: {a['total_conns']} → {b['total_conns']}  "
          f"(Δ{b['total_conns']-a['total_conns']:+d})")

    keys = set(a["by_type"]) | set(b["by_type"])
    print("  by type:")
    for k in sorted(keys):
        ka, kb = a["by_type"][k], b["by_type"][k]
        if ka != kb:
            print(f"    {k:8s} {ka} → {kb}  (Δ{kb-ka:+d})")

    keys = set(a["by_dport"]) | set(b["by_dport"])
    print("  top dport changes:")
    rows = sorted(((k, a["by_dport"][k], b["by_dport"][k]) for k in keys),
                  key=lambda r: -abs(r[2] - r[1]))
    for k, va, vb in rows[:8]:
        if va != vb:
            print(f"    :{k:6s} {va} → {vb}  (Δ{vb-va:+d})")

    only_a = a["listeners"] - b["listeners"]
    only_b = b["listeners"] - a["listeners"]
    if only_a or only_b:
        print("  listener changes:")
        for proto, port in sorted(only_a):
            print(f"    -  {proto}:{port} (gone)")
        for proto, port in sorted(only_b):
            print(f"    +  {proto}:{port} (new)")


def main(argv: list[str]) -> int:
    if len(argv) == 2:
        print_summary(summarize(Path(argv[1])))
    elif len(argv) == 3:
        a, b = summarize(Path(argv[1])), summarize(Path(argv[2]))
        print_summary(a); print(); print_summary(b); print()
        diff(a, b)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
