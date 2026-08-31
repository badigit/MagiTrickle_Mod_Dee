#!/usr/bin/env python3
"""etw_probe — isolate why nettrace stopped seeing events.

Runs three short Kernel-Network sessions and just counts what the callback
receives. Nothing is filtered by process, so a zero here means the ETW session
itself delivered nothing.

  A  old settings: 4 datasent ids, pywintrace default buffers
  B  new event ids (connect/accept/recv added), default buffers
  C  new event ids + nettrace's small-buffer / FlushTimer=1 properties

Each phase runs as its own child process: ETW's ProcessTrace can hang for a long
time inside stop(), so the child prints its numbers first and then hard-exits.

Run elevated:  python etw_probe.py [seconds_per_phase]
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import threading
import time
from collections import Counter

from etw import ETW, ProviderInfo
from etw.etw import TraceProperties
from etw.GUID import GUID

GUID_STR = "{7DD42A49-5329-4832-8DFD-43D979153A88}"
WANT = os.environ.get("PROBE_MATCH", "anydesk").lower()
PHASES = {
    "A": ("old ids, default buffers", [10, 42, 26, 58], False),
    "B": ("new ids, default buffers", [10, 12, 11, 15, 42, 43, 26, 28, 27, 31, 58, 59], False),
    "C": ("new ids, nettrace buffers", [10, 12, 11, 15, 42, 43, 26, 28, 27, 31, 58, 59], True),
}


def proc_name(pid):
    """Same lookup nettrace's filter uses — including its failure mode."""
    k = ctypes.windll.kernel32
    h = k.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return f"<denied:{ctypes.get_last_error() or 'err'}>"
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(1024)
        if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value.rsplit("\\", 1)[-1]
        return "<no-name>"
    finally:
        k.CloseHandle(h)


def run_phase(key, seconds):
    label, ids, use_props = PHASES[key]
    seen = Counter()
    pids = Counter()
    lock = threading.Lock()

    def cb(event):
        try:
            eid, data = event
        except (TypeError, ValueError):
            return
        with lock:
            seen[eid] += 1
            pid = data.get("PID") or data.get("ProcessId")
            if pid is not None:
                pids[int(pid)] += 1

    kwargs = dict(providers=[ProviderInfo("Microsoft-Windows-Kernel-Network", GUID(GUID_STR))],
                  event_id_filters=list(ids),
                  event_callback=cb)
    props = None
    if use_props:
        props = TraceProperties(ring_buf_size=64, min_buffers=16, max_buffers=64)
        props.get().contents.FlushTimer = 1
        kwargs["properties"] = props

    print(f"=== {key}  {label}: ids={ids} props={'custom' if use_props else 'default'} ({seconds}s)")
    print("    generate some traffic now")
    session = ETW(**kwargs)
    t0 = time.time()
    session.start()
    first = None
    while time.time() - t0 < seconds:
        time.sleep(0.25)
        with lock:
            if first is None and seen:
                first = time.time() - t0
                print(f"    first event after {first:.1f}s")

    # Numbers BEFORE stop() — that call can block for a long time on the flush.
    with lock:
        total = sum(seen.values())
        print(f"    total events: {total}")
        if total:
            print(f"    by event id: {dict(sorted(seen.items()))}")
            print("    top pids:")
            named = [(pid, n, proc_name(pid)) for pid, n in pids.most_common()]
            for pid, n, nm in named[:8]:
                print(f"      pid {pid:>6}  {n:>6} ev  {nm}")
            if len(named) > 8:
                print(f"      ... and {len(named) - 8} more pids")
            if WANT:
                hits = [x for x in named if WANT in x[2].lower()]
                print(f"    matching '{WANT}': "
                      + (", ".join(f"pid {p} = {n} ev ({nm})" for p, n, nm in hits)
                         if hits else "NOT SEEN AT ALL"))
        else:
            print("    NOTHING RECEIVED")
        if props is not None:
            print(f"    EventsLost: {props.get().contents.EventsLost}")
    sys.stdout.flush()

    done = threading.Event()
    threading.Thread(target=lambda: (session.stop(), done.set()), daemon=True).start()
    done.wait(5)
    os._exit(0 if total else 3)


def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("FATAL: run this from an elevated shell (ETW kernel session).")
        return 2

    if "--phase" in sys.argv:
        key = sys.argv[sys.argv.index("--phase") + 1]
        secs = int(sys.argv[sys.argv.index("--phase") + 2])
        return run_phase(key, secs)

    secs = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    got = {}
    for key in ("A", "B", "C"):
        print()
        r = subprocess.run([sys.executable, os.path.abspath(__file__), "--phase", key, str(secs)])
        got[key] = (r.returncode == 0)

    print("\n--- verdict")
    if all(got.values()):
        print("all three deliver — the capture is fine, the loss is in nettrace's\n"
              "process-name filter (match()/ProcResolver); check the pid table above:\n"
              "a <denied:...> name means the filter can never match that process")
    elif got["A"] and not got["B"]:
        print("the extended event_id_filters list broke it — revert to the 4 datasent ids")
    elif got["A"] and got["B"] and not got["C"]:
        print("the custom TraceProperties broke it — drop them, keep pywintrace defaults")
    elif not got["A"]:
        print("even the old settings deliver nothing — the problem is outside nettrace;\n"
              "check 'logman query -ets' for leaked sessions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
