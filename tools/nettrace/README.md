# nettrace

Per-process network diagnostic for verifying MagiTrickle routing — captures
**all outbound connections of a process, TCP _and_ UDP**, and annotates each
destination against MagiTrickle (`/api/v1/lookup`) plus ASN/country.

## Why not the PowerShell script

`network_watch.ps1` reads socket tables (`Get-NetTCPConnection` /
`Get-NetUDPEndpoint`). That works for TCP, but **UDP has no connection state** —
the endpoint table exposes only the *local* socket, never the remote address.
So the old script showed UDP as `local endpoint only` and was blind to where UDP
actually went (games, QUIC, etc.).

`nettrace` instead subscribes to the **ETW `Microsoft-Windows-Kernel-Network`
provider**, which emits a per-packet event carrying **PID + destination IP:port**
for both TCP and UDP. This is the only Windows source that ties a UDP datagram to
both its process and its destination.

## Requirements

- Windows 10 1809+ / 11
- Python 3.9+
- **Administrator** — ETW kernel sessions require elevation. Run from an elevated
  shell.

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
# watch Rocket League, TCP+UDP, until Ctrl+C, with MT + ASN annotation
python nettrace.py -n RocketLeague

# multiple processes, 60 seconds, also write TSV
python nettrace.py -n chrome -n RocketLeague --for 60 --tsv out.tsv

# by PID, UDP only
python nettrace.py --pid 12345 --no-tcp

# first elevated run — dump raw ETW field names (to validate field mapping)
python nettrace.py -n RocketLeague --debug-fields
```

### Output

```
[02:41:59] [RocketLeague] UDP 18.156.229.255:8097 [MT:--]        AS16509 | Amazon | DE
[02:41:59] [RocketLeague] TCP 104.18.2.64:443     [MT:CF] [x1]   AS13335 | Cloudflare | US
```

Color = MagiTrickle intent (not actual path — see limitation):
- **green** — destination matches an MT rule / is in an ipset → *should* be tunneled
- **yellow** — not covered by MT → will go DIRECT
- **gray** — RU (excluded from tunneling by convention)

`[MT:<group>]` = matched rule group · `[MT:ipset]` = in live ipset only ·
`[MT:--]` = not in MagiTrickle.

## Key flags

| flag | meaning |
|------|---------|
| `-n NAME` | process-name substring (repeatable) |
| `--pid N` | filter by PID (repeatable) |
| `--for N` | run N seconds (0 = until Ctrl+C) |
| `--mt-url URL` | MagiTrickle lookup endpoint (default `http://<ROUTER_IP>:8080/api/v1/lookup`; `''` disables) |
| `--no-check-ipset` | rule-match only, skip live ipset query |
| `--no-udp` / `--no-tcp` | restrict protocol |
| `--no-geo` | skip ASN/country lookup |
| `--tsv PATH` | also write TSV log |
| `--no-port-swap` | do not `ntohs()` ports (use if ports look wrong) |
| `--debug-fields` | print raw ETW field names of the first event |

## Learn & push to MagiTrickle

Instead of eyeballing the miss-list and adding rules by hand, `nettrace` can collect
uncovered destinations (with **real BGP-announced CIDR** + ASN, not a `/24` guess) and
push them into an MT group. Two workflows:

### Two-step (recommended): learn, then push

```powershell
# 1) play a few sessions — accumulate candidates (counts add up across runs)
python nettrace.py -n RocketLeague --learn game.json
python nettrace.py -n RocketLeague --learn game.json   # again next match

# 2) review the plan (dry-run — nothing is written)
python nettrace.py --import game.json --push-to-group RL

# 3) actually add
python nettrace.py --import game.json --push-to-group RL --confirm
```

`--import` is **push mode**: no capture, just read the store, refresh coverage against
live MT, aggregate uncovered IPs into subnets, and add the ones not already present.

### One-shot (capture + push in a single run)

```powershell
python nettrace.py -n RocketLeague --for 120 --push-to-group RL --confirm
```

### Aggregation & safety

| flag | meaning |
|------|---------|
| `--learn FILE` | accumulate captured endpoints (ASN + BGP-CIDR) into a JSON store |
| `--import FILE` | push mode: add uncovered subnets from a store to MT (no capture) |
| `--push-to-group G` | target MT group (name or id) |
| `--confirm` | actually push (default is **dry-run**) |
| `--agg cidr\|24\|16\|32` | `cidr` = real BGP prefix (default), or fixed mask |
| `--min-count N` | ignore endpoints seen fewer than N times (drop noise) |
| `--promote16 N` | with `--agg 24`: collapse a /16 when ≥N distinct /24 seen |
| `--allow-wide` | permit subnets wider than /16 (off by default) |

Only **uncovered** (not already in MT), **non-RU**, IPv4 candidates are pushed; existing
rules are deduped; subnets wider than `/16` are refused unless `--allow-wide`. This
replaces `mt_add_missing.ps1`.

## Limitations (v1)

- **Shows intent, not actual path.** MT annotation says whether a destination
  *should* be tunneled (rule/ipset). It does **not** prove the packet actually went
  through the tunnel — that only the router knows (conntrack `sport=5001` /
  mihomo `/connections`). Router path cross-check (TUNNEL vs DIRECT) and a
  test-case mode are planned — see beads `mt-wf4`.
- **ETW field names / byte order** for the Kernel-Network provider are validated
  at runtime; if IPs or ports look wrong on your build, run `--debug-fields` and
  adjust, and try `--no-port-swap`.
