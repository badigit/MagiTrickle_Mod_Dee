# Router Debug Playbook

Переиспользуемый сетап для отладки сетевого стека на проде-роутере (<ROUTER_IP>, Keenetic + Entware aarch64). Что есть, где лежит, как быстро снимать данные и что возвращать в норму.

---

## Машина

| | |
|---|---|
| Hostname / IP | `<ROUTER_IP>`, ssh алиас `<ROUTER_SSH>` |
| SSH | `ssh -p 222 root@<ROUTER_IP>` (Windows OpenSSH; не git-bash ssh) |
| Платформа | Keenetic, aarch64 (`aarch64-3.10_kn`), Entware на `/opt/` |
| Shell | BusyBox `sh` (нет `bash`, нет `python3`, нет `python`) |
| Установленный GNU | `coreutils 9.6`, `findutils 4.10`, `tar 1.35` (в `/opt/bin/tar`, busybox симлинк перекрывает в `$PATH`) |

### Откуда скрипты берут адрес

Конкретных адресов в репозитории нет — везде плейсхолдеры `<ROUTER_IP>` / `<ROUTER_SSH>`.
Скрипты (`scripts/deploy-*`, `scripts/speedtest.sh`, `scripts/test-redir-tproxy.py`,
`tools/domain-verdict/`, `tools/nettrace/`, `tools/reconnect-debug/pc-idle.py`,
скилл `router-snapshot`) читают их из переменных окружения или из `.router.env`
в корне репо — он в `.gitignore`:

```bash
cp .router.env.example .router.env   # и подставить свои значения
```

Ключи: `ROUTER_SSH` (алиас или `user@адрес`), `ROUTER_PORT`, `ROUTER_IP` (для http-API),
`ROUTER_SSH_MIPSEL`, `LOCAL_IP`. Без них скрипт не угадывает молча, а падает с указанием,
чего не хватает.

### Грабли

- **`scp` только Windows OpenSSH** — git-bash перехватывает MSYS-вариантом без доступа к Windows agent'у. Используем абсолютный `C:\Windows\System32\OpenSSH\scp.exe` или Windows OpenSSH в `~/bin/`.
- **`scp -O`** обязателен — sftp-server на роутере отсутствует.
- **BusyBox tar не умеет create** — для архивирования на роутере вызывать `/opt/bin/tar` (GNU) явно.
- **Анализ JSON / агрегаты** делаем локально на Windows — на роутере нет python.
- **PowerShell для Windows-команд** (ipconfig, netstat и т.п.) с `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`, иначе кракозябры.

---

## Сетевые компоненты

| Компонент | Слушает | Конфиг | Что делает |
|---|---|---|---|
| **MagiTrickle** (`magitrickled`) | TCP/UDP `:3553`, web `:8080`, mark-route to `tproxy :5001` | `/opt/var/lib/magitrickle/config.yaml` | DNS-MITM прокси: перехватывает домены клиентов, помечает их через ipset, маршрутизирует через mihomo |
| **mihomo** | DNS server `:6868`, mixed `:7890/:7891`, **API `:9090`** | `/opt/etc/mihomo/config.yaml` | Прокси-движок, рулзы, DNS-resolver |
| **ndnproxy** (Keenetic штатный) | `:53` | — | Системный DNS-прокси Keenetic; magitrickle перехватывает 53 через iptables redirect на 3553 |
| **zerotier-one** | `:44424` | — | mesh-оверлей, не имеет отношения к стеку |

**Цепочка DNS-запроса от клиента (dual-upstream, текущая):**
```
client → 53 (DNAT) → magitrickled :3553 ─┬─→ in-group:  mihomo :6868 → upstream DoH/DoT → vless gRPC
                                          └─→ out-of-group: ndnproxy :53 (Keenetic штатный)
```
MagiTrickle решает каким апстримом резолвить по правилам своих групп (domain/namespace/wildcard/regex). Subnet-правила игнорируются на pre-resolve и применяются post-resolve в `processARecord`. Loopback к `127.0.0.1:53` безопасен — все цепочки `MT_*` имеют `!lo` в PREROUTING. Подробности — [`research/mihomo-dns-inner-leak.md`](../research/mihomo-dns-inner-leak.md), Шаг 10.

### Полезные API

#### mihomo control-API (пример бэкенда; порт/секрет — по твоему конфигу)
- `GET /version` — версия и meta-флаг
- `GET /connections` — JSON со всеми трекер-записями
- `DELETE /connections` — закрыть всё (физически Close, не только map.Delete)
- `GET /connections/{id}` / `DELETE /connections/{id}` — точечно
- `GET /logs?level=debug` — websocket-стрим (через curl как long-poll)
- `GET /traffic` — секундная скорость
- **`GET /connections/inner-stats`** (наш патч) — `{joined, left, alive}` для INNER-conns; `alive` растёт = leak
- Web UI: `http://<ROUTER_IP>:9090/ui/` (если включён `external-ui`)

#### MagiTrickle `:8080`
- `GET /api/v1/system/version`
- `POST /api/v1/lookup` — резолв через MagiTrickle с применением правил группы (см. `reference_lookup_api`)
- `GET /api/v1/groups` — конфигурация групп с правилами
- Web UI: `http://<ROUTER_IP>:8080/`

---

## Быстрые команды

### Снимок состояния (всё-в-одном)

```bash
bash .claude/skills/router-snapshot/scripts/snapshot.sh [метка]
```
Один проход (~0.6с), кладёт в `.tmp/snapshots/<метка>-<ts>/`:
- `conntrack-{count,max,txt}` — состояние ядерного conntrack
- `listeners-{tcp,udp}.txt` — что слушает (`netstat -tlnp/-ulnp`)
- `ss-tcp.txt` — реальные ESTABLISHED сокеты по процессам
- `mihomo-{config.yaml, connections.json, version.json}`
- `magitrickle-{config.yaml, version.json}`
- `ps.txt`, `meta.txt` (label, timestamp, uptime)

### Анализ снимка / diff двух

```bash
PYTHONIOENCODING=utf-8 python3 .claude/skills/router-snapshot/scripts/analyze.py <snap_dir>
PYTHONIOENCODING=utf-8 python3 .claude/skills/router-snapshot/scripts/analyze.py <snap_a> <snap_b>
```

### Subagent для тяжёлого расследования

```
Используй router-evidence-gatherer
```
(после рестарта Claude CLI — он подхватит файл `.claude/agents/router-evidence-gatherer.md`)

Read-only, без изменений на роутере. Возвращает агрегированный отчёт ≤500 слов, не пихает сырые JSON в основной контекст.

### Триаж conntrack-давления (один-в-один)

```bash
ssh -p 222 root@<ROUTER_IP> 'cat /proc/sys/net/netfilter/nf_conntrack_count; \
  conntrack -L 2>/dev/null | grep -oE "dport=[0-9]+" | sort | uniq -c | sort -rn | head -10'
```

### Утечка Inner-конн в трекере mihomo (после патча)

```bash
ssh -p 222 root@<ROUTER_IP> 'curl -s http://127.0.0.1:9090/connections/inner-stats'
# норма: alive в пределах 0..30, колеблется
# leak:  alive растёт линейно
```

### Нагрузочный DNS-тест

```bash
cd tools/dns-bench
./run.sh all 100 30s    # in-group + out-of-group + mix, 100rps по 30 сек
```
Параллельно меряет `Δ alive` по `inner-stats` — индикатор leak'а под нагрузкой. Подробности и интерпретация: [`tools/dns-bench/README.md`](../tools/dns-bench/README.md).

**При dual-upstream дополнительно смотрим `Δ joined`** (а не только `alive`):
- out-of-group, 3000 запросов: `joined` должен прирасти **на 0–5** (всё пошло в ndnproxy, не в mihomo).
- in-group, 3000 запросов: `joined` прирастает на 5–30 (зависит от pool reuse).

Если на out-of-group `joined` прирастает на сотни — значит fallback не работает, проверь `dnsProxy.fallbackUpstream` в `/opt/var/lib/magitrickle/config.yaml`.

### Дебаг реконнектов «второй раз работает» (event-level корреляция)

Когда первый коннект падает, а второй проходит (Claude/Telegram) — это гонка, snapshot её
не ловит. Harness `tools/reconnect-debug/` снимает event-level улики и локализует слой по
conntrack `mark` (Magr=проксируется / 0=direct):
```bash
# роутер (read-only): conntrack mark + tcpdump SYN/RST + mihomo poll
scp -O -P 222 tools/reconnect-debug/router-capture.sh root@<ROUTER_IP>:/opt/bin/
ssh -p 222 root@<ROUTER_IP> '/opt/bin/router-capture.sh -d 300 -s <IP_ПК>'
# ПК (параллельно): зонд, воспроизводит «N-я попытка ок»
#   .\tools\reconnect-debug\local-probe.ps1 -For 300 -RouterHost root@<ROUTER_IP>
# анализ: python3 tools/reconnect-debug/correlate.py probe-*.tsv <ts>/conntrack.log
```
Гипотезы H1 (DNS)/H2-H3 (nftset-route)/H4 (mihomo flap) и A/B-откат на .14 — в
[`tools/reconnect-debug/README.md`](../tools/reconnect-debug/README.md). Эпик: beads `mt-ejz`.

## Dual-upstream DNS — настройка и проверка

В MagiTrickle `dnsProxy.fallbackUpstream` (опционально):
```yaml
dnsProxy:
    upstream:
        address: 127.0.0.1
        port: 6868              # primary — mihomo (in-group домены)
    fallbackUpstream:
        address: 127.0.0.1
        port: 53                # fallback — ndnproxy/Keenetic (out-of-group)
```
Если `fallbackUpstream` не задан — поведение строго старое (один upstream для всех).

**Кто куда идёт**:
- domain/namespace/wildcard/regex matched в любой группе → `upstream` (mihomo)
- субнет-only группа или вообще не matched → `fallbackUpstream` (ndnproxy)
- subnet-rule routing работает в обоих случаях (post-resolve `processARecord`)

**Проверка что роутинг идёт верно** (cache-busting через random subdomain):
```bash
ssh -p 222 root@<ROUTER_IP> '
RAND=$(date +%s)
curl -s :9090/connections/inner-stats   # baseline

for d in test1-${RAND}.yandex.ru test2-${RAND}.mail.ru; do
  nslookup $d 127.0.0.1:3553 >/dev/null 2>&1
done
echo "после RU:" $(curl -s :9090/connections/inner-stats)   # joined НЕ растёт

for d in test1-${RAND}.discord.com test2-${RAND}.openai.com; do
  nslookup $d 127.0.0.1:3553 >/dev/null 2>&1
done
echo "после in-group:" $(curl -s :9090/connections/inner-stats)   # joined растёт на 1-2
'
```

**Roll-back dual-upstream** (вернуть single-upstream поведение):
```bash
ssh -p 222 root@<ROUTER_IP> '
  cp /opt/var/lib/magitrickle/config.yaml.bak.20260506-161921 /opt/var/lib/magitrickle/config.yaml
  /opt/etc/init.d/S99magitrickle restart
'
```

### Сброс трекера mihomo (если опять полез leak)

```bash
ssh -p 222 root@<ROUTER_IP> 'curl -X DELETE http://127.0.0.1:9090/connections'
```
**ВНИМАНИЕ**: физически закрывает все ESTABLISHED HTTPS-стримы клиентов. Они переоткроются автоматически (браузер ретраит), но visible как короткая «икота».

---

## Сборка и деплой

### MagiTrickle (этот репо)

Сборка **только** через WSL (см. memory `feedback_always_wsl_build`). Готовые скрипты:

```bash
# aarch64
bash scripts/build-aarch64-kn-wsl.sh
# Деплой через ps1
powershell -File scripts/update-router-package.ps1
```

### mihomo (форк патчей)

Локальный клон: `<MIHOMO_SRC>` (`Meta` upstream, ветка `fix/dns-inner-leak`).

```bash
wsl -e bash -c '
  export GOROOT=$HOME/sdk/go1.23.0
  export PATH=$GOROOT/bin:$PATH
  cd <MIHOMO_SRC-WSL>
  make linux-arm64    # → bin/mihomo-linux-arm64 (~32MB)
'
```

Деплой:
```bash
ssh -p 222 root@<ROUTER_IP> '/opt/etc/init.d/S99mihomo stop && \
  cp /opt/sbin/mihomo /opt/sbin/mihomo.stock-$(date +%Y%m%d)'
scp -O -P 222 <MIHOMO_SRC>/bin/mihomo-linux-arm64 \
  root@<ROUTER_IP>:/opt/sbin/mihomo
ssh -p 222 root@<ROUTER_IP> 'chmod +x /opt/sbin/mihomo && /opt/etc/init.d/S99mihomo start'
```

### Roll-back mihomo

```bash
ssh -p 222 root@<ROUTER_IP> '
  /opt/etc/init.d/S99mihomo stop
  cp /opt/sbin/mihomo.stock-20260506 /opt/sbin/mihomo   # подставь актуальную дату
  /opt/etc/init.d/S99mihomo start
'
```

---

## Локальные dev-инструменты

### Ключевые исходники
- **MagiTrickle backend**: `src/backend/` (Go) — netlink, iptables, DNS-MITM, app
- **MagiTrickle frontend**: `src/frontend/` (Svelte 5 + TS + Vite)
- **mihomo (форк)**: `<MIHOMO_SRC>`
  - DNS upstream: `dns/{dot,doh,doq,resolver}.go`
  - Tunnel/dial: `tunnel/dns_dialer.go`, `tunnel/tunnel.go`
  - Tracker: `tunnel/statistic/{tracker,manager}.go`
  - HTTP API: `hub/route/connections.go`
  - Inner proxy chains: `component/proxydialer/proxydialer.go`

### Project hooks (уже установлены)
- `PreToolUse` на Bash блокирует прямой `go build/test/vet/install/run` без префикса `wsl` → `.claude/hooks/block-windows-go.sh`
- `PostToolUse` на Edit/Write для `*.go` → автопроверка `gofmt -l` через WSL → `.claude/hooks/gofmt-check.sh`

### Subagents
- `router-evidence-gatherer` — read-only форензика на роутере, см. `.claude/agents/`
- `Explore`, `general-purpose`, `Plan` — встроенные

### Skills
- `router-snapshot` — snapshot роутера, см. выше
- `update-config`, `commit`, `simplify` и пр. встроенные

---

## Включить debug-логи в mihomo (только для отладки)

```bash
ssh -p 222 root@<ROUTER_IP> '
  sed -i "s/^log-level: silent/log-level: debug/" /opt/etc/mihomo/config.yaml
  /opt/etc/init.d/S99mihomo restart
'
# смотрим стрим:
ssh -p 222 root@<ROUTER_IP> 'timeout 30 curl -s "http://127.0.0.1:9090/logs?level=debug" | grep INNER-DNS'
# вернуть как было:
ssh -p 222 root@<ROUTER_IP> '
  sed -i "s/^log-level: debug/log-level: silent/" /opt/etc/mihomo/config.yaml
  /opt/etc/init.d/S99mihomo restart
'
```

`debug` шумный — для прода держим `silent`.

---

## Чек-лист «что-то странное на роутере»

1. **Снимок**: `bash .claude/skills/router-snapshot/scripts/snapshot.sh trouble`
2. **Анализ**: `python3 .claude/skills/router-snapshot/scripts/analyze.py <snap>` — посмотреть распределения, top dst/dport
3. **Inner-conn чек**: `curl /connections/inner-stats` — `alive` растёт?
4. **Сетевая аномалия?** — diff с предыдущим snapshot (когда было ок)
5. **Проблема в логике mihomo/magitrickle?** — `curl /logs?level=debug` (mihomo) или `journalctl`/init.d-stderr (magitrickle, если выводит)
6. **Корень в исходниках?** — открой ветку `fix/...` в `<MIHOMO_SRC>`, патчи + сборка через WSL + деплой
7. **Документировать**: добавить запись в `research/<тема>.md`, обновить памятник через `memory/project_*.md`
