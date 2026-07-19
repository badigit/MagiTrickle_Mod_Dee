---
name: router-snapshot
description: Снимок состояния продакшен-роутера <ROUTER_IP> (conntrack, mihomo /connections, magitrickle, listeners, конфиги) в один ssh-проход. Сохраняет в .tmp/snapshots/<ts>/, умеет diff'ить два snapshot'а. Используй когда пользователь просит "посмотри что на роутере", при дебаге сетевых аномалий, при подозрении на утечки коннектов или DNS/прокси-проблемы.
---

# router-snapshot

Один ssh-batch собирает всё состояние роутера, кладёт локально в `.tmp/snapshots/<timestamp>/`, и прогоняет анализатор.

## Когда использовать
- Пользователь спрашивает «что сейчас на роутере?», «много соединений», «проверь mihomo/magitrickle»
- Перед/после изменения конфига (mihomo, magitrickle) — чтобы было с чем diff'нуть
- При подозрении на утечку соединений (Inner-conns в mihomo, conntrack growth)
- В начале и в конце сессии дебага — измеримая разница

## Инвокация

**Создать снимок:**
```
bash .Codex/skills/router-snapshot/scripts/snapshot.sh [метка]
```
`метка` — опциональное имя; иначе `<YYYYMMDD-HHMMSS>`. Возвращает путь к каталогу со снимком.

**Анализ снимка:**
```
python3 .Codex/skills/router-snapshot/scripts/analyze.py .tmp/snapshots/<ts>/
```

**Diff двух снимков:**
```
python3 .Codex/skills/router-snapshot/scripts/analyze.py .tmp/snapshots/<ts1>/ .tmp/snapshots/<ts2>/
```

## Что в снимке
| Файл | Что внутри |
|---|---|
| `conntrack-count` | текущее значение `nf_conntrack_count` |
| `conntrack.txt` | полный `conntrack -L` |
| `listeners-tcp.txt` / `listeners-udp.txt` | `netstat -tlnp` / `-ulnp` |
| `ss-tcp.txt` | `ss -tnp` (FD-уровневая правда) |
| `mihomo-connections.json` | `GET /connections` API |
| `mihomo-version.json` | `GET /version` |
| `magitrickle-config.yaml` | `/opt/var/lib/magitrickle/config.yaml` |
| `mihomo-config.yaml` | `/opt/etc/mihomo/config.yaml` |
| `ps.txt` | `ps w` |
| `meta.txt` | timestamp + uptime + label |

## Тонкости

- На роутере **нет python3** — анализ всегда локальный, на Windows. Скрипт использует `PYTHONIOENCODING=utf-8` чтобы не упасть на эмодзи в chains.
- `conntrack -L` может вернуть 30-50 KB на оживлённом роутере — не тащить в основной контекст; читать через analyze.py для агрегатов.
- `ss -tnp` на BusyBox роутере может не показать имя процесса — для соответствия PID→имя смотри `listeners-tcp.txt`.
- При сравнении двух снимков diff показывает: дельту conntrack, рост/убыль Inner-коннектов в mihomo по dst, новые/исчезнувшие listeners.

## Пример вывода analyze.py (single snapshot)
```
=== .tmp/snapshots/20260506-110000/ ===
conntrack: 616/32768
mihomo /connections: 864 total
  by type:    Inner=788  Redir=67  TProxy=6  ...
  by network: tcp=855  udp=6
  top dst ports: 853:788  443:67  80:6
  age buckets (Inner/853):  <1m:0  1-5m:0  5-60m:10  1-6h:0  6-12h:40  12-24h:0  24-48h:738
listeners new vs default: zerotier(:44424), mihomo(:6868,:7890,:7891,:9090)
```
