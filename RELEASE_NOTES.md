## Главное

**Раздельные DNS upstream'ы для покрытых и непокрытых правилами доменов.** В `config.yaml` появилось опциональное поле `app.dnsProxy.fallbackUpstream` — отдельный адрес второго DNS-апстрима.

- Запрос к домену, у которого есть match по правилам типа `Domain`/`Namespace`/`Wildcard`/`Regex` в любой группе, идёт в **primary upstream** (как было — обычно mihomo).
- Запрос к домену без такого матча идёт в **fallback upstream** (например `127.0.0.1:53` с локальным ndnproxy/dnsmasq).
- Subnet-правила работают post-resolve и не зависят от выбора апстрима — ответ от fallback так же проходит через `processARecord` и попадает в нужный ipset.
- Если `fallbackUpstream` в конфиге не задан — поведение строго прежнее, второй апстрим вообще не открывается.

Зачем: позволяет держать «не наши» домены на быстром локальном/провайдерском резолвере, а через mihomo гонять только то, что реально нужно для маршрутизации.

Пример конфигурации:

```yaml
app:
  dnsProxy:
    upstream:
      address: 127.0.0.1
      port: 5053       # mihomo
    fallbackUpstream:
      address: 127.0.0.1
      port: 53         # ndnproxy / dnsmasq / стандартный резолвер
```

---

**Установка / обновление на Keenetic (Entware):**

```sh
opkg update && opkg install wget-ssl ca-certificates
wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
```
