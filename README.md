<p align="center">
  <img src="https://gitlab.com/magitrickle/magitrickle/-/raw/develop/img/logo256.png" alt="MagiTrickle logo"/>
</p>

MagiTrickle
=======

## Назначение

MagiTrickle (произносится как *Мэджитрикл*) – утилита для точечной маршрутизации сетевого трафика по заданным доменным именам. Представляет собой установочный пакет, устанавливаемый в дополнение к операционной системе маршрутизатора.

<p align="center">
  <img src="https://gitlab.com/magitrickle/magitrickle/-/raw/develop/img/main_screenshot.png" alt="MagiTrickle Screenshot"/>
</p>

Принцип работы основан на подмене основного DNS-сервера через промежуточный компонент без его отключения. Это позволяет перехватывать входящие DNS-запросы, кешировать ответы и сопоставлять IP-адреса с доменными именами. Благодаря этому становится возможной маршрутизация трафика без необходимости очистки DNS-кэша на стороне клиентов. Очистка кэша требуется только при запуске или перезапуске сервиса MagiTrickle, поскольку в этот момент кэш ещё не прогрет, и маршрутизация невозможна до первого запроса к нужному домену.

## Установка

> Это форк [MagiTrickle](https://gitlab.com/magitrickle/magitrickle) с дополнительными возможностями: redir-tproxy, подписки на правила, захват DNS-запросов и др.

```shell
opkg update && opkg install wget-ssl ca-certificates && wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
```

Скрипт автоматически определяет архитектуру, скачивает последнюю версию с GitHub и устанавливает. Для повторного обновления — та же команда.

## Описание типов правил

### Namespace (Именное пространство)

Охватывает указанный домен и все его поддомены.

Например, при записи `example.com` будут обрабатываться:
```
✅ example.com
✅ sub.example.com
✅ sub.sub.example.com
❌ anotherexample.com
❌ example.net
```

### Wildcard (Подстановочный шаблон)

Шаблон с `*` и `?` — позволяет задавать гибкие условия:
- `*` — любое количество любых символов
- `?` — ровно один любой символ

Например, при записи `*example.com` будут обрабатываться:
```
✅ example.com
✅ sub.example.com
✅ sub.sub.example.com
✅ anotherexample.com
❌ example.net
```

### Domain (Точный домен)

Правило применяется только к строго указанному домену, без поддоменов.

Например, при записи `sub.example.com` будут обрабатываться:
```
❌ example.com
✅ sub.example.com
❌ sub.sub.example.com
❌ anotherexample.com
❌ example.net
```

### RegExp (Регулярное выражение)

Для опытных пользователей. Используется парсер [dlclark/regexp2](https://github.com/dlclark/regexp2).

Например, при записи `^[a-z]*example\.com$` будут обрабатываться:
```
✅ example.com
❌ sub.example.com
❌ sub.sub.example.com
✅ anotherexample.com
❌ example.net
```

## Режим redir-tproxy (прозрачный прокси)

MagiTrickle поддерживает маршрутизацию трафика через прозрачный прокси (например, mihomo, sing-box) с использованием комбинации TCP REDIRECT + UDP TPROXY.

### 1. Настройка прокси-сервера

Прокси-сервер (mihomo, sing-box и т.д.) должен принимать перенаправленный трафик (TCP REDIRECT + UDP TPROXY) на выбранном порту.

Пример для mihomo (`config.yaml`):

```yaml
redir-port: 5001
```

В mihomo `redir-port` обрабатывает и TCP (REDIRECT), и UDP (TPROXY) на одном порту.

### 2. DNS через прокси-сервер (опционально)

Если прокси-сервер использует доменные правила для фильтрации трафика (например, блокировка рекламы, разграничение доступа по категориям), то **DNS-upstream в MagiTrickle должен указывать на DNS прокси-сервера**. Это позволяет прокси-серверу сопоставлять IP-адреса с доменами и применять свои правила.

Если прокси-сервер просто направляет весь трафик в один туннель без доменных правил, этот шаг не нужен — DNS можно направить в любой резолвер.

Пример настройки для mihomo с доменными правилами:

В конфиге mihomo:

```yaml
dns:
  enable: true
  listen: 0.0.0.0:6868
  enhanced-mode: redir-host
```

В конфиге MagiTrickle (`config.yaml`):

```yaml
app:
  dnsProxy:
    upstream:
      address: 127.0.0.1
      port: 6868        # DNS-порт mihomo
```

Режим `redir-host` позволяет mihomo сопоставлять IP-адреса с доменами из своего DNS-кэша.

### 3. Настройка MagiTrickle и перезапуск

В конфиге `/opt/var/lib/magitrickle/config.yaml` укажите порт прокси-сервера:

```yaml
netfilter:
  tproxyPort: 5001
```

Где `tproxyPort` — тот же порт, что настроен в прокси-сервере на шаге 1.

```shell
/opt/etc/init.d/S99magitrickle restart
```

После запуска в веб-интерфейсе MagiTrickle появится виртуальный интерфейс **redir-tproxy**. Назначьте его группам правил, трафик которых должен идти через прозрачный прокси.

## Поддержка

* [Официальный сайт](https://magitrickle.dev)
* [Форум на Keenetic Community](https://forum.keenetic.ru/topic/20125-magitrickle)
* [Канал Telegram](https://t.me/MagiTrickle)
* [Чат Telegram](https://t.me/MagiTrickleChat)
* [Финансовая поддержка](https://boosty.to/magitrickle)