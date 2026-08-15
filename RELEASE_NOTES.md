## Исправлено

- **Переключатель приоритета direct-групп больше не откатывается.** В .16 выбор в настройках менялся только на вид: запрос на сервер не уходил, и после перезагрузки страницы возвращался прежний режим. Кто ставил режим вручную в `config.yaml` или через API — тех не касалось, там всё работало.

---

**Установка / обновление на Keenetic (Entware):**

```sh
opkg update && opkg install wget-ssl ca-certificates
wget -qO- https://raw.githubusercontent.com/badigit/MagiTrickle_mod_badigit/mod_badigit/scripts/install.sh | sh
```

Дальше можно обновляться прямо из веб-интерфейса, кнопкой «Обновить».
