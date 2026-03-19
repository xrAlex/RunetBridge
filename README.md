# 🌉 RunetBridge
Набор правил `mihomo` для жизни в сломанном рунете

Для тех, кто не хочет при каждой волне блокировок разбираться что отвалилось

Идея простая:

- весь трафик по умолчанию уходит в прокси
- напрямую идут только российские сервисы, которым нужна низкая задержка или российский IP
- списки собираются из внешних rule-set'ов и локальных исключений

По тенденции РКН продолжит ломать интернет дальше, поэтому стратегия "один раз настроил и забыл" по умолчанию работает всё хуже

## 📦 Что здесь есть 

- `dist/common/ru.yaml` — итоговыe ruleset'ы
- `providers/` — правила от внешних провайдеров
- `custom/` — правила созданные специально для этого репозитория
- `conf.yaml` — конфигурация для сборщика что и откуда брать
- `mihomo_sample/` — примеры конфигов `mihomo`
- `main.go` / `builder.go` — код сборщика

## 🔀 Логика маршрутизации

Подход "всё в `DIRECT`, а проксировать только чатжпт и телегу" становится все менее рабочим

Базовый сценарий использования такой:

1. `MATCH` отправляет весь трафик в прокси.
2. Российские сервисы и чувствительные к задержке ресурсы выносятся в отдельные rule-set
3. Эти rule-set'ы направляются в `DIRECT` или в отдельную группу, если вы хотите вручную переключать поведение

<details>
<summary>Нюансы такого подхода</summary>

- В некоторых играх пинг может вырасти, если их трафик не попал в `DIRECT` и ушёл через прокси
- Если `mihomo` стоит на роутере, торренты с устройств в сети по умолчанию тоже могут качаться через VPN (для этого есть отдельный набор правил torrent, но он не идеален)
- На роутере это влияет сразу на весь трафик в доме, поэтому ваш умный чайник желательно определить по IP и не проксировать его вообще
- Если у вас клиент стоит на ПК, то не используй ничего кроме набора правил из `common`, а задавайте правила по имени процесса
- Коорпоративные сервисы, для тех кто работает из дома тоже нужно ручками вносить в маршрутизацию, чтобы не светить ваш IP другой страны

</details>

## 🚀 Быстрый старт

Пример подключения в `mihomo`:

```yaml
rule-providers:
  ru-common:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/xrAlex/RunetBridge/refs/heads/main/dist/common/ru.yaml"
    path: ./providers/ru-common.yaml
    interval: 86400

  ru-games:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/xrAlex/RunetBridge/refs/heads/main/dist/games/ru.yaml"
    path: ./providers/ru-games.yaml
    interval: 86400

  ru-torents:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/xrAlex/RunetBridge/refs/heads/main/dist/torents/ru.yaml"
    path: ./providers/ru-torents.yaml
    interval: 86400

rules:
  - GEOIP,private,DIRECT,no-resolve
  - RULE-SET,ru-common,DIRECT
  - RULE-SET,ru-games,GAMES
  - RULE-SET,ru-torents,TORRENTS
  - MATCH,PROXY
```

## 🧩 Источники

- `blackmatrix7`
- `v2fly/domain-list-community`
- `itdoginfo/allow-domains`
- `hxehex/russia-mobile-internet-whitelist`
- `HYBB-rash/trackers_list_rule`

После этого правила приводятся к формату `mihomo` и собираются в итоговые `dist/<group>/ru.yaml`

## 🤝 Вклад

PR с новыми правилами приветствуются, особенно если это:

- игры, лаунчеры, античиты и CDN с чувствительностью к задержке
- стриминговые сервисы и медиа-площадки
- российские сервисы, которым нужен российский IP
- любые сервисы, которые на практике работают лучше через `DIRECT`, чем через прокси
