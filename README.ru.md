# Placitum modsec

[English](README.md) · Русский

Инспектор правил Placitum: OWASP Core Rule Set на движке Coraza. Смотрит запрос и ответ — заголовки,
строку запроса, тело — и отвечает вердиктом со счётом.

CRS встроен в бинарник, с диска читаются только профили: они и отличают одну установку от другой.
Coraza — чистый Go, включая регулярные выражения, поэтому образ статический, а катастрофического
бэктрекинга у движка нет.

```
модуль ──► waf.req.modsec ──►  modsec  ──► allow | score | deny
                                 │
                                 ├── профиль: наборы SecLang поверх CRS
                                 ├── тело: из буфера по локатору
                                 └── сигналы соседей: масштаб счёта, пропуск проверки
```

## Как он оценивает

Каждое сообщение становится транзакцией движка. Движок работает в `SecRuleEngine DetectionOnly`:
инспектор сообщает уверенность, а блокирует nginx по `waf_score_deny` своей фазы. Аномальный счёт CRS
калибруется в счёт 0–100: `min(100, round(100 × anomaly / threshold / 2))`, то есть одна
критическая находка (5 баллов при штатном пороге 5) даёт 50, а двойной порог — 100. Сырые
`crs_anomaly_score` и `crs_threshold` остаются в событии аудита, а `crs_would_block` показывает, что
сделал бы стоковый CRS.

Отказ, не зависящий от счёта, настраивается отдельно: `WAF_MODSEC_DENY_RULE_IDS` и
`WAF_MODSEC_DENY_TAGS` называют правила, срабатывание которых — блокировка, а не вклад в счёт.
Вмешательство движка сопоставляется странице блокировки через `status_map.yaml` (403 и 406 — `blocked`,
400 — `malformed`); код ответа из правила клиенту не уходит.

**Тело.** Тело крупнее порога инлайна приходит по локатору из буфера. Усечённое тело не
проверяется вовсе: префикс JSON или XML — уже не документ, правила промолчат, и чистый `allow` соврал
бы. Ответ — `error` с `MODSEC_BODY_TRUNCATED`; недоступное тело — `error` с
`MODSEC_BODY_UNAVAILABLE`. Исход выбирает маршрут через `waf_exception … inspector`.

**Фаза ответа** идёт в той же транзакции. С `keep=on` на вызове запроса инспектор держит транзакцию
открытой и отвечает своим subject; вызов ответа с `resume=` возвращается к ней, и фазы 3–4
доигрываются поверх настоящего состояния фаз 1–2. Если состояния нет (копия умерла, реестр переполнен,
срок вышел), `resume=prefer` собирает транзакцию заново по копии запроса, а `resume=require` отвечает
`error` с `MODSEC_RESUME_LOST`. В аудите оба пути различимы полем `resumed`.

**Кадры WebSocket** от клиента оцениваются синтетической транзакцией: POST на адрес рукопожатия с
заголовками рукопожатия и одним аргументом `frame=<полезная нагрузка>`, так что CRS видит содержимое
кадра в `ARGS_POST:frame`. Двоичные кадры пропускаются с `MODSEC_FRAME_BINARY`.

## Маршрут

```nginx
waf_inspector ip     subject=waf.req.ip;
waf_inspector modsec subject=waf.req.modsec profile=strict;

location /api/ {
    waf_capture request headers args body;
    waf_body_limit request 256k block;
    waf_inspect request ip     wave=0 timeout=5ms;
    waf_inspect request modsec wave=1 timeout=25ms keep=on;
    waf_deadline request 40ms;

    waf_hold response gate;
    waf_capture response headers body=64k;
    waf_inspect response modsec wave=0 timeout=100ms resume=prefer;
    waf_deadline response 200ms;

    proxy_pass http://api;
}
```

В волне 0 `modsec` не место: она для дешёвых проверок вроде инспектора адреса.

## Профили

Профиль — каталог файлов SecLang `profiles/http/<имя>/`, а имя — это `route.profile` из сообщения.
Файлы включаются в лексическом порядке:

| Файл | Что задаёт |
| --- | --- |
| `00-engine.conf` | настройки движка: `DetectionOnly`, разбор тела ответа |
| `10-crs-setup.conf` | уровень паранойи и оба порога |
| `20-crs.conf` | сам CRS: `REQUEST-*.conf` и `RESPONSE-*.conf` |
| `30-policy.conf` | локальная политика поверх |

В образе лежит только `default`: CRS, уровень паранойи 1, без `attack-dos` — флуд до шины режет
локальный слой модуля. Без `default` процесс не стартует. Маршрут, который называет незагруженный
профиль, получает `error` с `MODSEC_UNKNOWN_PROFILE`, а не откат на `default`: чужой набор правил —
проверка не того.

Профили приходят от контроллера поколением: новый набор компилируется рядом с боевым и подменяется
атомарно, некомпилирующийся набор не применяется. Файлы данных SecLang для `@pmFromFile` и
`@ipMatchFromFile` лежат рядом с `*.conf` профиля, относительные имена считаются от его каталога.

### Сигналы соседей и строки по исходу

`policy.yaml` в каталоге профиля держит обе стороны канала действий:

```yaml
prior:                          # чьи сигналы применять
  - from: ip                    # отправитель по имени; "*" не принимается: оба глагола ослабляют
    accept: [threshold, skip]
    codes: [IP_ALLOWLIST]       # пусто — любая причина

outcomes:                       # что инспектор сам говорит соседям
  - on: score                   # deny | allow | score | rule | overload
    at: 30                      # счёт, который уходит модулю, >= 30
    to: captcha
    do: challenge
    code: MODSEC_SUSPECT
  - on: score
    at: 5
    below: true                 # сравнение в другую сторону: < 5
    to: vlai
    do: skip
  - on: deny
    list: api_abusers           # запись субъекта в динамический набор
    write: net                  # addr | net | net_all | asn
    ttl: 1h
  - on: overload                # очередь заполнена не меньше чем на 60% или запрос сброшен
    at: 60
    list: shed_clients
    ttl: 10m
  - on: rule                    # сработало правило: номер и метка находки
    rules: ["942000-942999"]
    tags: [paranoia-level/1]
    do: mark
    marker: sqli-pl1
```

- `threshold` умножает счёт, который уходит модулю, на `1 + delta/100` (сумма держится в пределах
  −100..900); порог маршрута не двигается. `skip` отвечает `allow` с `MODSEC_SKIPPED`, не запуская
  движок, на обеих фазах.
- `on: score` сравнивает счёт, который уходит модулю, — уже после коэффициентов соседей.
- `on: rule` смотрит на находки фазы при любом вердикте: правило с номером из `rules` (`"942100"`,
  `"942000-942999"`) и меткой из `tags` байт в байт, как их отдаёт Coraza (`attack-sqli`,
  `paranoia-level/1`). Хоть один фильтр обязателен. Правило без сообщения находкой не считается.
  Повод, если у строки своего нет, — `CRS_RULE_<номер>`.
- `on: overload` срабатывает с `at` процентов заполнения очереди (25..100; без `at` — только на
  сброшенном запросе) и только на фазе запроса.
- Строка делает одно: `to` с `do` — сигнал соседу, `list` с `ttl` — запись в динамический набор. После
  блокировки сигналы соседям не доходят, а записи в наборы, маркеры и журнал работают. `net`, `net_all`
  и `asn` требуют кодер гео (`WAF_MODSEC_GEO_ADDR`); молчащий кодер — `error` с
  `MODSEC_GEO_UNAVAILABLE`.

Исход каждого доставленного сигнала (`applied` или `no_rule`) и значения `score_raw`,
`score_scale_percent`, `score_scaled` уходят в событие аудита.

## Коды причин

| Код | Что значит |
| --- | --- |
| `MODSEC_SKIPPED` | сигнал соседа `skip` снял проверку |
| `MODSEC_UNKNOWN_PROFILE` | маршрут называет незагруженный профиль |
| `MODSEC_BODY_TRUNCATED` | тело — префикс, и оно не проверяется |
| `MODSEC_BODY_UNAVAILABLE` | тело не пришло из буфера |
| `MODSEC_RESUME_LOST` | `resume=require`, а состояния транзакции нет |
| `MODSEC_FRAME_BINARY` | двоичный кадр WebSocket, пропущен |
| `MODSEC_GEO_UNAVAILABLE` | строка пишет сеть или систему, а кодер молчит |
| `MODSEC_SCORE_RANGE` | калиброванный счёт вышел за пределы шкалы |
| `MODSEC_QUEUE_LIMIT`, `MODSEC_DEADLINE_EXCEEDED` | перегрузка: очередь полна или бюджет вышел |
| `MODSEC_UNSUPPORTED_VERSION`, `MODSEC_MALFORMED_REQUEST`, `MODSEC_PHASE_NOT_SUPPORTED`, `MODSEC_INTERNAL_ERROR` | сообщение, которое инспектор обработать не может |

Что нужно рядом и все настройки — в [INSTALL.ru.md](INSTALL.ru.md).

## Лицензия

[Placitum License Agreement](LICENSE.md). Перевод на русский лежит в [LICENSE.ru.md](LICENSE.ru.md),
юридическую силу имеет английский текст.
