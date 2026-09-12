# internal/config

Конфигурация из переменных окружения, по образцу
[../../test/README.md#переменные-окружения](../../test/README.md#переменные-окружения), но со
своими значениями по умолчанию и дополнительными полями, которых нет у тестового инспектора —
Redis и секреты нужны только здесь.

Планируемые переменные:

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | Адреса шины через запятую |
| `WAF_MODSEC_SUBJECT` | `waf.req.modsec` | Subject подписки |
| `WAF_MODSEC_NAME` | `modsec` | Имя инспектора; ответ всегда использует имя из пришедшего сообщения, см. предупреждение в [../../test/README.md](../../test/README.md#переменные-окружения) |
| `WAF_MODSEC_QUEUE` | значение `WAF_MODSEC_NAME` | Имя queue group |
| `WAF_MODSEC_PROFILES` | `./profiles` | Bootstrap-каталог профилей (`http/`), внутри — одна подпапка на профиль |
| `WAF_MODSEC_DATA` | `<profiles>.applied` | Записываемое дерево после `send`; рестарт без KV поднимает его, если есть `http/default` |
| `WAF_MODSEC_CONF` | `./inspector.conf` | Файл очереди: `queue_max`, `queue_full` (`drop`\|`wait`), `queue_expand` (`off`\|`ask`, пока не отправляется) |
| `WAF_MODSEC_QUEUE_DEPTH` | из файла или `workers * 4` | Перекрывает `queue_max`; расчёт по умолчанию — см. `internal/queue` |
| `WAF_MODSEC_QUEUE_FULL` | из файла или `drop` | Перекрывает `queue_full` |
| `WAF_MODSEC_QUEUE_EXPAND` | из файла или `off` | Перекрывает `queue_expand` |
| `WAF_MODSEC_RESERVE_MS` | `2` | Резерв времени на сериализацию ответа, вычитается из `deadline_ms` |
| `WAF_MODSEC_MIN_BUDGET_MS` | — | Порог, ниже которого работа не начинается вообще |
| `REDIS_URL` | `url` блока `redis` из `inspector.conf` | Общий обменник: адрес(а) для чтения тела по локатору `driver=redis` |
| `REDIS_INTERNAL_URL` | `internal` блока `redis` из `inspector.conf`, без него обменник | Внутренний Redis контура: блобы поколения правил (`waf.blob.<sha256>`). Перекрывает директиву файла. Откат на обменник — предупреждение при старте. Промах забора повторяется раз в 30 с |
| `WAF_MODSEC_GEO_ADDR` | пусто | Кодер гео по gRPC (`host:port`, на стенде `geo:50051`) для записей в наборы с `write: net` / `net_all` / `asn`. Пусто — такие записи отвечают `error` (`MODSEC_GEO_UNAVAILABLE`), адрес пишется как обычно |
| `WAF_MODSEC_GEO_TIMEOUT` | `500ms` | Сколько ждать кодер на промахе, в бюджете сообщения; сам ответ стоит доли миллисекунды, бюджет — на дурную минуту сети ([замер](https://github.com/exemt/placitum-geo/blob/develop/docs/README.md)) |
| `WAF_MODSEC_GEO_NEG_MAX` | `0` | Потолок отрицательного кэша кодера; `0` — умолчание (миллион записей) |
| `WAF_MODSEC_SECRETS` | — | Источник ключей расшифровки тела (`kid` → ключ), не с провода |
| `WAF_MODSEC_STATUS_MAP` | `./status_map.yaml` | Таблица `intervention.status` → символьное имя ответа |
| `WAF_MODSEC_VERSIONS` | `2` | Версии схемы протокола, которые инспектор согласен обрабатывать |
| `WAF_MODSEC_LOG` | `info` | Стартовый уровень журнала: `debug`, `info`, `notice`, `warn`, `error`, `crit`, `alert` (словарь `error_log` nginx без `emerg`). Живьём его правит каталог инспекторов: блок `settings` пака перебивает переменную без рестарта, см. `docs/inspector-config-distribution.md` |
| `WAF_HEARTBEAT_EVERY` | `4s` | Пульс на `WAF_STATUS.inspector.<имя>.<id>` |
| `WAF_MODSEC_RESUME_MAX` | `queue_depth * 4` | Потолок транзакций, припаркованных между фазами. `0` выключает липкость: `continue` не выдаётся, фаза ответа переигрывает фазы 1–2. См. [internal/sticky](../sticky/README.md) |
| `WAF_MODSEC_RESUME_TTL` | `30s` | Срок, который экземпляр обещает модулю в `continue.ttl_ms`. Ждать приходится время апстрима, поэтому число грубое и с запасом |

Ошибка конфигурации (недостижимый Redis при заданном профиле, требующем `full` тело; отсутствующий
файл профиля; отсутствующий подкаталог `profiles/http/default/`) обнаруживается при старте
процесса, а не на первом сообщении — инспектор, который тихо пропускает всё из-за опечатки в пути,
хуже не запустившегося. Отсутствие профиля, названного в `route.profile` конкретного запроса (в
отличие от отсутствия `default`), — не ошибка старта: инспектор отвечает на такое сообщение
`verdict: error`, а исход выбирает `waf_exception` маршрута.
