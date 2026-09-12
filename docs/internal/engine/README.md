# internal/engine

Интерфейс движка правил, не зависящий от того, Coraza за ним или libmodsecurity. Отображение
сообщения инспекции на вызовы движка одинаково для обоих кандидатов — это прямая таблица из
docs/research/modsecurity-inspector.md#отображение-сообщения-на-api-движка (`docs/research/modsecurity-inspector.md`),
и интерфейс этого пакета следует ей по пяти фазам:

| Метод (план) | Соответствие в libmodsecurity v3 | Соответствие в Coraza v3 |
| --- | --- | --- |
| `ProcessConnection` + `ProcessURI` | `msc_process_connection`, `msc_process_uri` | `tx.ProcessConnection`, `tx.ProcessURI` |
| `AddRequestHeader*` → `ProcessRequestHeaders` | `msc_add_request_header`, `msc_process_request_headers` | `tx.AddRequestHeader`, `tx.ProcessRequestHeaders` |
| `WriteRequestBody` → `ProcessRequestBody` | `msc_append_request_body`/`msc_request_body_from_file`, `msc_process_request_body` | `tx.WriteRequestBody`/`tx.ReadRequestBodyFrom`, `tx.ProcessRequestBody` |
| `AddResponseHeader*` → `ProcessResponseHeaders` | `msc_add_response_header`, `msc_process_response_headers` | `tx.AddResponseHeader`, `tx.ProcessResponseHeaders` |
| `WriteResponseBody` → `ProcessResponseBody` | `msc_append_response_body`, `msc_process_response_body` | `tx.WriteResponseBody`, `tx.ProcessResponseBody` |

Каждый вызов, способный прервать обработку, возвращает вмешательство — структуру из пяти полей
(`status`, `pause`, `url`, `log`, `disruptive`), одинаковую по смыслу у обоих движков; перевод этой
структуры в вердикт протокола — обязанность `internal/verdict`, а не этого пакета. `internal/engine`
не решает, блокировать ли запрос, он только исполняет фазы и возвращает то, что вернул движок,
включая список сработавших правил для `audit`.

Две точки входа, по одной на фазу: `Apply` доводит транзакцию до фаз 1–2, `ApplyResponse` — до
фаз 3–4 поверх восстановленного контекста запроса. Разница между ними не в наборе вызовов, а в том,
чей результат считается: `ApplyResponse` отбрасывает вмешательства фаз 1–2 (их вердикт уже вынесен
на фазе запроса), отдаёт находки от третьей фазы и берёт исходящий счёт `AnomalyOutbound()` — свои
переменные CRS и свой порог. Складывать входящий счёт с исходящим нельзя: входящий модуль уже один
раз применил.

Транзакция создаётся и уничтожается в пределах одного сообщения (`NewTransactionWithID(rid)`,
`ProcessLogging()`, `Close()`) — согласно stateless-контракту инспектора, см.
[«Главное ограничение»](../../README.md#главное-ограничение-stateless-вызов-вместо-транзакции) в
основном README.

Реализация на старте — только [`coraza/`](coraza/README.md), по рекомендации
`docs/research/seclang-engines.md`. Решение по второй
реализации не принято; если она понадобится, для неё заводится каталог `modsecurity/` рядом,
интерфейс уже на это рассчитан.
