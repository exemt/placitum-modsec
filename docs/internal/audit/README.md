# internal/audit

Событие `kind=inspector` в поток `WAF_AUDIT`. Схема и join по `node`+`rid` —
`docs/audit.md`.

Пишется **после** ответа в inbox: обычный `PUB` на
`waf.audit.inspector.<name>`. Промах потока не двигает дедлайн волны. Поле
`audit` ответа уезжает сюда целиком — модуль его не хранит.
