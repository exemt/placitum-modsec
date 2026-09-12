# internal/desired

Поколение правил из JetStream KV `WAF_DESIRED/policy/modsec`. Спека —
`docs/inspector-config-distribution.md`.

Контроллер пишет манифест по `send`. Этот пакет смотрит ключ, пишет дерево в
`WAF_MODSEC_DATA`, компилирует и зовёт `rules.ReloadFrom`. Провал — откат
каталога, `apply=apply_failed`, в пульсе старый hash.

CRS сюда не входит: его по-прежнему отдаёт образ через `@owasp_crs/...`.
