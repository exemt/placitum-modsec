# Placitum modsec

English · [Русский](README.ru.md)

Placitum rules inspector: the OWASP Core Rule Set on the Coraza engine. It looks at the request and
the response (headers, query string, body) and answers with a verdict and a score.

CRS is built into the binary; only the profiles are read from disk, because they are what differs
between installations. Coraza is pure Go, regular expressions included, so the image is static and
the engine has no catastrophic backtracking.

```
module ──► waf.req.modsec ──►  modsec  ──► allow | score | deny
                                 │
                                 ├── profile: SecLang sets on top of CRS
                                 ├── body: from the exchange by locator
                                 └── neighbour requests: scale the score, skip the check
```

## How it judges

Each message becomes an engine transaction. The engine runs in `SecRuleEngine DetectionOnly`: the
inspector reports confidence, and nginx denies by `waf_score_deny` of its phase. The CRS anomaly
score is calibrated into a score of 0–100: `min(100, round(100 × anomaly / threshold / 2))`, so one
critical finding (5 points at the default threshold of 5) gives 50, and twice the threshold gives
100. The raw `crs_anomaly_score` and `crs_threshold` stay in the audit event, and
`crs_would_block` shows what stock CRS would have done.

A deny that does not depend on the score is configured apart: `WAF_MODSEC_DENY_RULE_IDS` and
`WAF_MODSEC_DENY_TAGS` name the rules whose match is a deny, not a score contribution. An engine
intervention maps to a deny page through `status_map.yaml` (403 and 406 to `blocked`, 400 to
`malformed`); the status from the rule never reaches the client.

**The body.** A body larger than the inline limit comes by locator from the exchange. A truncated
body is not checked at all: a JSON or XML prefix is no longer a document, the rules would stay
silent, and a clean `allow` would lie. The answer is `error` with `MODSEC_BODY_TRUNCATED`; an
unavailable body is `error` with `MODSEC_BODY_UNAVAILABLE`. The route decides with
`waf_exception … inspector`.

**The response phase** runs on the same transaction. With `keep=on` on the request call the inspector
keeps the transaction open and answers with its own subject; the response call with `resume=` comes
back to it, and phases 3–4 run on the real state of phases 1–2. If the state is gone (the copy died,
the registry was full, the time ran out), `resume=prefer` rebuilds the transaction from the request
snapshot, and `resume=require` answers `error` with `MODSEC_RESUME_LOST`. The audit tells the two
paths apart by `resumed`.

**WebSocket frames** from the client are judged by a synthetic transaction: a POST to the handshake
address with the handshake headers and one argument `frame=<payload>`, so CRS sees the frame content
in `ARGS_POST:frame`. Binary frames are skipped with `MODSEC_FRAME_BINARY`.

## Route

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

`modsec` does not belong in wave 0: that wave is for cheap checks such as the address inspector.

## Profiles

A profile is a directory of SecLang files, `profiles/http/<name>/`, and the name is `route.profile`
from the message. The files are included in lexical order:

| File | What it sets |
| --- | --- |
| `00-engine.conf` | engine settings: `DetectionOnly`, response body parsing |
| `10-crs-setup.conf` | paranoia level and both thresholds |
| `20-crs.conf` | CRS itself: `REQUEST-*.conf` and `RESPONSE-*.conf` |
| `30-policy.conf` | local policy on top |

The image ships only `default`: CRS, paranoia level 1, with `attack-dos` removed because the local
layer of the module handles floods before the bus. `default` must exist, or the process does not
start. A route naming a profile that is not loaded gets `error` with `MODSEC_UNKNOWN_PROFILE`, not a
fallback to `default`: another set of rules is a check of the wrong thing.

Profiles come from the controller as a generation: the new set is compiled next to the live one and
swapped atomically; a set that does not compile is not applied. SecLang data files for `@pmFromFile`
and `@ipMatchFromFile` lie next to the profile's `*.conf`, and relative names are resolved against
the profile directory.

### Neighbour requests and outcome rows

`policy.yaml` in the profile directory holds both sides of the action channel:

```yaml
prior:                          # whose requests to apply
  - from: ip                    # a named sender; "*" is rejected: both verbs weaken the check
    accept: [threshold, skip]
    codes: [IP_ALLOWLIST]       # empty means any reason

outcomes:                       # what the inspector itself tells the neighbours
  - on: score                   # deny | allow | score | rule | overload
    at: 30                      # the score that goes to the module is >= 30
    to: captcha
    do: challenge
    code: MODSEC_SUSPECT
  - on: score
    at: 5
    below: true                 # compare the other way: < 5
    to: vlai
    do: skip
  - on: deny
    list: api_abusers           # write the subject to a live set
    write: net                  # addr | net | net_all | asn
    ttl: 1h
  - on: overload                # the queue is at least 60% full, or the request was dropped
    at: 60
    list: shed_clients
    ttl: 10m
  - on: rule                    # a rule fired: number and tag of a finding
    rules: ["942000-942999"]
    tags: [paranoia-level/1]
    do: mark
    marker: sqli-pl1
```

- `threshold` scales the score sent to the module by `1 + delta/100` (the sum is kept within
  −100..900); the route threshold does not move. `skip` answers `allow` with `MODSEC_SKIPPED`
  without running the engine, in both phases.
- `on: score` compares the score that goes to the module, after neighbour factors.
- `on: rule` looks at the findings of the phase, whatever the verdict: a rule whose number is in
  `rules` (`"942100"`, `"942000-942999"`) and whose tag is in `tags`, byte for byte as Coraza gives
  them (`attack-sqli`, `paranoia-level/1`). At least one filter is required. Rules without a message
  are not findings. The reason code, when the row has none, is `CRS_RULE_<number>`.
- `on: overload` fires from `at` percent of queue fill (25..100; without `at` only on a dropped
  request), and only in the request phase.
- A row does one thing: `to` with `do` asks a neighbour, `list` with `ttl` writes to a live set.
  After a deny no neighbour request is delivered, but set writes, marks and records still work.
  `net`, `net_all` and `asn` need the geo coder (`WAF_MODSEC_GEO_ADDR`); a silent coder means `error`
  with `MODSEC_GEO_UNAVAILABLE`.

The outcome of each delivered request (`applied` or `no_rule`) and `score_raw`,
`score_scale_percent`, `score_scaled` go to the audit event.

## Reason codes

| Code | Meaning |
| --- | --- |
| `MODSEC_SKIPPED` | a neighbour's `skip` request switched the check off |
| `MODSEC_UNKNOWN_PROFILE` | the route names a profile that is not loaded |
| `MODSEC_BODY_TRUNCATED` | the body is a prefix and is not checked |
| `MODSEC_BODY_UNAVAILABLE` | the body did not come from the exchange |
| `MODSEC_RESUME_LOST` | `resume=require`, and the transaction state is gone |
| `MODSEC_FRAME_BINARY` | a binary WebSocket frame, skipped |
| `MODSEC_GEO_UNAVAILABLE` | a row writes a network or a system, and the coder is silent |
| `MODSEC_SCORE_RANGE` | the calibrated score fell outside the range |
| `MODSEC_QUEUE_LIMIT`, `MODSEC_DEADLINE_EXCEEDED` | overload: the queue is full or the budget is gone |
| `MODSEC_UNSUPPORTED_VERSION`, `MODSEC_MALFORMED_REQUEST`, `MODSEC_PHASE_NOT_SUPPORTED`, `MODSEC_INTERNAL_ERROR` | a message the inspector cannot handle |

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
