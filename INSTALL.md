# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus. It needs no address
and no service, and adding a copy touches neither the protection node nor the configuration. Usually
`placitum-core` installs it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the `waf.req.modsec` queue, audit, log, profile generations |
| Buffer Redis | yes | request and response bodies by locator; an unreachable buffer stops the start |
| Internal Redis | yes | generation blobs: profiles, data files, policies |
| Controller | yes | sends profiles as generations |
| `geo` | for network and system writes | announcements and AS number by address |

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `REDIS_URL`, `REDIS_INTERNAL_URL` | from `inspector.conf` | buffer and internal Redis |
| `WAF_MODSEC_SUBJECT` | `waf.req.modsec` | subscription; must match `subject=` in the inspector declaration |
| `WAF_MODSEC_NAME` | `modsec` | name in the inspector registry and the presence frame |
| `WAF_MODSEC_QUEUE` | the name | queue group on the bus |
| `WAF_MODSEC_PROFILES` | `./profiles`; `/app/profiles` in the image | profiles used until the first generation |
| `WAF_MODSEC_DATA` | `<profiles>.applied`; `/var/lib/waf/modsec` in the image | where rollout puts the applied generation |
| `WAF_MODSEC_STATUS_MAP` | `./status_map.yaml`; `/app/status_map.yaml` in the image | engine status to deny page name |
| `WAF_MODSEC_DENY_RULE_IDS`, `WAF_MODSEC_DENY_TAGS` | empty | rules and tags whose match is a deny, not a score contribution |
| `WAF_MODSEC_RESUME_MAX` | `4 × queue_max` | how many open transactions wait for their response phase |
| `WAF_MODSEC_RESUME_TTL` | `30s` | how long an open transaction waits |
| `WAF_MODSEC_SECRETS` | empty | secrets directory, if profiles refer to secrets |
| `WAF_MODSEC_GEO_ADDR` | empty | network directory (`host:port`); empty makes network and system writes answer `error` |
| `WAF_MODSEC_GEO_TIMEOUT`, `WAF_MODSEC_GEO_NEG_MAX` | `500ms`, `0` | network directory wait within the message budget and negative cache limit |
| `WAF_MODSEC_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_MODSEC_WORKERS` | number of CPUs | engine workers |
| `WAF_MODSEC_QUEUE_DEPTH`, `WAF_MODSEC_QUEUE_FULL`, `WAF_MODSEC_QUEUE_EXPAND` | `256`, `drop`, `off` | queue and overflow behaviour; the same through `inspector.conf` |
| `WAF_MODSEC_RESERVE_MS`, `WAF_MODSEC_MIN_BUDGET_MS` | `2`, `3` | reserve for the answer and the minimum budget below which the engine does not start |
| `WAF_MODSEC_VERSIONS` | `2` | accepted message schema versions |
| `WAF_MODSEC_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_LOG_SHIP` | `on` | whether the process log goes to the bus; `off` keeps it on stdout only |

## Docker Compose

```yaml
services:
  inspector-modsec:
    image: placitum/modsec
    scale: 5
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_MODSEC_GEO_ADDR: geo:50051
    depends_on: [nats, redis, redis-internal]
```

Run as many copies as you need: the bus queue spreads messages between them. CRS is the most
expensive inspector and is bound by CPU.

## Checking

The inspector has no port of its own, so it is checked the way it works, with a bus message. The
probe is in the image and in the `HEALTHCHECK`:

```sh
docker exec <container> modsec-probe --quiet --timeout 1s --uri /healthcheck
docker exec <container> modsec-probe --uri "/?id=1%27+or+1%3D1--"
```

The second call should come back with a score. The `start-period` of the health check is 20 seconds:
CRS compiles at start, and there is no subscription until it is done.

A healthy start logs the loaded profiles, the bus and buffer connections, the queue name, the worker
count, then `desired watch on` and the applied generation.

## Pitfalls

- **An unknown profile is an error, not a fallback to `default`.** Otherwise a mismatch between the
  route tag and the loaded sets would let traffic through unchecked.
- **Compiling the rule set takes CPU.** When several copies start at once, the first traffic until
  compilation ends meets the deadline policy, not a verdict.
- **A truncated body is not checked.** A route with `waf_body_limit … trim` gets `error` with
  `MODSEC_BODY_TRUNCATED` from modsec, not a check.
