# Code architecture

ReqSentry is a single Go monitoring engine with a primary CLI workflow and optional dashboard. Its data path is intentionally one way: access logs and optional local health inputs produce monitor-only decisions; the dashboard and integrations read those results but never change incoming traffic.

```text
access logs → watcher → parser → client identity → rolling aggregator
                                            ├→ analysis trigger → detectors → scoring
                                            │                              └→ SQLite / JSONL / notification destinations / CLI reports
                                            └→ dashboard API and shared SSE stream
Linux health / PHP-FPM ──────────────────────┘
```

## Where to change behavior

| Area | Package | Responsibility |
| --- | --- | --- |
| Entry point and CLI | `cmd/reqsentry` | Load configuration, run the engine, report/filter IP findings, replay logs, test notifications, toggle the UI, and clean local data. |
| Configuration | `internal/config` | Apply defaults, reject unsafe values, and resolve secrets from the environment or systemd credentials. |
| Input | `internal/watcher`, `internal/parser`, `internal/clientidentity`, `internal/correlation` | Follow log rotation with saved offsets, parse configured combined/JSON/logfmt and error formats, resolve trusted proxy/allowlist policy, and attach bounded error associations without changing scores. |
| In-memory state | `internal/aggregator` | Maintain exact rolling server/site counters and bounded tracked-IP evidence. The same state feeds detection and live dashboard views. |
| Decisions | `internal/serverhealth`, `internal/phpfpm`, `internal/detector`, `internal/scoring` | Sample optional resource context, calculate explainable signals, and assign monitor-only decisions. |
| Persistence and notifications | `internal/storage`, `internal/output`, `internal/maxmindupdate`, `internal/enrichment` | Save SQLite history and offsets, write local output, send optional Slack/Teams/SNS alerts, and maintain local MaxMind data. |
| Dashboard | `internal/dashboard` | Apply allowlist/authentication, expose bounded read-only API routes, and publish one aggregate SSE update for all viewers. `assets/` contains the embedded UI. |
| Orchestration | `internal/daemon`, `internal/replay` | Connect components for live monitoring or deterministic historical replay. |

The parser's configured site ID is authoritative; a request's `Host` header is supporting evidence. The aggregator retains 121 one-second buckets for closed-window analysis; live views remain bounded to their requested horizon. It preserves exact basic request/status totals even when tracked-IP detail reaches a configured cap or degraded mode. Path, query, User-Agent, and IP lists are samples with coverage labels; they are not complete historical inventories. See [dashboard data semantics](dashboard.md) and [storage behavior](storage-output.md).

## Concurrency and failure boundaries

- Watchers checkpoint file identity and offset. Rotation, truncation, a missing file, and an optional collector failure do not stop monitor mode.
- Deep analysis reads bounded snapshots outside the log parser. Scoring has no enforcement code path. The sink fanout keeps local persistence separate from independent optional destination delivery.
- SQLite dashboard reads use a separate read-only connection. API queries have row, range, and time limits. The dashboard rejects excess concurrent requests rather than queuing them behind the ingestion path.
- The SSE publisher builds one bounded snapshot per interval. Every viewer has one replaceable queued event; a slow viewer receives the newest state or disconnects. The dashboard can be disabled without changing log ingestion.
- The local Compose image runs Nginx and ReqSentry together for development. Production installation uses a systemd service; the Compose supervisor is not a deployment requirement.

## Safe change workflow

1. Update the relevant package and its focused tests. For detector or threshold changes, include normal and adversarial fixtures so false-positive behavior is visible.
2. Run `go test -race ./...` and `go vet ./...`. Use [replay validation](validation.md) to compare decisions on representative logs before changing production thresholds.
3. For dashboard changes, exercise the local Compose fixture and [k6 scenarios](../tests/k6/README.md), then check API coverage labels, denied routes, saved incidents, and resource use.
4. Keep the root [README](../README.md) short and update the appropriate operations guide when behavior or limits change.

The [original project brief](project-brief.md) explains the design goals. [Validation](validation.md) records delivery evidence and open production requirements.

Structured source selection is shared by live monitoring, preview, replay, and optional crash recovery. Error events remain distinct from requests; `internal/correlation` stores independent bounded request/error rings and produces immutable incident context. Notification workers own routing/retries and never perform provider work in the request hot path. [Structured logs](structured-logs.md), [error correlation](error-correlation.md), [notifications](notifications.md), and [storage/recovery](storage-output.md) define their contracts and limits.
