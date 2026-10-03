# Replay and V1 validation

ReqSentry can replay historical combined, JSON, and logfmt access logs plus configured error sources through the live parser, trusted-proxy resolution, rolling aggregator, HTTP and impact rules, and scoring engine. Replay makes no HTTP requests, sends no Slack/Teams/SNS alerts, and takes no enforcement action. It emits one JSON incident per line and a final summary containing parsed, malformed, allowlisted, dropped, error, incident, and per-source availability counts.

## Synthetic coverage

The test suite covers normal browsing and API traffic, high-404 and path enumeration, query enumeration, method scans, cross-site scans, burst and sustained rates, high 5xx and redirect ratios, and expensive lower-rate requests. It also covers Nginx and Apache formats, trusted and untrusted proxy headers, allowlists, IPv6, rotation, truncation, crash and clean restart offsets, unavailable PHP-FPM and MaxMind data, invalid MaxMind replacements and persistent retry, and Slack cooldown/threshold behavior. The daemon smoke test starts, stops, and restarts against an access log and checks exactly one new entry is ingested per run. The synthetic normal replay fixture produced no incident; the 404 scan fixture produced a monitor-only incident. Query enumeration and lower-rate cost fixtures set a lower watch score in their isolated tests so a single signal is visible as an incident; no default threshold was changed on the basis of these fixtures.

## Reproducible local benchmarks

Measured on an Apple M1 Pro (macOS arm64, Go 1.27.1) on 1 October 2026 with `-benchtime=100x` for replay and `-benchtime=3x` for watcher lag. These are local development measurements, not Linux production guarantees.

| Workload | Input | Replay wall time | Allocated bytes | Data loss |
| --- | ---: | ---: | ---: | --- |
| Normal browsing, 100 client IPs | 1,000 lines over 50 log seconds | 7.41 ms/run (~135k lines/s) | 8.26 MB/run | 0 dropped, 0 malformed |
| One-IP path scan | 10,000 lines over 10 log seconds | 15.77 ms/run (~634k lines/s) | 9.70 MB/run | 0 dropped, 0 malformed |
| Live file watcher batch | 1,000 appended lines | 253 ms from append to complete parse | — | 1,000/1,000 delivered |

The watcher uses a 250 ms polling interval, which dominates batch ingestion lag in this test. The replay CPU profile for 100 runs of each workload sampled 2.59 CPU seconds over 2.52 elapsed seconds, including Go test/runtime overhead; it is roughly one core during the benchmark. Allocated bytes are total allocations per replay run, not peak resident memory. Replay and watcher do not coalesce requests. SQLite, file, and Slack outputs use bounded queues; these benchmarks did not exercise their saturation behavior. The degraded-mode stress test ingests 20,000 requests from one IP without drops while preserving exact basic counters, and verifies rich tracking resumes after recovery.

On 2 October 2026, the same benchmark code ran in a Linux arm64 Go 1.26 container on Docker Desktop for macOS arm64. At `-benchtime=30x`, normal replay took 14.22 ms per 1,000 lines with 8.37 MB allocated per run; the 10,000-line path scan took 27.27 ms with 9.74 MB allocated per run. Both reported zero malformed or dropped lines. The 1,000-line watcher batch took 255 ms (`-benchtime=3x`). These timings include Docker Desktop overhead and are not measurements from the intended server. A replay of the four local development access logs parsed 31,777 lines with zero malformed, allowlisted, or dropped lines and emitted 32 monitor-only incidents. Those logs contain synthetic k6 traffic, so this is a pipeline check rather than a false-positive review.

Run the measurements again on the target host:

```sh
go test ./internal/replay -run '^$' -bench BenchmarkReplay -benchmem -benchtime=100x
go test ./internal/watcher -run '^$' -bench BenchmarkWatcherBatchLag -benchtime=3x
go test -race ./...
```

## Product enhancement validation

Tickets [055–067](../Tickets/README.md#product-improvements) were implemented and checked on 3 October 2026. The full Go race-checked suite, static checks, JavaScript syntax check, example configuration validation, Linux arm64 build, and Nginx configuration syntax check pass. The existing development container was used only for Nginx validation and was not reloaded.

Feature checks cover independent notification routing/failures, cooldowns, queue overflow/expiry, retry exhaustion and stable IDs, Teams Adaptive Card/throttling contracts, SNS JSON/attributes/payload budgets, permanent failures, stack-trace privacy, and secret redaction. Provider tests use fake transports; no live Teams or AWS message was sent. Use the [notification setup guide](notifications.md) for a controlled workflow/topic/subscriber smoke test before relying on an installation.

Combined, JSON, and logfmt versions of the same 300-request scan produce matching scores, decisions, request counts, and stable incident IDs. Nested mappings and the `ecs-v1` HTTP/PHP error subset verify timing units, optional zero/missing values, proxy trust, and redaction. Preview is bounded and creates no history; replay rejects out-of-order sources. Error correlation labels reused identifiers, site/server context, absent sources, and capped evidence without changing scores.

A real watcher test appended 20,000 JSON errors alongside 1,000 combined access records. All access records arrived in 249.6 ms with no loss; all error records were eventually parsed. Severity filtering, malformed diagnostics, and error-log rename/create rotation also passed. A separate 10,000-error storm left normal request counts and scores unchanged. These synthetic macOS checks demonstrate separation and bounded behavior, not production CPU/RSS or capacity guarantees.

| Local microbenchmark | Time per record | Allocated bytes | Allocations |
| --- | ---: | ---: | ---: |
| Canonical JSON access parser | 1.70 µs | 1,464 | 38 |
| Canonical logfmt access parser | 1.78 µs | 4,840 | 23 |
| Insert into a full bounded error ring | 24.8 ns | 0 | 0 |

Measured on Apple M1 Pro, macOS arm64, with the Go benchmark's default one-second target. Allocations describe each operation, not peak resident memory. Reproduce with:

```sh
go test ./internal/parser ./internal/correlation -run '^$' -bench 'BenchmarkStructured|BenchmarkFullErrorRing' -benchmem
go test -v ./internal/watcher -run TestErrorFlood
go test -race ./...
```

Retention tests verify read-only affected-count/range preview, cutoff boundaries, background minute cleanup, immutable incident snapshots, preserved system state, and disk diagnostics. Recovery tests retain complete-line overlap, reject excessive bytes and backward timestamps before emitting decisions, preserve partial trailing records, and suppress repeated SQLite incident IDs. A subprocess is killed and restarted twice across an unfinished 300-request window; the recovered count remains 300. Rotation/copy-truncation gaps and possible remote/JSONL duplicates remain documented in [storage guidance](storage-output.md).

Browser verification covered overview filters, three distinct request-associated samples sharing a timestamp/message, related incident links, immutable detail with a weaker site/time backend error, redacted messages, and horizontal sample-table scrolling on a narrow screen. This complements API bounds and escaping tests. Sustained concurrent access/error/dashboard load and peak RSS still need measurement on the intended Linux host under ticket 021.

## Incident sample and retention validation

Tickets [068–069](../Tickets/README.md#product-improvements) were implemented on 3 October 2026. The full `go test -race ./...` suite, `go vet ./...`, JavaScript syntax check, the configuration examples available at that time, and native/Linux arm64 builds pass. No existing development container or production daemon was restarted; browser verification used isolated temporary data on loopback port 18091. Slack tests still pass alongside the named-destination integration tests; no remote message was sent.

Sampler tests cover the five-sample cap, two bounded analysis epochs, site/client scoping, allowlist exclusion, late arrivals, closed-window boundary protection, copied optional values, UTF-8/byte/control bounds and omitted query values. Scoring tests verify identical score/decision/event ID with and without samples. Storage tests write ten incidents (plus other server/site examples), check exactly fifty scoped samples, stable-ID deduplication, request-ID/literal path/method/status filters, bounded pagination, older-incident compatibility, default four-day read expiry, shorter configured retention and parent/orphan cleanup. Essential state survives. Local output tests verify four-day boundaries, multiline operational continuations, initial idle/legacy cleanup, managed archive scope, preserved permissions and atomic failure for malformed/oversized records.

A full-suite run exposed a crash-test setup race: the dashboard could respond before the watcher captured its initial EOF, causing the fixture's first writes to be treated as pre-existing logs. The test now waits for the watcher readiness message, and timeout diagnostics capture the subprocess stage/output. The complete race suite and three additional fresh crash-test runs pass after this fix; the two-crash recovered request count remains 300.

A local Apple M1 Pro/macOS arm64 benchmark of the same aggregation fixture measured 448 ns/request, 32 bytes and two allocations without sampling, versus 709 ns/request, 88 bytes and eight allocations with sampling (approximately 0.26 microseconds added). This is an in-memory microbenchmark, not a sustained production throughput/RSS or disk/search contention result. Reproduce with:

```sh
go test ./internal/aggregator -run '^$' -bench BenchmarkObserveIncidentSamples -benchmem
```

Browser verification covered the populated Incident logs table, server/site/request-ID filters, repeated request examples from overlapping incidents, linked score details with five saved requests, site-scoped shortcuts, visible date labels and narrow-screen table scrolling. Retention work stays outside request ingestion, but physical deletion can lag the logical cutoff during bounded cleanup, file errors, or downtime. Production capacity/false-positive review remains open under ticket 021.

## README demonstration and review validation

On 3 October 2026, the [reproducible demo](demo.md) generated traffic from 60 reserved IPv4/IPv6 clients across four example sites through combined, JSON, logfmt, and ECS-mapped sources. The actual Linux daemon produced all three saved decision levels, an 88/100 `WOULD_BLOCK` site incident, five request samples per incident, and correlated request-ID/site-time error context. The 48 normal browser clients produced no incidents in this synthetic run. API checks verified scoped and request-ID search, populated minute history, live snapshot events, enrichment, health/pool views, and SQLite integrity inside the container hosting its WAL database.

The fresh full race suite, static checks, the configuration examples available during the review, Python/JavaScript syntax checks, native demo startup/shutdown, Linux arm64 build, and renamed Nginx configuration check pass. Browser checks exercised every dashboard section, evidence links, filtered incident search, and narrow-screen horizontal navigation/table scrolling. Four screenshots and an approximately 40-second GIF were captured from the running fixture and visually inspected; runtime data and raw frames remain ignored. See [review notes](review.md) for exact scope, publication checks, and remaining acceptance work.

## Dashboard refresh regression

The overview previously cleared its content and fetched error context for each live snapshot, causing blank intervals and replacing charts/filter controls. It now updates live values in place, retains the previous view until a complete history refresh is ready, coalesces snapshots during pending requests, preserves filter drafts during background refreshes, and retains labeled previous details with retry backoff when history is unavailable.

Seven frontend regressions pass; six fail against the prior script, including delayed-refresh blanking, repeated requests during loading, and lost filter drafts. The dashboard Go race suite, JavaScript syntax check, and Go static checks also pass. These development-only tests run with `npm ci && npm test` in `tests/dashboard`; Node.js is not a production dependency.

## Production monitor review pending

The repository does not contain representative production logs or a sustained Linux service run. Before marking ticket 021 complete or considering later enforcement work, replay logs from each intended site, inspect every `SUSPICIOUS` and `WOULD_BLOCK` example alongside normal API, crawler, and browser traffic, record the false-positive count and cause, and document each threshold or allowlist change with a before/after replay result. Observe the service across rotation and high load on the intended host; record CPU, peak RSS, watcher lag, SQLite/Slack queue failures, and dropped events there. Keep V1 in monitor mode throughout this review.

Use this review record for each intended site and log period. Keep replay output, client IPs, and request evidence in a restricted local directory outside Git.

| Evidence | Record |
| --- | --- |
| Host, site IDs, log period, traffic volume, ruleset/config revision | Exact environment and input used for replay |
| Replay summary | Parsed, malformed, allowlisted, dropped, and incident counts |
| Incident review | Count of true positives, false positives, and uncertain cases by decision and signal; examples with normal browser/API/crawler context |
| Tuning | Each proposed threshold or allowlist change, reason, and before/after replay counts on the same logs |
| Sustained run | Duration, average/peak CPU and RSS, watcher lag, queue failures, dropped events, rotation/restart observations, and dashboard availability |
| Decision | Whether monitor-only behavior is acceptable for the intended host; unresolved cases and owner |

The replay CLI emits one JSON incident per line followed by a `summary` object. Run it with the production config and log paths, redirecting output into a private local file for review. Do not use synthetic Docker fixture results as evidence of production false-positive rates.
