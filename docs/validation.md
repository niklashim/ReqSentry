# Replay and V1 validation

ReqSentry can replay historical combined-format access logs through the live parser, trusted-proxy resolution, rolling aggregator, HTTP and impact rules, and scoring engine. Replay makes no HTTP requests, sends no Slack alerts, and takes no enforcement action. It emits one JSON incident per line and a final summary containing parsed, malformed, allowlisted, dropped, and incident counts.

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

Run the measurements again on the target host:

```sh
go test ./internal/replay -run '^$' -bench BenchmarkReplay -benchmem -benchtime=100x
go test ./internal/watcher -run '^$' -bench BenchmarkWatcherBatchLag -benchtime=3x
go test -race ./...
```

## Production monitor review pending

The repository does not contain representative production logs or a sustained Linux service run. Before marking ticket 021 complete or considering later enforcement work, replay logs from each intended site, inspect every `SUSPICIOUS` and `WOULD_BLOCK` example alongside normal API, crawler, and browser traffic, record the false-positive count and cause, and document each threshold or allowlist change with a before/after replay result. Observe the service across rotation and high load on the intended host; record CPU, peak RSS, watcher lag, SQLite/Slack queue failures, and dropped events there. Keep V1 in monitor mode throughout this review.
