# Testing and validation

ReqSentry's test suite covers log parsing, client identity and proxy trust, bounded aggregation, scoring, error correlation, storage, retention, log rotation, recovery, notification contracts, and the optional dashboard.

## Go checks

From the repository root, with Go 1.26 or newer:

```sh
go mod verify
go vet ./...
go test -race ./...
go build -trimpath -o reqsentry ./cmd/reqsentry
./reqsentry -config configs/example.yaml config test
./reqsentry -config docker/webserver/reqsentry.yaml config test
```

The race suite includes local HTTP servers and process tests. Run it in an environment that permits loopback listeners. Tests use temporary files and fake notification transports; they do not send alerts to real Slack, Teams, or SNS destinations.

### Concurrency regressions

Exercise checkpoint deadlines, full-queue barriers, independent access/error processing, and rotation under a constrained scheduler:

```sh
GOMAXPROCS=1 go test -race ./internal/storage ./internal/watcher \
  -run '^(TestCheckpointDeadlineAndFullQueueBarrierDoNotBlockIngestion|TestErrorFloodDoesNotDisplaceAccessAndSurvivesRotation)$' \
  -count=3 -timeout=3m
```

The storage test uses a synthetic clock and controlled queue state to verify deadlines and that a waiting barrier leaves ingestion available. SQLite outage/retry tests separately verify real commits, bounded buffers, sticky loss reporting, and safe checkpoints. The watcher test holds an error callback while access traffic continues, rotates the error file, then verifies complete old/replacement error delivery, severity filtering, and malformed-line accounting.

## Dashboard checks

Frontend tests require Node.js 20+ and npm for development only:

```sh
cd tests/dashboard
npm ci
npm test
npm audit --audit-level=high
node --check ../../internal/dashboard/assets/app.js
```

These tests exercise the embedded dashboard script with a controlled DOM, API responses, and live events. They cover navigation, refresh races, filter drafts, loading states, and preservation of the displayed view during updates.

## Vulnerability checks

CI runs the Go checks, constrained-scheduler regressions, frontend tests, dependency audits, source vulnerability scans, and scans of the actual Linux container binary and operating-system packages. Container images, scanners, and actions are pinned in [.github/workflows/ci.yml](../.github/workflows/ci.yml).

To scan Go source locally:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
govulncheck ./...
```

Scan the release binary and runtime image as well as the development source. Rebuild package-update layers before release, and use current vulnerability databases. See [release checks](review.md).

## Replay representative logs

Replay evaluates recorded timestamps through the parser, client identity, aggregation, and scoring engine. It sends no notifications, takes no enforcement action, and does not change the live database or saved offsets:

```sh
reqsentry -config /etc/reqsentry/config.yaml replay /path/to/site1.access.log /path/to/site2.access.log
reqsentry -config /etc/reqsentry/config.yaml -json replay /path/to/site1.access.log > /private/path/replay.jsonl
```

Configure formats/profiles before replaying structured sources. The default output is readable findings and a summary; `-json` emits one JSON incident per line followed by a `summary` object with parsed, malformed, allowlisted, dropped, error, incident, and per-source counts.

Review `SUSPICIOUS` and `WOULD_BLOCK` findings alongside normal browser, API, crawler, and monitoring traffic. Check the evidence, site identity, score thresholds, and allowlist behavior. Compare the same input before and after configuration changes. Replay does not reconstruct historical host health or enable MaxMind, so live scores can differ.

Keep production logs and replay output in a restricted location outside the repository. Synthetic demo traffic exercises the pipeline; it does not establish production false-positive rates or capacity.

## Validate a deployment

Automated tests use synthetic inputs and fake provider transports. Validate the intended deployment with representative logs, sustained load, and real destination receipt before relying on it operationally.

| Area | Check |
| --- | --- |
| Sources and identity | Every site's files are readable, formats match the producer, proxy trust is correct, and parsed counts increase. |
| Detection quality | Review suspicious findings against normal traffic; record false positives, uncertain cases, and the effect of tuning. |
| Sustained monitoring | Measure CPU, peak memory, watcher lag, dropped events, queues, and SQLite growth under expected and peak load. |
| Rotation and recovery | Rotate/truncate logs and restart the engine; verify continuity and configured recovery behavior. |
| Retention | Verify the configured cutoff applies to history, samples, and ReqSentry output files. |
| Notifications | Send a synthetic test to each enabled destination and verify actual receipt; check failure/retry reporting. |
| Optional dashboard | Verify access rules, authentication, unavailable-data labels, refresh behavior, and responsiveness with concurrent viewers. |

Store deployment-specific measurements and incident examples privately. ReqSentry remains monitor-only: `WOULD_BLOCK` is an informational decision and does not enforce a block.
