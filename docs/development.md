# Development

Run the commands on this page from the repository root unless a section says otherwise.

The Go daemon follows multiple Nginx/Apache access logs, resolves trusted client IPs, keeps bounded rolling counters with a degraded mode, samples Linux health, and can poll local PHP-FPM status pages. It produces explainable monitor-only decisions, stores incident history and restart offsets in SQLite, writes JSONL incidents and operational logs, enriches incidents from local MaxMind MMDB files, schedules authenticated MMDB updates, and optionally sends Slack/Teams/SNS alerts, consumes JSON/logfmt access logs and mapped application errors, and saves bounded error correlation context. A Linux systemd unit, operator CLI, and historical replay are included. No V1 component changes web traffic or blocks clients.

## Optional dashboard

The embedded, read-only dashboard is disabled by default. It serves ReqSentry's own live aggregates, server and PHP-FPM health, local MaxMind enrichment, and SQLite minute/incident history from the daemon binary. There is no GoAccess integration or production Node.js requirement. See [dashboard setup and API guidance](dashboard.md) and the `web` section in [configs/example.yaml](../configs/example.yaml) for loopback access, SSH forwarding, allowlists, trusted proxies, authentication, live updates, and data coverage. The dashboard never blocks clients or changes ReqSentry configuration.

Use the [Linux installation and operations guide](install.md) for binary installation, least-privilege log access, systemd setup, and CLI commands. The [access-log guide](access-logs.md) describes supported formats and optional fields; [PHP-FPM guidance](php-fpm.md), [local history and output](storage-output.md), and [MaxMind enrichment and updates](maxmind.md) cover integrations. [Testing and validation](validation.md) covers automated checks and deployment testing.

## Build and test

With Go 1.26 or newer installed, check the project and configuration with:

```sh
go test ./...
go run ./cmd/reqsentry -config configs/example.yaml config test
```

Run `go run ./cmd/reqsentry -config /absolute/path/config.yaml` to start the monitor; the sample config's `/var/...` paths need adaptation to the host. The example defaults to continuous analysis (`trigger.mode: always`); its optional settings are commented out and can be enabled individually. The engine and CLI are the primary workflow; the dashboard is optional. `status` and `report` print readable results (`-json` for scripts); `-ip`, `-site`, and `-details` refine reports. `maxmind status`, `maxmind update`, `notifications preview`, `notifications test [NAME]`, `ui enable|disable`, and `data preview|clean` are local operator commands after `-config PATH`. See [CLI operations](cli.md) for cleanup confirmation and UI restart requirements. Use `replay LOG...` for historical combined-format logs; it streams readable findings and a summary without network integrations (`-json` for JSON lines).

Optional frontend regression tests require Node.js 20+ and npm. They exercise the actual dashboard script with an in-memory DOM and controlled API/stream responses; no browser, daemon, or external notification is started:

```sh
cd tests/dashboard
npm ci
npm test
```

Node.js and these development-only dependencies are not required to build or run ReqSentry. The tests cover live-update stability, delayed and failed refreshes, filter drafts, navigation races, and request coalescing. Browser checks complement them for focus, scrolling, and layout.

## Local Docker development

The primary development environment runs **Nginx and ReqSentry in the same Linux container**. A separate persistent k6 container generates traffic against Nginx; ReqSentry reads four real local access logs. The container process supervisor is for development only. Docker and Docker Compose are required on the development host; k6 runs in its container.

### Start and stop

```sh
docker compose up -d --build
docker compose ps
docker compose down
```

Open [shop.example](http://localhost:8081), [api.example](http://localhost:8082), [docs.example](http://localhost:8083), [blog.example](http://localhost:8084), and the [ReqSentry dashboard](http://localhost:8090). These are local fixture URLs; no DNS setup is needed. All five published ports bind to host loopback. Compose keeps `reqsentry-k6` running so tests launch with `docker exec`. The checked-in [Docker fixture configuration](../docker/webserver/reqsentry.yaml) is copied into the image and uses `mode: monitor`, `trigger.mode: always`, all four Nginx access logs, disabled Slack/MaxMind, and a **development-only** Docker bridge allowlist for the dashboard. Production dashboard defaults remain disabled and deny by default. The single user-facing configuration example is [configs/example.yaml](../configs/example.yaml); ReqSentry loads one selected file and does not merge these configurations.

The IP explorer lists the site names each tracked IP reached during the rolling minute, with links to site details. An incident with no site ID is a server-wide decision and appears as **All sites**. Saved incidents retain the site IDs configured when they were detected.

### Generate traffic

```sh
docker exec reqsentry-k6 k6 run /scripts/scenarios/normal.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/high-404.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/enumeration.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/methods.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/redirects.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/user-agents.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/cross-site.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/high-rate.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/dashboard-stress.js
```

For deliberate higher load, pass `RATE` and `DURATION` directly to the k6 container:

```sh
docker exec -e RATE=500 -e DURATION=30s reqsentry-k6 \
  k6 run /scripts/scenarios/high-rate.js
```

The safe default is 20 requests/second for 10 seconds. [k6 scenario details](../tests/k6/README.md) list fixed paths, request counts, expected responses, tags, and likely detector evidence. Traffic scenarios use Docker-network Nginx URLs. The dashboard stress scenario also reads dashboard APIs concurrently.

### Inspect logs and state

The host can read access and error logs for `site1` through `site4` under `dev-data/nginx/logs/`. The filename numbers map to the four domains in port order above. ReqSentry writes `dev-data/reqsentry/logs/reqsentry.log`, `dev-data/reqsentry/logs/incidents.jsonl`, `dev-data/reqsentry/data/reqsentry.db`, and optional MMDB files under `dev-data/reqsentry/maxmind/`. These directories are bind mounted and persist after `docker compose down` or image rebuild. Runtime files are ignored by Git.

```sh
docker compose logs --tail=100 reqsentry-web
docker compose ps
docker exec reqsentry-web sqlite3 /var/lib/reqsentry/reqsentry.db \
  'SELECT id,timestamp,site_id,ip_address,score,decision FROM incidents ORDER BY id DESC LIMIT 10;'
```

The dashboard uses the same live aggregator and saved incident data. Wait for the 30-second analysis window before expecting detector decisions. Incident presence depends on the ruleset; inspect stored signals rather than assuming every fixture produces a given decision.

### Restart, rotate, and reset

```sh
docker compose restart reqsentry-web
docker compose ps
docker exec reqsentry-web sqlite3 /var/lib/reqsentry/reqsentry.db \
  'SELECT COUNT(*) FROM incidents;'
```

Both processes should return, the dashboard should reopen, and the incident count should remain. Run `normal.js` again and confirm new log lines appear once; ReqSentry's SQLite watcher offsets prevent rereading existing lines after a clean restart. To test Nginx log rotation, run:

```sh
docker exec reqsentry-web sh -c \
  'mv /var/log/nginx/site1.access.log /var/log/nginx/site1.access.log.1 && nginx -s reopen'
docker exec reqsentry-k6 k6 run /scripts/scenarios/normal.js
```

Check that a new `site1.access.log` contains fresh lines, ReqSentry continues ingesting, and the rotated `.1` file remains on the host. To **intentionally delete all local test logs, incidents, and SQLite state**, stop containers first and remove generated files while preserving repository placeholders:

```sh
docker compose down
find dev-data/nginx/logs dev-data/reqsentry/logs dev-data/reqsentry/data dev-data/reqsentry/maxmind \
  -type f ! -name .gitkeep -delete
docker compose up -d --build
```

### Optional integrations

No credentials are needed for the base environment. Copy `.env.example` to `.env` only if you enable an integration. For MaxMind, set `maxmind.enabled: true`, `maxmind.update.enabled: true`, `account_id`, and `license_key_env: REQSENTRY_MAXMIND_LICENSE_KEY` in `docker/webserver/reqsentry.yaml`, then set the key in `.env` and rebuild. MMDB files persist under `dev-data/reqsentry/maxmind/`. For Slack, set `output.slack.enabled: true` and `webhook_env: REQSENTRY_SLACK_WEBHOOK`, set the webhook in `.env`, and rebuild. Never commit `.env` or real credentials. The `.env.example` account ID entry is a reminder; the YAML loader reads `account_id` from the config file.

### Troubleshooting

- Docker Desktop on macOS reports `docker: command not found` or `docker-credential-desktop` is missing: start Docker Desktop and add its bundled CLI directory to the shell path with `export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"`, then retry.
- Port conflict: stop the other local service on 8081–8084 or 8090, or change the Compose host-side port. The container ports and k6 URLs should stay 8081–8084.
- Dashboard 403: inspect `docker compose logs reqsentry-web` for the denied source IP. The local config permits loopback and common Docker bridge ranges only. Add the observed source CIDR to this **development** config when your Docker network differs; keep host port 8090 bound to loopback.
- Missing log ingestion: check that all four `site*.access.log` files appear under `dev-data/nginx/logs/`, the local config names those exact paths, and the supervisor reports ReqSentry running. Nginx uses [the canonical fixture format](../docker/webserver/nginx/nginx.conf).
- File permissions: bind mounts may be created by Docker with host root ownership. Inspect `docker compose logs` and directory permissions before changing ownership; SQLite and log directories must be writable inside `reqsentry-web`.
- Unhealthy or exited container: run `docker compose ps` and `docker compose logs --tail=200 reqsentry-web`. The supervisor exits if Nginx or ReqSentry exits unexpectedly, and the health check probes all four sites and the dashboard.
- Stale image after editing the Dockerfile, fixture, or local YAML: run `docker compose up -d --build` again. k6 scripts are mounted read-only and update without an image rebuild.
- k6 cannot reach Nginx: check `docker compose ps`; k6 waits for a healthy web service. Its `SITE1_URL` through `SITE4_URL` target `reqsentry-web` on the Compose network, not `localhost` inside k6.

The local fixture follows all four Nginx error logs and records generated request IDs in combined access logs. The Nginx configuration also defines an optional `reqsentry_json` format; change a site’s producer directive and ReqSentry source format together, and start a fresh log file rather than mixing formats in an existing persistent file. See the [complete configuration example](../configs/example.yaml), [structured log guide](structured-logs.md), and [error correlation guide](error-correlation.md).

## Automated release checks

The checked-in GitHub Actions workflow runs Go race/static/configuration checks, dashboard regressions, an npm dependency audit, and Go vulnerability checks. A separate job builds the actual Linux container binary, reports its embedded toolchain, scans it with `govulncheck`, and scans the runtime image for high/critical vulnerabilities. Findings fail the gate; no vulnerability exclusions are configured.

Container base images, scanner, and CI actions are pinned by digest or commit. Check current official release metadata before updating pins, rebuild the Alpine package-update layer with `--no-cache-filter runtime`, and rerun the release-binary and image scans. Record image IDs, embedded Go version, scan date/results, and package findings for each release. Alpine packages and vulnerability databases remain time-dependent; the base digest alone is not a fully reproducible runtime bill of materials. Use the Compose image for local development and the standalone daemon with the hardened Linux service for production.

The development runtime uses the official Nginx Alpine image with package updates. The Go build stage uses Go 1.26 Bookworm; the static daemon binary does not require glibc. The runtime includes the process supervisor, four local sites, SQLite utility, Python fixture support, and dashboard.
