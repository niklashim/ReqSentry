# Dashboard operations

ReqSentry has an optional, read-only dashboard in the daemon binary. It reads the existing aggregator, health samplers, detector results, MaxMind data, and SQLite history. It does not parse logs again or change traffic. The embedded HTML, CSS, and JavaScript require no Node.js runtime on the monitored server.

## Enable locally

Add or edit `web` in the configuration:

```yaml
web:
  enabled: true
  listen: 127.0.0.1
  port: 8090
  allowed_ips: [127.0.0.1, "::1"]
  trusted_proxies: []
  auth:
    enabled: false
  realtime:
    enabled: true
    interval: 2s
    max_clients: 32
```

The server is **disabled by default**. The default listen address is loopback; an empty `allowed_ips` denies every request, including local requests. `listen` must be a literal IPv4 or IPv6 address. `allowed_ips` accepts individual addresses and CIDRs. `/0` is deliberately rejected. To reach a remote server securely, use `ssh -L 8090:127.0.0.1:8090 server` and open `http://127.0.0.1:8090/` locally. The SSH tunnel connects from loopback on the server. Do not add loopback to `trusted_proxies` for this setup.

To listen externally, explicitly set `listen` to the server interface and restrict `allowed_ips`. For a reverse proxy, add only the proxy's direct TCP source to `trusted_proxies`; configure that proxy to overwrite or append one `X-Forwarded-For` header. ReqSentry ignores forwarded headers from untrusted peers. A trusted peer without exactly one valid forwarded header is denied. The effective client address is found from the rightmost untrusted address in the chain. Both the IP allowlist and optional Basic authentication must pass. Put TLS in front of Basic authentication for external access; alternatively keep the dashboard behind SSH. No dashboard route supports a write method.

## Authentication

```yaml
web:
  auth:
    enabled: true
    username: admin
    password_env: REQSENTRY_WEB_PASSWORD
```

Set the environment variable in the daemon process. Alternatively use `password_credential: dashboard-password` with a systemd credential named `dashboard-password`. Use exactly one secret reference. The password value is never placed in YAML or the CLI status. Invalid credentials return 403 and log a bounded denial count without request queries or passwords. The server does not log full URL paths on denial.

## Views and data semantics

The dashboard shows overview, sites, IPs, ASN networks, HTTP analytics, server/PHP-FPM health, and historical incidents. The banner and incidents say **MONITOR** and **WOULD_BLOCK** because no enforcement action is taken. The live update stream uses Server-Sent Events (`/api/v1/stream`) at one to ten seconds, two seconds by default. SSE needs only server-to-browser updates, has browser reconnection, and works with ordinary HTTP proxies. WebSockets would add a bidirectional protocol and more connection handling without a V1 need. The daemon builds one aggregate update for all viewers. Each client has a one-message queue and slow clients receive the newest update. The stream is limited to 64 KiB per event and 32 viewers by default (maximum 256 configured).

Server and per-site request/status/method totals are exact for the rolling 60-second window, including allowlisted traffic. Active IPs, top IPs, sampled paths, user agents, and ASN totals cover **bounded tracked clients**. They can be incomplete when the aggregator drops records, degrades evidence, or an IP is allowlisted. ASN entries do not imply malicious networks. User-Agent strings are informational. Historical minute rows default to a four-day retention ceiling and record requests, selected response statuses, tracked unique IPs within each minute, SQLite incident counts, CPU/load/memory and PHP-FPM worker values; absent measurements remain absent. Incident counts are exact for records committed by the minute boundary; if SQLite cannot flush/query in time, the count is unavailable and the chart shows a gap. Longer ranges combine complete minute rows into at most 500 buckets: traffic and incident counts are summed, tracked IPs are the largest minute count, and health/PHP-FPM are the latest available values in each bucket. A missing or partial minute makes its bucket a gap. Dashboard queries use a separate read-only SQLite connection so they do not occupy the incident writer connection. Distinct IPs across a selected multi-minute range are not currently available. The first/last minute of a process can be partial. The UI labels sampled coverage. Incident detail uses the immutable saved detection snapshot, including ruleset, signals, score, health and enrichment at detection time.

The HTTP analytics view shows exact method/status cross totals for the rolling minute. Its path, query, User-Agent, and unique-404-path lists cover bounded tracked IP samples and may omit traffic when evidence is capped or degraded.

## Read-only API

Overview and site views include optional [error evidence](error-correlation.md): bounded redacted samples, severity/category/association filters, source availability and last-record time, and persisted-sample timelines. Saved incident detail shows categories, association counts, source provenance, uncertainty, and missing/dropped evidence from detection time. Errors do not increment request totals or change a score. Older incidents explicitly show unavailable error context, and quiet/missing inputs are distinguished from zero observed failures. Narrow screens can scroll the sample table horizontally.

All routes require the same allowlist and authentication. Use `GET` or `HEAD` only. `/api/v1/status` returns web and analysis state. `/api/v1/server`, `/api/v1/stats`, `/api/v1/sites`, `/api/v1/sites/{site}`, `/api/v1/ips`, `/api/v1/ips/{ip}`, `/api/v1/asns`, `/api/v1/asns/{asn}`, `/api/v1/phpfpm`, and `/api/v1/user-agents` serve live bounded data. `stats` and site detail accept `range=1m|5m|15m|1h|6h|24h|7d`; history is capped at 500 points. Top IP/network lists are limited to 50. Site IDs and IPs should be URL encoded.

The IP explorer's aggregate rows include `site_ids`, the site names on which that tracked IP had traffic during the rolling window. They are links to site details and are separate from the aggregate request count. Saved incidents with an empty `site_id` are server-wide decisions; the UI labels them “All sites” rather than assigning a site after the fact.

`/api/v1/incidents` accepts `from`, `to` (RFC3339, at most 366 days, subject to configured retention), `site`, `server`, `ip`, `decision`, `min_score`, `max_score`, `signal`, `q`, `page`, and `limit` (1–100). Its default time range is the last 24 hours. `/api/v1/incidents/{id}` returns the original saved incident. Pages past the result return an empty array. No incident is rescored by the dashboard.

`/api/v1/errors` accepts `site`, `severity`, `category`, `association`, the standard `range`, and `limit` (1–50). Without an association filter it returns persisted samples plus an aggregate sample timeline. An association filter returns matching evidence from the latest 50 saved incidents in the range, with related incident IDs; it omits the unrelated aggregate timeline. Sampling, retention gaps, and source health are labeled. It uses the same read-only database and access controls as other history routes.

## Troubleshooting and limits

The daemon logs dashboard configuration/bind failures and continues monitoring. CLI `status` reports web enabled, listener, client count, and state. A 403 means the source is not allowed, a trusted proxy sent an invalid/missing forwarded header, or authentication failed. An empty allowlist denies everyone. A 503 from history means SQLite is unavailable; live monitoring remains active. The first complete history point appears after one minute. PHP-FPM or health panels show missing or stale data when those collectors are unavailable.

The API caps query strings at 2048 bytes, JSON responses at 1 MiB, result rows, top lists, lookback, and database query time. At most 32 ordinary dashboard requests run at once; additional requests receive 503. `/api/v1/status` reports `web.active_requests` and cumulative `web.rejected_requests`. SSE viewers have a separate configurable limit, a 64 KiB event cap, and one replaceable queued event each. The HTTP server limits headers to 16 KiB, header reading to 5 seconds, request reading and response writing to 10 seconds, and idle connections to 30 seconds. GET/HEAD requests with bodies are rejected. Every route sends CSP and frame protections. The normal stream carries aggregates rather than raw requests.

On 2 October 2026, the local Linux container on Docker Desktop for macOS arm64 handled a 20-second k6 run of 500 unique-path 404 requests/second plus 30 dashboard API reads/second. It completed 10,602 response checks with no failed checks or dropped k6 iterations; 10,001 requests reached Nginx and 601 dashboard reads completed. The 404 responses are intentional. ReqSentry remained healthy, its watcher reported zero malformed or dropped events, and monitor-only incidents were saved. A separate real-socket check filled the local 16-viewer SSE limit, received 503 for the next client, and observed client count return to baseline after disconnect. These are local development measurements, not a production capacity claim. See [validation](validation.md) and [dashboard stress commands](../tests/k6/README.md).

On 3 October 2026, a separate 10-second run targeted 10,000 unique-path 404 requests/second plus 30 dashboard reads/second. k6 completed 99,029 checks (about 9,886/second), all successful, and dropped 1,273 scheduled iterations because the generator could not sustain the target rate. Nginx served 98,728 intentional 404s. Afterward, the watcher had parsed 98,734 site-one lines with zero malformed lines or I/O errors; aggregation reported zero dropped events and was not degraded. The dashboard status endpoint remained available with zero rejected requests. This demonstrates bounded local behavior near the requested rate; it does not establish sustained 10,000 requests/second capacity.

For a busy installation, restrict dashboard viewers and keep the local or TLS-proxied deployment. Sustained measurements on the intended Linux host are still required before production performance claims are made.

## Incident logs

The **Incident logs** page searches up to five normalized request samples saved with each incident. Ten incidents contain at most fifty entries; no normal-request log collection is introduced. Filter by site, server, IP, method, HTTP status, dates, or text (path/request ID/trace ID/method/IP), and follow the incident link to its saved score/evidence. Site and incident detail include shortcuts. The incident list also accepts sample text and server filters. See [incident request samples](incident-logs.md) for capture, coverage and privacy details.

`/api/v1/request-samples` accepts `from`, `to`, `site`, `server`, `ip`, `method`, `status`, `q`, `incident_id`, `page`, and `limit` (1–50). Dates filter incident detection time; the displayed request timestamp comes from the source log. The default range is the last four days; configured retention can shorten it, and explicit dates can search a longer retained range (maximum 366 days per query). Pagination is bounded to 201 pages and offset 10,000. Queries use parameterized SQL, a separate read-only connection and a three-second deadline. Authentication/allowlists are identical to all other dashboard routes. Entries expire with their parent incident. Older incidents have no reconstructed samples, and overlapping incidents can repeat the same request.
