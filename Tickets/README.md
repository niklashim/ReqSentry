# ReqSentry tickets

This is the implementation backlog derived from the project brief and dashboard request. Tickets 001–020 are **Done** and live in [`archive/`](archive/); 021 is **In progress** pending production-log review and sustained Linux validation; 022–024 are **To do** and outside core V1. Tickets 025–041 cover the optional, read-only dashboard. Completed dashboard tickets are archived; 034, 036, and 040 remain in progress with explicit gaps. Move each ticket into `archive/` when it is done, and keep its index link current. IDs indicate a useful implementation sequence, not a promise of strict delivery order. Dependencies are listed in each ticket.

## V1: monitor-only

| ID | Ticket | Depends on |
| --- | --- | --- |
| 001 | [Go daemon skeleton and configuration](archive/001-daemon-config.md) | — |
| 002 | [Normalized request event and Nginx parser](archive/002-nginx-parser.md) | 001 |
| 003 | [Apache parser and log-format guidance](archive/003-apache-parser.md) | 002 |
| 004 | [Multi-log watchers and rotation](archive/004-log-watchers.md) | 002 |
| 005 | [Client IP, proxies, and allowlists](archive/005-client-identity.md) | 002 |
| 006 | [Bounded rolling aggregation](archive/006-aggregation.md) | 002, 005 |
| 007 | [Server health and analysis triggers](archive/007-health-triggers.md) | 001, 006 |
| 008 | [PHP-FPM health collection](archive/008-php-fpm.md) | 001 |
| 009 | [URL patterns and 404 enumeration](archive/009-url-enumeration.md) | 006 |
| 010 | [Rates, statuses, and redirects](archive/010-traffic-signals.md) | 006 |
| 011 | [Methods and User-Agent signals](archive/011-method-ua-signals.md) | 006 |
| 012 | [Cross-site and server-impact signals](archive/012-impact-signals.md) | 006, 007, 008 |
| 013 | [Explainable scoring and decisions](archive/013-scoring.md) | 009–012 |
| 014 | [SQLite history and ruleset versioning](archive/014-sqlite.md) | 013 |
| 015 | [Operational and JSONL output](archive/015-local-output.md) | 013 |
| 016 | [Local MaxMind enrichment](archive/016-maxmind-lookup.md) | 001, 005 |
| 017 | [MaxMind downloads and persistent updates](archive/017-maxmind-updates.md) | 014, 016 |
| 018 | [Slack incidents and operational alerts](archive/018-slack.md) | 013, 015 |
| 019 | [Resource limits and degraded mode](archive/019-degraded-mode.md) | 006, 013 |
| 020 | [Linux service and operator CLI](archive/020-service-cli.md) | 004, 007, 014–019 |
| 021 | [Replay and production validation](021-replay-validation.md) | 003–020 |

## Later, outside V1

| ID | Ticket |
| --- | --- |
| 022 | [Automatic trigger and site profiles](022-auto-profiles.md) |
| 023 | [Historical tuning and crawler verification](023-history-crawlers.md) |
| 024 | [Cloudflare enforcement and safety gates](024-enforcement.md) |

## Optional read-only dashboard

The dashboard uses ReqSentry's own live counters, detector results, health sampling, MaxMind enrichment, and SQLite history. [GoAccess](https://goaccess.io/features) is a product/UX reference only; there is no GoAccess integration or runtime dependency. Network access is deny by default, and no dashboard route changes traffic.

| ID | Epic | Ticket | Depends on |
| --- | --- | --- | --- |
| 025 | A — Web runtime | [Optional embedded web runtime](archive/025-web-runtime.md) | 001, 020 |
| 026 | B — Security | [IP allowlists and trusted proxies](archive/026-web-access-control.md) | 025 |
| 027 | B — Security | [Authentication and access audit](archive/027-web-auth-audit.md) | 026 |
| 028 | C — Core adapter | [Bounded live statistics](archive/028-live-statistics.md) | 006–008, 013, 025 |
| 029 | C — Core adapter | [Aggregated dashboard history](archive/029-dashboard-history.md) | 014, 028 |
| 030 | D — API | [Overview and live analytics API](archive/030-dashboard-api-core.md) | 027–029 |
| 031 | D — API | [Historical incident API](archive/031-dashboard-incidents-api.md) | 014, 027, 030 |
| 032 | E — Live transport | [Bounded statistics stream](archive/032-dashboard-stream.md) | 027, 028, 030 |
| 033 | F — Frontend | [Embedded shell and navigation](archive/033-dashboard-assets.md) | 025, 027, 030 |
| 034 | G — Overview | [Live server overview and charts](034-dashboard-overview.md) | 029, 030, 032, 033 |
| 035 | H — Sites | [Site list and detail](archive/035-dashboard-sites.md) | 030, 033, 034 |
| 036 | I — IP/network | [IP and ASN investigation](036-dashboard-ip-network.md) | 030, 031, 033 |
| 037 | J — HTTP | [Method, status, path, and User-Agent analytics](archive/037-dashboard-http-analytics.md) | 028, 030, 033 |
| 038 | K — Health | [Server and PHP-FPM health](archive/038-dashboard-health.md) | 008, 029, 030, 033 |
| 039 | L — Incidents | [Incident list and historical detail](archive/039-dashboard-incidents-ui.md) | 031, 033 |
| 040 | M — Hardening | [Security and load hardening](040-dashboard-hardening.md) | 025–039 |
| 041 | N — Operations | [Documentation and release guidance](archive/041-dashboard-docs.md) | 025–040 |

Recommended order is 025 → 026 → 027, then 028 and 029, followed by APIs 030–031 and stream 032. Frontend 033 starts once the API shape is stable. Views 034–039 can then proceed independently before hardening 040 and documentation 041. The optional raw-request debug view from the request is deferred; the primary live path transports aggregates only.

## Local Docker development environment

The local architecture amendment is tracked below. Tickets 042–052 and 054 are **Done** and archived after Docker smoke, scenario, restart, rotation, persistence, supervisor, and named-site checks; ticket 053 is future only. The primary development image runs Nginx and ReqSentry together; k6 is a separate persistent service. It uses direct `docker compose` and `docker exec` commands and no Makefile.

| ID | Epic | Ticket | Depends on |
| --- | --- | --- | --- |
| 042 | A — Combined container | [Combined Nginx and ReqSentry container](archive/042-combined-dev-container.md) | 025, 043, 045 |
| 043 | B — Nginx fixture | [Two-site Nginx fixture and canonical logs](archive/043-nginx-fixture.md) | 002, 004 |
| 044 | C — Persistent data | [Host-mapped development logs and state](archive/044-dev-persistence.md) | 042, 043 |
| 045 | D — Local config | [Monitor-only local ReqSentry configuration](archive/045-local-config.md) | 025, 043 |
| 046 | E — k6 framework | [Persistent k6 service and shared helpers](archive/046-k6-runtime.md) | 042, 043 |
| 047 | F — k6 scenarios | [Normal, high-404 and enumeration scenarios](archive/047-k6-normal-enumeration.md) | 043, 046 |
| 048 | F — k6 scenarios | [Methods, redirects and User-Agent scenarios](archive/048-k6-methods-redirects-ua.md) | 043, 046 |
| 049 | F — k6 scenarios | [Cross-site and configurable high-rate scenarios](archive/049-k6-cross-site-rate.md) | 043, 046 |
| 050 | G — Dashboard integration | [Dashboard exposure in local Compose](archive/050-dashboard-dev-integration.md) | 025–041, 042, 045 |
| 051 | H — Regression harness | [Deterministic integration and restart checks](archive/051-dev-regression-harness.md) | 043–050 |
| 052 | I — Developer documentation | [Local development README and troubleshooting](archive/052-dev-documentation.md) | 042–051 |
| 053 | Future — Sidecar | [Future separate ReqSentry sidecar](053-future-sidecar.md) | 042–052 |
| 054 | Local sites and IP explorer | [Named four-site fixture and per-IP site links](archive/054-named-sites-ip-explorer.md) | 028, 036, 042–052 |

V1 completion means the service can run on a production Linux web server for an extended period, survive rotation and missing optional inputs, identify obvious scanning with understandable evidence, avoid alert floods, remain stable during adversarial traffic, and never change network behavior.
