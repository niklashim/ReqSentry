# ReqSentry tickets

This is the implementation backlog derived from the project brief. Tickets 001–020 are **Done**; 021 is **In progress** pending production-log review and sustained Linux validation; 022–024 are **To do** and outside V1. IDs indicate a useful implementation sequence, not a promise of strict delivery order. Dependencies are listed in each ticket; work can proceed in parallel when they allow it. Acceptance criteria describe behavior to verify, not implementation mandates beyond the brief.

## V1: monitor-only

| ID | Ticket | Depends on |
| --- | --- | --- |
| 001 | [Go daemon skeleton and configuration](001-daemon-config.md) | — |
| 002 | [Normalized request event and Nginx parser](002-nginx-parser.md) | 001 |
| 003 | [Apache parser and log-format guidance](003-apache-parser.md) | 002 |
| 004 | [Multi-log watchers and rotation](004-log-watchers.md) | 002 |
| 005 | [Client IP, proxies, and allowlists](005-client-identity.md) | 002 |
| 006 | [Bounded rolling aggregation](006-aggregation.md) | 002, 005 |
| 007 | [Server health and analysis triggers](007-health-triggers.md) | 001, 006 |
| 008 | [PHP-FPM health collection](008-php-fpm.md) | 001 |
| 009 | [URL patterns and 404 enumeration](009-url-enumeration.md) | 006 |
| 010 | [Rates, statuses, and redirects](010-traffic-signals.md) | 006 |
| 011 | [Methods and User-Agent signals](011-method-ua-signals.md) | 006 |
| 012 | [Cross-site and server-impact signals](012-impact-signals.md) | 006, 007, 008 |
| 013 | [Explainable scoring and decisions](013-scoring.md) | 009–012 |
| 014 | [SQLite history and ruleset versioning](014-sqlite.md) | 013 |
| 015 | [Operational and JSONL output](015-local-output.md) | 013 |
| 016 | [Local MaxMind enrichment](016-maxmind-lookup.md) | 001, 005 |
| 017 | [MaxMind downloads and persistent updates](017-maxmind-updates.md) | 014, 016 |
| 018 | [Slack incidents and operational alerts](018-slack.md) | 013, 015 |
| 019 | [Resource limits and degraded mode](019-degraded-mode.md) | 006, 013 |
| 020 | [Linux service and operator CLI](020-service-cli.md) | 004, 007, 014–019 |
| 021 | [Replay and production validation](021-replay-validation.md) | 003–020 |

## Later, outside V1

| ID | Ticket |
| --- | --- |
| 022 | [Automatic trigger and site profiles](022-auto-profiles.md) |
| 023 | [Historical tuning and crawler verification](023-history-crawlers.md) |
| 024 | [Cloudflare enforcement and safety gates](024-enforcement.md) |

V1 completion means the service can run on a production Linux web server for an extended period, survive rotation and missing optional inputs, identify obvious scanning with understandable evidence, avoid alert floods, remain stable during adversarial traffic, and never change network behavior.
