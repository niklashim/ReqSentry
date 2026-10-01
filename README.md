# ReqSentry

<p align="center">
  <img src="logo.png" alt="ReqSentry logo" width="650">
</p>

**See suspicious web traffic in context, before you decide what to do about it.**

ReqSentry is a lightweight Go daemon for Linux web servers. It follows Nginx and Apache access logs, groups requests by client and site, and correlates HTTP behavior with server health and optional PHP-FPM metrics. Its detections carry the signals and score that led to each decision.

**V1 is monitor-only.** A `WOULD_BLOCK` decision is evidence to review; ReqSentry does not block requests, change web-server rules, or call Cloudflare.

## What you get

- **One view across sites:** spot an IP scanning several virtual hosts even when no single site's traffic looks large.
- **Explainable incidents:** inspect rates, 404s, path and query enumeration, methods, User-Agents, redirects, server impact, and the saved evidence behind a score.
- **Local operation:** bounded in-memory counters, log rotation handling, SQLite history and restart positions, JSONL incidents, and an operator CLI.
- **Optional context:** local MaxMind enrichment, PHP-FPM status, Slack notifications, and an embedded read-only dashboard.

```text
Nginx / Apache logs ──▶ rolling site + IP statistics ──▶ signals + score
                              ▲                              │
                         server health                 SQLite / JSONL
                         and PHP-FPM                  dashboard / Slack
```

<details>
<summary>Dashboard preview from the local fixture</summary>

<a href="docs/images/dashboard-overview.png"><img src="docs/images/dashboard-overview.png" alt="ReqSentry dashboard showing live metrics, trends, and saved incidents for the example sites" width="700"></a>

</details>

## Try it locally

Docker Compose starts four example Nginx sites and ReqSentry together, plus a separate k6 traffic generator. From the repository root:

```sh
docker compose up -d --build
docker exec reqsentry-k6 k6 run /scripts/scenarios/normal.js
```

Open the [dashboard](http://localhost:8090) and the example sites: [him.com](http://localhost:8081), [mycoolshop.se](http://localhost:8082), [ekstrom.nu](http://localhost:8083), and [wordpress-site.com](http://localhost:8084). These names are local fixture labels; no DNS setup is needed. To exercise detection, run `docker exec reqsentry-k6 k6 run /scripts/scenarios/cross-site.js` and inspect the IP explorer or incidents after the analysis window.

The fixture binds ports to host loopback and writes persistent test data under the Git-ignored `dev-data/` directory. See the [local development guide](docs/development.md) for every scenario, data paths, restart, reset, and troubleshooting commands.

## Run on Linux

The production-style deployment uses one ReqSentry daemon with a YAML config and a systemd unit. Start with [installation and operations](docs/install.md) and [the configuration example](configs/example.yaml). The dashboard is optional and disabled by default. Representative production-log review and sustained Linux validation are still open; see [validation status](docs/validation.md) before treating the current build as production validated.

## Documentation

| Topic | Guide |
| --- | --- |
| Local Docker environment, development commands, and current status | [Development](docs/development.md) |
| Linux setup and service operations | [Install](docs/install.md) |
| Dashboard setup, API, and data semantics | [Dashboard](docs/dashboard.md) |
| Nginx and Apache log formats | [Access logs](docs/access-logs.md) |
| SQLite, JSONL, and operational output | [Storage and output](docs/storage-output.md) |
| PHP-FPM and MaxMind integrations | [PHP-FPM](docs/php-fpm.md) · [MaxMind](docs/maxmind.md) |
| Testing and remaining validation | [Validation](docs/validation.md) |
| Design requirements and implementation work | [Original project brief](docs/project-brief.md) · [Tickets](Tickets/README.md) |

For code changes, run `go test ./...` with Go 1.26 or newer. The local Docker build includes its own Go toolchain.
