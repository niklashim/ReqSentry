# Demo

Run a local demo with synthetic traffic to explore incident scoring, error correlation, and the optional dashboard shown in the [README](../README.md#optional-dashboard). The fixture generates logs locally; it does not make HTTP requests to any displayed client address or site.

## Start

Requires Go 1.26+ and Python 3.9+. From the repository root:

```sh
python3 scripts/demo.py
```

Open `http://localhost:18092`. First decisions appear after an analysis window (30 seconds); leave it running for two minutes to populate minute history. The default run is five minutes. Ctrl+C stops the daemon and fixture server cleanly.

```sh
python3 scripts/demo.py --duration 900 --port 18095
# Skip the build when using an existing binary:
python3 scripts/demo.py --binary /absolute/path/reqsentry
```

Each invocation creates a fresh directory under `dev-data/demo/`, containing its config, input logs, generated demonstration MMDB, local output, and SQLite state. It does not modify an existing installation, the standard Compose fixture, or its database. Remote notifications and MaxMind downloads are disabled. A port collision makes startup fail rather than replacing another service.

## Traffic and context

The fixture uses 60 clients: 40 documentation IPv4 browser addresses, eight documentation IPv6 browser addresses, and 12 clients with scanning, repeated-404, or expensive-query patterns. It follows four sites through four formats:

| Site | Access format |
| --- | --- |
| `shop.example` | Nginx combined, including timings and request/trace IDs |
| `api.example` | Canonical single-line JSON |
| `docs.example` | Canonical logfmt |
| `blog.example` | Nested ECS fields using `ecs-v1` |

Every site also has a canonical JSON error source. Synthetic upstream failures share the corresponding site's request/trace IDs. The fixture varies browser volume so live rates and minute trends change, while normal browser traffic remains separate from scanner evidence. All detector thresholds and weights use application defaults.

`203.0.113.31` represents a fictional Germany-labelled hosting client. Numeric-path enumeration, diverse 404s, non-GET scans, and cross-site behavior produce scored evidence, including `WOULD_BLOCK`; no country-based rule is added. Other clients produce `WATCH` and `SUSPICIOUS` incidents. Normal clients remain visible in live aggregates without generating saved incidents under these patterns.

Country, ISP, private ASN values, and network classifications are invented. The script writes a small MMDB following the [MaxMind DB format specification](https://maxmind.github.io/MaxMind-DB/); the real local enrichment reader validates and reads it. This fixture is not a MaxMind geolocation dataset and makes no claim about real allocations. The PHP-FPM collector polls a real local HTTP endpoint returning simulated pool counters; it is not a PHP workload measurement. Linux CPU, memory, and load readings come from the running Linux system/container; unsupported host readings are unavailable.

## Explore the dashboard

1. **Overview:** watch live rates, status mix, active clients, and incident counts. Read the chart coverage labels.
2. **Sites:** open a site and compare its traffic, sampled networks, and error context.
3. **IP explorer:** investigate `203.0.113.31`. Read its fictional country/ASN alongside the actual request-pattern evidence.
4. **Incidents:** filter by IP/decision and open a saved `WOULD_BLOCK` incident. Review weighted signals, its immutable window, five request samples, and labeled error associations.
5. **Incident logs:** search the IP, site, status, path, or a saved request ID and follow the incident score link.
6. **HTTP analytics, Server health, PHP-FPM, Networks:** inspect the remaining views and their unavailable/sample-coverage labels.

These are read-only actions. Changing filters does not change a score or block a client.
