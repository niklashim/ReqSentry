# Product review notes

**Prepared 3 October 2026.** ReqSentry is ready for a monitor-only product demonstration and implementation review. Production acceptance remains open under [production validation](validation.md).

Start with the [README](../README.md) and its 40-second walkthrough. For an interactive review, run `python3 scripts/demo.py --duration 900` from the repository root and open `http://localhost:18092`. The [demo guide](demo.md) describes the fixture and a suggested investigation route.

## What the demonstration proves

The media is captured from the running application, with locally generated logs passing through the actual parsers, aggregation, default detection rules, scoring, error correlation, storage, and dashboard APIs. Incidents are calculated rather than inserted or given preset scores.

| Review area | Observed result |
| --- | --- |
| Multiple clients and sites | 60 active IPv4/IPv6 clients across four reserved example sites. Combined, JSON, logfmt, and mapped ECS inputs all contribute traffic. |
| Decisions | `WATCH`, `SUSPICIOUS`, and `WOULD_BLOCK` incidents are present. The 48 normal browser clients produced zero saved incidents in the captured run. This is a fixture result, not a production false-positive estimate. |
| Explainable investigation | `203.0.113.31`, with fictional Germany/hosting metadata, produces an 88/100 saved site incident with numeric-path enumeration, varied 404s, and method scans. IP, site, and ASN links open their corresponding views. |
| Request evidence | The selected incident contains five normalized requests. A database check found a maximum of five samples per incident. Queries and raw access-log lines are omitted from this search dataset. |
| Search | Server/site/IP/status filters return only the requested scope. A request-ID search finds the saved request and its incident; a nonexistent request returns zero results. Score links open the saved incident. |
| Errors | Persisted upstream errors appear in the dashboard. The checked site incident reports nine request-ID associations alongside weaker site/time context. The bounded chronological sample list is not an exhaustive list of those associations. |
| Health and live updates | Linux health measurements are available, the real PHP-FPM collector polls simulated counters from a local endpoint, and the live stream delivers snapshot events. Minute history is populated. |
| Storage | SQLite integrity check returns `ok`. Inspection ran inside the Linux container hosting the database. |
| Navigation and layout | Overview, Sites, IP explorer, Networks, Incidents, Incident logs, HTTP analytics, Server health, and PHP-FPM were exercised. The narrow dashboard panel keeps filters readable and provides horizontal table/navigation scrolling. |

The final live evidence check at 17:30 UTC recorded 60 clients, four sites, 156 `SUSPICIOUS`, 249 `WATCH`, and 453 `WOULD_BLOCK` incidents. Counts grow during the run and overlapping detection windows can repeat request samples. The README captures several moments during the investigation, not one immutable system snapshot.

## Implementation checks

- A fresh `go test -race -count=1 ./...` passes across all 20 Go packages. After correcting the dashboard evidence links, the focused dashboard/config race tests pass again.
- `go vet ./...`, dashboard and k6 configuration JavaScript syntax checks, Python fixture syntax validation, the configuration examples available during the review, and a Linux arm64 build pass.
- The documented native demo command was exercised through its build, watcher readiness, 30-second run, and clean shutdown.
- Renamed example-site Nginx configuration passes its syntax check in a separate container. The existing development stack was left running.
- The four PNG screenshots and looping GIF were visually inspected. The GIF is approximately 3.7 MB and includes live metrics, site/IP/network investigation, incident evidence, error context, request search, and health views.

The review exposed an evidence-rendering bug: IP/site/ASN links inside detail rows appeared as URL text. The dashboard now preserves those link elements, and browser checks verified the navigation. The example-config test was also updated to reflect the current continuous-monitoring starter and four-day defaults. More detailed feature tests and their limitations are recorded in [validation](validation.md).

The project is licensed under the [MIT License](../LICENSE), selected for its simple permissive terms. Existing third-party licenses and notices remain in place.

## Synthetic data and publication hygiene

All published dashboard media uses documentation IP ranges and reserved `.example` sites. Country/ISP/ASN labels come from an invented MMDB written by the demo script; no real MaxMind dataset or real client ownership claim is included. PHP-FPM counters are simulated. Linux system measurements come from the demonstration container and are not production capacity measurements.

Generated configs, access/error logs, output files, runtime databases, licensed MMDB downloads, raw capture frames, local agent state, and credential files are excluded from Git. Private/generated material is also excluded from the Docker build context. Only reviewed synthetic media in `docs/images/` is intended for publication. The existing enrichment test MMDB remains included because it is a public synthetic fixture with its accompanying MIT license.

The audit found no private-file candidates among tracked paths and no matches for the checked private-key, AWS access-key, Slack token/webhook, or GitHub token patterns in 235 current source files or 344 reachable historical Git blobs. Personal-looking demonstration domain labels were replaced with reserved example domains in the current source and screenshots. **Existing Git history still contains the old domain labels, including the previous dashboard screenshot.** Git ignore rules cannot remove those committed versions. Before making the repository public, publish a clean source snapshot or explicitly review and clean that history. No history rewrite was performed during this review.

Pattern checks do not establish that every possible secret format has been reviewed; inspect the final staged files and media before changing repository visibility.

## Remaining acceptance work

1. Replay representative logs from the intended sites and review suspicious incidents against normal API, browser, and crawler traffic. Record tuning and false-positive findings in the production validation checklist.
2. Run sustained monitoring on the intended Linux host, measuring CPU, peak memory, watcher lag, queue failures, dropped events, rotation/restart behavior, and concurrent dashboard use.
3. Smoke-test the intended Slack destination, Teams Workflow, and SNS topic/subscriber. Automated tests verify provider contracts with fake transports; this review sent no external notifications.
4. Resolve the old domain labels in Git history before public release if those associations should remain private. The project's MIT license is now included at the repository root.

V1 remains monitor-only throughout review. `WOULD_BLOCK` records a decision for investigation and takes no enforcement action.

## Engine and CLI review

The README leads with the monitoring engine, readable IP reports and local operations; dashboard media remains in the optional UI section. CLI reports accept IP/site filters and signal/request details, with `-json` retained for scripts. Maintenance includes scoped data preview/confirmed cleanup, configured MaxMind checks, notification tests (including legacy `output.slack`) and persistent UI toggles with restart instructions. The offline notification preview uses the actual formatter; no Slack screenshot or live delivery is claimed.

Race-checked process tests run the engine with the UI disabled, append synthetic requests, observe scored JSONL output and CLI findings, and verify that cleanup refuses a live engine. A second run verifies file output continues with SQLite unavailable. Cleanup fixtures cover confirmation, database/output scope, archives/quarantine, protected inputs, symlinks/hardlinks and fresh legacy heartbeats. UI tests preserve the complete commented config, access policy and permissions. Live production load and provider receipt checks remain open.
