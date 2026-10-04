# Engine and CLI operations

ReqSentry's primary workflow is log monitoring, explainable IP findings, and reporting. The optional dashboard is disabled by default. All commands load the one config selected by `-config`. Put flags before commands; `reqsentry -help` lists the available operations.

## Run and inspect

```sh
reqsentry -config /etc/reqsentry/config.yaml config test
reqsentry -config /etc/reqsentry/config.yaml
# In another terminal:
reqsentry -config /etc/reqsentry/config.yaml status
reqsentry -config /etc/reqsentry/config.yaml report
reqsentry -config /etc/reqsentry/config.yaml -ip 203.0.113.31 -details report
reqsentry -config /etc/reqsentry/config.yaml -site shop.example -limit 50 report
reqsentry -config /etc/reqsentry/config.yaml -json status
reqsentry -config /etc/reqsentry/config.yaml -json report
```

Without a command, the engine runs until SIGINT/SIGTERM. On Linux, install the [systemd service](install.md) for background operation. New sources initially start at EOF; later starts resume saved offsets. Missing inputs and collector/delivery failures are visible in status and diagnostics. Detection continues with the dashboard disabled.

Reports default to a readable table of detection time (UTC), IP, configured site, score, decision, request count, peak requests/second, country when available, and evidence codes. `-details` adds the server, window, ruleset, signal weights/strengths, and saved requests. Text from logs/config is bounded and stripped of terminal control characters. Limits range from 1 to 1,000; filters apply before the limit. An IPv4-mapped IPv6 filter is normalized to IPv4. Site IDs match exactly; an empty incident site is displayed as “All sites”. Server-wide and site-specific findings can both be present.

These are recent retained incident windows, not the current status of every client. No incident does not certify safety; normal traffic is not saved as incidents. Expired data is excluded using configured retention even when physical cleanup is delayed. A daemon heartbeat older than 30 seconds is displayed as stopped. `-json status` retains the full heartbeat, including health, recovery, resource, delivery, and ASN exclusion counters. Exclusions count analyzed site/server windows; unresolved ASNs remain monitored. For scripts that consume JSON, add `-json` to status, report, or replay.

`preview LOG` and `prune preview` remain JSON. MaxMind commands also return structured JSON. Validation, preview, report, and replay do not send remote messages. Report/status open the existing database using the service's storage setup; use the service account or root. The database must have been initialized by the engine, except MaxMind commands can initialize scheduler state before the first monitor run.

## Historical analysis

```sh
reqsentry replay /path/to/combined-access.log
reqsentry -config /etc/reqsentry/config.yaml replay /path/to/site1.log /path/to/site2.log
reqsentry -config /etc/reqsentry/config.yaml -json replay /path/to/site1.log
```

Replay streams readable findings with a final parsed/malformed/allowlisted/dropped/error/incident summary. `-json` emits one JSON incident per line and a final `summary` object. Multiple sources are merged by recorded time. Replay does not persist results, change watcher offsets, send notifications, reconstruct historical health, or download MaxMind data. Enabled MaxMind uses existing local MMDBs for enrichment and ASN exclusions; metadata reflects those files, not the historical request time. See [structured sources and replay](structured-logs.md#preview-replay-and-limits).

## Notifications

```sh
reqsentry -config /etc/reqsentry/config.yaml notifications preview
reqsentry -config /etc/reqsentry/config.yaml notifications test legacy-slack
reqsentry -config /etc/reqsentry/config.yaml notifications test teams-operations
```

Preview uses fictional data and the actual Slack incident formatter, without creating a sender or accessing secrets. Test explicitly sends a synthetic monitor-only test to an enabled destination. Legacy `output.slack` uses `legacy-slack`; named destinations use their own names. Omit the name if exactly one destination is enabled; multiple destinations require a name. Failures return a nonzero exit code. Provider acceptance still requires separate receipt verification.

Operator commands inherit the calling environment, not the systemd service's environment/credentials. Export the configured environment reference privately or supply the corresponding `CREDENTIALS_DIRECTORY`; never put webhook URLs or license keys in shell arguments. See [notification setup](notifications.md) and [service credentials](install.md).

## MaxMind update

```sh
sudo -u reqsentry reqsentry -config /etc/reqsentry/config.yaml maxmind status
sudo -u reqsentry reqsentry -config /etc/reqsentry/config.yaml maxmind update
```

Enable MaxMind and its update settings first, and make credentials available to the command. `maxmind update` respects the saved due time/backoff; `not_due` is a successful check, not a new download. It can download an initially missing database. Existing valid files with no scheduler state receive the configured interval before checking. Updates validate downloads and preserve active data on failure. A running engine observes an updated MMDB when its own updater next reloads it; restart the service when immediate use of a CLI-installed update is required. See [MaxMind details](maxmind.md).

## Enable or disable the UI

```sh
sudo reqsentry -config /etc/reqsentry/config.yaml ui enable
sudo systemctl restart reqsentry
sudo reqsentry -config /etc/reqsentry/config.yaml ui disable
sudo systemctl restart reqsentry
```

These commands atomically change `web.enabled`, validate the resulting config, and preserve YAML comments, other values, ownership and permissions. They require write access to the config's directory and refuse symlink configs. They do not start/stop a running listener themselves. Existing listener and explicit allowlist settings are retained. If no allowlist is configured, first-time enablement adds `127.0.0.1` and `::1`; the default listener is `127.0.0.1:8090`. An explicitly empty allowlist continues to deny everyone. Configure authentication/proxy policy separately as needed; see [dashboard access](dashboard.md). Disabling the UI leaves log monitoring and notification settings intact.

## Clean all collected data

```sh
sudo -u reqsentry reqsentry -config /etc/reqsentry/config.yaml data preview
sudo systemctl stop reqsentry
sudo -u reqsentry reqsentry -config /etc/reqsentry/config.yaml -confirm data clean
sudo systemctl start reqsentry
```

`data preview` lists existing targets without deleting anything. `data clean` requires `-confirm`, refuses active engine/database operator locks, and preflights every target before deletion. Older binaries without the lock are guarded by a fresh running heartbeat too; after stopping such a binary, allow up to 30 seconds for that heartbeat to expire.

The scope is the configured SQLite file and WAL/SHM/journal sidecars (incidents, request samples, errors, minute history, restart offsets, recovery and scheduler state), configured ReqSentry incident/operational files, and recognized managed archive/quarantine files. Explicit output paths are included even if currently disabled, so previously collected output can be cleared. Unconfigured historical output paths are outside this command's scope. The data/output lock files stay in place to preserve process coordination; they hold no incident data.

Configuration, input logs, MaxMind databases, unknown sibling files, external backups/journald copies, and already-delivered messages are preserved. Non-regular targets, symlinks and targets overlapping configured inputs/configuration are refused. This is file removal, not secure erasure of storage media or backups. An I/O error stops cleanup with a nonzero exit code; removed files are listed, so inspect and retry remaining targets. On restart, state is recreated and existing source logs start at EOF because saved offsets were cleared. Use replay separately for old traffic.
