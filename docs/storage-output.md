# Local history and output

ReqSentry stores monitor-mode incidents in the configured SQLite database. It uses WAL mode and batches up to 64 incidents or 250 ms of queued work per transaction. Each incident retains its JSON evidence, score, decision, ruleset version, time window, optional health/enrichment, and canonical site/IP identity. System state also stores the daemon status heartbeat and MaxMind update schedule. Normal requests stay in bounded memory; the database stores selected traffic windows only for incidents.

**All saved investigation history defaults to a four-day ceiling.** Set `database.retention.max_age: 96h` to retain incidents, their request samples/correlation snapshots, standalone errors, and dashboard minutes for at most four days. Increase or decrease this setting (minimum `1h`) to change the ceiling. Legacy per-table durations can shorten retention; omitted or zero durations inherit the ceiling, and longer values are capped. There is no unlimited incident-retention default. Plan disk capacity; retention is a time/work policy, not an absolute disk-size guarantee. Do not remove SQLite `-wal` or `-shm` files while ReqSentry is running. The database file is created with mode `0600`; its parent directory is created with mode `0700` if absent. Give the service account access to its configured database directory.

## Restart positions

At first start, an existing log starts at EOF and that position is saved. A clean stop drains complete lines, finishes one last analysis, flushes queued SQLite incidents, then saves the last complete-line offset together with the file device/inode. On restart, ReqSentry resumes there when the same file identity still exists and its size has not fallen below the offset. Lines appended while the daemon was stopped are therefore read. A new or rotated file starts at byte zero when discovered while running.

With default recovery settings, an unclean stop leaves the previous clean checkpoint. Requests since that checkpoint are replayed, so duplicate incidents are possible; this favors recovering unprocessed traffic. A long-running daemon may replay a large tail after a crash. The opt-in bounded policy below adds periodic safe checkpoints. If a log was replaced while ReqSentry was stopped, or copy-truncated and regrown beyond the saved offset, its old inode/offset cannot reliably recover every line. Keep rotated logs long enough for operational recovery and avoid copy-truncate where possible. If SQLite is unavailable, ingestion continues but restart catch-up and incident history are unavailable.

## Local files

`output.log` mirrors operational logs that always go to stderr. `output.incidents` writes one JSON object per line for every non-normal decision, with `monitor_only: true`; a `WOULD_BLOCK` decision takes no network action. Both destinations use bounded queues so a slow file does not block log ingestion. Queue overflow and write failures are reported to stderr. ReqSentry rotates its own configured output files hourly into adjacent `NAME.reqsentry.START.END.ID.archive` files and checks expiry at startup and every minute, including while idle. Completely expired archives are removed; a boundary archive is rewritten atomically to remove only expired dated records. The current configured file contains the active segment; recent older output lives in the adjacent archives. The first run also removes expired records from an existing flat output and archives its retained records. Allow temporary disk space for an atomic boundary/legacy rewrite. Malformed/oversized undated output prevents that file’s cleanup and reports a diagnostic instead of silently deleting evidence. One process must own each output path; use ReqSentry’s managed rotation for these files. Previously created external rotations/backups are not ReqSentry-managed archives and need their own cleanup. After an external rename/create rotation, the next record still opens the configured path. New output files use mode `0600`; existing files retain their current permissions. Create the configured output directories and give the service account write access before starting. Rotate by rename/create and signal or wait for the next record; the daemon reopens the new path automatically.

## Retention and disk status

`database.retention` accepts `max_age` (default `96h`, at least one hour), optional shorter `incidents`, `errors`, and `minutes` durations, `interval` (default one minute), `batch_size` (default 500, maximum 2,000), `error_samples_per_second` (default 20), and `minimum_free_bytes` (zero disables low-disk warnings). Background database pruning uses at most 20 bounded batches per table and a one-second deadline per maintenance run. Physical removal is periodic and can lag the age cutoff during a backlog or storage failure; the setting is not a hard real-time erasure guarantee. High sampling rates or slow storage may require a shorter interval or larger batch; watch pruning status and disk growth. Cleanup starts in a background worker on startup and repeats at the configured interval. Reads immediately exclude expired history even when physical deletion is catching up. Cleanup preserves essential system state and watcher positions needed for monitoring/recovery. SQLite foreign keys remove incident signals, request samples, and traffic windows together; orphan historical IP/site lookup rows are also removed.

`status.storage` shows database/WAL sizes, available filesystem bytes, configured low-disk state, retained incident range, and the last completed pruning run. Recurring low-disk conditions produce controlled operational warnings when subscribed. Expired rows do not necessarily return filesystem space immediately. Never VACUUM or delete WAL/SHM files on an active daemon; use a maintenance window and a SQLite-aware backup before optional space reclamation. The same `max_age` applies to ReqSentry’s configured JSONL and operational output files. Original input/rotated web-server logs, external backups, stderr/journald copies, and Slack/Teams/SNS messages have separate owner-controlled retention.

Preview affected row counts, occurrence-time ranges, and retention cutoffs without deleting or migrating data:

```sh
reqsentry -config /etc/reqsentry/config.yaml prune preview
```

The preview uses a read-only connection and requires an existing current-schema database. The daemon performs configured pruning in the background; the preview command has no write mode.

## Optional bounded crash recovery

`recovery.enabled: true` opts into event-time monitoring and periodic safe checkpoints; it currently requires `trigger.mode: always`. Leave it disabled to preserve the existing ingestion-time and clean-stop behavior. The default checkpoint interval is one minute and the total raw overlap/recovery budget is 16 MiB (`max_bytes`, configurable from 1 to 128 MiB).

A periodic checkpoint retains complete raw lines spanning two analysis windows instead of saving only the parser's consumed position. The local worker briefly pauses readers around a one-second-bounded SQLite flush/offset transaction. It defers checkpoint advancement during rotation drainage, failed flushes, or excessive overlap. On restart, captured ranges receive a bounded validation pass before any recovered decision is emitted. Ordered sources then merge by logged occurrence time through the normal replay/parser/scoring path, restoring recent counters and unfinished windows. A failed recovery discards partial warm counters before legacy catch-up. Only closed windows emit recovered decisions; live monitoring finishes a still-open window. Recovery captures file identities and complete-line end positions, then the watcher resumes after that captured data and keeps a trailing partial line for later completion.

With recovery enabled, live decisions use closed epoch-aligned windows so recovered decisions have stable IDs. SQLite suppresses repeated IDs without rewriting their first saved evidence; older records remain compatible. JSONL and remote outputs can still repeat events, identified by `event_id`. Recovered historical windows have no retrospective CPU/PHP-FPM measurements; unavailable health stays unavailable. Enabled MaxMind reads current local databases for enrichment and ASN exclusions, so metadata can differ from the logged period. Error correlation uses available recovered errors and preserves the monitor-only boundary.

`status.recovery` reports state, replayed request count, byte range, and a failure detail. Per-source status reports checkpoint time and deferral reason. If inputs changed identity, exceed the byte budget, or violate ordering, bounded recovery defers and preserves the prior offsets for operator replay. Monitoring continues with the legacy catch-up policy and periodic advancement is disabled for that run; manually address the reported backlog/gap before relying on bounded recovery. This is a bounded attempt, not an exactly-once guarantee. Retain rotated input files for recovery; replacement/copy-truncation can destroy unprocessed evidence.

## Retention configuration

```yaml
database:
  path: /var/lib/reqsentry/reqsentry.db
  retention:
    max_age: 96h # Four days; use 48h for two days or 240h for ten days.
```

Changing `max_age` changes the ceiling for every history table and both configured local output files. If you previously configured shorter per-table durations, remove them to make all histories use the new ceiling. Essential checkpoint/configuration state is not investigation history and is preserved. Pruning does not securely overwrite deleted SQLite pages, compact SQLite files, or erase independent backups. Slack’s existing `output.slack` configuration and named destinations keep their delivery behavior; local expiry cannot recall delivered messages.

## Write failures and damaged files

SQLite retains failed batches for retry, bounded to 320 pending incidents and 192 pending error samples in the worker, in addition to the existing input queues. Flush errors remain visible to every consumer until those batches commit. Queue rejection or retry-buffer overflow freezes checkpoint advancement for the rest of the process, even if the database later recovers. Resolve the storage problem and restart with the retained source logs so recovery can replay from the last safe checkpoint. Monitoring continues, but history can have gaps during a prolonged outage; replay remains subject to the configured byte budget, source identity, and input retention. Shutdown reports outstanding failures.

A partial or malformed local output file is moved to a permission-preserving `.reqsentry.*.quarantine` file, allowing new records to enter a healthy active file. Quarantine expiry uses the earliest known record time or original modification time, whichever is earlier, and the configured output retention. Files containing already-expired evidence are removed immediately. Managed quarantine files expire during periodic cleanup; unrelated files are never removed. Filesystem/permission failures remain visible through diagnostics and can delay cleanup or prevent writes.

Recovery analysis runs at epoch boundaries and retains up to 121 seconds of counter buckets to protect a preceding window during scheduling delay. Non-recovery monitoring retains its 61-second logical horizon. Bucket storage is bounded; recovery keeps five small samples per retained analysis epoch (up to 610 per identity with a one-second window), while each saved incident still contains at most five. Longer rich-data retention can hit configured diversity caps sooner; watch saturation and memory indicators. Delays beyond the retained horizon and events arriving after a closed window was scored still require operator replay.

## Inspecting container state

Use the container's ReqSentry CLI or dashboard API to inspect a live database. For inspection from a different operating system, stop the daemon and copy/export the database first; live SQLite WAL state should be read within the operating system hosting it.
