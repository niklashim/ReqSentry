# Local history and output

ReqSentry stores monitor-mode incidents in the configured SQLite database. It uses WAL mode and batches up to 64 incidents or 250 ms of queued work per transaction. Each incident retains its JSON evidence, score, decision, ruleset version, time window, optional health/enrichment, and canonical site/IP identity. System state is available for later integrations. Normal requests stay in bounded memory; the database stores selected traffic windows only for incidents.

There is currently **no automatic incident retention or pruning**. Plan disk capacity and archive or prune old records during a maintenance window. Do not remove SQLite `-wal` or `-shm` files while ReqSentry is running. The database file is created with mode `0600`; its parent directory is created with mode `0700` if absent. Give the service account access to its configured database directory.

## Restart positions

At first start, an existing log starts at EOF and that position is saved. A clean stop drains complete lines, finishes one last analysis, flushes queued SQLite incidents, then saves the last complete-line offset together with the file device/inode. On restart, ReqSentry resumes there when the same file identity still exists and its size has not fallen below the offset. Lines appended while the daemon was stopped are therefore read. A new or rotated file starts at byte zero when discovered while running.

After an unclean stop, the previous checkpoint remains. Requests since that checkpoint are replayed, so duplicate incidents are possible; this favors recovering unprocessed traffic. Because checkpoints currently advance only on clean stops, a long-running daemon may replay a large tail after a crash. If a log was replaced while ReqSentry was stopped, or copy-truncated and regrown beyond the saved offset, its old inode/offset cannot reliably recover every line. Keep rotated logs long enough for operational recovery and avoid copy-truncate where possible. If SQLite is unavailable, ingestion continues but restart catch-up and incident history are unavailable.

## Local files

`output.log` mirrors operational logs that always go to stderr. `output.incidents` writes one JSON object per line for every non-normal decision, with `monitor_only: true`; a `WOULD_BLOCK` decision takes no network action. Both destinations use bounded queues so a slow file does not block log ingestion. Queue overflow and write failures are reported to stderr. After a rename/create rotation, the next record opens the configured path. New output files use mode `0600`; existing files retain their current permissions. Create the configured output directories and give the service account write access before starting. Rotate by rename/create and signal or wait for the next record; the daemon reopens the new path automatically.
