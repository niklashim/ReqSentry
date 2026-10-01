# 029 — Aggregated dashboard history

**Status:** Done  
**Epic:** C — Core statistics adapter  
**Depends on:** 014, 028

## Objective

Provide bounded historical traffic and health charts without persisting raw requests.

## Technical description and subtasks

- Add a versioned SQLite migration for minute-level server/site traffic, status totals, incident counts, CPU/load/memory, and PHP-FPM samples.
- Batch or periodically write aggregated samples; cap retention and index time/site queries.
- Provide bounded range queries for 5m, 15m, 1h, 6h, 24h, and 7d with controlled bucket resolution.

## Implementation considerations

Preserve existing incident/offset state and monitor-only operation. History writing must be asynchronous or low frequency.

## Acceptance criteria

- Charts survive restart; raw request paths/IPs are not persisted solely for dashboard charts.
- Queries have row/time limits, use indexes, and do not starve SQLite incident writes.

## Testing requirements

Migration from schema v1, retention, bucket math, concurrent writes/reads, and missing-sample labeling.

## Documentation impact

Document retention, storage cost, coverage, and query limits.

## Security considerations

Restrict database file access; do not expose history without dashboard access control.

## Completion notes

Minute history and exact committed incident counts are saved in SQLite. The bounded seven-day query combines every complete minute into at most 500 chart buckets and marks missing or partial data as gaps. Dashboard queries use a separate read-only WAL connection; a reader/writer concurrency test covers incident commits while a dashboard read transaction is open. Sustained representative Linux load validation remains in ticket 040.
