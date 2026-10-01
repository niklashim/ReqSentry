# 031 — Historical incident API

**Status:** Done  
**Epic:** D — Read-only API  
**Depends on:** 014, 027, 030

## Objective

Query immutable historical incident snapshots with bounded search and filtering.

## Technical description and subtasks

- Add incident ID lookup plus paginated list filters for time, site, score, decision, IP, and signal code.
- Query SQLite using indexed predicates and stable order; return the saved JSON evidence, ruleset, health, PHP-FPM, and enrichment exactly as recorded.
- Add `/api/v1/incidents` and `/api/v1/incidents/{id}` with total/next-page metadata.

## Implementation considerations

Never replace historical evidence with a client's current live state. Limit page size and range.

## Acceptance criteria

- Detail shows the original monitor-only decision and signals; list filters and pagination are correct.
- Invalid IDs/filters return 400 or 404 without unbounded scans.

## Testing requirements

Concurrent SQLite writes, pagination boundaries, filter combinations, invalid IDs, and old ruleset snapshots.

## Documentation impact

Document filter parameters, pagination, retention, and audit semantics.

## Security considerations

All history routes use the same allowlist/auth policy and query limits.

## Completion

SQLite incident search and ID lookup return saved payloads with indexed signal and nanosecond time filters; API supports bounded pagination.
