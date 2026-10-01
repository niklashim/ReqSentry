# 028 — Bounded live dashboard statistics

**Status:** Done  
**Epic:** C — Core statistics adapter  
**Depends on:** 006, 007, 008, 013, 025

## Objective

Expose current traffic and detection state from the existing ReqSentry core without parsing logs or rescoring in the web layer.

## Technical description and subtasks

- Publish immutable, bounded one-second snapshots from the existing aggregator and daemon.
- Include server totals, site totals, top IPs, methods/statuses, 404s, path/query/User-Agent samples, incident counts, health, and PHP-FPM state.
- Correlate MaxMind ASN metadata only where already available or through bounded background enrichment; label unavailable fields.

## Implementation considerations

Reuse existing counters and incident values. Add only bounded aggregate counters needed by the UI; avoid storing every request.

## Acceptance criteria

- Active IP, rate, status, and site counts reflect live ingestion with clear 60-second coverage.
- Snapshot capture never blocks ingestion on disk/network work; caps and degraded evidence remain visible.

## Testing requirements

Normal/attack traffic, multiple sites, IPv6, high-cardinality caps, and concurrent snapshot reads.

## Documentation impact

Define metric windows and incompleteness labels.

## Security considerations

Snapshot APIs must be protected by the web access middleware.

## Completion

The existing rolling aggregator supplies bounded server, site, and tracked-IP statistics, while daemon adapters supply health, incidents, and local enrichment.
