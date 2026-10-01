# 034 — Live server overview and charts

**Status:** In progress  
**Epic:** G — Server overview  
**Depends on:** 029, 030, 032, 033

## Objective

Answer what the server is doing now and how traffic relates to resource pressure.

## Technical description and subtasks

- Show RPS/RPM, active IPs, status ratios, suspicious/WOULD_BLOCK counts, CPU/load/memory, and PHP-FPM totals.
- Draw bounded time series for traffic, 404/5xx, incidents, CPU/load, and workers with shared time axes.
- Show recent incident links and availability/degraded-state labels.

## Implementation considerations

Use the core's aggregate windows; chart missing samples as gaps and avoid charting every request.

## Acceptance criteria

- Initial view loads quickly, refreshes without page reload, and makes monitor mode obvious.
- Charts stay bounded during high traffic and allow visual time correlation.

## Testing requirements

Snapshot/chart mapping, empty data, stale health, stream reconnect, and large value rendering.

## Documentation impact

Explain metric windows and chart coverage.

## Security considerations

Render all site/IP/signal strings as text; no controls can change traffic.

## Remaining work

Distinct IPs across selected multi-minute ranges are not available without retaining a bounded mergeable sketch. Exact committed incident counts now appear in complete historical buckets, and absent or partial buckets display as gaps.
