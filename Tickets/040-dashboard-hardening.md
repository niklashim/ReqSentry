# 040 — Dashboard security and load hardening

**Status:** In progress  
**Epic:** M — Performance and resilience  
**Depends on:** 025–039

## Objective

Keep monitoring responsive and dashboard exposure bounded during attacks.

## Technical description and subtasks

- Cap clients, stream memory, response bytes, result rows, query time/ranges, request header/query sizes, and top-N collections.
- Exercise 10,000 req/sec equivalent traffic, many active IPs, unique paths, and incident generation while API clients are slow.
- Audit middleware coverage, CSP, path traversal, spoofed headers, auth failures, and denied-request logging.

## Implementation considerations

Dashboard overload should degrade or reject dashboard clients before affecting watcher, SQLite writes, or scoring.

## Acceptance criteria

- Bounded growth and no ingestion blocking under stress; limits are observable and documented.
- Unauthorized clients cannot reach assets, API, or stream; mutation methods remain unavailable.

## Testing requirements

Race, fuzz/invalid input, slow client, concurrent writes/queries, attack-scale load, and browser security checks.

## Documentation impact

Record measured limits, benchmark environment, and deployment advice.

## Security considerations

Deny by default; do not log credentials; use explicit response and connection timeouts.

## Remaining work

Sustained Linux load, slow-browser, and real-socket deployment checks remain; local binding is restricted in this environment.
