# 006 — Bounded rolling aggregation

**Status:** To do  
**Milestone:** V1  
**Depends on:** 002, 005  
**Brief:** §§5, 8, 11–13, 40, 53, 63

Maintain lightweight in-memory statistics for each site/IP and across all sites per IP. Collection continues even when deep analysis is inactive.

## Acceptance criteria

- Rolling 1s, 10s, 30s, and 60s views expose request counts, peaks, status families/key statuses, method counts, bytes, and available timing.
- Per-site and server-wide views agree with the same input stream; old buckets expire predictably.
- Active IPs, paths, 404 paths, User-Agents, and query-pattern state have configurable caps and expiry; saturation is explicitly represented in snapshots.
- The per-line path performs no SQLite transaction, MaxMind network access, Slack request, or expensive scoring.
- Tests cover window boundaries, multi-site traffic, high-cardinality attacks, and low-traffic collection before trigger activation.
