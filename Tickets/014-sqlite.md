# 014 — SQLite history and ruleset versioning

**Status:** To do  
**Milestone:** V1  
**Depends on:** 013  
**Brief:** §§23, 26, 37, 39–41, 67

Persist incidents and operational metadata for investigation without one transaction per request.

## Acceptance criteria

- Schema and migrations cover sites, canonical IPs, incidents, selected traffic windows, and persistent system/update state.
- Incident records retain reason evidence, score, decision, ruleset version, timestamps, and optional enrichment/health fields.
- Writes are batched or queued away from the request hot path; overload and database errors are surfaced without stopping monitoring.
- Reopening the database retains history and update state; a mixed IPv4/IPv6 fixture round-trips correctly.
- Normal traffic need not be stored as every rolling window; retention behavior is documented.
