# 014 — SQLite history and ruleset versioning

**Status:** Done

**Milestone:** V1  
**Depends on:** 013  
**Brief:** §§23, 26, 37, 39–41, 67

Persist incidents and operational metadata for investigation without one transaction per request.

## Acceptance criteria

- Schema and migrations cover sites, canonical IPs, incidents, selected traffic windows, and persistent system/update state.
- Incident records retain reason evidence, score, decision, ruleset version, timestamps, and optional enrichment/health fields.
- Writes are batched or queued away from the request hot path; overload and database errors are surfaced without stopping monitoring.
- Reopening the database retains history and update state; a mixed IPv4/IPv6 fixture round-trips correctly.
- Persist watcher file identity and offsets so a clean restart resumes unread entries in the same active log without replaying all history. Define and test crash-window behavior explicitly.
- Normal traffic need not be stored as every rolling window; retention behavior is documented.

Retention and checkpoint limits are documented in [local history and output](../docs/storage-output.md).
