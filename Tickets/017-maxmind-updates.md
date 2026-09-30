# 017 — MaxMind first download and persistent updates

**Status:** To do  
**Milestone:** V1  
**Depends on:** 014, 016  
**Brief:** §§24–28, 47, 67

Manage MMDB freshness independently of traffic monitoring, with credentials outside plain configuration.

## Acceptance criteria

- On startup, a missing database triggers an initial download; an existing valid database is used immediately and does not trigger a request merely due to restart.
- Last check, last success, next check, and failure count persist across restarts; the normal interval defaults to 24 hours.
- Failures keep the current MMDB active and apply persistent capped retry backoff, without interrupting log analysis.
- Downloads go to a temporary file, are validated, then atomically replace the active MMDB and reload its reader; invalid files never replace a working database.
- License credentials are loaded via environment/systemd credentials; status and repeated failures are available for local logs and operational alerts.
