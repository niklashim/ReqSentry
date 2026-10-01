# 008 — PHP-FPM health collection

**Status:** Done

**Milestone:** V1  
**Depends on:** 001  
**Brief:** §§4, 30–31, 47, 67

Read available PHP-FPM status data without making PHP-FPM a requirement for operating the daemon.

## Acceptance criteria

- Configured status endpoint(s) provide active, idle, total/max workers, max-children events, and slow-request counters where exposed.
- Samples include timestamps and a clear unavailable/stale state; absent fields do not become zero-valued evidence.
- Sampling failures are bounded, logged, and never stop access-log monitoring.
- Incident snapshots can include PHP-FPM saturation near the same traffic window.
