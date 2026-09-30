# 018 — Slack incident and operational alerts

**Status:** To do  
**Milestone:** V1  
**Depends on:** 013, 015  
**Brief:** §§44–47, 58, 67

Send optional, concise alerts for high-confidence incidents and repeated operational failures.

## Acceptance criteria

- A configured score floor controls incident alerts; messages include server/site, IP, window, top evidence, available health/enrichment, score, and decision.
- Every hypothetical action states `MONITOR MODE — NO ACTION WAS TAKEN` or equivalent.
- Per-incident/IP cooldown and active-incident deduplication suppress one alert per analysis window; a later distinct incident may alert again.
- Webhook secrets come from environment/systemd credentials; timeouts and failures never block log ingestion.
- Repeated failures in inputs, SQLite, PHP-FPM, or MaxMind can emit controlled operational alerts without a flood from transient errors.
