# 024 — Future Cloudflare enforcement and safety gates

**Status:** To do  
**Milestone:** Later; explicitly outside V1  
**Depends on:** Validated V1 monitor data, 021, 023  
**Brief:** §§38, 55, 58–60, 69

Consider Cloudflare challenge, rate limiting, or temporary blocks only after measured false-positive rates support it.

## Acceptance criteria

- A separate enforcer consumes decisions; detection and scoring contain no Cloudflare-specific logic.
- Explicit operator enablement, allowlists, maximum actions/minute, circuit breaker, monitor fallback, and action audit trail guard all actions.
- A dry-run comparison using replay and production monitor data shows expected actions and false-positive review before any live enablement.
- Failures in Cloudflare or the enforcer leave monitoring available and do not silently change policy.
