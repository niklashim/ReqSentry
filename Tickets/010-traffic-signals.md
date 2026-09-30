# 010 — Rates, statuses, and redirects

**Status:** To do  
**Milestone:** V1  
**Depends on:** 006  
**Brief:** §§12–13, 17, 33

Derive rate and response signals from rolling snapshots, using redirects as supporting evidence.

## Acceptance criteria

- Detectors can use requests per second/10s/30s/minute, peak rate, sustained rate, and bursts.
- Key status counts include 2xx, 301, 302, 403, 404, and 5xx; ratios use explicit denominators.
- Redirect-follow behavior is assessed only when the necessary target information is available; otherwise it is marked unavailable.
- High volume or redirects alone cannot produce a high-confidence `WOULD_BLOCK` classification.
- Tests cover bursts, steady traffic, missing optional fields, and redirect-follow examples.
