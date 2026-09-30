# 013 — Explainable scoring and monitor decisions

**Status:** To do  
**Milestone:** V1  
**Depends on:** 009, 010, 011, 012  
**Brief:** §§32–36, 39, 58–59

Turn deterministic signals into one versioned incident and a monitor-only decision that every output can consume.

## Acceptance criteria

- Weights and thresholds are configurable; scores are bounded to 0–100 and each contribution records a reason code, weight, and underlying evidence.
- Supporting metadata alone cannot accumulate into `WOULD_BLOCK`; that decision requires a strong signal or multiple independent behavioral signals.
- Classifications include NORMAL, WATCH, SUSPICIOUS, and `WOULD_BLOCK`; any added `WOULD_*` decisions remain hypothetical.
- Every incident contains site/server scope, IP, time window, available health/enrichment, score, decision, and `ruleset_version`.
- Detection has no network-enforcement code path. Tests demonstrate explainable decisions and false-positive controls.
