# 022 — Automatic trigger and site profiles

**Status:** To do  
**Milestone:** Later  
**Depends on:** V1 monitor data and 007, 011  
**Brief:** §§8, 18, 21

Add an `auto` trigger using traffic/5xx/PHP-FPM/latency anomalies, plus optional site and endpoint method expectations.

## Acceptance criteria

- Auto activation has documented thresholds, hysteresis, and behavior when inputs are missing.
- Site/endpoint profiles can make methods and browser-like signals contextual without treating APIs as browsers.
- Historical replay demonstrates the effect on false positives before enabling by default.
