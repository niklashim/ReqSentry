# 012 — Cross-site and server-impact signals

**Status:** Done

**Milestone:** V1  
**Depends on:** 006, 007, 008  
**Brief:** §§5, 9, 30–31, 33

Connect per-IP traffic to cross-site scanning and contemporaneous server/PHP-FPM pressure without claiming unsupported causality.

## Acceptance criteria

- A client spreading similar scanning traffic across several sites can trigger a server-wide signal even if no site threshold is crossed.
- Traffic share is calculated against all observed requests in the same window and labels incomplete log coverage.
- Available request/upstream timing, CPU/load/memory, and PHP-FPM samples are included as timestamped evidence.
- Impact signals require aligned time windows and describe correlation or contribution, not proof that one IP caused high CPU.
- Tests cover multi-site scanning and expensive low-volume traffic.
