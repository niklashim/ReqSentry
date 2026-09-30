# 021 — Replay and production validation

**Status:** To do  
**Milestone:** V1  
**Depends on:** 003–020  
**Brief:** §§56, 63, 68–69

Feed historical access logs through the normal parser, aggregator, and detector, then verify V1 against representative and adversarial traffic.

## Acceptance criteria

- `reqsentry replay <access.log>` uses the same normalized events and rules as live monitoring and reports decisions without network actions.
- Fixtures cover normal browsing/API traffic, high-404 scanning, query/path enumeration, method scans, cross-site scans, and expensive lower-rate requests.
- End-to-end checks cover rotation, restart, proxy identity, IPv6, unavailable PHP-FPM/MaxMind/Slack, and persistent MaxMind retry state.
- Benchmarks report CPU, memory, ingestion lag, and dropped/coalesced data at normal and attack-scale loads; any limits are documented.
- A monitor-mode review records false positives and threshold changes before considering future enforcement.
