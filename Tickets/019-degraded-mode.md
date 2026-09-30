# 019 — Resource limits and degraded mode

**Status:** To do  
**Milestone:** V1  
**Depends on:** 006, 013  
**Brief:** §§53–55, 63, 68

Protect the web server from monitoring overhead during very large or adversarial traffic volumes.

## Acceptance criteria

- Configurable limits bound active IP records, unique paths/404 paths, User-Agents, patterns, queues, and retained string sizes.
- A configured memory/resource threshold enters degraded mode and stops expensive tracking while preserving IP, request, status, method, and basic rate counters.
- Saturated or degraded evidence is labeled so the scorer cannot present incomplete counts as exact counts.
- Recovery is controlled and observable; overloaded output or database queues cannot grow without bound.
- Stress tests show bounded growth and continued ingestion at traffic levels well above normal load.
