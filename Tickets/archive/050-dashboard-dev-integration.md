# 050 — Dashboard exposure in local Compose

**Status:** Done  
**Epic:** G — Dashboard integration  
**Depends on:** 025–041, 042, 045

## Objective

Dashboard exposure in local Compose for the production-like local Linux environment.

## Technical description and subtasks

Expose dashboard on localhost:8090 with a development-only Docker source CIDR allowlist; verify live traffic, sites, incidents and access denial without changing production defaults.

## Acceptance criteria

The browser reaches the dashboard and generated Nginx traffic appears through log ingestion.

## Testing requirements

Docker access-policy, API, UI and live-update smoke checks.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The localhost dashboard returned HTTP 200. Its API reported traffic from both sites and five saved incidents, with minute history and an immutable incident detail. The SSE endpoint emitted live snapshots. Access-control denial paths are covered by the dashboard security tests.
