# 043 — Two-site Nginx fixture and canonical logs

**Status:** Done  
**Epic:** B — Nginx fixture  
**Depends on:** 002, 004

## Objective

Two-site Nginx fixture and canonical logs for the production-like local Linux environment.

## Technical description and subtasks

Configure site1 on 8081 and site2 on 8082, each with independent access/error logs, predictable pages and 301/302 endpoints. Use ReqSentry-recommended fields in a canonical log format.

## Acceptance criteria

Both sites respond locally and write separate valid parseable logs for requests, methods, redirects and optional timing fields.

## Testing requirements

Nginx config validation, endpoint and parser fixtures.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

Nginx config validation passed. Both sites returned HTTP 200 on their mapped ports and wrote separate access logs with canonical fields. Live method and redirect fixtures returned expected statuses, and ReqSentry consumed the logs.
