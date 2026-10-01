# 048 — Methods, redirects and User-Agent scenarios

**Status:** Done  
**Epic:** F — k6 scenarios  
**Depends on:** 043, 046

## Objective

Methods, redirects and User-Agent scenarios for the production-like local Linux environment.

## Technical description and subtasks

Implement GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS, followed/unfollowed 301/302 traffic, and normal/missing/rotating User-Agent patterns.

## Acceptance criteria

Each scenario has predictable endpoints and bounded default load across both sites.

## Testing requirements

Response expectation and log-field checks.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The method, redirect, and User-Agent scenarios completed with 28, 8, and 12 successful response checks respectively. Nginx logs showed method and redirect statuses and the requested User-Agent variants.
