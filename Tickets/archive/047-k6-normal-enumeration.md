# 047 — Normal, high-404 and enumeration scenarios

**Status:** Done  
**Epic:** F — k6 scenarios  
**Depends on:** 043, 046

## Objective

Normal, high-404 and enumeration scenarios for the production-like local Linux environment.

## Technical description and subtasks

Implement conservative, deterministic normal browser traffic, 90-unique-404/10-valid traffic, and sequential path/query enumeration across configured target URLs.

## Acceptance criteria

Scenarios use shared helpers/tags and produce recognizable Nginx log patterns for future regression checks.

## Testing requirements

k6 script validation and inspect generated log samples.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

Normal traffic produced 50 successful checks; high-404 produced 90 expected 404s and 10 valid responses; enumeration produced 200 successful checks. The independent Nginx logs contained the fixed paths, and ReqSentry recorded 404 and enumeration signals.
