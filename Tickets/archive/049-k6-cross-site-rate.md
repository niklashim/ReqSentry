# 049 — Cross-site and configurable high-rate scenarios

**Status:** Done  
**Epic:** F — k6 scenarios  
**Depends on:** 043, 046

## Objective

Cross-site and configurable high-rate scenarios for the production-like local Linux environment.

## Technical description and subtasks

Use the same k6 client IP across two sites for suspicious traffic; add a rate-controlled scenario with conservative defaults and RATE/DURATION overrides.

## Acceptance criteria

Cross-site logs share a client source and high-rate tests only become aggressive with explicit settings.

## Testing requirements

k6 threshold/config validation and bounded smoke run.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

Cross-site traffic passed 200 checks and both site logs showed the same k6 source IP. The high-rate default passed 201 checks. An explicit `RATE=50 DURATION=3s` run completed 151 requests at about 50 requests/second without failed checks.
