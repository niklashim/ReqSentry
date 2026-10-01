# 051 — Deterministic integration and restart checks

**Status:** Done  
**Epic:** H — Regression harness  
**Depends on:** 043–050

## Objective

Deterministic integration and restart checks for the production-like local Linux environment.

## Technical description and subtasks

Document and implement repeatable checks for scenario → Nginx logs → ReqSentry aggregation/incident evidence, plus restart and log-rotation behavior. Avoid claims for signals not yet implemented.

## Acceptance criteria

A developer can reproduce tests and inspect actual saved evidence, offsets and continued ingestion.

## Testing requirements

Scenario assertions, restart, rotation and retained SQLite history.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The documented direct Docker commands reproduced scenario traffic in Nginx logs and corresponding ReqSentry incidents in SQLite. Restart and rebuild retained incident history and offsets; the documented rotation procedure produced a fresh site1 log and ReqSentry resumed ingestion. No Makefile or wrapper was needed.
