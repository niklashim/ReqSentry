# 045 — Monitor-only local ReqSentry configuration

**Status:** Done  
**Epic:** D — Local config  
**Depends on:** 025, 043

## Objective

Monitor-only local ReqSentry configuration for the production-like local Linux environment.

## Technical description and subtasks

Create a checked-in `configs/config.local.example.yaml` using two Nginx logs, always-on analysis, monitor mode, disabled optional integrations and localhost dashboard access via a documented development-only allowlist.

## Acceptance criteria

No credentials are required; both site logs are watched; core production dashboard defaults stay deny by default.

## Testing requirements

Config validation and Docker source-IP access checks.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The checked-in example config passed in-image validation without credentials. Runtime logs confirmed monitor mode, always-on analysis and both watched sites. The dashboard returned HTTP 200 through the development-only Docker allowlist; production defaults remain deny by default.
