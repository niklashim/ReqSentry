# 046 — Persistent k6 service and shared helpers

**Status:** Done  
**Epic:** E — k6 framework  
**Depends on:** 042, 043

## Objective

Persistent k6 service and shared helpers for the production-like local Linux environment.

## Technical description and subtasks

Add a separate, persistent k6 Compose container with read-only scripts mount, Docker-network site URLs, shared config/helpers and useful tags. Launch scenarios with `docker exec` only.

## Acceptance criteria

k6 remains available after Compose start and can call both Nginx sites without a host k6 installation.

## Testing requirements

Compose config, k6 version, connectivity and script import checks.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The separate k6 v1.8.1 container remained running after Compose start. Scripts ran with `docker exec`, reached both Nginx sites through the Compose network, and required no host k6 installation. The scripts mount read-only.
