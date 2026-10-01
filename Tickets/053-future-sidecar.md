# 053 — Future separate ReqSentry sidecar

**Status:** Future  
**Epic:** Future — Sidecar  
**Depends on:** 042–052

## Objective

Future separate ReqSentry sidecar for the production-like local Linux environment.

## Technical description and subtasks

Later evaluate a separate ReqSentry container with Nginx logs mounted read-only. This is explicitly outside the primary local development architecture.

## Acceptance criteria

No implementation in this milestone; design notes preserve the read-only log mount requirement.

## Testing requirements

Future only.

## Documentation impact

Record exact Docker and inspection commands in `docs/development.md` or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.
