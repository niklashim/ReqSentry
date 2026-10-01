# 044 — Host-mapped development logs and state

**Status:** Done  
**Epic:** C — Persistent data  
**Depends on:** 042, 043

## Objective

Host-mapped development logs and state for the production-like local Linux environment.

## Technical description and subtasks

Bind `/var/log/nginx` to `dev-data/nginx/logs` and ReqSentry SQLite/log/MMDB paths to `dev-data/reqsentry`, with reproducible permissions and safe reset instructions.

## Acceptance criteria

Log and SQLite data survive container restart/rebuild and can be inspected from the host.

## Testing requirements

Restart, file permission, log rotation and checkpoint-resume checks.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

Host-mounted logs, JSONL incidents and SQLite were inspectable. Five incidents and minute history survived both restart and image rebuild. Clean shutdown saved nonzero watcher offsets. After site1 rotation, Nginx created a new access log and ReqSentry reported and followed it. Generated files are ignored by Git.
