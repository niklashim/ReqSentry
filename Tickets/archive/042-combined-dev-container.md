# 042 — Combined Nginx and ReqSentry container

**Status:** Done  
**Epic:** A — Combined container  
**Depends on:** 025, 043, 045

## Objective

Combined Nginx and ReqSentry container for the production-like local Linux environment.

## Technical description and subtasks

Build one Linux image with Nginx and ReqSentry, supervise both, forward signals, report process failure and shut down cleanly. Keep this process model development-only.

## Acceptance criteria

`docker compose up -d --build` starts both processes in one `reqsentry-web` container; either process failing makes the container unhealthy or stopped.

## Testing requirements

Image build, supervisor lifecycle, signal and process-failure checks.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The image built and passed Nginx and ReqSentry config checks. Both processes ran in `reqsentry-web`; stopping either child made the supervisor exit with status 1. A Compose restart stopped ReqSentry cleanly and returned the container to healthy.
