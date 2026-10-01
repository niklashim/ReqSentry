# 052 — Local development README and troubleshooting

**Status:** Done  
**Epic:** I — Developer documentation  
**Depends on:** 042–051

## Objective

Local development README and troubleshooting for the production-like local Linux environment.

## Technical description and subtasks

Make the root README the command source of truth for Compose, site/dashboard URLs, docker exec k6, data paths, restart/reset, optional MaxMind/Slack and common failures. Do not add a Makefile.

## Acceptance criteria

A new developer can start, run tests, inspect outputs and stop using standard Docker commands.

## Testing requirements

Follow documented commands on a clean machine.

## Documentation impact

Record exact Docker and inspection commands in the root README or `tests/k6/README.md`.

## Security considerations

Keep the environment local, preserve monitor-only behavior, and never commit credentials.

## Completion evidence

The original root README and k6 README documented direct Compose and `docker exec` commands, host output paths, restart, rotation, reset, optional integrations and troubleshooting. The detailed walkthrough now lives in `docs/development.md`, linked from the shorter root README. The first local build pulled official images and completed the documented walkthrough. The checked-in config is named as an example, and runtime data and `.env` are ignored by Git.
