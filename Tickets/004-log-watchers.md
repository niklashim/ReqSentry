# 004 — Multi-log watchers and rotation

**Status:** Done

**Milestone:** V1  
**Depends on:** 002  
**Brief:** §§5, 47, 52, 67–68

Follow every configured Nginx and Apache access file through a single daemon, preserving the source site for each event.

## Acceptance criteria

- Multiple logs can be followed concurrently without mixing site identities.
- Rotation by rename/create and truncation is detected; the new active file is followed without restart or rereading the full previous file.
- Partial lines, temporarily missing files, permission errors, and reopen retries are handled without stopping other watchers.
- Rotation and restart behavior is tested with fixtures that detect skipped or duplicate events at the handoff boundary.
- Persistent failures are observable through operational logs/health state for later alerts.

Implementation and restart limits are documented in [local history and output](../docs/storage-output.md).
