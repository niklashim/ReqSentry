# 020 — Linux service and operator CLI

**Status:** Done

**Milestone:** V1  
**Depends on:** 004, 007, 014, 015, 016, 017, 018, 019  
**Brief:** §§57, 62, 67–68

Package the monitor for Linux/systemd and provide basic local diagnostics.

## Acceptance criteria

- Installation guidance covers the binary, config, state/log directories, least-privilege log access, and systemd service lifecycle.
- `reqsentry config test` validates configuration; `status` reports monitor/trigger state, watched logs, current health, SQLite, MaxMind, and Slack status where available.
- `report` summarizes recent incidents; MaxMind status/update commands expose and respect the persistent scheduler.
- Documentation explains recommended access-log formats and how to verify each configured site is monitored.
- A smoke test starts, restarts, and stops the service against sample logs without any traffic-changing capability.

The CLI, status heartbeat, systemd unit, and [installation guide](../docs/install.md) are implemented. The daemon smoke test exercises start, restart, and stop with an access log. The systemd unit is provided for the target Linux host; it has not been run on this macOS development host.
