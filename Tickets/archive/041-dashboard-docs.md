# 041 — Dashboard operations and API documentation

**Status:** Done  
**Epic:** N — Dashboard documentation  
**Depends on:** 025–040

## Objective

Make secure one-binary dashboard deployment and investigation repeatable.

## Technical description and subtasks

- Document disabled/default localhost configuration, allowed IPs/CIDRs, IPv6, SSH tunneling, trusted proxies, authentication credentials, and TLS/reverse proxy setup.
- Document endpoints, filters, pagination, live stream, data windows, history retention, and troubleshooting.
- Update example YAML, systemd guidance, root README, and ticket index with actual behavior and limits.

## Implementation considerations

Examples must be safe by default and avoid public unauthenticated listeners.

## Acceptance criteria

- An operator can enable and inspect the dashboard using the binary alone and verify access denial.
- Documentation distinguishes live samples, historical incident snapshots, and unsupported metrics.

## Testing requirements

Validate configuration snippets, links, commands, and an offline embedded-assets smoke test.

## Documentation impact

This ticket owns the final dashboard guide and release notes.

## Security considerations

Do not publish real credentials, client IPs, or production query data in examples.

## Completion

Example YAML, dashboard operations/API guidance, installation notes, and root README describe safe setup and measured data coverage.
