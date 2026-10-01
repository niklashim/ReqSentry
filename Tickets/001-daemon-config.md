# 001 — Go daemon skeleton and configuration

**Status:** Done

**Milestone:** V1  
**Depends on:** None  
**Brief:** §§1–8, 62–65

Create the Go application structure, daemon lifecycle, and YAML configuration contract. Keep detection separate from output or future enforcement interfaces.

## Acceptance criteria

- A Linux binary starts in `monitor` mode, handles shutdown cleanly, and validates configuration before starting watchers.
- YAML supports server identity, multiple access files/sites, trigger settings, analysis windows, database, MaxMind, and output settings; invalid values fail with useful errors.
- Secrets are referenced through environment variables or systemd credentials rather than required as plaintext YAML values.
- Interfaces establish a normalized request event and an incident/decision boundary; no enforcement implementation or Cloudflare dependency is included.
- A sample config documents defaults and absolute paths without claiming a runnable installation before integration.
