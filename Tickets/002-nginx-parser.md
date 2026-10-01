# 002 — Normalized request event and Nginx parser

**Status:** Done

**Milestone:** V1  
**Depends on:** 001  
**Brief:** §§9–10, 49, 65

Parse supported Nginx access-log formats into a common request event with timestamp, site, client IP, method, path, query, status, bytes, referrer, User-Agent, and optional request/upstream timing.

## Acceptance criteria

- Required fields are validated; unavailable optional fields are represented as absent, never fabricated as zero-valued evidence.
- IPv4 and IPv6 addresses parse consistently, including malformed-address rejection.
- Standard access logs work with reduced signals, and a documented recommended format supplies richer timing and host data.
- Bad lines are counted/logged at a bounded rate while later valid lines continue to parse.
- Fixtures cover quoting, escaped fields, long URLs, missing timing, and representative Nginx lines.
