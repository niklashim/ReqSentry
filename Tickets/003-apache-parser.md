# 003 — Apache parser and log-format guidance

**Status:** To do  
**Milestone:** V1  
**Depends on:** 002  
**Brief:** §§4, 9–10, 65, 67

Normalize Apache access logs into the same request event as Nginx, and document recommended formats for both servers.

## Acceptance criteria

- Standard Apache access logs and a recommended extended format parse without server-specific logic leaking into detection.
- Each configured log maps to a stable site identity; host information is retained when present.
- Documentation shows Nginx and Apache configurations that include client IP, host, method, URI/query, status, bytes, referrer, User-Agent, and available timing fields.
- Missing timing or other optional fields disable only dependent signals.
- Parser fixtures include IPv6, malformed lines, and both minimal and enriched formats.
