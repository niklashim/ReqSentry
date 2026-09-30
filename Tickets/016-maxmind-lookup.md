# 016 — Local MaxMind enrichment

**Status:** To do  
**Milestone:** V1  
**Depends on:** 001, 005  
**Brief:** §§22–23, 49, 67

Enrich IPs from local MMDB files without network activity on the request hot path.

## Acceptance criteria

- Local lookups can provide available ASN, organization, ISP/network type, and country for IPv4 and IPv6.
- MMDB files remain the source database; bounded lookup caching may use memory or SQLite metadata.
- Missing databases, unsupported fields, or lookup failures leave detection operational and mark enrichment unavailable.
- Hosting/cloud classification is only a supporting risk modifier and cannot independently trigger `WOULD_BLOCK`.
- Reader replacement can occur safely when an update installs a new validated file.
