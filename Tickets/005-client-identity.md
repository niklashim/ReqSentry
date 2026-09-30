# 005 — Client IP, trusted proxies, and allowlists

**Status:** To do  
**Milestone:** V1  
**Depends on:** 002  
**Brief:** §§48–50, 67–68

Resolve client identity safely before aggregation, supporting IPv4, IPv6, proxy deployments, and trusted IP/CIDR exclusions.

## Acceptance criteria

- A forwarded client header is considered only when the immediate sender belongs to a configured trusted-proxy CIDR; arbitrary headers cannot spoof client identity.
- Proxy-chain selection and malformed/missing header behavior are documented and tested for IPv4 and IPv6.
- IP/CIDR allowlists are validated on load and excluded from detection statistics while remaining operationally observable.
- The same canonical IP representation is used by aggregation, storage, and MaxMind lookup.
