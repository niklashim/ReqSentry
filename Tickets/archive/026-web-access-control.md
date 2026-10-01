# 026 — Dashboard IP allowlists and trusted proxies

**Status:** Done  
**Epic:** B — Dashboard security  
**Depends on:** 025

## Objective

Reject every dashboard request whose effective client IP is not explicitly allowed.

## Technical description and subtasks

- Parse IPv4/IPv6 addresses and CIDRs from `web.allowed_ips`; an empty list denies all.
- Resolve forwarded IPs only when the direct TCP peer matches `web.trusted_proxies`, using a bounded right-to-left chain.
- Apply the same middleware to HTML, assets, REST, and live streams; return a generic 403.

## Implementation considerations

Keep the dashboard trust list independent of log-ingestion proxy trust. Do not treat a User-Agent or spoofed header as identity.

## Acceptance criteria

- Individual IPv4/IPv6 and CIDR policies work; unlisted addresses are denied.
- Untrusted `X-Forwarded-For` is ignored, including spoofed multiple-hop headers.
- Localhost/SSH tunnel use can be configured explicitly.

## Testing requirements

Table tests for allowed/denied IPv4 and IPv6, empty allowlist, trusted/untrusted peers, malformed chains, and header spoofing.

## Documentation impact

Document CIDRs, IPv6, SSH tunneling, and reverse proxy trust.

## Security considerations

The direct TCP peer is authoritative until proven trusted; reject before exposing route details.

## Completion

IPv4/IPv6 allowlists and trusted-proxy chain checks cover all routes; spoof and duplicate-header tests pass.
