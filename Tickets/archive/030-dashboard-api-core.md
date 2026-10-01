# 030 — Versioned overview and live analytics API

**Status:** Done  
**Epic:** D — Read-only API  
**Depends on:** 027, 028, 029

## Objective

Expose stable, bounded JSON for current server, health, sites, IPs, HTTP, and time-series views.

## Technical description and subtasks

- Implement `/api/v1/status`, `/server`, `/stats`, `/sites`, `/sites/{id}`, `/ips`, `/ips/{ip}`, `/asns`, `/asns/{asn}`, `/phpfpm`, and `/user-agents` from core snapshots.
- Validate IDs/IPs/ASNs, cap top-N and ranges, return explicit unavailable/incomplete fields, and use 404 for unknown resources.
- Keep responses read-only and encode untrusted strings as JSON, never hand-built HTML.

## Implementation considerations

The API may be split across packages but should share one snapshot schema and access middleware.

## Acceptance criteria

- Endpoints return valid bounded JSON and no mutation method is accepted.
- Site/IP/ASN detail links use the same core data and exact detector signal values.

## Testing requirements

Response schemas, invalid IDs/IP/ASN, caps, time ranges, malformed/oversized queries, and forbidden methods.

## Documentation impact

Publish endpoint and window semantics for external consumers.

## Security considerations

Require access control on every route; prevent path traversal and oversized inputs.

## Completion

Versioned read-only endpoints expose live server, site, IP, ASN, HTTP, and health data with bounded queries and coverage labels.
