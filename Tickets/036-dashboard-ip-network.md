# 036 — IP and ASN investigation views

**Status:** In progress  
**Epic:** I — IP and network analytics  
**Depends on:** 030, 031, 033

## Objective

Explain a client's current behavior, prior incidents, and available network context.

## Technical description and subtasks

- Build searchable IP list/detail with current requests, 404s, methods, paths/query patterns, sites, score/decision, exact signals, and historical incident links.
- Build ASN list/detail with organization, classification, observed IPs/sites, request/404 totals where measured, suspicious counts, and incident links.
- Mark missing MaxMind data and incomplete bounded samples.

## Implementation considerations

Differentiate live window from history; do not infer maliciousness from ASN membership or User-Agent alone.

## Acceptance criteria

- IPv4/IPv6 routes work; decisions show the original detector evidence and monitor-only meaning.
- Network metrics identify their coverage and avoid unsupported historical request totals.

## Testing requirements

IPv4/IPv6, no MaxMind, multiple sites/ASNs, old incidents, and path/query encoding.

## Documentation impact

Explain current versus historical fields and ASN caveats.

## Security considerations

Bound search and text rendering; never expose raw query values beyond core retention policy.

## Remaining work

IP first/last seen and full historical sites accessed are not indexed yet; current investigation uses bounded live data and saved incident links.
