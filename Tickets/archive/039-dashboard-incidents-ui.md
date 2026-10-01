# 039 — Incident list and historical detail UI

**Status:** Done  
**Epic:** L — Incident investigation  
**Depends on:** 031, 033

## Objective

Browse and audit the exact evidence behind saved decisions.

## Technical description and subtasks

- Build a paginated incident list with time/site/score/decision/IP/signal filters.
- Build a detail view from the immutable saved incident payload, including window, traffic, health, PHP-FPM, enrichment, signals/weights, score, ruleset, and decision.
- Link incident to site, IP, and ASN views while keeping historical snapshot labels clear.

## Implementation considerations

Historical detail must never silently substitute current IP behavior or health.

## Acceptance criteria

- Filtering and pagination work; every `WOULD_BLOCK` detail states no action was taken.
- Old rulesets and missing optional evidence remain understandable.

## Testing requirements

Old/current snapshots, filters, pages, unavailable enrichments, and XSS-safe rendering.

## Documentation impact

Explain retention and historical evidence interpretation.

## Security considerations

Sensitive incident evidence is accessible only after network and auth checks.

## Completion

Incident list supports filters and pagination; detail renders the immutable saved signal, health, PHP-FPM, score, and ruleset snapshot.
