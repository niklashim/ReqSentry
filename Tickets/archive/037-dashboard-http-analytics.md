# 037 — HTTP method, status, path, and User-Agent analytics

**Status:** Done  
**Epic:** J — HTTP analytics  
**Depends on:** 028, 030, 033

## Objective

Show bounded HTTP behavior, with special attention to 404s and enumeration.

## Technical description and subtasks

- Add method/status tables with 2xx, 301, 302, 403, 404, and 5xx counts/rates.
- Show top requested/404 paths, normalized path/query patterns, missing and top User-Agents, and associated IP links where measured.
- Label sampled/top-N/incomplete values instead of claiming exact global cardinality.

## Implementation considerations

Use existing normalization and detector signals; the UI must not implement its own URL or bot classifier.

## Acceptance criteria

- HTTP page updates from aggregate data and remains bounded under unique-URL attacks.
- Operators can trace a 404 or method anomaly to IP and incident evidence.

## Testing requirements

Method/status fixture, URL/query enumeration, missing User-Agent, caps, and attack-scale rendering.

## Documentation impact

Define observed-window, sample, and top-N semantics.

## Security considerations

Escape all request-derived strings; do not persist raw query values for dashboard use.

## Completion notes

The live aggregator now keeps exact bounded method/status cross totals for the server and each site. The HTTP page shows those totals, 404 leaders with bounded unique-path evidence, normalized path/query samples, and User-Agent samples with coverage labels and IP links. A User-Agent row also shows how many sampled IPs have recent suspicious or would-block incidents; this is an association, not proof that the User-Agent caused the decision. Global path and User-Agent counts are intentionally presented as tracked samples; the dashboard does not persist raw requests or claim exact global cardinality. Attack-scale aggregation bounds are covered by the 10,000-request test; sustained Linux load testing remains in ticket 040.
