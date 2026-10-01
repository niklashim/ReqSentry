# 038 — Server and PHP-FPM health views

**Status:** Done  
**Epic:** K — Resource health  
**Depends on:** 008, 029, 030, 033

## Objective

Correlate traffic and incidents with observed server and PHP-FPM pressure.

## Technical description and subtasks

- Show CPU, memory, load 1/5/15 minute values and their sampled-at/staleness state.
- Show each PHP-FPM pool's active/idle/total workers, max children reached, slow requests, listen queue, and unavailable/stale state.
- Plot resource samples on the same bounded time axis as traffic/incidents where history exists.

## Implementation considerations

Reuse the existing samplers; the dashboard must not poll `/proc` or PHP-FPM independently.

## Acceptance criteria

- Missing samples are visibly unavailable, not zero; timelines allow comparison without claiming causality.

## Testing requirements

Available/stale/missing health, multiple pools, no PHP-FPM configuration, and alignment with traffic buckets.

## Documentation impact

Explain sample timing and correlation limits.

## Security considerations

No PHP-FPM status endpoint or infrastructure secret leaks through error text.

## Completion

Server health and PHP-FPM panels expose current, missing, and stale values plus bounded comparative history charts.
