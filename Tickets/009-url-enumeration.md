# 009 — URL patterns and 404 enumeration

**Status:** To do  
**Milestone:** V1  
**Depends on:** 006  
**Brief:** §§14–16, 33, 53

Distinguish repeated missing assets from broad path/query enumeration while respecting memory caps.

## Acceptance criteria

- Snapshots expose 404 count/rate, distinct 404 paths, repeated paths, and a diversity ratio, with saturation clearly marked.
- Numeric path segments and query values normalize into stable patterns such as `/users/{NUMBER}` and `/product?id={NUMBER}`; raw sensitive query values are not retained without need.
- Signals identify sequential or high-diversity enumeration with evidence counts, not merely a high 404 rate.
- A repeatedly missing single asset does not receive the same enumeration signal as many distinct IDs.
- Tests include changing query parameters, URL encoding, normalization collisions, and capped cardinality.
