# 054 — Named four-site fixture and per-IP site links

**Status:** Done  
**Depends on:** 028, 036, 042–052

## Objective

Show which sites a tracked IP reached, and provide four realistic, locally testable site names.

## Implementation

- Add `site_ids` to aggregate IP dashboard rows from active per-site records in the same rolling window. Sort names and link each one to site details in the IP explorer.
- Label saved server-wide incidents with an empty site ID as “All sites” without rewriting historical evidence.
- Configure `him.com`, `mycoolshop.se`, `ekstrom.nu`, and `wordpress-site.com` as four independent Nginx fixtures on local ports 8081–8084, each with its own access log. Keep the dashboard on 8090.
- Run k6 scenarios across all four sites with matching Host headers and site tags. Use relative fixture redirects so followed requests remain on the Compose network.
- Document the site URLs, log mapping, rolling site association, and historical incident behavior.

## Acceptance and verification

`go test ./...`, JavaScript syntax checks, and `docker compose config -q` passed. The Compose image built with valid Nginx and ReqSentry configuration and became healthy. All eight k6 scenarios passed their response checks. After normal and cross-site traffic, `/api/v1/ips` showed one source IP with all four site IDs; `/api/v1/sites` showed four named rows. Each log recorded the matching Host name. SQLite retained older `site1`/`site2` and server-wide incidents while saving new incidents under the domain IDs.
