# k6 traffic fixtures

Start Compose from the repository root, then run scripts in the persistent `reqsentry-k6` container. k6 sends HTTP requests to **Nginx** on ports 8081–8084; ReqSentry observes four access logs. The site URLs come from `SITE1_URL` through `SITE4_URL` in Compose. Requests use the example domain in the `Host` header and the `site` tag, along with `scenario` and `traffic_type` tags.

| Site | Local URL | Log file |
| --- | --- | --- |
| `him.com` | http://localhost:8081 | `site1.access.log` |
| `mycoolshop.se` | http://localhost:8082 | `site2.access.log` |
| `ekstrom.nu` | http://localhost:8083 | `site3.access.log` |
| `wordpress-site.com` | http://localhost:8084 | `site4.access.log` |

| Script | Deterministic traffic | Possible detector evidence |
| --- | --- | --- |
| `normal.js` | Browser-like pages/assets on all four sites | Usually no strong signal |
| `high-404.js` | 90 distinct 404s, 10 valid pages | 404 rate/diversity |
| `enumeration.js` | Sequential product IDs and missing user paths | Query/path enumeration |
| `methods.js` | Seven methods on valid/missing paths | Method anomalies |
| `redirects.js` | Followed/unfollowed 301/302 | Redirect-follow behavior |
| `user-agents.js` | Browser, curl, Python, bot, empty, rotating agents | User-Agent observations |
| `cross-site.js` | 50 missing user paths per site from one k6 source | Cross-site IP aggregation |
| `high-rate.js` | Configurable requests per second to `him.com` | Request rate |

```sh
docker exec reqsentry-k6 k6 run /scripts/scenarios/normal.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/high-404.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/enumeration.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/methods.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/redirects.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/user-agents.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/cross-site.js
docker exec reqsentry-k6 k6 run /scripts/scenarios/high-rate.js
```

High-rate defaults to 20 requests/second for 10 seconds. Increase it deliberately:

```sh
docker exec -e RATE=500 -e DURATION=30s reqsentry-k6 \
  k6 run /scripts/scenarios/high-rate.js
```

`RATE` must be 1–10,000. `DURATION` accepts a positive count of seconds or minutes. k6 targets that iteration rate; achieved throughput may be lower when resources are constrained. Other scenarios use one VU or a small fixed iteration count.

The `high-404` fixture produces `high404-000` through `high404-089`, then 10 `/about.html` requests. Enumeration and cross-site scenarios also use fixed ID ranges. Inspect host files in `dev-data/nginx/logs/`, then ReqSentry's `incidents.jsonl` or SQLite. A generated pattern is not proof that a particular signal will fire under the current ruleset. For manual regression, start from a known test state, run one script, wait at least the 30-second analysis window, and inspect the dashboard or saved incident evidence. The [development guide](../../docs/development.md) documents restart, rotation, state inspection, and intentional reset.
