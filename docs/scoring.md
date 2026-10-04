# WordPress traffic scoring

ReqSentry scores the behavior of an IP during a site or server analysis window. The score describes pressure and suspicious patterns in that window; it is neither a probability of abuse nor a permanent reputation. `WOULD_BLOCK` remains an informational decision. The [README scoring table](../README.md#how-the-score-is-calculated) lists every default weight and trigger.

## WordPress endpoints

WordPress exposes a core sitemap index at `/wp-sitemap.xml`, with additional sitemap files for content types. Fetching these is ordinary crawler behavior. [WordPress sitemap documentation](https://make.wordpress.org/core/2020/07/22/new-xml-sitemaps-functionality-in-wordpress-5-5/).

The endpoint flood counter recognizes these path/query patterns:

| Endpoint | Examples |
| --- | --- |
| XML sitemaps | `/wp-sitemap.xml`, `/wp-sitemap-posts-post-1.xml`, `/sitemap_index.xml`, `/post-sitemap2.xml` |
| Login and XML-RPC | `/wp-login.php`, `/xmlrpc.php` |
| AJAX and REST | `/wp-admin/admin-ajax.php`, `/wp-json/`, query key `rest_route` or `wc-ajax` |
| Search and feeds | Query key `s` or `feed`, paths ending in `/feed` or `/feed/` |

Path matching also recognizes subdirectory installations. Sitemap filenames must end in `.xml` and begin with `wp-sitemap`/`sitemap` or contain `-sitemap`. Static files under `/wp-content/` do not qualify merely because of that directory. This is path classification, not verification that a server runs WordPress. Query values are neither retained nor used as identities. Oversized paths are not classified, and oversized queries are ignored for query-key classification; a recognized path still counts even when its query is oversized.

`WORDPRESS_ENDPOINT_FLOOD` adds **30 points** when the window is at least ten seconds, contains at least 100 matching requests, averages at least ten matching requests/second, and has matching requests in at least 80% of its seconds. These conditions use the matching requests, not all requests from the IP. Counts are scoped to the client and site; a server-wide window can combine configured sites. Fixed endpoint counters remain available when optional rich evidence is degraded.

For a 30-second site window with 300 evenly spread sitemap requests from a hosting IP, the default score is **80**: high request rate (15), sustained rate (15), endpoint flood (30), and hosting (20). A residential origin with identical traffic scores **60**; residential metadata grants no safety exemption. Small or intermittent sitemap fetches do not satisfy the flood rule. Legitimate headless WordPress clients, integrations, and crawlers can reach these thresholds, so review the window and tune for the site's expected traffic.

## Weighting and corroboration

The defaults prioritize missing-path diversity, path/method scans, sustained WordPress endpoint pressure, request rate, and hosting context. Hosting contributes **20 points**, but alone remains below the `WATCH` threshold. A claimed Googlebot User-Agent grants no exception. Missing/rotating User-Agents, common automation strings, and redirect ratios retain visible evidence with zero default weight.

Numeric query variation receives ten supporting points because it can describe ordinary pagination. 404/5xx ratios and resource impact also remain supporting evidence: a broken asset, failing API, slow server, or shared exit can affect legitimate clients. They do not supply independent corroboration for `WOULD_BLOCK`, even with higher configured weights. Multiple rate signals count as one behavioral group.

This approach distinguishes automation from abuse. OWASP recommends protecting legitimate crawlers, monitoring, and integration tools and using endpoint/identity context rather than treating an unusual User-Agent as decisive. [OWASP bot management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html).

The numeric weights are ReqSentry policy defaults, not values prescribed by those sources or statistically fitted to production traffic. No universal set of weights is best for every WordPress installation. The default ruleset version is `2`; saved incidents keep their original weights and version. `ruleset_version` labels a configuration; selecting an older number does not restore an older algorithm. Give custom weight/threshold sets a distinct version.

## Google ASN exclusion

`detection.excluded_asns` defaults to `[15169]`. An analysis candidate resolved to that ASN is excluded before incident output and notifications, including during replay and bounded recovery. Requests still contribute to live traffic totals. Existing saved incidents are not deleted by adding an exclusion. An explicit `[]` disables ASN exclusions; a supplied list replaces the default. The list supports at most 64 unique, nonzero ASN numbers.

Enable MaxMind and supply a local ASN-capable MMDB, such as GeoLite2-ASN or GeoIP2-Enterprise. A country-only database cannot resolve ASN policy. Missing files, failed lookups, and absent ASN fields leave the client monitored; they never imply Google or residential status. CLI status and replay summaries show configured exclusions, excluded candidate windows, and unresolved candidate windows. Site and server windows are counted separately; these counters are not distinct IP counts.

This policy excludes the entire ASN and does not verify Googlebot. Google documents separate crawler/fetcher IP lists and forward-confirmed reverse DNS, and distinguishes user-triggered fetchers from common search crawlers. Use the existing IP/CIDR allowlist with the appropriate published crawler ranges when that narrower policy is wanted; ReqSentry does not download crawler lists automatically. [Google request verification](https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests).

Local lookups run during analysis, outside request ingestion. Replay reads enabled existing MMDB files without downloads or notification delivery. Current MMDB metadata may differ from the historical request period; CPU/PHP-FPM history is not reconstructed.

## Distributed traffic limits

Per-IP scoring is useful for concentrated WordPress crawling and floods. It cannot reliably identify a campaign that sends only one or two normal-looking requests from each rotating address. Increasing hosting or rate weights cannot create evidence that the logs do not contain. Residential exits do not receive a negative weight, and ReqSentry does not equate a common ASN, country, or User-Agent with one actor.

Cloudflare describes residential proxy rotation defeating IP reputation/rate limits and the risk of penalizing legitimate traffic sharing those exits. [Cloudflare residential proxy research](https://blog.cloudflare.com/residential-proxy-bot-detection-using-machine-learning/). OWASP also describes proxy networks distributing credential attacks below per-IP limits. [OWASP credential-stuffing guidance](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html).

Detecting that class of activity requires additional endpoint/campaign aggregation and trustworthy session/account or connection context. The current engine does not provide those identities, credential-stuffing detection, or TLS/browser fingerprints. Neither a zero score nor absence from incident history certifies a client as safe.

## Calibrate for your site

1. Replay representative logs containing normal sitemap refreshes, crawl peaks, search, AJAX/REST integrations, cache misses, broken assets, outages, and any confirmed abuse.
2. Label windows by observed behavior and investigate false positives and missed activity. Separate hosting, residential, shared exits, excluded Google traffic, and unknown metadata.
3. Compare candidate weights and thresholds on the same input. Adjust `wordpress_rps`, `wordpress_min_requests`, and `wordpress_active_ratio` for expected endpoint activity. A zero signal weight removes its contribution without deleting matched evidence.
4. Validate the chosen settings on a separate log period before changing live notifications. Record the config version and review precision, missed known incidents, and resource use; do not optimize only for the loudest attack examples.

Use [the complete config](../configs/example.yaml), [CLI replay](cli.md#historical-analysis), and [deployment testing](validation.md#validate-a-deployment). Synthetic regression fixtures protect behavior for sitemap/XML-RPC floods, normal fetching, static assets, hosting and residential traffic, pagination, outages, scanning, ASN exclusions, and rotating exits; they do not estimate production false-positive rates.
