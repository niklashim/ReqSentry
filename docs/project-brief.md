# ReqSentry original project brief

> This is the original design brief. It records goals and examples from planning; use the linked operations guides and configuration files for the current implementation.
<p align="center">
  <img src="../logo.png" alt="ReqSentry" width="900">
</p>
## 1. Project Overview

ReqSentry is a lightweight Linux daemon for detecting abusive, automated, or abnormal web traffic.

It is specifically designed for web servers running:

- Nginx
- Apache
- PHP-FPM

ReqSentry analyzes existing web-server access logs and correlates HTTP behavior with server and PHP-FPM health.

The objective is not simply to determine whether a visitor is a "bot."

The primary question is:

> Is this client behaving abnormally, and is its traffic negatively affecting the web server?

ReqSentry should be lightweight, deterministic, explainable and safe to deploy on production servers.

The initial version is **monitor-only**.

It detects suspicious traffic and records what it WOULD have done, but it does not block, challenge, rate-limit or otherwise modify traffic.

Future versions may integrate with Cloudflare for enforcement, but Cloudflare enforcement is explicitly outside the initial scope.

---

# 2. Core Design Principles

ReqSentry should follow these principles:

1. Web traffic only.
2. Nginx, Apache and PHP-FPM focused.
3. One daemon per server.
4. Support multiple websites/access logs.
5. Extremely lightweight per-request processing.
6. Keep live statistics primarily in memory.
7. Persist historical information in SQLite.
8. Use deterministic behavioral detection rather than AI.
9. Every detection must be explainable.
10. Monitor mode must be safe for production.
11. Detection and future enforcement must remain separate.
12. Memory usage must be bounded.
13. The daemon must degrade gracefully during extremely large attacks.
14. IPv4 and IPv6 must both be supported.
15. External service failures must never prevent ReqSentry from monitoring traffic.

---

# 3. High-Level Architecture

    Nginx / Apache
          │
          ├── site1.access.log
          ├── site2.access.log
          ├── site3.access.log
          │
          ▼
    ┌──────────────────┐
    │     ReqSentry    │
    └────────┬─────────┘
             │
             ├── Log watchers
             │
             ├── Log parser
             │
             ├── In-memory aggregation
             │
             ├── HTTP behavior analysis
             │
             ├── CPU/load monitoring
             │
             ├── PHP-FPM monitoring
             │
             ├── MaxMind enrichment
             │
             ├── Detection/scoring engine
             │
             └── Historical reputation
                     │
          ┌──────────┼───────────┐
          ▼          ▼           ▼
       SQLite     Log files     Slack
                                  │
                                  ▼
                         Administrator

Future:

    Detection Engine
           │
           ▼
        Decision
           │
      ┌────┴─────┐
      ▼          ▼
    Monitor    Enforcer
                 │
              Cloudflare

The enforcer is NOT part of the initial implementation.

---

# 4. Supported Inputs

ReqSentry should initially support:

## Web-server logs

- Nginx access logs
- Apache access logs

Future/extended input support:

- Nginx error logs
- Apache error logs

## Server health

- CPU usage
- system load
- memory usage

## PHP-FPM

Where available:

- active processes
- idle processes
- total processes
- max active processes
- max children reached
- slow requests
- PHP-FPM saturation indicators

---

# 5. Multiple Website Support

A single ReqSentry daemon monitors all configured websites on the server.

Example:

    /var/log/nginx/site1.access.log
    /var/log/nginx/site2.access.log
    /var/log/nginx/site3.access.log
    /var/log/apache/site4.access.log

Each request must be associated with its source site/log.

ReqSentry maintains statistics at two levels:

## Per-site + IP

Example:

    site1 + 65.21.x.x

## Server-wide + IP

Example:

    all-sites + 65.21.x.x

This is necessary to detect clients deliberately spreading scanning activity across multiple virtual hosts.

Example:

    site1    200 requests
    site2    190 requests
    site3    210 requests
    site4    205 requests
    site5    195 requests

No individual website necessarily crosses a threshold.

However:

    Total requests: 1,000
    Websites:       5
    404 responses:  870

This may represent server-wide scanning.

---

# 6. Initial Configuration

Configuration should use YAML.

Example:

    server:
      name: web-prod-03

    mode: monitor

    access_files:
      - /var/log/nginx/site1.access.log
      - /var/log/nginx/site2.access.log
      - /var/log/nginx/site3.access.log

    trigger:
      mode: cpu

      cpu_start: 80
      cpu_stop: 60

      start_duration: 10s
      stop_duration: 60s

    analysis:
      window: 30s

    database:
      path: /var/lib/reqsentry/reqsentry.db

    maxmind:
      enabled: true
      account_id: "123456"
      license_key_env: REQSENTRY_MAXMIND_LICENSE_KEY

      database_dir: /var/lib/reqsentry/maxmind

      update:
        enabled: true
        interval: 24h

    output:
      log:
        enabled: true
        path: /var/log/reqsentry/reqsentry.log

      incidents:
        enabled: true
        path: /var/log/reqsentry/incidents.jsonl

      slack:
        enabled: true
        webhook_env: REQSENTRY_SLACK_WEBHOOK
        minimum_score: 80
        cooldown: 10m

---

# 7. Trigger Modes

ReqSentry should support at least two analysis trigger modes.

## Always

    trigger:
      mode: always

Deep traffic analysis runs continuously.

## CPU

    trigger:
      mode: cpu

Lightweight traffic collection always continues.

Deep analysis activates when CPU usage becomes high.

Example:

    CPU > 80% for 10 seconds
             ↓
       DEEP ANALYSIS ON

Deep analysis remains active until:

    CPU < 60% for 60 seconds
             ↓
       DEEP ANALYSIS OFF

Separate start and stop thresholds provide hysteresis and prevent constant switching around a single CPU threshold.

---

# 8. Important CPU-Mode Behavior

CPU-triggered mode must NOT mean that ReqSentry stops reading logs when CPU usage is low.

ReqSentry should always maintain inexpensive rolling counters.

Therefore, when CPU suddenly rises, the previous traffic window is already available.

Conceptually:

                  ALWAYS
                    │
                    ▼
    Access logs → lightweight counters
                    │
            ┌───────┴───────┐
            ▼               ▼
         CPU LOW          CPU HIGH
            │               │
        basic mode      deep analysis

A future `auto` trigger may additionally activate deep analysis based on:

- abnormal request rate
- high 5xx rate
- PHP-FPM saturation
- abnormal latency
- other server-health anomalies

`auto` is not required for the initial implementation but the trigger architecture should allow it later.

---

# 9. Access Log Information

Where supported by the configured log format, ReqSentry should extract:

- timestamp
- client IP
- site
- HTTP method
- request path
- query string
- HTTP status
- response bytes
- referrer
- User-Agent
- request time
- upstream response time

Request and upstream timing are particularly useful because request volume alone does not indicate server cost.

Example:

    IP A:
      2,000 requests
      average processing: 0.003 sec

    IP B:
      500 requests
      average processing: 1.8 sec

IP B may create substantially more server pressure despite generating fewer requests.

---

# 10. Recommended Nginx/Apache Log Format

ReqSentry should document a recommended log format containing:

- client IP
- host
- request method
- URI
- query
- status
- bytes
- referrer
- User-Agent
- request time
- upstream response time

ReqSentry should still operate with standard access logs where some optional information is unavailable.

Detection rules requiring unavailable fields should simply not run.

---

# 11. Live Aggregation

Live statistics should primarily exist in RAM.

Do NOT write to SQLite for every HTTP request.

For each IP/site combination, maintain rolling statistics.

Suggested windows:

    1 second
    10 seconds
    30 seconds
    60 seconds

Example:

    IP: 65.21.x.x
    Site: site1

    Requests:          1,824
    Peak req/sec:         91

    Unique paths:      1,702
    Unique 404 paths:  1,557

    GET:               1,720
    POST:                 71
    PATCH:                14
    OPTIONS:              19

    2xx:                 103
    301:                  42
    302:                  31
    404:               1,604
    5xx:                  17

---

# 12. Request Rate Analysis

ReqSentry should monitor:

- requests per second
- requests per 10 seconds
- requests per 30 seconds
- requests per minute
- peak requests/second
- sustained request rate
- sudden request bursts

High traffic alone must NOT automatically classify an IP as abusive.

Request rate is one signal among several.

---

# 13. HTTP Status Analysis

ReqSentry should track HTTP response families and important individual statuses.

At minimum:

    2xx
    301
    302
    403
    404
    5xx

---

# 14. 404 Analysis

404 behavior is a major detection signal.

Track:

- total 404s
- 404 percentage
- unique 404 paths
- unique 404 ratio
- repeated 404 paths
- changing query parameters associated with 404s
- normalized 404 patterns

Example:

    Requests:       1,824
    404:            1,604
    404 rate:       87.9%
    Unique 404:     1,557

This is considerably more suspicious than:

    Requests:       1,824
    404:               4

---

# 15. 404 Diversity

ReqSentry must distinguish between repeated requests for the same missing resource and enumeration.

Example A:

    /old-logo.png → 404 × 500

This could simply be a broken page/application.

Example B:

    /product?id=10001 → 404
    /product?id=10002 → 404
    /product?id=10003 → 404
    ...
    /product?id=10500 → 404

This strongly suggests enumeration.

Unique 404 diversity should therefore be an important detection signal.

---

# 16. URL and Query Normalization

ReqSentry should normalize changing URL components where practical.

Example:

    /product?id=18291
    /product?id=18292
    /product?id=18293

becomes:

    /product?id={NUMBER}

Similarly:

    /users/18291
    /users/18292

becomes:

    /users/{NUMBER}

Possible future patterns:

    {NUMBER}
    {UUID}
    {HEX}
    {TOKEN}

This allows ReqSentry to identify systematic crawling and enumeration.

Example finding:

    Pattern:
    /product?id={NUMBER}

    Attempts:       1,591
    Different IDs:  1,540
    404:            1,487
    404 rate:       93.5%

---

# 17. 301 / 302 Analysis

Redirect behavior should also be analyzed.

A browser commonly follows redirects:

    GET /old-page
        ↓
    301 /new-page
        ↓
    GET /new-page
        ↓
    200

A basic scanner may generate hundreds of redirect responses without following the destination.

ReqSentry should track:

- 301 count
- 302 count
- redirect ratio
- apparent redirect-follow behavior where detectable

Example:

    Requests:             900
    Redirect responses:   720
    Redirect follow-ups:   12

Redirect behavior should generally be a supporting signal rather than a standalone block-level signal.

---

# 18. HTTP Method Analysis

Track at least:

    GET
    HEAD
    POST
    PUT
    PATCH
    DELETE
    OPTIONS

ReqSentry should detect unusual method behavior.

Examples:

    PATCH /about-us
    DELETE /image/logo.png
    POST /random-generated-url
    OPTIONS /random-generated-url

However, methods cannot be considered suspicious globally.

For an API:

    OPTIONS /api/resource

may be completely legitimate.

Eventually ReqSentry should support endpoint/site profiles.

Example:

    /login
      expected: GET, POST

    /static/*
      expected: GET, HEAD

    /api/*
      expected:
        GET
        POST
        PUT
        PATCH
        DELETE
        OPTIONS

This makes method detection contextual.

---

# 19. Method + Status Correlation

Combining HTTP methods with response status is more useful than either alone.

Example:

    POST   /random1 → 404
    PATCH  /random2 → 404
    PUT    /random3 → 404
    DELETE /random4 → 404

This is substantially more suspicious than:

    GET /missing-image.jpg → 404

ReqSentry should therefore support signals based on combinations of:

    method
      +
    endpoint
      +
    status

---

# 20. User-Agent Analysis

ReqSentry should collect User-Agent information.

Per IP, track:

- primary User-Agent
- User-Agent request counts
- missing User-Agent
- number of distinct User-Agents
- rapid User-Agent rotation
- obviously automated User-Agents
- claimed crawler identities

Example:

    User-Agent:
    python-requests/2.x

User-Agent must never be trusted as proof of identity.

A client claiming:

    Mozilla/5.0 Chrome...

while simultaneously:

    generating 90 req/sec
    producing 94% 404s
    enumerating IDs
    never following redirects
    sending unusual methods

should still be considered suspicious.

Behavior is more important than User-Agent claims.

---

# 21. Browser-Like Behavior

For sites primarily serving browsers, ReqSentry may use browser request patterns as supporting evidence.

A browser commonly requests:

    /
    /style.css
    /app.js
    /logo.svg
    /favicon.ico
    /api/menu

A crawler may instead request:

    /product/10001
    /product/10002
    /product/10003
    /product/10004

without normal page assets.

This must remain a supporting signal because legitimate API clients and other software may not request assets.

---

# 22. MaxMind Enrichment

ReqSentry should support local MaxMind MMDB databases.

For a new IP, enrichment may include:

    IP
    ASN
    ASN organization
    network/user type
    ISP
    country

Example:

    IP:              65.21.x.x
    ASN:             AS24940
    Organization:    Hetzner
    Network:         Hosting
    Country:         Finland

Possible network categories include:

    Residential
    Cellular
    Business
    Hosting
    Cloud
    CDN
    Search crawler
    VPN/Proxy
    Unknown

Network classification is a supporting risk modifier.

Hosting/cloud traffic must NOT automatically be considered malicious.

---

# 23. MaxMind Storage

The MaxMind database itself remains an MMDB file.

Example:

    /var/lib/reqsentry/maxmind/GeoIP.mmdb

Lookup results may be cached in SQLite.

Example IP metadata:

    ip
    asn
    asn_org
    network_type
    country
    maxmind_updated

---

# 24. MaxMind Automatic Updates

ReqSentry should manage MaxMind database freshness automatically.

Configuration:

    maxmind:
      enabled: true

      account_id: "123456"
      license_key_env: REQSENTRY_MAXMIND_LICENSE_KEY

      database_dir:
        /var/lib/reqsentry/maxmind

      update:
        enabled: true
        interval: 24h

Credentials should not need to be stored directly in the YAML configuration.

Secrets should be loadable from environment variables/systemd credentials.

---

# 25. MaxMind First Startup Behavior

When ReqSentry starts:

    Does MMDB exist?
           │
       ┌───┴───┐
       │       │
      NO      YES
       │       │
       ▼       ▼
    Download   Check persistent
    immediately update state

If the database does not exist, ReqSentry should download it immediately.

If it exists, ReqSentry should use it immediately.

An existing database must NOT automatically be downloaded again simply because ReqSentry restarted.

---

# 26. MaxMind Persistent Update State

The update schedule must survive application restarts.

A boot loop must NOT cause repeated MaxMind downloads or update requests.

Persist values such as:

    maxmind_last_check
    maxmind_last_success
    maxmind_next_check
    maxmind_failure_count

Example:

    DB exists
    Last check: 7 minutes ago
    Next check: 23h 53m

    → use existing DB
    → do not contact MaxMind

Normal update check interval:

    24 hours

---

# 27. MaxMind Failure Handling

If an update fails:

- continue using the existing MMDB
- do not disable traffic analysis
- log the failure
- retry using persistent backoff

Possible retry sequence:

    first failure   → retry in 1h
    second failure  → retry in 2h
    third failure   → retry in 4h
    subsequent      → maximum 6h interval

Retry state must survive application restarts.

After multiple consecutive failures, optionally send a Slack warning.

---

# 28. Atomic MaxMind Updates

Never overwrite the active database directly.

Process:

    Download
       ↓
    GeoIP.mmdb.tmp
       ↓
    Validate MMDB
       ↓
    Atomic rename
       ↓
    Reload MaxMind reader

If validation fails:

    delete temporary file
    retain existing database
    log error

---

# 29. Server Health Monitoring

ReqSentry should monitor at least:

- CPU percentage
- system load
- memory usage

Server-health information should be captured when an incident occurs.

Example:

    CPU:       94%
    Load 1m:   7.82
    Memory:    63%

---

# 30. PHP-FPM Monitoring

ReqSentry should integrate with PHP-FPM health/status information where available.

Potential statistics:

    Active workers
    Idle workers
    Total workers
    Max children
    Max children reached
    Slow requests

Example:

    PHP-FPM

    Active workers:     47
    Idle workers:        3
    Max children:       50
    Max children hit:   YES

This information should be correlated with HTTP traffic.

---

# 31. Server Impact Attribution

One of ReqSentry's important differentiators is determining which traffic is contributing to server pressure.

Example:

    Server requests during window:
    3,912

    Requests from IP:
    1,824

    Traffic contribution:
    46.6%

Combined with:

    CPU:             94%
    PHP-FPM:         47/50 active
    IP 404 rate:     87.9%
    Network:         Hosting

this provides significantly more useful evidence than request count alone.

---

# 32. Detection Philosophy

ReqSentry should NOT simply ask:

    "Is this IP a bot?"

Instead:

    "Is this client's behavior abnormal and/or harmful?"

A human running an abusive script is still abusive.

A bot performing legitimate monitoring may be harmless.

Detection should therefore prioritize behavior.

---

# 33. Detection Signals

Potential signals include:

## Traffic

    HIGH_REQUEST_RATE
    HIGH_BURST_RATE
    SUSTAINED_HIGH_RATE
    HIGH_TRAFFIC_SHARE

## HTTP status

    HIGH_404_RATE
    HIGH_404_DIVERSITY
    HIGH_5XX_CONTRIBUTION
    ABNORMAL_REDIRECT_BEHAVIOR

## URL behavior

    URL_ENUMERATION
    QUERY_ENUMERATION
    PATH_ENUMERATION
    SENSITIVE_PATH_SCAN

## HTTP methods

    UNEXPECTED_METHODS
    METHOD_404_SCAN
    METHOD_ENUMERATION

## Identity/network

    HOSTING_NETWORK
    CLOUD_NETWORK
    PROXY_NETWORK
    MISSING_USER_AGENT
    AUTOMATED_USER_AGENT
    USER_AGENT_ROTATION

## Cross-site

    CROSS_SITE_SCAN

## Server impact

    CPU_SPIKE_CONTRIBUTOR
    PHP_FPM_SATURATION_CONTRIBUTOR
    HIGH_REQUEST_COST

---

# 34. Risk Scoring

ReqSentry should combine multiple signals into an explainable score.

Example:

    HIGH_REQUEST_RATE          +15
    HIGH_404_RATE              +20
    HIGH_404_DIVERSITY         +20
    URL_ENUMERATION            +25
    UNEXPECTED_METHODS         +10
    HOSTING_NETWORK             +5
    CPU_SPIKE_CONTRIBUTOR      +15

    Raw score:                 110
    Final score:               100

Possible initial classifications:

    0–29       NORMAL
    30–59      WATCH
    60–79      SUSPICIOUS
    80–100     WOULD_BLOCK

Exact thresholds and weights should be configurable and should be tuned using real monitor-mode data.

---

# 35. Strong vs Supporting Signals

ReqSentry should avoid a weakness of simple additive scoring where many weak signals accidentally produce a block-level score.

Signals should eventually be classified by strength.

## Supporting

Examples:

    Hosting ASN
    Odd User-Agent
    Redirect behavior
    Country/network metadata

## Behavioral

Examples:

    High request rate
    High 404 ratio
    Unusual HTTP methods
    Cross-site activity

## Strong

Examples:

    Very high unique 404 diversity
    Sequential enumeration
    Known scanner paths
    Extreme sustained request rate

A WOULD_BLOCK decision should generally require:

- at least one strong signal

OR

- multiple independent behavioral signals

rather than simply accumulating weak metadata signals.

---

# 36. Explainability

Every detection must record WHY the score was generated.

Example:

    Score: 96

    Reasons:

    +25 HIGH_404_RATE
    +25 HIGH_404_DIVERSITY
    +20 URL_ENUMERATION
    +10 HIGH_REQUEST_RATE
    +10 UNEXPECTED_METHODS
    + 6 HOSTING_NETWORK

Do not produce opaque decisions.

---

# 37. Historical Reputation

SQLite should retain historical IP information.

Potential fields:

    IP
    first seen
    last seen
    ASN
    ASN organization
    network type
    country
    total incidents
    highest risk score
    recent incidents

Repeated suspicious behavior can eventually influence decisions.

Example:

    IP:
    65.21.x.x

    Previous incidents: 12
    Websites targeted:   6
    Highest score:       98

Historical suspicion should decay over time rather than permanently accumulating.

---

# 38. Future Strike/Escalation Model

Although enforcement is not part of V1, the architecture should allow future escalation.

Concept:

    Detection
       ↓
    Is current behavior abusive?
       ↓
      YES
       ↓
    Historical offender?
       ↓
    Determine enforcement duration

Possible future example:

    First offense      → 10 minutes
    Second offense     → 1 hour
    Third offense      → 24 hours
    Repeated offender  → longer

This should remain separate from the behavior score itself.

---

# 39. Score/Ruleset Versioning

Every persisted incident should record which detection ruleset produced the score.

Example:

    score:            87
    ruleset_version:  3

This allows historical results to remain interpretable after scoring changes.

---

# 40. SQLite

SQLite should be used for persistent history and metadata.

Potential tables:

    sites
    ips
    traffic_windows
    incidents
    system_state

Do not write one SQLite transaction per HTTP request.

Writes should be batched.

---

# 41. Traffic Windows

Relevant traffic windows can be persisted.

Example:

    timestamp   site   ip          requests  404  unique404  score
    ----------------------------------------------------------------
    22:00:00    shop   65.21.x.x   1824      1604 1557       96
    22:00:30    shop   65.21.x.x   2102      1891 1802       98
    22:01:00    shop   65.21.x.x    892       721  700       91

Normal traffic does not necessarily need every 30-second window persisted forever.

Retention policies should be configurable later.

---

# 42. Local Logs

ReqSentry should produce a normal operational log.

Example:

    /var/log/reqsentry/reqsentry.log

Example entries:

    23:04:17 INFO  watching /var/log/nginx/site1.access.log
    23:04:17 INFO  MaxMind database loaded
    23:04:18 INFO  SQLite ready
    23:12:08 WARN  65.21.x.x score=71 site=site1 SUSPICIOUS
    23:12:38 ALERT 65.21.x.x score=96 site=site1 WOULD_BLOCK
    23:12:38 INFO  Slack notification sent

---

# 43. Structured Incident Log

ReqSentry should also output JSON Lines.

Example:

    /var/log/reqsentry/incidents.jsonl

Example record:

    {
      "server": "web-prod-03",
      "site": "site1",
      "ip": "65.21.x.x",
      "asn": 24940,
      "network": "hosting",
      "window": 30,
      "requests": 1824,
      "status_404": 1604,
      "unique_404": 1557,
      "score": 96,
      "decision": "WOULD_BLOCK",
      "ruleset_version": 1
    }

JSONL makes future integration with systems such as Loki, Elasticsearch, Splunk or a custom dashboard straightforward.

---

# 44. Slack Notifications

Slack notifications should be optional.

Configuration example:

    output:
      slack:
        enabled: true
        webhook_env: REQSENTRY_SLACK_WEBHOOK
        minimum_score: 80
        cooldown: 10m

The Slack webhook secret should not need to appear directly in the configuration file.

---

# 45. Slack Incident Example

A high-confidence incident could produce:

    🚨 ReqSentry — WOULD BLOCK

    Server: web-prod-03
    Site: site1

    IP 65.21.x.x has been detected as abusive traffic.

    IP:               65.21.x.x
    ASN:              AS24940
    Network:          Hosting

    Window:           30 seconds
    Requests:         1,824
    Peak:             91 req/sec

    HTTP Methods:
      GET             1,720
      POST               71
      PATCH              14
      OPTIONS            19

    Responses:
      2xx               103
      301                42
      302                31
      404             1,604
      5xx                17

    Unique paths:      1,702
    Unique 404s:       1,557

    User-Agent:
      python-requests/2.x

    Server:
      CPU:             94%
      Load:            7.82

    PHP-FPM:
      Active:          47/50
      Max children:    YES

    Traffic share:
      46.6%

    Detected:
      HIGH_404_RATE
      HIGH_404_DIVERSITY
      URL_ENUMERATION
      HIGH_REQUEST_RATE
      UNEXPECTED_METHODS
      HOSTING_NETWORK
      CPU_SPIKE_CONTRIBUTOR

    Score:
      96/100

    Decision:
      WOULD_BLOCK

    MONITOR MODE — NO ACTION WAS TAKEN

---

# 46. Slack Deduplication

ReqSentry must avoid notification spam.

If an attacker remains active for 20 minutes, do not send a Slack message every analysis window.

Suggested behavior:

    First high-confidence detection
           ↓
       SEND SLACK
           ↓
    Incident remains active
           ↓
      suppress alerts
           ↓
    cooldown expires
           ↓
    optional status update

If the incident ends and the IP returns later, it may generate a new alert.

---

# 47. Operational Alerts

Slack may also be used for important ReqSentry operational failures.

Examples:

    MaxMind update failing repeatedly
    Access log unavailable
    SQLite failure
    PHP-FPM monitor unavailable

Transient single failures should generally remain in local logs.

Repeated failures may generate Slack notifications.

---

# 48. Trusted Proxies

Trusted proxy handling is critical.

ReqSentry may operate behind:

- Cloudflare
- HAProxy
- Nginx reverse proxies
- load balancers

ReqSentry must safely determine the real client IP.

Never blindly trust arbitrary `X-Forwarded-For` or similar headers.

Configuration should eventually support trusted proxy CIDRs and the appropriate client-IP header.

---

# 49. IPv6

IPv6 must be supported from the beginning.

This includes:

- parsing
- aggregation
- SQLite
- MaxMind
- CIDRs
- allowlists
- future enforcement

Do not design database fields or parsing logic around IPv4-only assumptions.

---

# 50. Allowlists

ReqSentry should support explicit IP/CIDR allowlists.

Examples:

    internal office IPs
    VPNs
    monitoring services
    trusted API clients

Even in monitor mode, allowlists are useful because trusted traffic should not pollute detection statistics.

---

# 51. Known Crawler Verification

Do not trust User-Agent alone for known crawlers.

A client claiming:

    Googlebot

must not automatically be trusted.

Future crawler verification may use:

- official IP ranges
- reverse DNS
- forward DNS confirmation

depending on the provider.

---

# 52. Log Rotation

ReqSentry must correctly handle log rotation.

Example:

    site1.access.log
        ↓
    site1.access.log.1

The watcher must detect file/inode changes and continue following the new active log without:

- losing events
- rereading the entire old log
- requiring daemon restart

---

# 53. Memory Protection

Attackers must not be able to exhaust ReqSentry's RAM by generating unlimited unique values.

Bound:

- active IP records
- unique URLs per IP
- unique 404 URLs per IP
- User-Agent values
- query patterns

Example:

    max unique 404 paths/IP/window = 1,000

Once an IP reaches:

    unique404 >= 1,000

the exact number may no longer matter for detection.

Do not retain unlimited strings.

---

# 54. Degraded Mode

ReqSentry must protect the server from ReqSentry itself.

If resource usage becomes too high:

    ReqSentry memory > configured ceiling
                ↓
        enter degraded mode
                ↓
        stop expensive tracking
                ↓
        retain:
          IP
          request counts
          status counts
          method counts
          basic rates

The monitoring daemon must never become the cause of the outage.

---

# 55. Detection Safety

Even when enforcement is eventually introduced, safety controls should exist.

Concepts to design for now:

    maximum actions/minute
    global enforcement circuit breaker
    allowlists
    monitor fallback
    action audit trail

Example future behavior:

    >30 new blocks/minute
           ↓
    STOP ENFORCEMENT
           ↓
    revert to monitor
           ↓
    alert administrator

This protects against a bad ruleset causing mass blocking.

---

# 56. Replay Mode

ReqSentry should eventually support replaying historical logs through the detection engine.

Example:

    reqsentry replay /var/log/nginx/access.log

This allows developers/operators to test new rules against historical production traffic.

Replay mode is particularly useful for tuning false positives without waiting for new live incidents.

---

# 57. CLI

Potential commands:

    reqsentry status

    reqsentry report

    reqsentry config test

    reqsentry maxmind status

    reqsentry maxmind update

    reqsentry replay <access.log>

Potential status output:

    ReqSentry 0.1.0

    Mode:              MONITOR
    Trigger:           CPU
    Deep analysis:     ACTIVE

    Access logs:       14
    Active IPs:        382
    Incidents today:   17

    Server:
      CPU:             84%
      Load:            5.12

    PHP-FPM:
      Active:          38
      Idle:            12

    MaxMind:
      Database:        GeoIP2 Enterprise
      Last check:      14h ago
      Next check:      in 10h
      Status:          OK

    SQLite:
      Status:          OK
      Size:            84 MB

    Slack:
      Enabled:         YES
      Last alert:      22:51

---

# 58. Monitor Mode

V1 must be monitor-only.

Possible decisions:

    NORMAL
    WATCH
    SUSPICIOUS
    WOULD_CHALLENGE
    WOULD_RATE_LIMIT
    WOULD_BLOCK

However:

    NO NETWORK ACTION IS TAKEN.

This must be explicit in logs and Slack messages.

---

# 59. Future Enforcement Boundary

Detection and enforcement must be separate interfaces/components from day one.

Conceptually:

    detector.Analyze(...)
            ↓
         Decision
            ↓
       Output modules

V1 output modules:

    Logger
    JSONL
    SQLite
    Slack

Future:

    CloudflareEnforcer

The detector itself must never contain Cloudflare-specific logic.

---

# 60. Cloudflare

Cloudflare enforcement is intentionally NOT part of the initial project.

Future functionality may include:

- challenge
- rate limiting
- temporary IP blocking
- escalating repeat offenders
- managed IP lists

Cloudflare should only be considered after monitor-mode data demonstrates acceptable false-positive rates.

---

# 61. What ReqSentry Is Not

ReqSentry is NOT intended to be:

- a general IDS
- a host intrusion prevention system
- a replacement for CrowdSec
- a replacement for fail2ban
- a WAF
- a ModSecurity replacement
- a SQL injection request-body scanner
- a malware scanner
- an SSH security tool

Its scope is deliberately narrow:

> HTTP client behavior and its effect on web-server resources.

---

# 62. Implementation Language

The preferred implementation language is Go.

Reasons include:

- low runtime overhead
- good concurrency primitives
- straightforward log streaming
- strong HTTP/network libraries
- easy Linux deployment
- single compiled binary
- relatively low memory footprint

The desired deployment model is approximately:

    /usr/local/bin/reqsentry

    /etc/reqsentry/
      config.yaml

    /var/lib/reqsentry/
      reqsentry.db

      maxmind/
        GeoIP.mmdb

    /var/log/reqsentry/
      reqsentry.log
      incidents.jsonl

    /etc/systemd/system/
      reqsentry.service

---

# 63. Performance Expectations

The request hot path should be extremely small.

For every log entry:

    Read line
       ↓
    Parse required fields
       ↓
    Find/create in-memory IP statistics
       ↓
    Increment counters
       ↓
    Continue

Do NOT perform:

    MaxMind network download
    SQLite transaction
    Slack request
    expensive scoring

for every access-log line.

Those operations happen asynchronously or periodically.

At approximately 1,000 requests/minute (~17 requests/sec), ReqSentry should impose negligible server overhead when implemented correctly.

The design should also remain safe during traffic levels orders of magnitude larger.

---

# 64. Suggested Internal Components

Potential Go package/component structure:

    cmd/
      reqsentry/

    internal/
      config/
      watcher/
      parser/
      aggregator/
      detector/
      scoring/
      patterns/
      serverhealth/
      phpfpm/
      maxmind/
      storage/
      notifier/
      output/
      replay/

Conceptual responsibilities:

## watcher

Follow multiple log files and handle rotation.

## parser

Convert Nginx/Apache lines into normalized request events.

## aggregator

Maintain rolling per-IP/per-site statistics.

## patterns

Normalize URLs/query parameters and detect enumeration.

## serverhealth

Monitor CPU/load/memory.

## phpfpm

Monitor PHP-FPM health.

## maxmind

Perform local IP enrichment and manage database updates.

## detector

Convert statistics into detection signals.

## scoring

Convert signals into explainable scores/decisions.

## storage

SQLite persistence.

## notifier

Slack notifications.

## output

Operational log and JSONL incident output.

## replay

Feed historical access logs through the normal detector.

---

# 65. Example Normalized Request Event

Internally, a request may become:

    RequestEvent {
        Timestamp
        SiteID
        ClientIP
        Method
        Path
        Query
        Status
        Bytes
        Referrer
        UserAgent
        RequestTime
        UpstreamTime
    }

All parsers should convert their respective web-server format into this common structure.

This keeps detection independent of whether the source is Nginx or Apache.

---

# 66. Example Incident Structure

A detection incident may conceptually contain:

    Incident {
        Timestamp
        Server
        Site
        IP

        ASN
        ASNOrganization
        NetworkType
        Country

        Window

        Requests
        PeakRPS

        StatusCounts
        MethodCounts

        UniquePaths
        Unique404Paths

        UserAgents

        Patterns

        CPU
        Load
        Memory

        PHPFPMStats

        TrafficShare

        Signals
        Score
        Decision

        RulesetVersion
    }

The same Incident object can then be consumed by:

    SQLite
    JSONL
    human-readable logs
    Slack

This avoids each output implementation calculating its own version of the event.

---

# 67. V1 Definition

The first deployable ReqSentry release should aim to provide:

- Go Linux daemon
- systemd service
- YAML configuration
- multiple Nginx access logs
- multiple Apache access logs
- log rotation handling
- normalized HTTP request events
- per-site statistics
- server-wide statistics
- rolling request windows
- request-rate analysis
- 404 analysis
- unique-404 analysis
- URL/query enumeration detection
- 301/302 analysis
- HTTP method analysis
- User-Agent collection/analysis
- CPU monitoring
- system load monitoring
- memory monitoring
- PHP-FPM monitoring
- MaxMind local enrichment
- automatic MaxMind initial download
- persistent 24-hour MaxMind update scheduling
- update retry/backoff
- SQLite persistence
- historical incidents
- ruleset versioning
- human-readable operational log
- JSONL incident log
- Slack webhook notifications
- Slack cooldown/deduplication
- IP/CIDR allowlists
- IPv4 and IPv6
- trusted proxy configuration
- bounded memory
- degraded mode
- monitor-only decisions
- no Cloudflare enforcement

---

# 68. Initial Success Criteria

ReqSentry V1 is successful if it can be installed on a production web server and safely run for an extended period while:

1. Monitoring all configured websites.
2. Consuming negligible resources during normal traffic.
3. Surviving log rotation.
4. Correctly identifying real client IPs.
5. Detecting obvious crawling/scanning behavior.
6. Identifying high-404 enumeration.
7. Detecting unusual HTTP method behavior.
8. Correlating suspicious traffic with server/PHP-FPM pressure.
9. Enriching suspicious IPs with useful ASN/network information.
10. Producing understandable incident explanations.
11. Sending useful Slack alerts without flooding the channel.
12. Persisting enough data to investigate false positives.
13. Never blocking legitimate traffic because V1 has no enforcement capability.
14. Remaining stable during very large or intentionally adversarial traffic.
15. Providing enough real-world data to design and validate future Cloudflare enforcement.

---

# 69. Longer-Term Goal

Once ReqSentry has collected enough production data, detection thresholds and scoring can be tuned based on actual traffic rather than assumptions.

The development loop should be:

    OBSERVE
       ↓
    DETECT
       ↓
    EXPLAIN
       ↓
    REVIEW
       ↓
    IDENTIFY FALSE POSITIVES
       ↓
    TUNE RULES
       ↓
    REPLAY HISTORICAL LOGS
       ↓
    VALIDATE
       ↓
    EVENTUALLY ENFORCE

Only after this process demonstrates sufficiently reliable detection should automated Cloudflare actions be considered.

The core product philosophy remains:

> ReqSentry does not need to prove that a client is a bot. It needs to determine, using explainable HTTP and server-health evidence, whether that client's behavior is abnormal and harmful to the web server.

---
