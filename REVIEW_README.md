# ReqSentry — Production review and remediation

Review date: 2026-10-04  
Reviewed revision: `187775a` (`v1`)  
Status: all 11 findings remediated locally on 2026-10-04; production acceptance remains open.

This file preserves the original review of `187775a` and records the subsequent fixes below. File references are relative to the repository root. Line numbers refer to the reviewed revision and may shift after changes. Findings should be checked against the current source before implementation. The original review was read-only; this handoff document was subsequently added at the user's request.

## Remediation status — 4 October 2026

All 11 findings have implementation fixes and regression coverage in the working tree. The original report below is retained as an audit trail; its old line numbers and pre-fix behavior do not describe the current implementation.

| Finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| F1 | Combined headers occupy two fixed positions; extensions are parsed only afterward. Common format ends at bytes. | Every recognized extension prefix as quoted referrer/UA, with and without genuine extensions, through parser → resolver → allowlisting → aggregation. |
| F2 | Failed batches remain bounded and retryable. Every flush observes unresolved failures. Queue/buffer loss freezes checkpoints until restart/replay; shutdown reports outstanding failures. | Repeated unrelated flushes, blocked offsets, successful retry, outage/reopen with unchanged checkpoint and stable-ID replay. |
| F3 | Analysis timers align to window boundaries; recovery retains 121 seconds. Samples share replay/live boundaries, including 31-second windows. | Windows 1/30/31/60 seconds at multiple ingestion phases, late arrivals, unchanged closed-window scores/IDs and five samples. |
| F4 | Sensitive free-form diagnostics are suppressed as complete records before persistence. SNS omits application messages and stacks. | Authorization, multi-cookie and nested JSON markers through parsing, stored incident/error APIs, local JSONL, and fake SNS export. |
| F5 | Shared IP-range normalization validates effective scope after IPv4 unmapping. | IPv4/IPv6 `/0`, mapped `/96`, narrow mapped ranges, and configuration/resolver/dashboard consumers. |
| F6 | Authentication failures return HTTP 401 with the Basic challenge; IP/proxy policy failures remain 403. | Missing, invalid, valid credentials and denied network-source routes. |
| F7 | Damaged output is quarantined, and new records use a healthy file. Quarantine has bounded, configurable retention without extending dated evidence. | Restart with truncated/malformed JSONL, retained bytes, new writes, decreased retention, oversized records and expired evidence. |
| F8 | Analysis uses a shared snapshot iterator, one prune per timestamp, and indexed site counts. Scoring/output work runs outside aggregation locks. | Cardinality benchmarks with allocation reporting; concurrent ingestion plus dashboard scans. |
| F9 | Every route renders into a detached view and only the current generation may commit. Search/page actions use that same ownership rule. | Reordered responses across 12 routes/details plus same-route search, and the existing Overview refresh regressions. |
| F10 | Up to sixteen configured pools poll concurrently within an interval-bounded deadline; each successful acquisition receives its actual timestamp. | Healthy pools before/after 15 delayed failures, bounded concurrency, retained stale failures and recovery. |
| F11 | Incident limits reach 100; pagination is validated against the 10,000-row offset ceiling and never advertises an invalid next page. | Limits 50/51/100 and pages 100–102, following every returned next page; other route limits remain bounded. |

### Verification

- Full Go race suite, static checks, module integrity, both configuration examples, and JavaScript syntax checks passed.
- All 20 dashboard regressions passed; npm audit reported zero vulnerabilities.
- Actual Linux ARM64 release binary built with pinned Go 1.26.8: `govulncheck` reported no vulnerabilities. Source scan on Go 1.27.1 also reported none.
- The original Debian runtime scan reported 190 HIGH/CRITICAL package findings. Available upgrades removed 61, leaving 129 without reported fixes. The development runtime now uses pinned official Nginx Alpine plus package updates; its OS scan reported **zero HIGH/CRITICAL package findings**, without exclusions. Go packages are scanned separately with `govulncheck`.
- The replacement runtime built successfully, passed Nginx/config checks, started its supervisor, and served all four sites and dashboard locally.
- Browser smoke checks on isolated synthetic data exercised all nine dashboard sections and linked incident details containing five saved requests.
- A checked-in CI workflow runs regressions, dependency audits, the actual container binary scan and a HIGH/CRITICAL runtime OS gate. Action/scanner/base references are pinned. YAML and corresponding local commands were verified; its first hosted run awaits pushing these changes.

Local Apple M1 Pro measurements (not production capacity claims):

| Clients / records | Analysis pass | Analysis + dashboard, concurrent ingestion | Observed ingestion rate | Maximum observed ingestion latency |
| --- | ---: | ---: | ---: | ---: |
| 128 / 256 | 0.81 ms | 1.95 ms | 193,418/s | 5.99 ms |
| 1,024 / 2,048 | 9.96 ms | 19.26 ms | 169,222/s | 9.61 ms |
| 4,096 / 8,192 | 84.14 ms | 110.15 ms | 90,483/s | 73.43 ms |

The 4,096-client analysis fixture previously took about 1.81 seconds. Reproduce with `go test ./internal/aggregator -run '^$' -bench 'BenchmarkAnalysis(Pass|WithIngestion)' -benchmem`. These are short in-memory fixtures, with timestamp held constant; they do not measure source lag, sustained production RSS/disk contention or false-positive rates.

### Remaining acceptance work

Representative production-log review, sustained load/RSS/source-lag measurements on the intended Linux host, and real Slack/Teams/SNS destination/subscriber checks remain required. No live notification was sent. Existing historical demo domain labels still require a publication/history decision. The CI workflow has not run on GitHub yet. Recovery remains bounded by retained counters, input files and byte budget; prolonged storage outages or excessively late events require operator replay. The product remains monitor-only.


## 1. Executive summary

**Original assessment of `187775a`, before the fixes below: I would not yet rely on that version as a production security monitor.** The main blockers are an attacker-controlled log parsing ambiguity and a persistence failure that can let recovery checkpoints advance past lost incidents.

The review identified **11 actionable findings: 2 HIGH, 8 MEDIUM, and 1 LOW**. No CRITICAL issue was confirmed.

The repository has useful safeguards: bounded aggregation and queues, parameterized database queries, restricted dashboard access, constant-time credential comparisons, restrictive browser security headers, and a hardened systemd service. The findings primarily concern interactions between these components.

**Scope and verification**

Reviewed the application, dashboard, storage, recovery, integrations, configuration, deployment files, dependencies, documentation, and tests. Final source verification matched commit `187775a` (`v1`).

Completed:

- Full Go test suite with race detection.
- Go static analysis and module integrity verification.
- Go vulnerability scan: **no vulnerabilities reported** for the tested dependency graph and Go 1.27.1 toolchain.
- Existing dashboard tests and JavaScript syntax checks.
- Linux ARM64 build.
- Clean dashboard test dependency installation: **zero reported npm vulnerabilities**.
- Targeted reproductions and an aggregation benchmark in a temporary copy.

**No repository files were modified during the review.** This was source review and local verification; production Linux load testing, actual provider delivery, and the built container's operating-system vulnerability scan remain unverified.

## 2. Architecture and trust-boundary overview

ReqSentry is a single, monitor-only Go application. Its primary flow is:

```text
Access/error logs
    → parsing and client identity resolution
    → bounded aggregation and error correlation
    → detection and scoring
    → SQLite, local files, notifications
    → read-only dashboard and live updates
```

Supporting components collect Linux host and PHP-FPM health, perform optional MaxMind enrichment/downloads, manage retention, and checkpoint log offsets. CLI commands provide configuration validation, reporting, replay, previews, and integration checks.

The important trust boundaries are:

| Boundary | Security significance |
|---|---|
| HTTP requests → access logs | Attackers control paths, queries, User-Agent, and some other logged fields. |
| Log parsing → client identity | Header content must never become trusted connection metadata. Finding F1 crosses this boundary. |
| Application error messages → stored/exported evidence | Messages may already contain credentials. Redaction must happen before persistence and notification. |
| Queued writes → committed data → checkpoints | Accepted queue entries are not durable data. F2 breaks this distinction. |
| Dashboard connection → authorized viewer | IP restrictions and optional Basic authentication protect all dashboard data. |
| Local configuration → external integrations | Provider destinations and credential references are administrator-controlled. |

There is no application-level role or tenant isolation model. An authorized dashboard viewer can inspect the monitored installation; site filters are presentation filters, not authorization boundaries.

The reviewed SQL, DOM rendering, download handling, and outbound URL restrictions did not establish a separate actionable SQL injection, XSS, command injection, path traversal, or SSRF finding.

## 3. CRITICAL findings

None confirmed.

## 4. HIGH findings

### F1 — A crafted User-Agent can spoof client identity or remove requests from analysis

**Severity:** HIGH  
**Confidence:** HIGH  
**Category:** Security  
**Location:** [internal/parser/combined.go](internal/parser/combined.go), lines 74–95 and 114–120; [internal/clientidentity/resolver.go](internal/clientidentity/resolver.go), lines 51–68.

**Problem and impact:** The combined-log parser decides whether a field is a referrer/User-Agent or a trusted extension by examining its contents. Quote provenance is lost. Consequently, a legitimate quoted User-Agent such as `peer=127.0.0.1` becomes connection metadata.

I reproduced both outcomes:

- Plain combined format: logged client `198.51.100.77` resolved to `127.0.0.1` and was excluded when that address was allowlisted.
- Extended format containing a genuine `peer=` field: the injected duplicate caused the entire request to be rejected by the parser.

**Realistic scenario:** An attacker sends requests with this User-Agent. They can evade analysis through parse failures, distribute activity across invented identities, or select an allowlisted identity. Configuring no trusted proxies does not prevent the plain-format spoof because the resolver already treats `PeerIP` as authoritative.

**Root cause:** Untrusted positional header fields and trusted extension fields share content-based parsing.

**Recommended fix:** Parse each supported log schema explicitly. Preserve field position and provenance; only accept extensions after the schema's referrer and User-Agent positions.

**Tradeoff:** Ambiguous common/combined formats may require explicit configuration or migration.

**Regression:** Pass every recognized extension prefix through quoted User-Agent/referrer fields in plain and extended formats. Assert unchanged identity, no unintended allowlisting, and successful request accounting through parser, resolver, and aggregator.

### F2 — Failed database batches can be forgotten before recovery checkpoints advance

**Severity:** HIGH  
**Confidence:** HIGH  
**Category:** Reliability  
**Location:** [internal/storage/sqlite.go](internal/storage/sqlite.go), lines 344–369 and 385–389; [internal/watcher/recovery.go](internal/watcher/recovery.go), lines 77–84; [internal/daemon/history.go](internal/daemon/history.go), lines 77–79.

**Problem and impact:** Failed batches are discarded. Their error survives only until the next `Flush`, which returns it and clears it. A later `Flush` succeeds despite the missing records, allowing recovery offsets to advance.

An unrelated dashboard-history flush can also consume the error before checkpointing sees it.

**Verified scenario:** I injected a database insert failure. The first flush failed; after removing the failure, the second flush succeeded, while the database still contained zero incidents. Once a checkpoint moves beyond the recovery overlap, restart cannot recover the omitted incident from that checkpoint.

**Root cause:** `Flush` reports errors since the previous barrier, rather than proving all relevant input was durably processed.

**Recommended fix:** Track durable progress separately from queue progress. Retain a failure state until failed records are retried or deliberately replayed; prohibit checkpoint advancement across unresolved losses. Include queue rejection in the persistence contract.

**Tradeoff:** Retrying requires bounded buffering, backpressure, or a durable spool. A persistent storage outage must have an explicit operational policy.

**Regression:** Inject a write failure, perform an unrelated history flush, advance beyond the overlap, and restart. Require either successful recovery with stable incident IDs or an unchanged checkpoint.

## 5. MEDIUM findings

### F3 — Recovery-mode analysis can evaluate data after its buckets have been overwritten

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Correctness  
**Location:** [internal/daemon/daemon.go](internal/daemon/daemon.go), lines 531–562; [internal/aggregator/aggregator.go](internal/aggregator/aggregator.go), lines 19–21 and 505–522.

**Problem:** Recovery mode evaluates the preceding epoch-aligned window, but the ticker runs relative to daemon startup. The aggregator retains only 61 seconds.

**Verified scenario:** With an accepted 60-second analysis window and evaluation 45 seconds after a minute boundary, continued traffic overwrote most of the target minute. Only **16 of 60 requests** remained. The same completed scan generated **two incidents at the boundary and zero at the delayed evaluation**.

**Root cause:** Evaluation timing, historical window selection, and retention capacity use incompatible assumptions.

**Fix:** Align analysis with window boundaries and retain enough history for scheduling delay and supported lateness. Reject unsafe recovery/window combinations as an interim restriction.

**Tradeoff:** More retained history costs memory; waiting for late data increases detection latency.

**Regression:** Compare live and replay results across startup phases and windows of 1, 30, 31, and 60 seconds, including continued and late-arriving traffic.

### F4 — Credential redaction leaves common secret formats intact

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Security  
**Location:** [internal/parser/errors.go](internal/parser/errors.go), lines 23–31; [internal/output/notifications.go](internal/output/notifications.go), lines 450–460.

**Problem:** The redaction expression removes only one token after a keyword. Verified examples:

| Input | Retained secret |
|---|---|
| `Authorization: Bearer AUDIT_SECRET` | `AUDIT_SECRET` |
| `Cookie: session=FIRST; refresh=SECOND` | `refresh=SECOND` |
| `{"password":"AUDIT_SECRET"}` | Entire value remains |

**Scenario and impact:** If a monitored application logs an authentication failure containing these values, ReqSentry can persist them and expose them through incident evidence. SNS serialization removes stack traces but retains these messages, creating an additional disclosure destination.

**Root cause:** A token-based expression is being used as a credential sanitization boundary.

**Fix:** Handle complete authorization/cookie values and structured secret fields. Prefer an explicit safe evidence schema for remote notifications; suppress uncertain free-form content.

**Tradeoff:** Conservative sanitization removes useful diagnostic detail.

**Regression:** Use marker secrets in parsed error events and assert absence from stored incidents, dashboard responses, local output, and captured SNS payloads.

### F5 — IPv4-mapped CIDRs bypass the prohibition on allow-all ranges

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Security  
**Location:** [internal/config/config.go](internal/config/config.go), lines 541–552; [internal/dashboard/server.go](internal/dashboard/server.go), lines 257–270; [internal/clientidentity/resolver.go](internal/clientidentity/resolver.go), lines 111–120.

**Problem:** `::ffff:0.0.0.0/96` passes validation, then becomes `0.0.0.0/0` after normalization.

**Verified scenario:** Configuration accepted this value, an arbitrary IPv4 client became allowlisted, and the dashboard returned HTTP 200 to that client.

**Impact:** An operator using this mapped range can unintentionally permit every IPv4 viewer, exclude every IPv4 client from detection, or trust all IPv4 proxy sources, depending on its configuration location. This requires that configuration; it is not a default remote bypass.

**Root cause:** Broad-range checks happen before normalization, in three duplicated implementations.

**Fix:** Normalize through one shared implementation, then validate the effective prefix.

**Tradeoff:** Previously accepted mapped allow-all configurations become invalid, consistent with the existing policy.

**Regression:** Cover ordinary IPv4/IPv6 `/0`, mapped `/96`, narrower mapped prefixes, and all three consumers.

### F6 — Basic authentication returns the wrong status for a login challenge

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Correctness  
**Location:** [internal/dashboard/server.go](internal/dashboard/server.go), lines 177–180 and 254.

**Problem:** Missing or invalid credentials produce `WWW-Authenticate` with HTTP **403**, because authentication failures use the generic deny function.

**Scenario and impact:** An allowed user opening the dashboard without cached credentials cannot rely on the normal browser Basic-authentication challenge. There is no separate login form. Clients sending credentials preemptively conceal the problem in tests.

**Root cause:** Authentication challenges and access-policy denials share one response status.

**Fix:** Return 401 with the challenge for authentication failures; retain 403 for IP/proxy-policy failures. This follows [HTTP authentication semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-401-unauthorized).

**Tradeoff:** Tests and clients expecting 403 for bad credentials must change.

**Regression:** Verify the initial unauthenticated browser flow, invalid credentials, valid credentials, and disallowed source addresses.

### F7 — A partial JSONL record can permanently stop subsequent file output

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Reliability  
**Location:** [internal/output/file.go](internal/output/file.go), lines 170–175; [internal/output/retention.go](internal/output/retention.go), lines 134–143.

**Problem:** Before opening an existing output file, the writer requires retention parsing to succeed. A malformed trailing record causes that check to fail; every subsequent queued record follows the same failing path and is discarded.

**Verified scenario:** A valid record followed by a partial JSON object prevented a new valid incident from being written. The original bytes remained unchanged, and diagnostics repeatedly reported retention failure.

**Impact:** A crash, interrupted write, or full disk can turn a temporary incident into a persistent loss of that output sink after restart.

**Root cause:** Successful historical maintenance is a prerequisite for accepting new output.

**Fix:** Preserve or quarantine damaged content and establish a healthy output file. Decouple retention failure from the ability to write new records, and expose persistent sink failure operationally.

**Tradeoff:** Quarantined files need their own retention and inspection policy.

**Regression:** Restart with truncated tails and malformed records; verify preservation of old evidence and successful new writes.

### F8 — Analysis performs quadratic work in the number of tracked identities

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Performance  
**Location:** [internal/aggregator/aggregator.go](internal/aggregator/aggregator.go), lines 305–307, 423–440, and 497–501; [internal/daemon/daemon.go](internal/daemon/daemon.go), lines 572–580.

**Problem:** Every identity snapshot scans the entire record map to prune it. Every global identity also scans the map for its site count. The outer analysis loop visits every identity.

**Impact:** Raising capacity produces approximately quadratic analysis cost. These operations share the aggregation lock with ingestion and dashboard reads.

**Measured scenario:** A sparse 4,096-client workload took approximately **1.81 seconds per snapshot/site-count pass**, before detector or database work. That already exceeds an accepted one-second analysis interval.

**Root cause:** Global maintenance and relationship discovery are repeated inside per-identity operations.

**Fix:** Prune once per analysis pass and compute site counts in one pass or maintain an index. Consider a batch snapshot API with short lock ownership.

**Tradeoff:** Additional indexes require memory and consistency checks.

**Regression:** Benchmark increasing identity counts and measure concurrent ingestion latency, analysis duration, allocations, and source lag.

### F9 — Late responses from previous dashboard routes modify the current page

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Correctness  
**Location:** [internal/dashboard/assets/app.js](internal/dashboard/assets/app.js), lines 443–446 and 514–520; another instance at lines 1341–1354.

**Problem:** Several route functions append to the shared root after awaiting a request, without checking whether navigation has changed.

**Verified scenario:** I delayed Sites, navigated to Incidents, then released the Sites response. Both “Monitored sites” and incident content appeared under the Incidents page.

**Impact:** Under ordinary latency, analysts can see mixed or stale evidence associated with the wrong navigation context.

**Root cause:** Navigation-generation protection covers some rendering paths but is not a shared invariant.

**Fix:** Construct each view separately and commit it only if its route/generation remains current. Cancellation can supplement that check.

**Tradeoff:** Rendering needs a common lifecycle contract; obsolete requests may still consume some work.

**Regression:** Reorder responses across every route and detail view, including rapid filter changes. Assert that only the current navigation can update the page.

### F10 — Slow PHP-FPM pools make freshly fetched healthy samples appear stale

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Category:** Reliability  
**Location:** [internal/phpfpm/collector.go](internal/phpfpm/collector.go), lines 64–82 and 85–94.

**Problem:** Pools are fetched sequentially, but every successful sample receives the poll's start timestamp. Staleness is measured against twice the configured interval.

**Verified scenario:** With a supported one-second interval, 15 slow failed responses delayed the healthy final pool by approximately 2.26 seconds. Its successful response was immediately classified as stale.

With the default five-second interval, six two-second timeouts can produce the same problem.

**Impact:** An unhealthy group of pools can suppress useful evidence from healthy pools precisely during an overload. Impact detection excludes stale samples.

**Root cause:** Sequential polling and a shared timestamp couple independent pools' freshness.

**Fix:** Use bounded concurrent polling and record each sample's actual acquisition time. Keep per-pool timeouts and cancellation.

**Tradeoff:** Concurrency increases simultaneous local connections; cap it explicitly.

**Regression:** Place healthy pools before and after delayed/failing pools. Require accurate timestamps and usable healthy results regardless of pool order.

## 6. LOW findings

### F11 — Incident pagination advertises requests that its own validation rejects

**Severity:** LOW  
**Confidence:** HIGH  
**Category:** Correctness  
**Location:** [internal/dashboard/api.go](internal/dashboard/api.go), lines 43–46, 468–475, and 526–540.

**Problem:** Shared validation limits `limit` to 50, although the incident handler accepts 100. Separately, page numbers stop at 101, but `next_page` can advertise 102.

**Verified scenario:** `limit=100` returned 400. With sufficient results, page 101 returned `next_page: 102`; requesting it returned 400.

**Impact:** History browsing terminates unexpectedly, and clients cannot use the incident handler's declared limits.

**Root cause:** Shared and route-specific validators express different contracts; next-page calculation does not honor the effective cap.

**Fix:** Validate pagination at the route level and derive page availability from the same limit/offset policy. Return no next page when the cap is reached.

**Tradeoff:** Retaining bounded offset pagination still limits how much history one query can traverse; cursor pagination is a larger alternative.

**Regression:** Exercise limits 50, 51, and 100; pages 100–102; offset boundaries; and every emitted next-page link.

## 7. Performance bottlenecks and optimization opportunities

F8 is the strongest measured bottleneck.

The temporary benchmark exercised the analysis snapshot/site-count loop with one request per client and one site:

| Clients | Aggregation records | Approximate time per pass |
|---:|---:|---:|
| 128 | 256 | 1.40 ms |
| 512 | 1,024 | 17.2 ms |
| 1,024 | 2,048 | 67.8 ms |
| 4,096 | 8,192 | 1.81 s |

These are local Apple M1 Pro microbenchmark results, not production throughput guarantees. Detector execution and persistence would add work.

Prioritize:

- Removing repeated global scans before increasing aggregation capacity.
- Fixing PHP-FPM head-of-line blocking in F10.
- Measuring high-cardinality traffic, not just high request rates from a few clients.
- Monitoring queue drops, source lag, analysis duration, and retention backlog during sustained Linux tests.

Existing bounds are valuable. Increasing them indiscriminately would magnify CPU, memory, and persistence pressure.

## 8. Reliability/correctness concerns

The most important missing system invariants are:

- **A successful checkpoint must prove relevant evidence is durable.** F2 currently invalidates that assumption.
- **The evaluated window must still exist in memory.** F3 violates this for supported recovery configurations.
- **Damaged historical output must not permanently prevent new output.** F7 makes maintenance failure contagious.
- **Freshness must describe the individual measurement.** F10 uses a timestamp unrelated to later samples' acquisition.
- **Only the active view may update the dashboard.** F9 applies that protection inconsistently.

The race detector passed, but these are ordering and state-contract failures that can occur without a data race.

## 9. Dependency and configuration concerns

The Go dependency scan and npm audit returned no reported vulnerabilities in the tested environment. That does not establish the security of a separately built container or a different Go toolchain.

Deployment points requiring attention:

- The Docker build uses a Go 1.26 image family, whereas local verification used Go 1.27.1. Scan the actual release binary and image.
- Container base tags are mutable. Record or pin resolved image digests for reproducible releases, with a deliberate update process.
- The Compose stack is a local development setup combining Nginx and ReqSentry. Its loopback port bindings mitigate exposure; the hardened systemd unit is the stronger production deployment baseline.
- External dashboard access depends on TLS termination or SSH as documented. Basic authentication itself supplies no transport encryption.
- F5 makes the configuration validator's “no allow-all” guarantee inaccurate.
- F3 means not every accepted recovery/window configuration is operationally safe.

No confirmed live credential was identified by the targeted current-tree checks. That was not an exhaustive audit of Git history or external secret stores.

## 10. Missing or inadequate tests

Existing tests pass, but several stop at individual component behavior and miss the cross-component failure.

Highest-value additions are:

| Area | Missing protection |
|---|---|
| Client identity | Quoted extension-like headers through parsing, resolution, allowlisting, and aggregation. |
| Durability | Failed batch → multiple flush consumers → checkpoint → restart. |
| Recovery | Startup-phase and retention-boundary equivalence between live analysis and replay. |
| Redaction | Marker secrets through persistence and every notification serializer. |
| Authentication | Initial browser challenge, rather than only preemptively supplied credentials. |
| Output recovery | Continued writing after a partial or malformed historical record. |
| Dashboard | Response reordering across all routes, not only Overview. |
| PHP-FPM | Multiple pools with heterogeneous delays and failures. |
| Pagination | Every returned next-page link is valid. |
| Capacity | Cardinality scaling with concurrent ingestion and dashboard activity. |

I found no checked-in CI workflow enforcing the existing Go and dashboard checks. Making these checks release gates would give the current test investment practical value.

## 11. Technical-debt/architecture concerns

The worthwhile structural changes are those directly tied to the findings:

- **Centralize address normalization and validation.** Three implementations currently reproduce the same security-policy defect.
- **Separate queue acceptance, durable completion, and checkpoint eligibility.** The current `Flush` abstraction is insufficient for multiple consumers.
- **Introduce batch aggregation reads.** This removes repeated scans and makes the analysis consistency boundary explicit.
- **Share dashboard render ownership.** Individual route functions should not each implement navigation safety.
- **Define an explicit export-safe evidence model.** Remote serializers should not depend solely on heuristic free-text redaction.

These are targeted changes with concrete security or reliability benefits; a wholesale rewrite is unnecessary.

## 12. Prioritized remediation plan

| Order | Work | Completion criterion |
|---:|---|---|
| 1 | F1: parser/identity boundary | Header content cannot change identity or suppress valid request accounting. |
| 2 | F2: persistence/checkpoint contract | Checkpoints cannot advance across unresolved write loss. |
| 3 | F4: secret sanitization | Credential markers disappear from stored and exported evidence. |
| 4 | F3 and F7: recovery correctness | Supported windows retain their evidence; damaged output does not stop future writes. |
| 5 | F5 and F6: access configuration/authentication | Normalized range policy and browser authentication behave as specified. |
| 6 | F10 and F8: operational scaling | Healthy pools remain usable; analysis meets the intended interval under representative cardinality. |
| 7 | F9 and F11: dashboard correctness | Navigation is isolated and pagination is internally consistent. |
| 8 | Automated release verification | Run regression suites, actual-toolchain scans, and representative Linux deployment tests. |

## What I would fix before production

- **F1 and F2 unconditionally:** request attribution and durable evidence are fundamental to the product.
- **F4 before ingesting real application error logs or exporting their evidence.**
- **F7 before relying on retained file output.**
- **F3 before enabling recovery with affected analysis windows; reject unsafe configurations until fixed.**
- **F5 before relying on CIDR validation as a deployment safeguard.**
- **F6 before enabling dashboard Basic authentication.**
- **F10 for multi-pool PHP-FPM monitoring, and F8 before deploying at capacities or intervals where analysis cannot keep up.**
