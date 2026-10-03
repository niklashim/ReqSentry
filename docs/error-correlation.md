# Error evidence and correlation

Optional `error_files` collect web-server/application failures alongside access traffic. They produce separate error events and never increment HTTP request counters or change detection scores. The local Compose configuration follows all four existing Nginx error files. See the commented `error_files`, `log_profiles`, and `correlation` sections in the [complete configuration example](../configs/example.yaml).

Supported text formats are `nginx-error` and the bracketed Apache 2.4 error layout. `type: nginx|apache` selects the corresponding error format by default. Set `timezone` to the producer's IANA zone when text timestamps lack offsets; the default is UTC. Optional `minimum_severity` defaults to `warning`. JSON/logfmt error sources use the same [mapping profiles](structured-logs.md), with required timestamp, severity, and message plus optional error type/code, path, client/peer address, and request/trace IDs. The ECS preset supports a documented error-field subset. Arbitrary Apache custom layouts and multiline plaintext PHP-FPM stack assembly are outside this parser contract.

Each error retains occurrence/ingestion time, configured site/source, normalized severity/category, bounded redacted message, optional identifiers, and a `v1:` message fingerprint. Known categories include upstream timeouts/refusals, missing files, and resource limits; application error types can supply their own bounded categories. Fingerprints replace volatile numeric values and do not include request IDs as separate keys. They are investigation aids, not security classifications. Recent fingerprint storage is bounded by the error ring; evictions increase the dropped-evidence count instead of growing an unlimited fingerprint index.

URL/query values, credential-like fields, and filesystem paths are redacted from stored messages. JSON string limits apply before parsing, and saved messages are capped at 1,024 bytes plus a truncation marker. Stack traces are omitted unless `retain_stack_trace: true` is set on an error source, then use the same local redaction/size policy. Remote alerts always omit stack traces. Redaction is deterministic and cannot recognize every application's sensitive vocabulary; configure producers to exclude secrets before logging.

A PHP application can emit this canonical single-line JSON record:

```json
{"timestamp":"2026-10-03T12:00:00Z","severity":"error","error_type":"PHPException","error_code":"E42","message":"Database operation failed","request_id":"req-1","trace_id":"trace-1","stack_trace":"Exception at /var/www/app.php\n#0 handler()"}
```

With an `ecs-v1` profile, the equivalent error fields are nested:

```json
{"@timestamp":"2026-10-03T12:00:00Z","log":{"level":"error"},"error":{"type":"PHPException","code":"E42","message":"Database operation failed"},"http":{"request":{"id":"req-1"}},"trace":{"id":"trace-1"}}
```

Neither record becomes an HTTP request. For Apache IPv6 addresses with ports, the supported unambiguous form is `[client [2001:db8::1]:1234]`; custom layouts that concatenate an unbracketed address and port need normalization at the producer.

## Association semantics

`correlation.max_events` defaults to 4,096 records each for access context and errors. These independent rings prevent an exception storm from evicting every request sample. Request paths and identifiers are bounded, and correlation runs while building incident evidence, outside request parsing. Context supports these labeled methods:

| Method | Meaning |
| --- | --- |
| `request_id` | Shared log request ID within the configured site; IDs observed across different clients are ambiguous and fall back to weaker context |
| `trace_id` | Shared trace, which may span multiple requests; uncertain association |
| `logged_client_path_time` | Same logged client and path in the selected time range; logged identity is not independently authenticated |
| `site_time` | Failure on the site around the incident; does not attribute it to this client |
| `server_time` | Unattributed/shared server failure; does not attribute it to this client |

Nginx connection IDs are retained as context and never treated as unique request IDs. Standard Nginx errors often have no request ID; JSON application errors and custom Apache `[R:...]` records can carry one. Combined access logs may append `rid="..."` and `trace="..."`; the fixture includes Nginx's generated request ID.

The association time range runs from the incident start minus `correlation.window` (default 60 seconds, maximum five minutes) through the incident end. Clock differences and delayed records can prevent a match. Errors arriving after an incident is saved do not rewrite it or emit a replacement decision. The live dashboard/error history may show them later. No source, unavailable sources, stale inputs, ring eviction, or persistence sampling must not be read as zero failures. Incident snapshots retain coverage, unavailable source paths, drop counts, bounded category/association counts, and up to eight samples. A many-client backend outage remains site/server context; no error-only scoring signal is enabled.

## Dashboard and persistence

The overview and site views show bounded errors, severity/category/association filters, source health, and a timeline of persisted error samples. Incident detail shows its immutable association snapshot and uncertainty labels; older incidents show unavailable context. The source column shows the filename with its full configured path in the tooltip. `/api/v1/errors` is read-only and uses the existing authentication/allowlists, `site`, `severity`, `category`, `association`, `range`, and `limit` (maximum 50) filters. History ranges are limited to seven days; database queries use a separate read-only SQLite connection with a three-second deadline. Timeline buckets contain persisted samples across all severities/categories, not total failures, and empty intervals can be missing data.

An association filter searches the most recent 50 saved incidents within the selected range and returns their bounded matching samples plus related incident links. Identical snapshots are deduplicated, while separate request IDs remain separate errors. This view does not claim exhaustive historical associations; its aggregate timeline is omitted because unrelated persisted errors would misrepresent the selection. No association filter shows standalone persisted samples, including failures with no incident. Source counts cover the current process; a last-record timestamp or unavailable status helps distinguish quiet inputs from missing coverage.

The separate SQLite error queue holds 128 events and persists batches outside ingestion. `database.retention.error_samples_per_second` defaults to 20 across all sources; excess samples are dropped visibly, while source parsed counts still record all accepted error lines. Errors default to the shared four-day retention ceiling; [storage guidance](storage-output.md) explains pruning and capacity. Saved incident snapshots survive expiry of standalone error samples. Normal and malformed/error-flood fixtures verify that errors do not add HTTP requests or independently raise scores.
