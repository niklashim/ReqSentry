# Structured log inputs

Access sources can use `format: combined` (the existing default), `json`, or `logfmt`. The producer `type: nginx|apache` is separate from the parser format. Each source has an authoritative configured `site`; a logged Host value cannot select another site. All formats produce the same normalized requests and use the existing trusted-proxy/allowlist resolver.

## Canonical fields

One complete record occupies one line. Required access fields are `timestamp`, `client_ip`, `method`, `status`, and either `target` or `path` plus optional `query`. `timestamp` defaults to RFC3339 with an explicit offset; `status` is an integer from 100 to 599. Numbers may be JSON numbers or explicit numeric strings. Optional fields are `bytes`, `host`, `user_agent`, `referrer`, `request_time`, `upstream_time`, `location`, `peer_ip`, `forwarded_for`, `cf_connecting_ip`, `x_real_ip`, `request_id`, and `trace_id`.

```json
{"timestamp":"2026-10-03T12:00:00Z","client_ip":"192.0.2.1","peer_ip":"192.0.2.1","method":"GET","target":"/api/items?id=2","status":200,"bytes":120,"request_time":0.012,"request_id":"request-1"}
```

Canonical durations are seconds; missing, null, empty, and dash values remain unavailable, while numeric zero is a measurement. Multiple upstream attempts remain unavailable as a single upstream duration. Encoded paths stay encoded, and queries remain separate. Request/trace identifiers are optional, bounded log claims used for correlation, not authenticated client identities.

For Nginx, use `log_format NAME escape=json` and JSON-escape quoted string variables. The complete `reqsentry_json` example is in [the fixture configuration](../docker/webserver/nginx/nginx.conf). Select it in a site's `access_log` directive and set that source's `format: json` together. Do not change only one side. The fixture still defaults to combined logs so persisted development files do not mix formats.

## Mapping profiles

Declare `log_profiles` and reference a profile by name from `access_files` or structured `error_files`. Mapping keys are normalized target fields; values are literal producer keys unless they begin with `/`, in which case they are nested object selectors. JSON Pointer `~1` and `~0` escapes represent slash and tilde. Arrays are not traversed. A dotted selector such as `elapsed.ms` is a literal key, while `/elapsed/ms` selects a nested object. Selectors compile once at startup.

```yaml
log_profiles:
  app:
    timestamp: rfc3339
    duration_unit: ms
    fields:
      timestamp: /metadata/time
      client_ip: /remote/client
      peer: /remote/peer
      method: /http/method
      target: /http/target
      status: /http/status
      request_time: elapsed.ms
access_files:
  - path: /var/log/app/access.jsonl
    site: shop
    format: json
    profile: app
```

Target names for identity extensions are `peer`, `xff`, `cfip`, and `xrealip`; canonical producer keys differ as listed above. Timestamp modes `unix_s`, `unix_ms`, and `unix_ns` accept integer epochs without unit guessing. Durations explicitly support `s`, `ms`, `us`, and `ns`. Invalid required fields reject the record; unmapped or unsupported optional values remain unavailable. No scripts, general JSONPath expressions, wildcard searches, or arbitrary coercion are supported.

`preset: ecs-v1` (`ecs` is an alias) provides version 1 of ReqSentry's [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) mapping subset: `@timestamp`, nested `client.ip`, `source.ip` as peer, `http.request.method/id`, `http.response.status_code/body.bytes`, `url.path/query/domain`, `user_agent.original`, `event.duration` in nanoseconds, `trace.id`, `log.level`, and `error.message/type/code/stack_trace`. Fixtures test these field names, types, and units; no producer `ecs.version` is inferred or validated. These are field-level mappings, not full ECS ingestion. Verify that the producer's `source.ip` represents its underlying peer before using forwarding headers. Override selectors when a producer writes flattened dotted keys instead of nested objects.

## Logfmt

Logfmt uses the [go-logfmt dialect](https://github.com/go-logfmt/logfmt): whitespace-separated keys/values, double-quoted strings, escaped quotes/backslashes, and optional bare keys. Values containing spaces or equals signs need quoting. Bare/empty required values reject the access record. Duplicate keys, invalid quoting, and multiple records on one input line are rejected. Dotted keys remain literal keys, and mapping/unit declarations work as for JSON.

```text
timestamp=2026-10-03T12:00:00Z client_ip=192.0.2.1 method=GET target="/api?id=2" status=200 request_time=0.012
```

## Preview, replay, and limits

```sh
reqsentry -config /etc/reqsentry/config.yaml -limit 20 preview /var/log/app/access.jsonl
reqsentry -config /etc/reqsentry/config.yaml replay /var/log/nginx/access.log /var/log/app/access.jsonl /var/log/nginx/error.log
```

Preview reads at most 1,000 lines (default 20), prints at most five redacted samples, and reports normalized identity and field availability. It changes no offsets or history and sends no messages. Paths/queries are redacted in access samples. Structured error samples are redacted by the error policy; locally opted-in stack traces remain visible in preview, so protect preview output as incident evidence.

Replay uses configured formats/profiles for each file, including error sources. Unconfigured files explicitly fall back to combined access logs and a filename-derived site; configure structured sources before replaying them. Replay rejects backward timestamps within a source rather than silently reordering or corrupting windows. It merges ordered sources deterministically and reports per-source malformed, parsed, filtered, error, and missing-field counts. It performs no remote notifications or database writes.

Records are limited to 1 MiB, JSON depth to 16, JSON values to 4,096, strings to 64 KiB, and logfmt fields to 256. Structured timestamps must fit the signed 64-bit nanosecond storage range; overflowing epochs and extreme RFC3339 dates are rejected. Duplicate JSON keys and ambiguous arrays are rejected or unavailable. Pretty-printed multiline JSON, top-level arrays, XML, and automatic format detection are not supported. Source `status` shows malformed categories and missing measurements so absent timings do not become misleading zeros.
