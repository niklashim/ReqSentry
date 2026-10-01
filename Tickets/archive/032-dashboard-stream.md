# 032 — Bounded live statistics stream

**Status:** Done  
**Epic:** E — Real-time transport  
**Depends on:** 027, 028, 030

## Objective

Refresh dashboards every 1–2 seconds using aggregate snapshots, without broadcasting raw requests.

## Technical description and subtasks

- Compare SSE and WebSockets for one-way updates, browser support, reconnect behavior, proxying, authentication, and resource cost; record the decision.
- Implement a bounded stream with one aggregate event per interval, client cap, disconnect handling, and heartbeat/reconnect behavior.
- Send only current snapshot or aggregate deltas; slow clients must not queue unbounded events.

## Implementation considerations

HTTP/1.1 proxy buffering and idle timeouts need deployment guidance.

## Acceptance criteria

- Multiple clients receive updates; a slow/disconnected client does not delay log ingestion or other clients.
- Reconnection refreshes current state; no per-request browser firehose exists.

## Testing requirements

Connect/disconnect/reconnect, client cap, slow clients, cancellation, and attack-scale update size.

## Documentation impact

Record transport choice and reverse proxy settings.

## Security considerations

Authorize before opening a stream; cap concurrent clients and event sizes.

## Completion

One shared SSE publisher uses bounded queues, client limits, reconnect snapshots, and write deadlines.
