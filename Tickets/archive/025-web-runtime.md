# 025 — Optional embedded web runtime

**Status:** Done  
**Epic:** A — Embedded web server  
**Depends on:** 001, 020

## Objective

Serve a read-only dashboard from the ReqSentry process only when explicitly enabled.

## Technical description and subtasks

- Add strict `web.enabled`, `listen`, and `port` configuration with loopback defaults and invalid-address rejection.
- Start and stop an `http.Server` with the daemon context; expose only versioned GET/HEAD routes, static assets, and the live stream.
- Publish bind and runtime state to CLI status. Keep HTTP work off the log-ingestion goroutine.

## Implementation considerations

Bind failure should be visible and leave core monitoring running. External binding must require an explicit listen address and access policy.

## Acceptance criteria

- Web is disabled by default; an enabled loopback listener starts and shuts down cleanly.
- No dashboard route changes traffic, configuration, scores, or enforcement state.
- A listener error is reported locally without stopping log ingestion.

## Testing requirements

Configuration defaults/rejection, disabled mode, listener lifecycle, and GET-only routing tests.

## Documentation impact

Document enablement, port, loopback use, and CLI status.

## Security considerations

No wildcard binding by default; access checks precede static and API routing.

## Completion

Optional loopback HTTP runtime, lifecycle, and CLI web state are wired into the daemon; listener failure leaves monitoring running.
