# 033 — Embedded frontend shell and navigation

**Status:** Done  
**Epic:** F — Dashboard foundation  
**Depends on:** 025, 027, 030

## Objective

Serve a responsive dashboard from one Go binary with clear monitor-mode identity.

## Technical description and subtasks

- Choose a no-runtime frontend build strategy and embed compiled HTML/CSS/JS with Go `embed`.
- Build navigation for Overview, Sites, IPs, Networks, HTTP, Health, PHP-FPM, and Incidents.
- Add shared loading/error/empty states, accessible tables and charts, and safe text rendering.

## Implementation considerations

Keep assets small and cacheable; no Node.js, Python, PHP, or external CDN at runtime.

## Acceptance criteria

- The binary serves the UI while offline; desktop and mobile layouts remain usable.
- `MONITOR MODE` and `WOULD_BLOCK` wording never implies enforcement.

## Testing requirements

Embedded asset test, missing asset/path traversal handling, browser smoke, and narrow-viewport review.

## Documentation impact

Describe one-binary deployment and asset rebuild steps.

## Security considerations

Restrictive CSP, no untrusted `innerHTML`, and auth/allowlist on assets.

## Completion

HTML, CSS, and JavaScript are embedded in the Go binary; the responsive shell provides safe text rendering and section navigation.
