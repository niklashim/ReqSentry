# 027 — Independent authentication and access audit

**Status:** Done  
**Epic:** B — Dashboard security  
**Depends on:** 026

## Objective

Add a second optional authentication layer and safe records of denied dashboard access.

## Technical description and subtasks

- Add `web.auth.enabled`, `username`, and password environment/systemd credential references; never accept a YAML plaintext password.
- Require HTTP Basic authentication after IP allowlisting, compare secrets without timing leakage, and avoid credential values in logs/status.
- Log bounded access-denial reason and source IP; omit URLs entirely to avoid leaking tokens carried in paths or query strings, and throttle repeated failures.

## Implementation considerations

IP allowlisting remains mandatory even with auth enabled. Warn operators to use localhost tunneling or TLS termination for Basic auth.

## Acceptance criteria

- Both allowlist and auth must pass when auth is on; a missing secret prevents web startup only.
- Denials never disclose protected data or passwords; CLI status shows configuration without secrets.

## Testing requirements

Correct/incorrect credentials, missing secret, denied IP before auth, header spoofing, and log redaction.

## Documentation impact

Document credential setup and reverse proxy/TLS operation.

## Security considerations

Constant-time comparison, bounded log content, and no secret-bearing URLs or query logs.

## Completion

Basic authentication resolves environment or systemd credential secrets, checks independently of the allowlist, and logs bounded denial counts without sensitive URLs.
