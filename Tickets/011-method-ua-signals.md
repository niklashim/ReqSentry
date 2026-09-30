# 011 — HTTP methods and User-Agent signals

**Status:** To do  
**Milestone:** V1  
**Depends on:** 006  
**Brief:** §§18–21, 33, 51

Analyze method/status/path combinations and User-Agent patterns as contextual evidence.

## Acceptance criteria

- GET, HEAD, POST, PUT, PATCH, DELETE, and OPTIONS are counted; unusual method plus 404/path scanning can emit an evidence-bearing signal.
- User-Agent summaries include primary value, missing values, distinct count, and rapid rotation within configured caps.
- User-Agent claims, including known-crawler names, never prove identity or bypass detection by themselves.
- API OPTIONS traffic and normal missing static assets are covered as false-positive cases.
- Browser-like asset patterns, if implemented, remain supporting evidence only.
