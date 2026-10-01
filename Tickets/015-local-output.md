# 015 — Operational log and JSONL incident output

**Status:** Done

**Milestone:** V1  
**Depends on:** 013  
**Brief:** §§42–43, 58–59, 66

Expose daemon health and incidents locally through human-readable logs and structured JSON Lines.

## Acceptance criteria

- Operational logs report lifecycle, watcher failures, health/integration failures, trigger changes, and notable decisions at controlled volume.
- Each JSONL line is one valid incident with score, decision, ruleset version, signals/evidence, site/server identity, IP, and available context.
- Output failures are handled and observable; one failing destination cannot block log ingestion or other outputs.
- `WOULD_BLOCK` and similar decisions clearly state that no action was taken.
- File permissions and rotation behavior are documented for Linux deployment.

File permissions and rotation are documented in [local history and output](../docs/storage-output.md).
