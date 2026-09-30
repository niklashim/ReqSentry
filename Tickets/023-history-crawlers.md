# 023 — Historical tuning and verified crawlers

**Status:** To do  
**Milestone:** Later  
**Depends on:** V1 monitor data and 014, 021  
**Brief:** §§37–38, 41, 51, 69

Use monitor-mode evidence to tune history retention, decaying reputation, and verified crawler treatment.

## Acceptance criteria

- Historical suspicion decays and cannot permanently condemn an IP; retention controls are documented and configurable.
- Known crawler identity requires provider-supported verification such as official ranges or DNS checks, never a User-Agent claim alone.
- Replay compares proposed rules with stored incidents and records false-positive impact before rollout.
- Repeat-offender escalation remains separate from the behavior score and takes no network action here.
