# 007 — Server health and analysis triggers

**Status:** To do  
**Milestone:** V1  
**Depends on:** 001, 006  
**Brief:** §§7–8, 29, 67

Sample CPU, system load, and memory, and control periodic deep analysis with `always` and CPU-triggered modes.

## Acceptance criteria

- `always` runs deep analysis continuously; CPU mode starts after a configured high-CPU duration and stops after a separate low-CPU duration.
- Hysteresis prevents threshold flapping, and pre-trigger traffic windows remain available when analysis starts.
- CPU, load, and memory samples are timestamped and available to incidents.
- Missing or failed health sampling is visible and does not interrupt log collection.
- Trigger logic has a narrow interface that can later accept non-CPU activation without changing collectors.
