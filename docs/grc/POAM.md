# Plan of Action & Milestones (POA&M) (Draft)

This document tracks planned improvements, tied back to risks and evidence reliability.

## Status
- Planned
- In Progress
- Complete

---

## POAM-001: Baseline Integrity Validation

**Related risk(s):** R-001  
**Goal:** Prevent undetected baseline tampering.

**Planned work:**
- Create baseline manifest with hashes
- Validate manifest before drift comparisons
- Document baseline maintenance process

**Status:** Planned

---

## POAM-002: Evidence Collection Heartbeat

**Related risk(s):** R-002  
**Goal:** Detect missed scheduled runs.

**Planned work:**
- Add a small “last-run” marker file per script
- Add alert when evidence is stale

**Status:** Planned