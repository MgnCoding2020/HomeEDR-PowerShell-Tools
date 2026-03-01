# Control Narratives (Draft)

This document explains *why* each evidence script exists and how its output supports security monitoring and control validation.

## How to Read This
Each entry includes:
- **Control intent**: what good looks like
- **What we collect**: what the script measures
- **Evidence artifact**: the output file(s)
- **Cadence**: how often it should run
- **Failure signals**: what indicates the control may not be operating

---

## CN-01: Endpoint Health & Security Posture Snapshot

**Intent:** Maintain visibility into baseline endpoint health and security configuration over time.

**What we collect:** OS info, uptime, disk status, Windows Update status, firewall profiles, Defender status, key event log summaries.

**Evidence artifact(s):**
- `HealthSnapshot_<timestamp>.txt` (or similar)

**Cadence:**
- Suggested: Daily (or weekly for low-change systems)

**Failure signals:**
- Evidence not generated on schedule
- Output missing key sections (Defender/Firewall/Update status)

**Notes:**
- This narrative started as a posture monitoring exercise and is being refactored into governance-oriented evidence collection.