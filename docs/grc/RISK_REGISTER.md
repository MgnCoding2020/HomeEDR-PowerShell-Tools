# Risk Register (Draft)

This register tracks risks identified through threat modeling and operational experience.

## Scale (Simple)
- **Likelihood:** Low / Medium / High
- **Impact:** Low / Medium / High
- **Status:** Open / Mitigating / Closed

---

## R-001: Baseline Tampering

**Description:** An attacker or accidental change could modify baseline reference files, causing drift detection to become unreliable.

**Likelihood:** Medium  
**Impact:** High  
**Status:** Open  

**Mitigation idea(s):**
- Hash and validate baseline files
- Restrict baseline folder ACLs
- Optional: sign baseline manifests

**Evidence / Signals:**
- Baseline hash changes unexpectedly
- Baseline files changed outside expected maintenance window

---

## R-002: Scheduled Task Disabled (Missed Evidence Collection)

**Description:** Scheduled tasks may be disabled or fail, resulting in missing evidence and reduced monitoring coverage.

**Likelihood:** Medium  
**Impact:** Medium  
**Status:** Open  

**Mitigation idea(s):**
- “Heartbeat” file updated each run
- Alert if last-run timestamp exceeds threshold

**Evidence / Signals:**
- No new reports within expected cadence
- Task Scheduler logs show failures