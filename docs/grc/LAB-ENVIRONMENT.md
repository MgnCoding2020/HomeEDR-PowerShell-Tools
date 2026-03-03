# Lab Environment (RMF-aligned)

This repository is a Windows endpoint governance lab. The goal is to learn and demonstrate concepts in evidence collection, control mapping, and continuous monitoring using NIST RMF/NIST SP 800-53 as the organizing framework.

This is **not** an ATO package, and it does **not** claim “Authorization” decisions. It is a portfolio-safe lab showing how evidence would be collected and mapped in a real program.

## Systems in Scope

### Host
- OS: Windows 10 (extended support)
- Hyper-V: Enabled

### Guest VM
- Hyper-V VM: Windows 10 Pro (Generation 1)
- Patch posture: Fully updated at time of baseline
- Baseline checkpoint: `Baseline-Clean-Patched.`

## Evidence Collection Approach

Scripts in `scripts/` are used to collect endpoint posture artifacts (configuration, services/tasks, network posture, software inventory, and event log summaries).

The lab uses two evidence tiers:

### 1) Raw evidence (not committed)
- Location: `evidence/`
- Purpose: Full-fidelity outputs produced from the host/VM.
- Policy: **Not committed to GitHub** to avoid exposing hostnames, usernames, installed software inventories, IPs, or event log content.

### 2) Sanitized sample evidence (committed)
- Location: `sample-output/`
- Purpose: Redacted examples showing what evidence artifacts look like and how they support control mapping.
- Policy: Safe for public sharing (redacted identifiers, shortened logs, removed environment-specific values).

## Continuous Monitoring (Planned / Lab Scope)

This lab may use:
- Sysmon (Windows event telemetry)
- Wazuh (agent + manager) as a monitoring plane

Monitoring integrations are documented as **RMF Step 6 (Monitor)** learning artifacts and kept intentionally small (a few use-cases, not a full SOC build).

## Control Mapping

Control-to-evidence mapping is maintained in `controls/` and is used to generate `CONTROL_EVIDENCE.md`.

Mappings are written as “what artifact supports what control objective” for this lab scope, not as claims of enterprise-wide compliance.
