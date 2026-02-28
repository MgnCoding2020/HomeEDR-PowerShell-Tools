# Architecture – Home EDR PowerShell Monitoring Framework

## Architectural Overview

Home EDR follows a baseline-driven monitoring model inspired by endpoint detection principles.

The architecture separates:

- Trusted baseline state
- Recurring system snapshots
- Drift comparison logic
- Alert generation
- Historical retention

The system is modular, with each script serving a defined monitoring category.

---

## High-Level Workflow

The monitoring lifecycle consists of five phases:

1. Initial Baseline Generation
2. Scheduled Snapshot Execution
3. State Comparison Engine
4. Drift Classification
5. Snapshot Retention & Archival

---

## 1. Baseline Layer

Directory: /baseline/

The baseline represents a trusted system state captured after hardening.

Baseline data includes:

- Scheduled tasks
- Services and start types
- Persistence mechanisms (Run keys, startup entries)
- Installed software inventory
- Security configuration posture
- Hardware inventory
- Network state summary

Baseline files serve as the reference dataset for all future comparisons.

---

## 2. Snapshot Layer

Directory: /snapshots/

Snapshots are generated via Windows Task Scheduler at defined intervals.

Each execution:

- Collects current system telemetry
- Writes structured output files
- Maintains consistent formatting for comparison logic

Snapshots are intentionally separated from baseline data to preserve integrity.

---

## 3. Comparison Engine

Comparison logic performs structured diff operations between:

/baseline/<component>.csv/
/snapshots/<component>_<timestamp>.csv/

Comparison categories include:

### Scheduled Tasks Drift
- Task added
- Task removed
- Task modified (trigger, action, state)

### Services Drift
- StartType changes
- Binary path changes
- Service status transitions
- Newly installed services

### Persistence Drift
- New Run keys
- Removed Run keys
- Startup folder modifications
- Auto-launch registry changes

The comparison model is state-based rather than event-based.

---

## 4. Alert & Reporting Layer

Directory: /alerts/

If drift is detected:

- A structured drift report is generated
- Changes are categorized
- Output is separated by monitoring domain

Reports are designed for human interpretation rather than raw diff dumps.

Sanitized versions in this repository reflect summary-form output for portfolio purposes.

---

## 5. Retention & Archival

Directory: /archive/<year>/<month>/

To maintain long-term visibility without directory clutter:

- Snapshots older than 30 days are automatically relocated
- Archive structure preserves chronological grouping
- Baseline data remains immutable unless intentionally regenerated

This approach maintains forensic traceability while preventing report sprawl.

---

## Monitoring Domains

The system monitors multiple defensive layers:

- Task Scheduler (execution persistence)
- Windows Services (service-level integrity)
- Registry persistence mechanisms
- Installed application deltas
- Event log summaries
- Network posture indicators
- Defender security status

This layered monitoring model reflects defense-in-depth principles.

---

## Design Principles

### Baseline-First Strategy
Rather than reacting to alerts alone, the system continuously validates the system state against a trusted configuration.

### Separation of Concerns
Baseline, snapshot, alert, and archive directories are intentionally segregated.

### Human-Readable Reporting
Reports prioritize structured summaries over raw system dumps.

### Drift Over Noise
The system focuses on meaningful configuration changes rather than transient runtime events.

---

## Security Considerations

Public repository samples have been sanitized to remove:

- Hostnames
- Usernames
- IP addresses
- MAC addresses
- Hardware serial numbers
- Personal file paths

Sensitive identifiers are excluded to prevent system fingerprinting.

---

## Future Architectural Enhancements

Planned evolution includes:

- Drift severity scoring
- Rule-based best practice validation
- Context-aware interpretation engine
- Consolidated posture scoring model
- Modular plugin-based monitoring extensions
- GUI-based visualization layer (future release)

---

## Summary

Home EDR is a structured, baseline-driven monitoring framework built to:

- Reinforce defensive security principles
- Practice telemetry analysis
- Develop drift detection workflows
- Build security reasoning capabilities

The architecture reflects layered monitoring and lifecycle management rather than isolated script execution.
