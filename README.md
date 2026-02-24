# Home EDR – PowerShell Posture & Drift Monitoring

## Overview

Home EDR is a PowerShell-based endpoint posture monitoring and drift detection system designed for Windows environments.

This project originated as a hands-on security exercise while studying for Network+ and Security+. The goal was to move beyond theory and implement practical defensive security automation that continuously monitors system state and detects configuration drift.

This repository contains the foundational PowerShell automation layer of the system.

---

## Motivation

While preparing for CompTIA Network+ and Security+, I hardened my personal Windows system and wanted a way to:

- Continuously monitor security posture
- Detect unintended configuration drift
- Track changes to services, scheduled tasks, and persistence mechanisms
- Practice structured log analysis
- Develop defensive monitoring workflows

The objective was not simply to automate scripts, but to build visibility and security reasoning into the system.

---

## Core Design Model

The system follows a structured lifecycle model:

1. Baseline Creation  
   An initial full system scan generates baseline reference files stored in:  
   //baseline//

2. Scheduled Snapshots  
   Recurring scans are executed via Windows Task Scheduler and written to:  
   //snapshots//

3. Drift Detection  
   Snapshot results are compared against the baseline.  
   If changes are detected, drift reports are generated and written to:  
   //alerts//

4. Retention & Archiving  
   Snapshots older than 30 days are automatically moved to:  
   //archive/<year>/<month>//

This structure allows clean separation between the trusted state, current state, and detected changes.

---

## What This Project Demonstrates

- Windows security monitoring fundamentals  
- Baseline vs. live state comparison logic  
- Drift detection methodology  
- Registry and persistence analysis  
- Service configuration tracking  
- Scheduled task auditing  
- Security log summarization  
- Automated lifecycle management  
- Practical application of defensive security concepts  

This is not a commercial EDR product, but rather a structured educational and defensive security project inspired by endpoint monitoring principles.

---

## Report Categories

The system generates structured reports, including:

- Health Snapshot  
- Security Event Log Summary  
- Installed Application Inventory  
- Hardware Inventory  
- Network Audit  
- Services Drift Report  
- Scheduled Tasks Drift Report  
- Persistence Drift Report  
- Consolidated Posture Drift Summary  

All sample reports included in this repository have been sanitized to remove:

- Hostnames  
- Usernames  
- IP addresses  
- MAC addresses  
- Hardware serial numbers  
- Personal file paths  
- Version-specific internal identifiers  

---

## Design Philosophy

The goal was to:

- Build a monitoring workflow, not just scripts  
- Interpret system telemetry  
- Identify potential hardening gaps  
- Think like a blue team analyst  
- Create structured outputs that can be reasoned about  

Each script serves a defined purpose within the overall monitoring lifecycle.

---

## Evolution of the Project

The project evolved in stages:

Scripts → Structured Reports → Scheduled Automation → Interpretation Layer (in progress)

The long-term vision is to provide contextual feedback based on observed posture changes rather than raw output alone.

---

## Future Direction

Planned enhancements include:

- Rule-based posture scoring  
- Best-practice recommendation engine  
- Drift severity classification  
- Automated hardening suggestions  
- Consolidated interpretation layer  
- GUI dashboard (future release / in-progress)  

---

## Disclaimer

This project is for educational and defensive security purposes.  
It is intended for personal lab and learning environments.

---


