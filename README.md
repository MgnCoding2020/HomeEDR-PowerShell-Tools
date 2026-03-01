# Home EDR – From Posture Monitoring to Governance Automation

## What This Is

Home EDR started as a personal project while I was studying for Network+ and Security+.

Instead of only reading about endpoint security and system hardening, I wanted to actually build something that monitored my Windows system and told me when things changed.
What began as a few PowerShell scripts slowly turned into a structured monitoring workflow.

Now the project is evolving again — toward mapping technical monitoring into governance concepts like control validation and continuous evidence collection.
This repository represents that progression.

---

## Why I Built This

While hardening my own Windows 10 system, I kept asking:

- How would I know if something changed later?
- What would configuration drift actually look like?
- Could I automate monitoring instead of manually checking?
- How do blue teams think about baseline vs current state?

So I built a system that:

- Captures a baseline  
- Takes scheduled snapshots  
- Compares the two  
- Generates structured drift reports  
- Archives everything cleanly  

This project helped me move from theory into practical defensive thinking.

---

## What It Does (In Plain Terms)

This project:

- Collects system configuration data  
- Stores a "known good" baseline  
- Runs scheduled scans  
- Detects changes in services, tasks, and persistence mechanisms  
- Generates readable reports  
- Keeps historical records  

It is not a commercial EDR tool.  
It is a structured learning project focused on understanding monitoring workflows.

---

## How It Works (Simple Flow)

1. Create a baseline of your system.  
2. Schedule recurring scans using Task Scheduler.  
3. Compare new snapshots against the baseline.  
4. Generate drift reports if changes are detected.  
5. Archive older reports for history tracking.  

Simple idea — structured execution.

---

## Getting Started

### Option 1 – Download from GitHub

1. Click the green **Code** button.  
2. Select **Download ZIP**.  
3. Extract the folder somewhere on your system (example: `C:\HomeEDR`).  

---

### Option 2 – Clone with Git

Open Command Prompt, PowerShell, or Git Bash and run:

```bash
git clone https://github.com/YOUR-USERNAME/HomeEDR-PowerShell-Tools.git
```

---

## Running a Script (Example: HealthSnapshot.ps1)

1. Open PowerShell as Administrator.  
2. Navigate to the scripts folder:

```powershell
cd C:\HomeEDR-PowerShell-Tools\scripts
```

3. Run:

```powershell
.\HealthSnapshot.ps1 -OutputDir C:\Reports
```

If you receive an execution policy warning, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then execute the script again.

Reports will be written to the directory you specify.

---

## Example Output

Sample sanitized reports are available in the `sample-output/` folder.

Sensitive data has been removed, including:

- Hostnames  
- Usernames  
- IP addresses  
- MAC addresses  
- Hardware serial numbers  
- Personal file paths  

These samples show the structure and format of generated monitoring reports.

---

## Project Evolution

The project has grown in stages:

Scripts  
→ Structured Reports  
→ Scheduled Automation  
→ Drift Detection  
→ Governance-Oriented Framing (current direction)  

The current focus is on exploring how technical monitoring outputs can support control validation and structured evidence tracking concepts.

---

## What I’ve Learned So Far

- Monitoring is more about structure than complexity.  
- A baseline only matters if you protect and validate it.  
- Drift detection requires context, not just differences.  
- Automation is helpful, but interpretation is what creates value.  

---

## Disclaimer

This project is for educational and defensive security learning purposes.  
It is intended for personal lab environments and experimentation.
