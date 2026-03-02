# Lab Environment

## Why This Exists

Up to this point, all scripts and evidence artifacts were generated directly from my host machine during development.
To make the project more realistic and better aligned with security assessment practices, I built a dedicated Windows 10 virtual machine using Hyper-V.
This VM now acts as the "endpoint under evaluation."

---

## Host System (Development)

- Windows 10 (Extended Support)
- 32 GB RAM
- Hyper-V Manager enabled

The host is used for:
- Script development
- GitHub repo management
- Control mapping updates
- Reviewing generated artifacts

The host is not the intended long-term assessment target.

---

## Virtual Machine (Assessment Endpoint)

- Name: HomeEDR-lab-02
- Hyper-V Generation: Gen 1
- RAM: 8 GB
- CPU: 2 vCPU
- OS: Windows 10 Pro 22H2 (x64)
- Network: Hyper-V Default Switch (NAT)

The VM was:
1. Freshly installed
2. Fully patched via Windows Update
3. Verified with Defender enabled
4. Restart validated

This VM represents a controlled Windows workstation that can be modified, tested, and reverted without impacting the host system.

---

## Why Separate Host and VM?

Running scripts only on the host does not simulate real endpoint assessment.

By cloning the repo inside the VM and running the same PowerShell scripts there:

- HealthSnapshot.ps1 pulls VM-specific data
- InstalledApps-Inventory.ps1 reflects VM software state
- Network-Audit.ps1 reflects VM network configuration

Outputs generated inside the VM will differ from the host, which makes comparisons possible.

---

## Next Phase

The plan is to:

- Clone the repository inside the VM
- Run scripts from the VM
- Store VM-generated artifacts separately
- Compare baseline vs modified states
- Expand control mappings as evidence becomes endpoint-driven

This moves the project from development-only testing to structured endpoint assessment.
