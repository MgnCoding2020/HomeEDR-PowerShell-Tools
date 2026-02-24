<#
  Audit-Network.ps1
  Home EDR Dashboard - Network Audit (read-only)

  Output:
    Network_yyyyMMdd_HHmmss.txt   (UTF-8 text)

  Notes:
  - Designed to be GUI-friendly: supports -OutputDir and writes UTF-8.
  - Includes additional visibility sections (connections, DNS cache, routes).
  - Read-only collectors only.
#>

[CmdletBinding()]
param(
    # Where to write the report file (GUI passes this)
    [string]$OutputDir = "C:\Scripts\Reports",

    # Kept for backward compatibility with existing callers/UI
    [switch]$Force
)

# ----------------------------
# Paths / output file
# ----------------------------
$reportRoot = $OutputDir
New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$out = Join-Path $reportRoot ("Network_{0}.txt" -f $timestamp)

# Force UTF-8 so the GUI reads the report cleanly
$enc = "utf8"

# Helper: write a section title
function Write-Section([string]$Title) {
    "" | Out-File $out -Append -Encoding $enc
    ("==== {0} ====" -f $Title) | Out-File $out -Append -Encoding $enc
}

# Helper: safely run a command and write output without breaking the script
function Write-CommandOutput([string]$Label, [scriptblock]$Command) {
    $Label | Out-File $out -Append -Encoding $enc
    try {
        & $Command | Out-String | Out-File $out -Append -Encoding $enc
    } catch {
        ("ERROR: {0}" -f $_.Exception.Message) | Out-File $out -Append -Encoding $enc
    }
}

# Header
"Home EDR Dashboard - Network Audit" | Out-File $out -Encoding $enc
("Generated: {0}" -f (Get-Date)) | Out-File $out -Append -Encoding $enc
("Computer:  {0}" -f $env:COMPUTERNAME) | Out-File $out -Append -Encoding $enc
("User:      {0}" -f $env:USERNAME) | Out-File $out -Append -Encoding $enc

# ----------------------------
# Core network configuration
# ----------------------------
Write-Section "IP Configuration (ipconfig /all)"
Write-CommandOutput "ipconfig /all:" { ipconfig /all }

Write-Section "Network Adapters"
Write-CommandOutput "Get-NetAdapter:" {
    Get-NetAdapter |
      Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress |
      Format-Table -AutoSize
}

Write-Section "IP Addresses"
Write-CommandOutput "Get-NetIPAddress:" {
    Get-NetIPAddress |
      Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength |
      Sort-Object InterfaceAlias, AddressFamily |
      Format-Table -AutoSize
}

# ----------------------------
# Routing
# ----------------------------
Write-Section "Route Table (default routes)"
Write-CommandOutput "Default routes (0.0.0.0/0):" {
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
      Select-Object InterfaceAlias, NextHop, RouteMetric |
      Sort-Object RouteMetric |
      Format-Table -AutoSize
}

# ----------------------------
# Connections / ports
# ----------------------------
Write-Section "Active TCP Connections"
Write-CommandOutput "Get-NetTCPConnection (top 50):" {
    Get-NetTCPConnection |
      Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
      Sort-Object State |
      Select-Object -First 50 |
      Format-Table -AutoSize
}

Write-Section "Listening TCP Ports"
Write-CommandOutput "Get-NetTCPConnection -State Listen:" {
    Get-NetTCPConnection -State Listen |
      Select-Object LocalAddress, LocalPort, OwningProcess |
      Sort-Object LocalPort, LocalAddress |
      Format-Table -AutoSize
}

# ----------------------------
# FIXED: Process names for listening ports
#   IMPORTANT: Do NOT use $pid (PowerShell automatic variable $PID is read-only).
# ----------------------------
Write-Section "Running Processes for Listening Ports (best-effort)"
Write-CommandOutput "Process names for listening ports:" {
    $listens = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object -Unique LocalPort, OwningProcess

    $rows = foreach ($l in $listens) {
        $procName = ""
        try { $procName = (Get-Process -Id $l.OwningProcess -ErrorAction Stop).ProcessName } catch { $procName = "?" }
        [pscustomobject]@{
            LocalPort      = $l.LocalPort
            OwningProcess  = $l.OwningProcess
            ProcessName    = $procName
        }
    }

    $rows | Sort-Object LocalPort | Format-Table -AutoSize
}

# ----------------------------
# DNS
# ----------------------------
Write-Section "DNS Client Cache (top 50)"
Write-CommandOutput "Get-DnsClientCache:" {
    try {
        Get-DnsClientCache |
          Select-Object -First 50 |
          Format-Table -AutoSize
    } catch {
        "Get-DnsClientCache not available on this system."
    }
}

Write-Section "DNS Server Addresses"
Write-CommandOutput "Get-DnsClientServerAddress:" {
    Get-DnsClientServerAddress |
      Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
      Format-Table -AutoSize
}

# ----------------------------
# Firewall profile summary
# ----------------------------
Write-Section "Firewall Profiles"
Write-CommandOutput "Get-NetFirewallProfile:" {
    Get-NetFirewallProfile |
      Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
      Format-Table -AutoSize
}

# ----------------------------
# Wireless (if present)
# ----------------------------
Write-Section "Wi-Fi Profiles (netsh wlan show profiles)"
Write-CommandOutput "Wi-Fi profiles:" {
    netsh wlan show profiles
}

# ----------------------------
# Summary
# ----------------------------
Write-Section "Summary"
Write-CommandOutput "Basic network summary:" {
    $adaptersUp = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).Count
    $ips = (Get-NetIPAddress | Where-Object {$_.IPAddress -and $_.AddressFamily -in @("IPv4","IPv6")}).Count
    [pscustomobject]@{
        AdaptersUp = $adaptersUp
        IPEntries  = $ips
    } | Format-List
}

"Done." | Out-File $out -Append -Encoding $enc
Write-Output $out
exit 0