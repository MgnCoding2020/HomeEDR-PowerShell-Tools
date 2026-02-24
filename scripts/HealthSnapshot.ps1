<# 
HealthSnapshot.ps1
Creates a daily health & security snapshot file with key system info.
This script is read-only (no changes to the system).
#>

param(
    [string]$OutputDir = 'C:\Scripts\Reports'
)

$ErrorActionPreference = 'Stop'

# Ensure output folder exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Build a timestamped report path
$ts = Get-Date -Format 'yyyyMMdd_HHmm'
$ReportPath = Join-Path $OutputDir ("HealthSnapshot_{0}.txt" -f $ts)

# Small helper to append a line to the report in UTF-8
function Write-Line {
    param([string]$Text = '')
    $Text | Out-File -FilePath $ReportPath -Append -Encoding UTF8
}

# Header
Write-Line ("==== Health & Security Snapshot ====")
Write-Line ("Host: {0}" -f $env:COMPUTERNAME)
Write-Line ("Time: {0}" -f (Get-Date))
Write-Line ("Report: {0}" -f $ReportPath)

# Privilege context (best effort)
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Write-Line ("Running as Admin: {0}" -f $isAdmin)
} catch {
    Write-Line "Running as Admin: (unknown)"
}

Write-Line ('------------------------------------')
Write-Line ''

# ---------- helpers ----------
function Write-Section {
    param([string]$Title)
    Write-Line ""
    Write-Line ("## {0}" -f $Title)
    Write-Line ("-" * 40)
}

# ---------- Windows Update ----------
Write-Section "Windows Update"

# 1) Pending updates (count + details)
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    # Search for software updates that are not installed:
    $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
    $pending  = $result.Updates.Count
    Write-Line ("Pending updates: {0}" -f $pending)

    if ($pending -gt 0) {
        # List a few pending updates for context (title + KB when available).
        # Note: Not all updates have KBArticleIDs (feature/driver updates may not).
        $maxList = [math]::Min($pending, 10)
        Write-Line "Pending update details (up to 10):"
        for ($i = 0; $i -lt $maxList; $i++) {
            $u = $result.Updates.Item($i)
            $kb = ''
            try {
                if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) {
                    $kb = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ', '
                }
            } catch { }
            $sev = ''
            try { $sev = $u.MsrcSeverity } catch { }
            if ($kb) {
                Write-Line ("  - {0} [{1}]" -f $u.Title, $kb)
            } else {
                Write-Line ("  - {0}" -f $u.Title)
            }
            if ($sev) { Write-Line ("      Severity: {0}" -f $sev) }
        }
        if ($pending -gt 10) {
            Write-Line ("  (and {0} more...)" -f ($pending - 10))
        }
    }

    # Reboot required (best effort)
    try {
        $sysinfo = New-Object -ComObject Microsoft.Update.SystemInfo
        Write-Line ("Reboot required for updates: {0}" -f $sysinfo.RebootRequired)
    } catch {
        Write-Line ("Reboot required for updates: (unable to query) - {0}" -f $_.Exception.Message)
    }
} catch {
    Write-Line ("Pending updates: (unable to query) - {0}" -f $_.Exception.Message)
}

# 2) Last successful detection (Windows Update 'check for updates')
# Try multiple locations; if none found, fall back to WU history via COM.
try {
    $found = $false
    $candidates = @(
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect';  Name='LastSuccessTime' },
        @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install'; Name='LastSuccessTime' },
        @{ Path='HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings';                                         Name='LastScanTime' }
    )

    foreach ($c in $candidates) {
        try {
            $val = (Get-ItemProperty -Path $c.Path -ErrorAction Stop).PSObject.Properties[$c.Name].Value
            if ($val) {
                # Some values are already DateTime; some are strings; try parse when string
                $dt = $null
                if ($val -is [datetime]) { $dt = $val }
                else {
                    # Try to parse common formats
                    [datetime]::TryParse($val, [ref]$dt) | Out-Null
                    if (-not $dt) { $dt = $val }  # leave raw if unknown format
                }
                Write-Line ("Last successful update check: {0}" -f $dt)
                $found = $true
                break
            }
        } catch { }
    }

    if (-not $found) {
        # Fallback: use Windows Update history
        try {
            $session  = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $count    = $searcher.GetTotalHistoryCount()
            if ($count -gt 0) {
                $hist     = $searcher.QueryHistory(0, [math]::Min($count, 50))
                $lastDate = ($hist | Sort-Object Date -Descending | Select-Object -First 1).Date
                Write-Line ("Last Windows Update activity (from history): {0}" -f $lastDate)
            } else {
                Write-Line "Last Windows Update activity: (no history entries)"
            }
        } catch {
            Write-Line ("Last Windows Update activity: (unable to query) - {0}" -f $_.Exception.Message)
        }
    }
} catch {
    Write-Line ("Last successful update check: (unknown) - {0}" -f $_.Exception.Message)
}

# 3) Recently installed updates (last 5)
try {
    $recentHFs = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
    if ($recentHFs) {
        Write-Line "Recently installed updates (last 5):"
        foreach ($hf in $recentHFs) {
            Write-Line ("  {0}  {1}  {2}" -f ($hf.InstalledOn), ($hf.HotFixID), ($hf.Description))
        }
    } else {
        Write-Line "Recently installed updates: (none found)"
    }
} catch {
    Write-Line ("Recently installed updates: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- OS / System ----------
Write-Section "System"
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Line ("OS: {0}" -f $os.Caption)
    Write-Line ("Version: {0}  Build: {1}" -f $os.Version, $os.BuildNumber)
    Write-Line ("Install Date: {0}" -f ($os.InstallDate))
    Write-Line ("Last Boot: {0}" -f ($os.LastBootUpTime))
    $uptime = (Get-Date) - $os.LastBootUpTime
    Write-Line ("Uptime: {0} days {1}h {2}m" -f [int]$uptime.TotalDays, $uptime.Hours, $uptime.Minutes)
} catch {
    Write-Line ("System: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Disk ----------
Write-Section "Disk"
try {
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    foreach ($d in $drives) {
        $freeGB  = [math]::Round(($d.FreeSpace / 1GB), 2)
        $sizeGB  = [math]::Round(($d.Size / 1GB), 2)
        $pctFree = if ($d.Size -gt 0) { [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) } else { 0 }
        Write-Line ("Drive {0}  Free: {1} GB / {2} GB ({3}% free)" -f $d.DeviceID, $freeGB, $sizeGB, $pctFree)
    }
} catch {
    Write-Line ("Disk: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Windows Firewall ----------
Write-Section "Windows Firewall"
try {
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        Write-Line ("Profile: {0}" -f $p.Name)
        Write-Line ("  Enabled: {0}" -f $p.Enabled)
        Write-Line ("  DefaultInboundAction:  {0}" -f $p.DefaultInboundAction)
        Write-Line ("  DefaultOutboundAction: {0}" -f $p.DefaultOutboundAction)
        Write-Line ("  NotifyOnListen:        {0}" -f $p.NotifyOnListen)
        Write-Line ("  AllowLocalFirewallRules: {0}" -f $p.AllowLocalFirewallRules)
        Write-Line ("  AllowLocalIPsecRules:    {0}" -f $p.AllowLocalIPsecRules)
    }

    # Count enabled rules (best effort)
    $inRules  = (Get-NetFirewallRule -Enabled True -Direction Inbound  -ErrorAction SilentlyContinue | Measure-Object).Count
    $outRules = (Get-NetFirewallRule -Enabled True -Direction Outbound -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Line ("Enabled inbound rules:  {0}" -f $inRules)
    Write-Line ("Enabled outbound rules: {0}" -f $outRules)
} catch {
    Write-Line ("Windows Firewall: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Defender / Security Center ----------
Write-Section "Windows Security / Defender"
try {
    $mp = Get-MpComputerStatus
    Write-Line ("AMServiceEnabled: {0}" -f $mp.AMServiceEnabled)
    Write-Line ("AntivirusEnabled: {0}" -f $mp.AntivirusEnabled)
    Write-Line ("AntispywareEnabled: {0}" -f $mp.AntispywareEnabled)
    Write-Line ("NISEnabled: {0}" -f $mp.NISEnabled)
    Write-Line ("RealTimeProtectionEnabled: {0}" -f $mp.RealTimeProtectionEnabled)
    Write-Line ("BehaviorMonitorEnabled: {0}" -f $mp.BehaviorMonitorEnabled)
    Write-Line ("OnAccessProtectionEnabled: {0}" -f $mp.OnAccessProtectionEnabled)
    Write-Line ("IoavProtectionEnabled: {0}" -f $mp.IoavProtectionEnabled)
    Write-Line ("IsTamperProtected: {0}" -f $mp.IsTamperProtected)
    Write-Line ("AntivirusSignatureLastUpdated: {0}" -f $mp.AntivirusSignatureLastUpdated)
} catch {
    Write-Line ("Windows Security / Defender: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Recent System/Application Errors (last 24h) ----------
Write-Section "Recent Errors/Warnings (last 24h)"
try {
    $since = (Get-Date).AddHours(-24)
    $filters = @(
        @{ LogName='System';      Level=1,2,3; StartTime=$since },
        @{ LogName='Application'; Level=1,2,3; StartTime=$since }
    )
    foreach ($f in $filters) {
        $events = Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | Select-Object -First 50
        Write-Line ("Log: {0}  (showing up to 50 most recent)" -f $f.LogName)
        if (-not $events) {
            Write-Line "  (none)"
            continue
        }
        foreach ($e in $events) {
            $lvl = $e.LevelDisplayName
            $msg = ($e.Message -replace '\s+', ' ').Trim()
            if ($msg.Length -gt 160) { $msg = $msg.Substring(0,160) + '...' }
            Write-Line ("  {0:o}  ID {1}  {2}  {3}  {4}" -f $e.TimeCreated, $e.Id, $lvl, $e.ProviderName, $msg)
        }
        Write-Line ""
    }
} catch {
    Write-Line ("Recent Errors/Warnings: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- File Integrity Hashes ----------
Write-Section "Integrity Hashes (key files)"
try {
    $paths = @(
        "$env:WINDIR\System32\drivers\etc\hosts",
        "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            $h = Get-FileHash -Path $p -Algorithm SHA256
            Write-Line ("{0}  {1}" -f $h.Hash, $p)
        } else {
            Write-Line ("(missing) {0}" -f $p)
        }
    }
} catch {
    Write-Line ("Integrity Hashes: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Network ----------
Write-Section "Network"
try {
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -and $_.InterfaceAlias }
    foreach ($ip in $ips) {
        Write-Line ("{0}  {1}  {2}" -f $ip.InterfaceAlias, $ip.IPAddress, $ip.PrefixLength)
    }
} catch {
    Write-Line ("Network: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Listening Ports ----------
Write-Section "Listening Ports"
try {
    $conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort
    $shown = 0
    foreach ($c in $conns) {
        Write-Line ("{0}:{1}  PID {2}" -f $c.LocalAddress, $c.LocalPort, $c.OwningProcess)
        $shown++
        if ($shown -ge 80) { break } # keep report readable
    }
    if ($conns.Count -gt 80) {
        Write-Line ("(showing first 80 of {0})" -f $conns.Count)
    }
} catch {
    Write-Line ("Listening Ports: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Startup / Autorun (high-level) ----------
Write-Section "Startup (high-level)"
try {
    $startup = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
    if (-not $startup) {
        Write-Line "(none)"
    } else {
        foreach ($s in $startup | Sort-Object Name) {
            Write-Line ("{0}  |  {1}  |  {2}" -f $s.Name, $s.Location, $s.Command)
        }
    }
} catch {
    Write-Line ("Startup: (unable to query) - {0}" -f $_.Exception.Message)
}

# ---------- Services (quick posture check) ----------
Write-Section "Service Health (selected)"
try {
    $servicesToCheck = @('wuauserv','WinDefend','eventlog','BITS')  # Windows Update, Defender, Event Log, Background Intelligent Transfer
    foreach ($sn in $servicesToCheck) {
        $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Line ("{0}: Status={1}  StartType={2}" -f $svc.Name, $svc.Status, $svc.StartType)
        } else {
            Write-Line ("{0}: (not found)" -f $sn)
        }
    }
} catch {
    Write-Line ("Service Health: (unable to query) - {0}" -f $_.Exception.Message)
}

Write-Line ""
Write-Line "==== End of Snapshot ===="
Write-Output $ReportPath