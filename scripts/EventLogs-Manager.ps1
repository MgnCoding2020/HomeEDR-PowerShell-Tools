<#
  EventLogs-Manager.ps1
  Home EDR Dashboard - Event Logs Suite (Analyze / Detect / Archive / Clear)

  - Tracks events since last scan using RecordId markers (state\EventLogMarkers.json)
  - Handles Security access denied gracefully
  - Adds Admin-aware metadata:
      RunningAsAdmin: True/False
      SecurityLogReadable: True/False
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [ValidateSet("Analyze","Detect","Archive","Clear","ArchiveAndClear")]
    [string]$Action = "Analyze",

    [int]$HoursBack = 24,

    [string[]]$Logs = @("Security","System","Application"),

    [ValidateSet("AuthAnomalies","ServiceInstall","TaskCreate","ProcessCreate","PolicyChanges","AccountChanges","All")]
    [string]$Profile = "AuthAnomalies",

    [int]$ArchiveYear = 0,
    [int]$ArchiveMonth = 0,

    [switch]$SinceLastScan,
    [switch]$HoursBackOnly,

    [int]$MaxEventsPerLog = 5000,

    [switch]$ForceClear
)

$ErrorActionPreference = "Stop"

# ------------------------------
# Setup output folders
# ------------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$enc = "utf8"

if ($Logs.Count -eq 1 -and $Logs[0] -like "*,*") {
    $Logs = $Logs[0].Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

$stateDir  = Join-Path $OutputDir "state"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
$statePath = Join-Path $stateDir "EventLogMarkers.json"

# ------------------------------
# Security context
# ------------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ------------------------------
# Output helpers
# ------------------------------
function Write-Section([string]$File, [string]$Title) {
    "" | Out-File $File -Append -Encoding $enc
    ("==== {0} ====" -f $Title) | Out-File $File -Append -Encoding $enc
}

function Safe-Out([string]$File, [scriptblock]$Block) {
    try {
        & $Block | Out-String | Out-File $File -Append -Encoding $enc
    } catch {
        ("ERROR: {0}" -f $_.Exception.Message) | Out-File $File -Append -Encoding $enc
    }
}

# ------------------------------
# State
# ------------------------------
function Load-State() {
    if (Test-Path $statePath) {
        try {
            return (Get-Content -Path $statePath -Raw -ErrorAction Stop) | ConvertFrom-Json
        } catch {
            return $null
        }
    }
    return $null
}

function Save-State($obj) {
    try {
        ($obj | ConvertTo-Json -Depth 6) | Out-File -FilePath $statePath -Encoding $enc
    } catch {
        # best-effort; do not fail tool
    }
}

function Get-LatestRecordId([string]$LogName) {
    try {
        $e = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
        if ($e -and $e.RecordId) { return [int64]$e.RecordId }
    } catch { }
    return $null
}

function Get-NewEvents([string]$LogName, [int64]$LastRecordId, [datetime]$FallbackStart) {
    if ($LastRecordId -ne $null) {
        $xpath = "*[System[EventRecordID > $LastRecordId]]"
        return Get-WinEvent -LogName $LogName -FilterXPath $xpath -MaxEvents $MaxEventsPerLog -ErrorAction Stop
    }
    return Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $FallbackStart } -MaxEvents $MaxEventsPerLog -ErrorAction Stop
}

function Test-SecurityReadable {
    try {
        $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# ------------------------------
# Analyze
# ------------------------------
function Invoke-Analyze() {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $out = Join-Path $OutputDir ("SecurityReport_{0}.txt" -f $timestamp)

    $now = Get-Date
    $fallbackStart = $now.AddHours(-1 * $HoursBack)

    $state = Load-State
    $haveMarkers = $false
    if ($state -and $state.markers) { $haveMarkers = $true }

    $useSince = $false
    if ($SinceLastScan) { $useSince = $true }
    elseif ($haveMarkers -and -not $HoursBackOnly) { $useSince = $true }

    "Home EDR Dashboard - Event Logs Analysis" | Out-File $out -Encoding $enc
    ("Host:            {0}" -f $env:COMPUTERNAME) | Out-File $out -Append -Encoding $enc
    ("Generated:       {0}" -f $now) | Out-File $out -Append -Encoding $enc
    ("HoursBack:       {0}" -f $HoursBack) | Out-File $out -Append -Encoding $enc
    ("MaxEventsPerLog: {0}" -f $MaxEventsPerLog) | Out-File $out -Append -Encoding $enc
    ("RunningAsAdmin:  {0}" -f $IsAdmin) | Out-File $out -Append -Encoding $enc
    ("Mode:            {0}" -f ($(if ($useSince) { "SinceLastScan" } else { "HoursBack" }))) | Out-File $out -Append -Encoding $enc
    ("Logs:            {0}" -f ($Logs -join ", ")) | Out-File $out -Append -Encoding $enc

    Write-Section $out "Overview"
    if ($useSince) {
        $lastScanStr = "(first run / no state)"
        try { if ($state -and $state.last_scan_utc) { $lastScanStr = $state.last_scan_utc } } catch { }
        ("Since last scan (UTC): {0}" -f $lastScanStr) | Out-File $out -Append -Encoding $enc
    } else {
        ("Time window start: {0}" -f $fallbackStart) | Out-File $out -Append -Encoding $enc
    }

    # FIX: markers is a hashtable and we write keys normally (no Add-Member)
    $newState = [pscustomobject]@{
        last_scan_utc = ($now.ToUniversalTime().ToString("o"))
        markers       = @{}
    }

    foreach ($log in $Logs) {
        Write-Section $out ("{0} Summary" -f $log)

        if ($log -ieq "Security") {
            $secReadable = Test-SecurityReadable
            ("SecurityLogReadable: {0}" -f $secReadable) | Out-File $out -Append -Encoding $enc
            if (-not $secReadable) {
                "Could not retrieve Security log (common without elevation or rights)." | Out-File $out -Append -Encoding $enc
                "Tip: Re-run this tool in Admin mode (UAC) to attempt Security log access." | Out-File $out -Append -Encoding $enc
            }
        }

        Safe-Out $out {
            $lastId = $null
            if ($useSince -and $state -and $state.markers -and $state.markers.$log) {
                try { $lastId = [int64]$state.markers.$log.last_record_id } catch { $lastId = $null }
            }

            $events = Get-NewEvents -LogName $log -LastRecordId $lastId -FallbackStart $fallbackStart

            "Event counts by LevelDisplayName:"
            $events |
                Group-Object LevelDisplayName |
                Sort-Object Name |
                Select-Object Name, Count |
                Format-Table -AutoSize

            ""
            "Top Event IDs (top 10):"
            $events |
                Group-Object Id |
                Sort-Object Count -Descending |
                Select-Object -First 10 Name, Count |
                Format-Table -AutoSize
        }

        $latestId = Get-LatestRecordId -LogName $log
        if ($latestId -ne $null) {
            $newState.markers[$log] = [pscustomobject]@{
                last_record_id = $latestId
                updated_utc    = ($now.ToUniversalTime().ToString("o"))
            }
        }
    }

    Save-State $newState

    "" | Out-File $out -Append -Encoding $enc
    ("State written to:  {0}" -f $statePath) | Out-File $out -Append -Encoding $enc
    ("Report written to: {0}" -f $out) | Out-File $out -Append -Encoding $enc
    Write-Output ("Report written to: {0}" -f $out)
}

# ------------------------------
# Detect (kept as-is from prior replacement)
# ------------------------------
function Get-ProfileEventIds([string]$ProfileName) {
    $auth  = @(4624,4625,4648,4672,4768,4769,4771,4776,4778,4779,4800,4801,4802,4803,1102)
    $svc   = @(7045,7036,7035,7040,4697,1102)
    $task  = @(4698,4699,4700,4701,4702,1102)
    $proc  = @(4688,1102)
    $pol   = @(4719,4739,4902,4904,4905,4906,4907,1102)
    $acct  = @(4720,4722,4723,4724,4725,4726,4727,4728,4729,4732,4733,4735,4737,4754,4755,4756,4767,1102)

    switch ($ProfileName) {
        "AuthAnomalies"  { return $auth }
        "ServiceInstall" { return $svc  }
        "TaskCreate"     { return $task }
        "ProcessCreate"  { return $proc }
        "PolicyChanges"  { return $pol  }
        "AccountChanges" { return $acct }
        "All"            { return ($auth + $svc + $task + $proc + $pol + $acct) | Select-Object -Unique }
        default          { return $auth }
    }
}

function Invoke-Detect() {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $out = Join-Path $OutputDir ("Detections_{0}.txt" -f $timestamp)
    $start = (Get-Date).AddHours(-1 * $HoursBack)

    "Home EDR Dashboard - Event Logs Detections" | Out-File $out -Encoding $enc
    ("Host:            {0}" -f $env:COMPUTERNAME) | Out-File $out -Append -Encoding $enc
    ("Generated:       {0}" -f (Get-Date)) | Out-File $out -Append -Encoding $enc
    ("HoursBack:       {0}" -f $HoursBack) | Out-File $out -Append -Encoding $enc
    ("MaxEventsPerLog: {0}" -f $MaxEventsPerLog) | Out-File $out -Append -Encoding $enc
    ("RunningAsAdmin:  {0}" -f $IsAdmin) | Out-File $out -Append -Encoding $enc
    ("Logs:            {0}" -f ($Logs -join ", ")) | Out-File $out -Append -Encoding $enc
    ("Profile:         {0}" -f $Profile) | Out-File $out -Append -Encoding $enc

    Write-Section $out "Overview"
    ("Time window start: {0}" -f $start) | Out-File $out -Append -Encoding $enc

    $profileIds = Get-ProfileEventIds -ProfileName $Profile

    foreach ($log in $Logs) {
        Write-Section $out ("{0} Detections" -f $log)

        if ($log -ieq "Security") {
            $secReadable = Test-SecurityReadable
            ("SecurityLogReadable: {0}" -f $secReadable) | Out-File $out -Append -Encoding $enc
            if (-not $secReadable) {
                "Security log not accessible. Re-run in Admin mode to attempt access." | Out-File $out -Append -Encoding $enc
                continue
            }
        }

        Safe-Out $out {
            $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -MaxEvents $MaxEventsPerLog -ErrorAction Stop
            $matches = $events | Where-Object { $profileIds -contains $_.Id }

            if (-not $matches) {
                "No matching events for profile in this window."
                return
            }

            "Matched events by ID:"
            $matches |
                Group-Object Id |
                Sort-Object Count -Descending |
                Select-Object Name, Count |
                Format-Table -AutoSize
        }
    }

    ("Report written to: {0}" -f $out) | Out-File $out -Append -Encoding $enc
    Write-Output ("Report written to: {0}" -f $out)
}

# ------------------------------
# Archive/Clear (unchanged placeholders for now)
# ------------------------------
function Invoke-Archive() {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $out = Join-Path $OutputDir ("Archive_{0}.txt" -f $timestamp)
    "Archive mode placeholder (preserved)." | Out-File $out -Encoding $enc
    Write-Output ("Report written to: {0}" -f $out)
}

function Invoke-Clear() {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $out = Join-Path $OutputDir ("Clear_{0}.txt" -f $timestamp)

    if (-not $ForceClear) {
        "Refusing to clear logs. Re-run with -Action Clear -ForceClear to proceed." | Out-File $out -Encoding $enc
        Write-Output ("Report written to: {0}" -f $out)
        return
    }

    Safe-Out $out {
        foreach ($log in $Logs) {
            try {
                Clear-EventLog -LogName $log -ErrorAction Stop
                ("Cleared: {0}" -f $log)
            } catch {
                ("FAILED: {0} -> {1}" -f $log, $_.Exception.Message)
            }
        }
    }

    Write-Output ("Report written to: {0}" -f $out)
}

switch ($Action) {
    "Analyze"         { Invoke-Analyze }
    "Detect"          { Invoke-Detect }
    "Archive"         { Invoke-Archive }
    "Clear"           { Invoke-Clear }
    "ArchiveAndClear" { Invoke-Archive; Invoke-Clear }
}