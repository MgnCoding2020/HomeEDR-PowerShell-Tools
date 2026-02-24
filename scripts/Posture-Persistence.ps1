<#
  Posture-Persistence.ps1
  Home EDR Dashboard - Security Posture (Persistence)

  IMPORTANT SCHEDULER CHANGE (v1.5+):
  - When run as SYSTEM (LocalSystem), HKCU + CurrentUser startup folder do NOT represent your user account.
    In that mode:
      • Skip CurrentUser Startup folder
      • Skip HKCU Run key
    We write a Context NOTE file so the GUI can explain what was skipped.

  What it collects (read-only):
    - Startup folder entries (Current User + All Users)
    - Registry Run keys (HKCU + HKLM)

  Baseline + Drift:
    - Writes/updates baseline CSV into -BaselineDir
    - Writes a current-run CSV into -OutputDir
    - If drift is detected, writes a Diff TXT into -OutputDir
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [Parameter(Mandatory = $true)]
    [string]$BaselineDir,

    [switch]$UpdateBaseline
)

function Test-IsSystemContext {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($id -and $id.User -and $id.User.Value -eq "S-1-5-18") { return $true }
    } catch {}
    return $false
}
$IsSystem = Test-IsSystemContext

# -----------------------------
# Setup
# -----------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null

$enc = "utf8"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"

$baselinePath = Join-Path $BaselineDir "Persistence_Baseline.csv"
$currentPath  = Join-Path $OutputDir ("Posture_Persistence_{0}.csv" -f $stamp)
$diffPath     = Join-Path $OutputDir ("Posture_Persistence_Diff_{0}.txt" -f $stamp)
$notePath     = Join-Path $OutputDir ("Posture_Persistence_Context_{0}.txt" -f $stamp)

# Write context note (helps GUI explain SYSTEM/S4U behavior)
@(
    "Beacon Posture: Persistence (read-only)",
    ("Generated: {0}" -f (Get-Date)),
    ("RunAs: {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name)),
    ("IsSYSTEM: {0}" -f $IsSystem),
    ""
) | Out-File -FilePath $notePath -Encoding $enc

if ($IsSystem) {
    @(
        "NOTE: Running as SYSTEM (LocalSystem).",
        "      HKCU and CurrentUser Startup do not represent the signed-in user in SYSTEM mode.",
        "      For accuracy we are skipping:",
        "        • CurrentUser Startup folder entries",
        "        • HKCU Run key entries",
        ""
    ) | Out-File -FilePath $notePath -Append -Encoding $enc
}

# -----------------------------
# Helpers
# -----------------------------
function New-Row {
    param(
        [string]$Category,
        [string]$Location,
        [string]$Name,
        [string]$Value,
        [string]$Source
    )

    $key = "{0}|{1}|{2}" -f $Category, $Location, $Name

    [pscustomobject]@{
        Key      = $key
        Category = $Category
        Location = $Location
        Name     = $Name
        Value    = $Value
        Source   = $Source
    }
}

function Safe-GetChildItem {
    param([string]$Path)
    try {
        if (Test-Path $Path) {
            return Get-ChildItem -Path $Path -Force -ErrorAction Stop
        }
    } catch { }
    return @()
}

function Safe-GetItemProperty {
    param([string]$RegPath)
    try {
        if (Test-Path $RegPath) {
            return Get-ItemProperty -Path $RegPath -ErrorAction Stop
        }
    } catch { }
    return $null
}

function Write-TextLine([string]$Path, [string]$Line) {
    $Line | Out-File -FilePath $Path -Append -Encoding $enc
}

# -----------------------------
# Collect: Startup folders
# -----------------------------
$rows = @()

# Current user startup folder (skip in SYSTEM)
if (-not $IsSystem) {
    $cuStartup = [Environment]::GetFolderPath("Startup")
    foreach ($item in (Safe-GetChildItem $cuStartup)) {
        $rows += New-Row -Category "StartupFolder" -Location "CurrentUser" `
            -Name $item.Name -Value $item.FullName -Source "FS"
    }
}

# All users startup folder
$allStartup = [Environment]::GetFolderPath("CommonStartup")
foreach ($item in (Safe-GetChildItem $allStartup)) {
    $rows += New-Row -Category "StartupFolder" -Location "AllUsers" `
        -Name $item.Name -Value $item.FullName -Source "FS"
}

# -----------------------------
# Collect: Registry Run keys
# -----------------------------
# HKCU Run (skip in SYSTEM)
if (-not $IsSystem) {
    $hkcuRun = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $cuProps = Safe-GetItemProperty $hkcuRun
    if ($cuProps) {
        foreach ($p in $cuProps.PSObject.Properties) {
            if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
            $rows += New-Row -Category "RunKey" -Location "HKCU_Run" `
                -Name $p.Name -Value ([string]$p.Value) -Source "REG"
        }
    }
}

# HKLM Run
$hklmRun = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$lmProps = Safe-GetItemProperty $hklmRun
if ($lmProps) {
    foreach ($p in $lmProps.PSObject.Properties) {
        if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
        $rows += New-Row -Category "RunKey" -Location "HKLM_Run" `
            -Name $p.Name -Value ([string]$p.Value) -Source "REG"
    }
}

# Normalize / sort
$rows = $rows | Sort-Object Key, Value

# Write current snapshot
$rows | Export-Csv -Path $currentPath -NoTypeInformation -Encoding UTF8

# -----------------------------
# Baseline logic
# -----------------------------
$baselineExists = Test-Path $baselinePath

if ($UpdateBaseline -or -not $baselineExists) {
    $rows | Export-Csv -Path $baselinePath -NoTypeInformation -Encoding UTF8
    Write-Output ("Baseline written to: {0}" -f $baselinePath)
    Write-Output ("Current snapshot written to: {0}" -f $currentPath)
    Write-Output ("Context note written to: {0}" -f $notePath)
    exit 0
}

# -----------------------------
# Drift detection
# -----------------------------
try {
    $baseline = Import-Csv -Path $baselinePath
} catch {
    Write-Error ("Failed to read baseline CSV: {0}" -f $baselinePath)
    exit 1
}

$baseByKey = @{}
foreach ($b in $baseline) { $baseByKey[$b.Key] = $b }

$curByKey = @{}
foreach ($c in $rows) { $curByKey[$c.Key] = $c }

$added = @()
$removed = @()
$changed = @()

foreach ($k in $curByKey.Keys) {
    if (-not $baseByKey.ContainsKey($k)) {
        $added += $curByKey[$k]
        continue
    }
    if ($baseByKey[$k].Value -ne $curByKey[$k].Value) {
        $changed += [pscustomobject]@{
            Key      = $k
            Category = $curByKey[$k].Category
            Location = $curByKey[$k].Location
            Name     = $curByKey[$k].Name
            OldValue = $baseByKey[$k].Value
            NewValue = $curByKey[$k].Value
        }
    }
}

foreach ($k in $baseByKey.Keys) {
    if (-not $curByKey.ContainsKey($k)) {
        $removed += $baseByKey[$k]
    }
}

$hasDrift = ($added.Count -gt 0 -or $removed.Count -gt 0 -or $changed.Count -gt 0)

if (-not $hasDrift) {
    Write-Output ("No drift detected. Current snapshot: {0}" -f $currentPath)
    Write-Output ("Context note: {0}" -f $notePath)
    exit 0
}

Write-TextLine $diffPath ("Drift detected: {0}" -f (Get-Date))
Write-TextLine $diffPath ("Current:  {0}" -f $currentPath)
Write-TextLine $diffPath ("Baseline: {0}" -f $baselinePath)
Write-TextLine $diffPath ("Context:  {0}" -f $notePath)
Write-TextLine $diffPath ""

if ($added.Count -gt 0) {
    Write-TextLine $diffPath "ADDED:"
    foreach ($a in $added) {
        Write-TextLine $diffPath (" + {0} | {1}" -f $a.Key, $a.Value)
    }
    Write-TextLine $diffPath ""
}

if ($removed.Count -gt 0) {
    Write-TextLine $diffPath "REMOVED:"
    foreach ($r in $removed) {
        Write-TextLine $diffPath (" - {0} | {1}" -f $r.Key, $r.Value)
    }
    Write-TextLine $diffPath ""
}

if ($changed.Count -gt 0) {
    Write-TextLine $diffPath "CHANGED:"
    foreach ($c in $changed) {
        Write-TextLine $diffPath (" * {0} | {1} -> {2}" -f $c.Key, $c.OldValue, $c.NewValue)
    }
    Write-TextLine $diffPath ""
}

Write-Output ("Drift written to: {0}" -f $diffPath)
Write-Output ("Context note: {0}" -f $notePath)
exit 0