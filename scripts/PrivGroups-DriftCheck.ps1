<#
  PrivGroups-DriftCheck.ps1
  Read-only: snapshots privileged local groups and compares to a baseline.

  Compatibility note:
  - Older baseline CSVs may use headers like GroupName/Name/MemberSID.
  - This version normalizes rows so we don't crash under StrictMode.

  Output:
    - Current CSV snapshot:   PrivGroups_<timestamp>.csv
    - Diff TXT report:        PrivGroups_Diff_<timestamp>.txt
    - Diff JSON (structured): PrivGroups_Diff_<timestamp>.json
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "C:\Scripts\Reports",
    [string]$BaselineDir = "",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $BaselineDir -or $BaselineDir.Trim() -eq "") {
    $BaselineDir = Join-Path (Split-Path $OutputDir -Parent) "baseline"
}

$reportRoot  = $OutputDir
$baselineDir = $BaselineDir
$timestamp   = Get-Date -Format 'yyyyMMdd_HHmm'

$currentCsv  = Join-Path $reportRoot ("PrivGroups_{0}.csv" -f $timestamp)
$diffTxt     = Join-Path $reportRoot ("PrivGroups_Diff_{0}.txt" -f $timestamp)
$diffJson    = Join-Path $reportRoot ("PrivGroups_Diff_{0}.json" -f $timestamp)
$baselineCsv = Join-Path $baselineDir 'PrivGroups.csv'

New-Item -ItemType Directory -Path $reportRoot  -Force | Out-Null
New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null

$groups = @(
    'Administrators',
    'Remote Desktop Users',
    'Backup Operators',
    'Power Users'
)

function Safe-Count {
    param($Obj)
    try {
        return (@($Obj)).Count
    } catch {
        try { return ($Obj | Measure-Object).Count } catch { return 0 }
    }
}

function Get-PropValue {
    param(
        [Parameter(Mandatory=$true)] $Obj,
        [Parameter(Mandatory=$true)] [string[]] $Names
    )
    foreach ($n in $Names) {
        $p = $Obj.PSObject.Properties[$n]
        if ($null -ne $p) {
            return $p.Value
        }
    }
    return $null
}

function Normalize-CsvRow {
    param(
        [Parameter(Mandatory=$true)] $Row
    )

    $g = Get-PropValue -Obj $Row -Names @('Group','GroupName','LocalGroup','GroupDisplayName')
    $m = Get-PropValue -Obj $Row -Names @('MemberName','Name','Member','Account','User')
    $sid = Get-PropValue -Obj $Row -Names @('SID','MemberSID','Sid','MemberSid')
    $objClass = Get-PropValue -Obj $Row -Names @('ObjectClass','Class','Type')
    $src = Get-PropValue -Obj $Row -Names @('PrincipalSource','Source','Origin')

    if (-not $g) { $g = "" }
    if (-not $m) { $m = "" }
    if (-not $sid) { $sid = "" }
    if (-not $objClass) { $objClass = "" }
    if (-not $src) { $src = "" }

    $id = $sid
    if (-not $id -or $id.Trim() -eq "") { $id = $m }

    [pscustomobject]@{
        Group           = [string]$g
        MemberName      = [string]$m
        ObjectClass     = [string]$objClass
        PrincipalSource = [string]$src
        SID             = [string]$sid
        Key             = ("{0}|{1}" -f $g, $id)
    }
}

function Normalize-MemberRow {
    param(
        [string]$Group,
        $Member
    )

    $name   = $null
    $obj    = $null
    $src    = $null
    $sidVal = $null

    try { $name = $Member.Name } catch {}
    try { $obj  = $Member.ObjectClass } catch {}
    try { $src  = $Member.PrincipalSource } catch {}
    try { if ($Member.SID) { $sidVal = $Member.SID.Value } } catch {}

    if (-not $name) { $name = "" }
    if (-not $obj)  { $obj  = "" }
    if (-not $src)  { $src  = "" }
    if (-not $sidVal) { $sidVal = "" }

    $id = $sidVal
    if (-not $id -or $id.Trim() -eq "") { $id = $name }

    [pscustomobject]@{
        Group           = $Group
        MemberName      = $name
        ObjectClass     = $obj
        PrincipalSource = $src
        SID             = $sidVal
        Key             = ("{0}|{1}" -f $Group, $id)
    }
}

# ---- Collect current membership ----
$rows = @()

foreach ($g in $groups) {
    $grp = Get-LocalGroup -Name $g -ErrorAction SilentlyContinue
    if (-not $grp) { continue }

    try {
        $members = Get-LocalGroupMember -Group $g -ErrorAction Stop
        foreach ($m in $members) {
            if ($null -eq $m) { continue }
            $r = Normalize-MemberRow -Group $g -Member $m
            if ($r.MemberName -and $r.MemberName.Trim() -ne "") {
                $rows += $r
            }
        }
    } catch {
        $rows += [pscustomobject]@{
            Group           = $g
            MemberName      = ("ERROR: {0}" -f $_.Exception.Message)
            ObjectClass     = ""
            PrincipalSource = ""
            SID             = ""
            Key             = ("{0}|ERROR" -f $g)
        }
    }
}

$rows = $rows | Sort-Object Group, MemberName, SID -Unique

# Write current snapshot (CSV without Key)
$rows | Select-Object Group, MemberName, ObjectClass, PrincipalSource, SID |
    Export-Csv -Path $currentCsv -NoTypeInformation -Encoding UTF8

# If no baseline exists, create it
if (-not (Test-Path $baselineCsv)) {
    $rows | Select-Object Group, MemberName, ObjectClass, PrincipalSource, SID |
        Export-Csv -Path $baselineCsv -NoTypeInformation -Encoding UTF8

    "Baseline created at: $baselineCsv" | Out-File -FilePath $diffTxt -Encoding UTF8
    "No drift (baseline created)."      | Out-File -FilePath $diffTxt -Append -Encoding UTF8

    $payload = [pscustomobject]@{
        generated       = (Get-Date).ToString("o")
        baselineCreated = $true
        baselinePath    = $baselineCsv
        currentPath     = $currentCsv
        driftDetected   = $false
        added           = @()
        removed         = @()
        current         = ($rows | Select-Object Group, MemberName, ObjectClass, PrincipalSource, SID)
    }
    $payload | ConvertTo-Json -Depth 6 | Out-File -FilePath $diffJson -Encoding UTF8

    Write-Output $diffTxt
    exit 0
}

# ---- Load baseline + compute diff (normalize legacy CSV columns) ----
$baseRaw = Import-Csv -Path $baselineCsv
$currRaw = Import-Csv -Path $currentCsv

$base = @($baseRaw | ForEach-Object { Normalize-CsvRow $_ }) | Where-Object { $_.Group -and $_.MemberName }
$curr = @($currRaw | ForEach-Object { Normalize-CsvRow $_ }) | Where-Object { $_.Group -and $_.MemberName }

function To-KeyedMap {
    param($list)
    $map = @{}
    foreach ($x in @($list)) {
        $k = $x.Key
        if (-not $k) { continue }
        if (-not $map.ContainsKey($k)) { $map[$k] = $x }
    }
    return $map
}

$baseMap = To-KeyedMap $base
$currMap = To-KeyedMap $curr

$addedKeys   = @()
$removedKeys = @()

foreach ($k in $currMap.Keys) {
    if (-not $baseMap.ContainsKey($k)) { $addedKeys += $k }
}
foreach ($k in $baseMap.Keys) {
    if (-not $currMap.ContainsKey($k)) { $removedKeys += $k }
}

$added   = @($addedKeys   | Sort-Object | ForEach-Object { $currMap[$_] })
$removed = @($removedKeys | Sort-Object | ForEach-Object { $baseMap[$_] })

$drift = (Safe-Count $added) -gt 0 -or (Safe-Count $removed) -gt 0

# ---- Write TXT ----
if (-not $drift) {
    "No drift detected." | Out-File -FilePath $diffTxt -Encoding UTF8
} else {
    "Privileged Group Drift Detected" | Out-File -FilePath $diffTxt -Encoding UTF8
    ("Generated: {0}" -f (Get-Date))  | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    ("Baseline:  {0}" -f $baselineCsv)| Out-File -FilePath $diffTxt -Append -Encoding UTF8
    ("Current:   {0}" -f $currentCsv) | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    "" | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    ("Added:   {0}" -f (Safe-Count $added))   | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    ("Removed: {0}" -f (Safe-Count $removed)) | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    "" | Out-File -FilePath $diffTxt -Append -Encoding UTF8

    function Write-Section {
        param(
            [string]$Title,
            $Items
        )
        ("==== {0} ====" -f $Title) | Out-File -FilePath $diffTxt -Append -Encoding UTF8

        $n = Safe-Count $Items
        if ($n -eq 0) {
            " (none)" | Out-File -FilePath $diffTxt -Append -Encoding UTF8
            "" | Out-File -FilePath $diffTxt -Append -Encoding UTF8
            return
        }

        @($Items) | Sort-Object Group, MemberName, SID | Group-Object Group | ForEach-Object {
            ("[{0}]" -f $_.Name) | Out-File -FilePath $diffTxt -Append -Encoding UTF8
            foreach ($i in @($_.Group)) {
                $sid = $i.SID
                if (-not $sid) { $sid = "" }
                (" - {0}  {1}" -f $i.MemberName, $sid) | Out-File -FilePath $diffTxt -Append -Encoding UTF8
            }
            "" | Out-File -FilePath $diffTxt -Append -Encoding UTF8
        }
    }

    Write-Section -Title "ADDED MEMBERS"   -Items $added
    Write-Section -Title "REMOVED MEMBERS" -Items $removed

    "==== CURRENT MEMBERS (post-run) ====" | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    @($curr) | Sort-Object Group, MemberName, SID | Group-Object Group | ForEach-Object {
        ("[{0}]" -f $_.Name) | Out-File -FilePath $diffTxt -Append -Encoding UTF8
        foreach ($i in @($_.Group)) {
            $sid = $i.SID
            if (-not $sid) { $sid = "" }
            (" - {0}  {1}" -f $i.MemberName, $sid) | Out-File -FilePath $diffTxt -Append -Encoding UTF8
        }
        "" | Out-File -FilePath $diffTxt -Append -Encoding UTF8
    }
}

# ---- Write JSON for UI parsing ----
$payload = [pscustomobject]@{
    generated     = (Get-Date).ToString("o")
    baselinePath  = $baselineCsv
    currentPath   = $currentCsv
    driftDetected = $drift
    added         = (@($added)   | Select-Object Group, MemberName, ObjectClass, PrincipalSource, SID)
    removed       = (@($removed) | Select-Object Group, MemberName, ObjectClass, PrincipalSource, SID)
    current       = (@($curr)    | Select-Object Group, MemberName, ObjectClass, PrincipalSource, SID)
}
$payload | ConvertTo-Json -Depth 6 | Out-File -FilePath $diffJson -Encoding UTF8

Write-Output $diffTxt
exit 0