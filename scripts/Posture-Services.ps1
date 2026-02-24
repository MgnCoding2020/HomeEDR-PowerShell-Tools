<#
  Posture-Services.ps1
  Home EDR Dashboard - Security Posture (Services)

  Collects (read-only):
    - Windows services with a focus on persistence
    - Captures service start type + binary path (ImagePath) for drift

  Baseline + Drift:
    Baseline:
      <BaselineDir>\Services_Baseline.csv
    Current:
      <OutputDir>\Posture_Services_<timestamp>.csv
    Diff (only if changed):
      <OutputDir>\Posture_Services_Diff_<timestamp>.txt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [Parameter(Mandatory = $true)]
    [string]$BaselineDir,

    [switch]$UpdateBaseline
)

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null

$enc = "utf8"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"

$baselinePath = Join-Path $BaselineDir "Services_Baseline.csv"
$currentPath  = Join-Path $OutputDir ("Posture_Services_{0}.csv" -f $stamp)
$diffPath     = Join-Path $OutputDir ("Posture_Services_Diff_{0}.txt" -f $stamp)

function Write-TextLine([string]$Path, [string]$Line) {
    $Line | Out-File -FilePath $Path -Append -Encoding $enc
}

function New-Row {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$Status,
        [string]$StartType,
        [string]$ImagePath
    )

    [pscustomobject]@{
        Key         = $Name
        Name        = $Name
        DisplayName = $DisplayName
        Status      = $Status
        StartType   = $StartType
        ImagePath   = $ImagePath
    }
}

# Collect services from CIM to reliably get the binary path
$rows = @()

try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop
} catch {
    Write-Error "Failed to query services via CIM. If this system restricts CIM, try running PowerShell as admin."
    exit 1
}

foreach ($s in $services) {
    $rows += New-Row `
        -Name $s.Name `
        -DisplayName ([string]$s.DisplayName) `
        -Status ([string]$s.State) `
        -StartType ([string]$s.StartMode) `
        -ImagePath ([string]$s.PathName)
}

$rows = $rows | Sort-Object Key
$rows | Export-Csv -Path $currentPath -NoTypeInformation -Encoding UTF8

# Baseline logic
$baselineExists = Test-Path $baselinePath
if ($UpdateBaseline -or -not $baselineExists) {
    $rows | Export-Csv -Path $baselinePath -NoTypeInformation -Encoding UTF8
    Write-Output ("Baseline written to: {0}" -f $baselinePath)
    Write-Output ("Current snapshot written to: {0}" -f $currentPath)
    exit 0
}

# Drift detection
try { $baseline = Import-Csv -Path $baselinePath } catch {
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

    $b = $baseByKey[$k]
    $c = $curByKey[$k]

    $diffFields = @()
    foreach ($field in @("StartType","ImagePath","Status")) {
        if ($b.$field -ne $c.$field) { $diffFields += $field }
    }

    if ($diffFields.Count -gt 0) {
        $changed += [pscustomobject]@{
            Key        = $k
            Name       = $c.Name
            DiffFields = ($diffFields -join ", ")
            OldStart   = $b.StartType
            NewStart   = $c.StartType
            OldPath    = $b.ImagePath
            NewPath    = $c.ImagePath
            OldStatus  = $b.Status
            NewStatus  = $c.Status
        }
    }
}

foreach ($k in $baseByKey.Keys) {
    if (-not $curByKey.ContainsKey($k)) {
        $removed += $baseByKey[$k]
    }
}

if (($added.Count + $removed.Count + $changed.Count) -gt 0) {
    "Home EDR Dashboard - Services Drift Report" | Out-File $diffPath -Encoding $enc
    Write-TextLine $diffPath ("Generated: {0}" -f (Get-Date))
    Write-TextLine $diffPath ("Baseline:  {0}" -f $baselinePath)
    Write-TextLine $diffPath ("Current:   {0}" -f $currentPath)

    Write-TextLine $diffPath ""
    Write-TextLine $diffPath ("Added:   {0}" -f $added.Count)
    Write-TextLine $diffPath ("Removed: {0}" -f $removed.Count)
    Write-TextLine $diffPath ("Changed: {0}" -f $changed.Count)

    if ($added.Count -gt 0) {
        Write-TextLine $diffPath ""
        Write-TextLine $diffPath "==== ADDED SERVICES ===="
        foreach ($a in $added) {
            Write-TextLine $diffPath ("{0} :: Start={1} :: Path={2}" -f $a.Name, $a.StartType, $a.ImagePath)
        }
    }

    if ($removed.Count -gt 0) {
        Write-TextLine $diffPath ""
        Write-TextLine $diffPath "==== REMOVED SERVICES ===="
        foreach ($r in $removed) {
            Write-TextLine $diffPath ("{0} :: Start={1} :: Path={2}" -f $r.Name, $r.StartType, $r.ImagePath)
        }
    }

    if ($changed.Count -gt 0) {
        Write-TextLine $diffPath ""
        Write-TextLine $diffPath "==== CHANGED SERVICES ===="
        foreach ($c in $changed) {
            Write-TextLine $diffPath ("{0} (fields: {1})" -f $c.Name, $c.DiffFields)
            Write-TextLine $diffPath ("  StartType: {0} -> {1}" -f $c.OldStart, $c.NewStart)
            Write-TextLine $diffPath ("  ImagePath: {0} -> {1}" -f $c.OldPath, $c.NewPath)
            Write-TextLine $diffPath ("  Status:    {0} -> {1}" -f $c.OldStatus, $c.NewStatus)
        }
    }

    Write-Output ("Drift detected. Diff written to: {0}" -f $diffPath)
}
else {
    Write-Output "No drift detected (current matches baseline)."
}

Write-Output ("Current snapshot written to: {0}" -f $currentPath)
exit 0