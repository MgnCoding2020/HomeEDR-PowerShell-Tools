<#
  Posture-ScheduledTasks.ps1
  Home EDR Dashboard - Security Posture (Scheduled Tasks)

  Collects (read-only):
    - Scheduled tasks and key properties
    - Action command + arguments (captures ALL actions, joined)
    - Principal context (RunAs + LogonType + RunLevel)
    - Useful for persistence detection (new tasks, changed actions)

  Baseline + Drift:
    Baseline:
      <BaselineDir>\ScheduledTasks_Baseline.csv
    Current:
      <OutputDir>\Posture_ScheduledTasks_<timestamp>.csv
    Diff (only if changed):
      <OutputDir>\Posture_ScheduledTasks_Diff_<timestamp>.txt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [Parameter(Mandatory = $true)]
    [string]$BaselineDir,

    [switch]$UpdateBaseline
)

# -----------------------------
# Setup
# -----------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null

$enc = "utf8"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"

$baselinePath = Join-Path $BaselineDir "ScheduledTasks_Baseline.csv"
$currentPath  = Join-Path $OutputDir ("Posture_ScheduledTasks_{0}.csv" -f $stamp)
$diffPath     = Join-Path $OutputDir ("Posture_ScheduledTasks_Diff_{0}.txt" -f $stamp)

function Write-TextLine([string]$Path, [string]$Line) {
    $Line | Out-File -FilePath $Path -Append -Encoding $enc
}

function New-Row {
    param(
        [string]$TaskPath,
        [string]$TaskName,
        [string]$State,
        [string]$Author,
        [string]$RunAs,
        [string]$LogonType,
        [string]$RunLevel,
        [string]$LastRunTime,
        [string]$NextRunTime,
        [string]$ActionExecute,
        [string]$ActionArguments
    )

    # Key identifies the task uniquely (path + name)
    $key = "{0}{1}" -f $TaskPath, $TaskName

    [pscustomobject]@{
        Key             = $key
        TaskPath        = $TaskPath
        TaskName        = $TaskName
        State           = $State
        Author          = $Author
        RunAs           = $RunAs
        LogonType       = $LogonType
        RunLevel        = $RunLevel
        LastRunTime     = $LastRunTime
        NextRunTime     = $NextRunTime
        ActionExecute   = $ActionExecute
        ActionArguments = $ActionArguments
    }
}

# -----------------------------
# Collect tasks
# -----------------------------
$rows = @()

$tasks = @()
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
} catch {
    Write-Error "Failed to query scheduled tasks. Try running PowerShell as admin if access is restricted."
    exit 1
}

foreach ($t in $tasks) {
    # Capture ALL actions (joined); many tasks have 1, but persistence can hide in additional actions.
    $execList = @()
    $argList  = @()

    try {
        if ($t.Actions) {
            foreach ($a in $t.Actions) {
                $ex = ""
                $ar = ""
                if ($a.PSObject.Properties.Name -contains "Execute")   { $ex = [string]$a.Execute }
                if ($a.PSObject.Properties.Name -contains "Arguments") { $ar = [string]$a.Arguments }
                if ($ex -or $ar) {
                    $execList += $ex
                    $argList  += $ar
                }
            }
        }
    } catch { }

    $exec = ($execList -join " | ")
    $args = ($argList  -join " | ")

    # Runtime info (best effort)
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }

    $lastRun = ""
    $nextRun = ""
    if ($info) {
        $lastRun = [string]$info.LastRunTime
        $nextRun = [string]$info.NextRunTime
    }

    # Principal context (best effort)
    $runAs = ""
    $logonType = ""
    $runLevel = ""

    try {
        if ($t.Principal) {
            if ($t.Principal.UserId)    { $runAs = [string]$t.Principal.UserId }
            if ($t.Principal.LogonType) { $logonType = [string]$t.Principal.LogonType }
            if ($t.Principal.RunLevel)  { $runLevel = [string]$t.Principal.RunLevel }
        }
    } catch { }

    # Author (best effort)
    $author = ""
    try {
        if ($t.RegistrationInfo -and $t.RegistrationInfo.Author) { $author = [string]$t.RegistrationInfo.Author }
    } catch { }

    $rows += New-Row `
        -TaskPath $t.TaskPath `
        -TaskName $t.TaskName `
        -State ([string]$t.State) `
        -Author $author `
        -RunAs $runAs `
        -LogonType $logonType `
        -RunLevel $runLevel `
        -LastRunTime $lastRun `
        -NextRunTime $nextRun `
        -ActionExecute $exec `
        -ActionArguments $args
}

$rows = $rows | Sort-Object Key, ActionExecute, ActionArguments
$rows | Export-Csv -Path $currentPath -NoTypeInformation -Encoding UTF8

# -----------------------------
# Baseline logic
# -----------------------------
$baselineExists = Test-Path $baselinePath

if ($UpdateBaseline -or -not $baselineExists) {
    $rows | Export-Csv -Path $baselinePath -NoTypeInformation -Encoding UTF8
    Write-Output ("Baseline written to: {0}" -f $baselinePath)
    Write-Output ("Current snapshot written to: {0}" -f $currentPath)
    exit 0
}

# -----------------------------
# Drift detection
# -----------------------------
$baseline = @()
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

    # High-signal persistence fields:
    $diffFields = @()
    foreach ($field in @("State","RunAs","LogonType","RunLevel","ActionExecute","ActionArguments")) {
        if ($b.$field -ne $c.$field) { $diffFields += $field }
    }

    if ($diffFields.Count -gt 0) {
        $changed += [pscustomobject]@{
            Key         = $k
            TaskPath    = $c.TaskPath
            TaskName    = $c.TaskName
            DiffFields  = ($diffFields -join ", ")
            OldExecute  = $b.ActionExecute
            NewExecute  = $c.ActionExecute
            OldArgs     = $b.ActionArguments
            NewArgs     = $c.ActionArguments
            OldRunAs    = $b.RunAs
            NewRunAs    = $c.RunAs
            OldLogon    = $b.LogonType
            NewLogon    = $c.LogonType
            OldRunLevel = $b.RunLevel
            NewRunLevel = $c.RunLevel
            OldState    = $b.State
            NewState    = $c.State
        }
    }
}

foreach ($k in $baseByKey.Keys) {
    if (-not $curByKey.ContainsKey($k)) {
        $removed += $baseByKey[$k]
    }
}

if (($added.Count + $removed.Count + $changed.Count) -gt 0) {
    "Home EDR Dashboard - Scheduled Tasks Drift Report" | Out-File $diffPath -Encoding $enc
    Write-TextLine $diffPath ("Generated: {0}" -f (Get-Date))
    Write-TextLine $diffPath ("Baseline:  {0}" -f $baselinePath)
    Write-TextLine $diffPath ("Current:   {0}" -f $currentPath)

    Write-TextLine $diffPath ""
    Write-TextLine $diffPath ("Added:   {0}" -f $added.Count)
    Write-TextLine $diffPath ("Removed: {0}" -f $removed.Count)
    Write-TextLine $diffPath ("Changed: {0}" -f $changed.Count)

    if ($added.Count -gt 0) {
        Write-TextLine $diffPath ""
        Write-TextLine $diffPath "==== ADDED TASKS ===="
        foreach ($a in $added) {
            Write-TextLine $diffPath ("{0}{1} :: {2} {3}" -f $a.TaskPath, $a.TaskName, $a.ActionExecute, $a.ActionArguments)
        }
    }

    if ($removed.Count -gt 0) {
        Write-TextLine $diffPath ""
        Write-TextLine $diffPath "==== REMOVED TASKS ===="
        foreach ($r in $removed) {
            Write-TextLine $diffPath ("{0}{1} :: {2} {3}" -f $r.TaskPath, $r.TaskName, $r.ActionExecute, $r.ActionArguments)
        }
    }

    if ($changed.Count -gt 0) {
        Write-TextLine $diffPath ""
        Write-TextLine $diffPath "==== CHANGED TASKS ===="
        foreach ($c in $changed) {
            Write-TextLine $diffPath ("{0}{1} (fields: {2})" -f $c.TaskPath, $c.TaskName, $c.DiffFields)
            Write-TextLine $diffPath ("  Execute:  {0} -> {1}" -f $c.OldExecute, $c.NewExecute)
            Write-TextLine $diffPath ("  Args:     {0} -> {1}" -f $c.OldArgs, $c.NewArgs)
            Write-TextLine $diffPath ("  RunAs:    {0} -> {1}" -f $c.OldRunAs, $c.NewRunAs)
            Write-TextLine $diffPath ("  LogonType:{0} -> {1}" -f $c.OldLogon, $c.NewLogon)
            Write-TextLine $diffPath ("  RunLevel: {0} -> {1}" -f $c.OldRunLevel, $c.NewRunLevel)
            Write-TextLine $diffPath ("  State:    {0} -> {1}" -f $c.OldState, $c.NewState)
        }
    }

    Write-Output ("Drift detected. Diff written to: {0}" -f $diffPath)
}
else {
    Write-Output "No drift detected (current matches baseline)."
}

Write-Output ("Current snapshot written to: {0}" -f $currentPath)
exit 0