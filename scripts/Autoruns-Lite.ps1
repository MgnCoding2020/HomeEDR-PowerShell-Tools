<#
  Autoruns-Lite.ps1 (read-only, no admin required)

  IMPORTANT SCHEDULER CHANGE (v1.5+):
  - When run as SYSTEM (LocalSystem), HKCU does NOT represent the signed-in user.
    In that mode we skip HKCU autoruns and "Current User" startup locations and write a clear NOTE.
  - This keeps results accurate and avoids confusing false negatives.

  Outputs (to -OutputDir):
    - AutorunsLite_yyyyMMdd_HHmmss.txt
    - AutorunsLite_yyyyMMdd_HHmmss.csv
    - AutorunsLite_yyyyMMdd_HHmmss.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# -------------------------
# Output paths
# -------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$outTxt  = Join-Path $OutputDir ("AutorunsLite_{0}.txt" -f $stamp)
$outCsv  = Join-Path $OutputDir ("AutorunsLite_{0}.csv" -f $stamp)
$outJson = Join-Path $OutputDir ("AutorunsLite_{0}.json" -f $stamp)

function Write-Line([string]$s) { $s | Out-File -FilePath $outTxt -Append -Encoding utf8 }

# -------------------------
# Context detection
# -------------------------
function Test-IsSystemContext {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($id -and $id.User -and $id.User.Value -eq "S-1-5-18") { return $true }
    } catch {}
    return $false
}
$IsSystem = Test-IsSystemContext

Write-Line "Beacon Autoruns-lite (read-only)"
Write-Line ("Generated: {0}" -f (Get-Date))
Write-Line ("OutputDir: {0}" -f $OutputDir)
Write-Line ("RunAs: {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name))
Write-Line ""

if ($IsSystem) {
    Write-Line "NOTE: This run is executing as SYSTEM (LocalSystem)."
    Write-Line "      HKCU/CurrentUser autoruns do not represent your user account in SYSTEM mode."
    Write-Line "      HKCU autoruns + CurrentUser startup folder checks are skipped for accuracy."
    Write-Line ""
}

function Expand-EnvVars([string]$s) {
    if (-not $s) { return $s }
    try { return [Environment]::ExpandEnvironmentVariables($s) } catch { return $s }
}

function Get-FirstPathFromCommand([string]$cmd) {
    if (-not $cmd) { return $null }
    $c = Expand-EnvVars $cmd
    $c = $c.Trim()

    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $tok = ($c -split '\s+')[0]
    return $tok.Trim('"')
}

function Is-UserWritablePath([string]$path) {
    if (-not $path) { return $false }
    $p = $path.ToLowerInvariant()

    # If SYSTEM, env:USERPROFILE points to systemprofile. We still treat user locations as user-writable,
    # but we avoid mislabeling the SYSTEM profile path as "user writable".
    if ($IsSystem) {
        if ($p -like "c:\users\*") { return $true }
        if ($p -like "$env:temp*") { return $true }
        if ($p -like "c:\windows\temp*") { return $true }
        if ($p -like "c:\programdata\*") { return $true }
        return $false
    }

    if ($p -like "$env:USERPROFILE*") { return $true }
    if ($p -like "c:\users\*") { return $true }
    if ($p -like "$env:TEMP*") { return $true }
    if ($p -like "c:\windows\temp*") { return $true }
    if ($p -like "c:\programdata\*") { return $true }
    return $false
}

function Get-Publisher([string]$exePath) {
    if (-not $exePath) { return "" }
    if (-not (Test-Path $exePath)) { return "" }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
            $m = [regex]::Match($sig.SignerCertificate.Subject, 'CN=([^,]+)')
            if ($m.Success) { return $m.Groups[1].Value }
            return $sig.SignerCertificate.Subject
        }
    } catch {}
    return ""
}

function Get-SignatureStatus([string]$exePath) {
    if (-not $exePath) { return "" }
    if (-not (Test-Path $exePath)) { return "MissingFile" }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status) { return [string]$sig.Status }
    } catch {}
    return ""
}

function Risk-Tag([string]$exePath, [string]$publisher, [string]$sigStatus) {
    $tags = @()

    if (-not $exePath) { $tags += "UnknownPath" }
    elseif (-not (Test-Path $exePath)) { $tags += "MissingTarget" }

    if (Is-UserWritablePath $exePath) { $tags += "UserWritablePath" }
    if (-not $publisher -or $publisher.Trim().Length -eq 0) { $tags += "NoPublisher" }
    if ($sigStatus -and $sigStatus -ne "Valid") { $tags += ("Sig:" + $sigStatus) }

    if ($tags.Count -eq 0) { return "OK" }
    return ($tags -join ",")
}

try {
    $items = New-Object System.Collections.Generic.List[object]

    # -------------------------
    # Registry autoruns
    # -------------------------
    $regLocations = @(
        @{ Scope="HKCU"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";        Kind="Run" },
        @{ Scope="HKCU"; Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce";    Kind="RunOnce" },
        @{ Scope="HKLM"; Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Run";        Kind="Run" },
        @{ Scope="HKLM"; Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce";    Kind="RunOnce" },
        @{ Scope="HKLM"; Path="HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";     Kind="Run32" },
        @{ Scope="HKLM"; Path="HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"; Kind="RunOnce32" }
    )

    if ($IsSystem) {
        $regLocations = $regLocations | Where-Object { $_.Scope -ne "HKCU" }
    }

    foreach ($loc in $regLocations) {
        $path = $loc.Path
        if (-not (Test-Path $path)) { continue }

        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
            $cmd = [string]$p.Value
            if (-not $cmd) { continue }

            $exe = Get-FirstPathFromCommand $cmd
            $pub = Get-Publisher $exe
            $sig = Get-SignatureStatus $exe
            $risk = Risk-Tag $exe $pub $sig

            $items.Add([pscustomobject]@{
                SourceScope   = $loc.Scope
                Location      = $path
                Name          = $p.Name
                Command       = $cmd
                TargetPath    = $exe
                Publisher     = $pub
                Signature     = $sig
                Risk          = $risk
                Kind          = $loc.Kind
            }) | Out-Null
        }
    }

    # -------------------------
    # Startup folders
    # -------------------------
    $startupFolders = @()

    if (-not $IsSystem) {
        $startupFolders += [pscustomobject]@{ Scope="CurrentUser"; Path=[Environment]::GetFolderPath("Startup") }
    }
    $startupFolders += [pscustomobject]@{ Scope="AllUsers"; Path=[Environment]::GetFolderPath("CommonStartup") }

    foreach ($sf in $startupFolders) {
        if (-not (Test-Path $sf.Path)) { continue }
        Get-ChildItem -Path $sf.Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $target = $_.FullName
            $pub = Get-Publisher $target
            $sig = Get-SignatureStatus $target
            $risk = Risk-Tag $target $pub $sig

            $items.Add([pscustomobject]@{
                SourceScope   = $sf.Scope
                Location      = $sf.Path
                Name          = $_.Name
                Command       = $target
                TargetPath    = $target
                Publisher     = $pub
                Signature     = $sig
                Risk          = $risk
                Kind          = "StartupFolder"
            }) | Out-Null
        }
    }

    $arr = $items | Sort-Object Kind, SourceScope, Name

    # Write summary
    Write-Line ("Total autorun entries: {0}" -f ($arr | Measure-Object).Count)
    Write-Line ""

    # Write files
    $arr | Export-Csv -Path $outCsv -NoTypeInformation -Encoding utf8
    $arr | ConvertTo-Json -Depth 5 | Out-File -FilePath $outJson -Encoding utf8

    Write-Line ("CSV:  {0}" -f $outCsv)
    Write-Line ("JSON: {0}" -f $outJson)
    Write-Line ""
    Write-Line "Done."
    exit 0
}
catch {
    Write-Line ""
    Write-Line "ERROR:"
    Write-Line $_.Exception.Message
    exit 1
}