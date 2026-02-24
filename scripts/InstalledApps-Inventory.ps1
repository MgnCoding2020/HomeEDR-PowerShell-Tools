<#
  InstalledApps-Inventory.ps1
  Home EDR Dashboard - Installed Apps Inventory (read-only)

  IMPORTANT SCHEDULER CHANGE (v1.5+):
  - When run as SYSTEM (LocalSystem), HKCU does NOT represent the signed-in user.
    In that mode, HKCU uninstall keys are skipped (even if -IncludeUserInstalls is true),
    and we clearly explain that in the TXT summary.

  Outputs (timestamped, written to -OutputDir):
    - InstalledAppsInventory_yyyyMMdd_HHmmss.csv   (detail)
    - InstalledAppsInventory_yyyyMMdd_HHmmss.txt   (summary for Tool Info)
    - InstalledAppsInventory_yyyyMMdd_HHmmss.json  (structured future UI)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [switch]$IncludeUserInstalls = $true,

    [switch]$IncludeAppx = $true,

    # Kept for backward compatibility with existing callers/UI
    [switch]$Force
)

function Test-IsSystemContext {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($id -and $id.User -and $id.User.Value -eq "S-1-5-18") { return $true }
    } catch {}
    return $false
}
$IsSystem = Test-IsSystemContext

# ---- Output paths ----
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outCsv = Join-Path $OutputDir ("InstalledAppsInventory_{0}.csv" -f $stamp)
$outTxt = Join-Path $OutputDir ("InstalledAppsInventory_{0}.txt" -f $stamp)
$outJson = Join-Path $OutputDir ("InstalledAppsInventory_{0}.json" -f $stamp)
$enc = "utf8"

"Beacon Installed Apps Inventory (read-only)" | Out-File $outTxt -Encoding $enc
("Generated: {0}" -f (Get-Date))            | Out-File $outTxt -Append -Encoding $enc
("RunAs: {0}" -f ([Security.Principal.WindowsIdentity]::GetCurrent().Name)) | Out-File $outTxt -Append -Encoding $enc
"" | Out-File $outTxt -Append -Encoding $enc

# ---- Registry paths ----
$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

if ($IncludeUserInstalls) {
    if ($IsSystem) {
        "NOTE: Running as SYSTEM (LocalSystem). HKCU uninstall entries do not represent your user account." | Out-File $outTxt -Append -Encoding $enc
        "      Skipping HKCU user installs for accuracy in SYSTEM mode." | Out-File $outTxt -Append -Encoding $enc
        "" | Out-File $outTxt -Append -Encoding $enc
        $IncludeUserInstalls = $false
    } else {
        $regPaths += 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    }
}

# ---- "System-ish" heuristics: used only to reduce noise in the summary ----
$publisherWhitelist = @(
    'Microsoft','Intel','NVIDIA','AMD','Realtek','Broadcom','Dell','HP','Lenovo',
    'Synaptics','Logitech','Apple'
)
$protectedKeywords = @(
    'Windows','Microsoft','Intel','NVIDIA','AMD','Realtek','Update','Service Pack',
    'Driver','Runtime','Redistributable','Framework','Security','Defender'
)

function Get-UninstallEntriesFromPath([string]$path) {
    $items = @()
    try {
        Get-ChildItem -Path $path -ErrorAction Stop | ForEach-Object {
            try {
                $p = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                if ($p.DisplayName -and $p.DisplayName.Trim() -ne "") {
                    $items += [pscustomobject]@{
                        Name            = $p.DisplayName
                        Version         = $p.DisplayVersion
                        Publisher       = $p.Publisher
                        InstallDate     = $p.InstallDate
                        InstallLocation = $p.InstallLocation
                        UninstallString = $p.UninstallString
                        Source          = $path
                    }
                }
            } catch {}
        }
    } catch {}
    return $items
}

$all = @()
foreach ($rp in $regPaths) {
    $all += Get-UninstallEntriesFromPath $rp
}

# ---- Appx packages (optional) ----
$appx = @()
if ($IncludeAppx) {
    try {
        $appx = Get-AppxPackage -ErrorAction Stop | Select-Object Name, Version, Publisher, InstallLocation
    } catch {
        $appx = @()
    }
}

# ---- Deduplicate (by name+version) ----
$dedup = @{}
foreach ($a in $all) {
    $k = ($a.Name + "|" + $a.Version)
    if (-not $dedup.ContainsKey($k)) { $dedup[$k] = $a }
}
$apps = $dedup.Values | Sort-Object Name

# ---- Write CSV ----
$apps | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

# ---- Build summary ----
$total = ($apps | Measure-Object).Count
("Total classic installs (registry): {0}" -f $total) | Out-File $outTxt -Append -Encoding $enc

# Basic "protected/system-ish" filter for summary
function Is-Systemish($row) {
    if ($row.Publisher) {
        foreach ($p in $publisherWhitelist) {
            if ($row.Publisher -like "*$p*") { return $true }
        }
    }
    foreach ($k in $protectedKeywords) {
        if ($row.Name -like "*$k*") { return $true }
    }
    return $false
}

$thirdParty = $apps | Where-Object { -not (Is-Systemish $_) }
("Third-party (heuristic): {0}" -f (($thirdParty | Measure-Object).Count)) | Out-File $outTxt -Append -Encoding $enc
"" | Out-File $outTxt -Append -Encoding $enc

"Top 25 third-party installs (heuristic):" | Out-File $outTxt -Append -Encoding $enc
$thirdParty | Select-Object -First 25 | ForEach-Object {
    (" - {0}  {1}" -f $_.Name, $(if ($null -ne $_.Version) { $_.Version } else { "" })) | Out-File $outTxt -Append -Encoding $enc
}

# ---- Appx summary ----
if ($IncludeAppx) {
    "" | Out-File $outTxt -Append -Encoding $enc
    ("Appx packages: {0}" -f (($appx | Measure-Object).Count)) | Out-File $outTxt -Append -Encoding $enc
}

# ---- JSON output (future UI) ----
$payload = [pscustomobject]@{
    generated = (Get-Date).ToString("o")
    run_as    = ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    is_system = $IsSystem
    registry_apps = $apps
    appx_packages = $appx
}
$payload | ConvertTo-Json -Depth 6 | Out-File -FilePath $outJson -Encoding UTF8

Write-Output $outTxt
exit 0