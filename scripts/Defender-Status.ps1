<#
  Defender-Status.ps1 (read-only, best-effort)

  ASCII-safe output to avoid encoding/parser issues.

  Outputs (to -OutputDir):
    - DefenderStatus_yyyyMMdd_HHmmss.txt
    - DefenderStatus_yyyyMMdd_HHmmss.json

  Exit behavior:
    - exits 0 as long as it can write the TXT report
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = (Join-Path (Get-Location) "reports")
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Ensure output dir exists; fall back to TEMP if needed
try {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
} catch {
    $OutputDir = $env:TEMP
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$outTxt  = Join-Path $OutputDir ("DefenderStatus_{0}.txt" -f $stamp)
$outJson = Join-Path $OutputDir ("DefenderStatus_{0}.json" -f $stamp)

function Write-Line([string]$s) {
    $s | Out-File -FilePath $outTxt -Append -Encoding utf8
}

function Has-Command([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    return ($null -ne $cmd)
}

# Write header immediately so we always have a report
Write-Line "Windows Defender / Security Status (read-only)"
Write-Line ("Generated: {0}" -f (Get-Date))
Write-Line ("OutputDir: {0}" -f $OutputDir)
Write-Line ""

$result = [ordered]@{
    generated = (Get-Date).ToString("s")
    mp_status = $null
    mp_prefs  = $null
    securitycenter_av = @()
    recent_threats = @()
    notes = @()
}

# Defender status
if (Has-Command "Get-MpComputerStatus") {
    try { $result.mp_status = Get-MpComputerStatus } catch { $result.notes += ("Get-MpComputerStatus error: " + $_.Exception.Message) }
} else {
    $result.notes += "Defender cmdlets not available (Get-MpComputerStatus missing)."
}

# Defender preferences (subset)
if (Has-Command "Get-MpPreference") {
    try {
        $pref = Get-MpPreference
        $result.mp_prefs = [ordered]@{
            DisableRealtimeMonitoring = $pref.DisableRealtimeMonitoring
            DisableBehaviorMonitoring = $pref.DisableBehaviorMonitoring
            DisableIOAVProtection     = $pref.DisableIOAVProtection
            DisableScriptScanning     = $pref.DisableScriptScanning
            MAPSReporting             = $pref.MAPSReporting
            SubmitSamplesConsent      = $pref.SubmitSamplesConsent
            PUAProtection             = $pref.PUAProtection
            ExclusionPath             = $pref.ExclusionPath
        }
    } catch {
        $result.notes += ("Get-MpPreference error: " + $_.Exception.Message)
    }
} else {
    $result.notes += "Defender cmdlets not available (Get-MpPreference missing)."
}

# Recent threats (best-effort)
if (Has-Command "Get-MpThreatDetection") {
    try {
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue
        if ($threats) {
            $recent = $threats | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20
            foreach ($t in $recent) {
                $result.recent_threats += [ordered]@{
                    ThreatName = $t.ThreatName
                    SeverityID = $t.SeverityID
                    ActionSuccess = $t.ActionSuccess
                    InitialDetectionTime = $t.InitialDetectionTime
                    Resources = $t.Resources
                }
            }
        }
    } catch {
        $result.notes += ("Get-MpThreatDetection error: " + $_.Exception.Message)
    }
} else {
    $result.notes += "Defender cmdlets not available (Get-MpThreatDetection missing)."
}

# Security Center AV products (WMI)
try {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    if ($av) {
        foreach ($p in $av) {
            $result.securitycenter_av += [ordered]@{
                displayName = $p.displayName
                pathToSignedProductExe = $p.pathToSignedProductExe
                productState = $p.productState
                timestamp = $p.timestamp
            }
        }
    } else {
        $result.notes += "SecurityCenter2 returned no AV products (may be restricted)."
    }
} catch {
    $result.notes += ("SecurityCenter2 query error: " + $_.Exception.Message)
}

# Human-readable summary
if ($result.mp_status) {
    $s = $result.mp_status

    $sigAgeHours = $null
    try {
        $sigAge = (New-TimeSpan -Start $s.AntivirusSignatureLastUpdated -End (Get-Date))
        $sigAgeHours = [int]$sigAge.TotalHours
    } catch { }

    $headline = "Everything looks good"
    $status = "OK"

    if ($s.AntivirusEnabled -eq $false) { $headline = "Antivirus not enabled"; $status = "Needs attention" }
    elseif ($s.RealTimeProtectionEnabled -eq $false) { $headline = "Real-time protection is OFF"; $status = "Needs attention" }
    elseif ($sigAgeHours -ne $null -and $sigAgeHours -gt 72) { $headline = "Signatures may be out of date"; $status = "Review" }

    Write-Line ("Status: {0} - {1}" -f $status, $headline)
    Write-Line ""
    Write-Line "Key signals:"
    Write-Line ("  - AntivirusEnabled: {0}" -f $s.AntivirusEnabled)
    Write-Line ("  - RealTimeProtectionEnabled: {0}" -f $s.RealTimeProtectionEnabled)
    Write-Line ("  - BehaviorMonitorEnabled: {0}" -f $s.BehaviorMonitorEnabled)
    Write-Line ("  - IoavProtectionEnabled: {0}" -f $s.IoavProtectionEnabled)
    Write-Line ("  - NISEnabled: {0}" -f $s.NISEnabled)
    Write-Line ("  - AMServiceEnabled: {0}" -f $s.AMServiceEnabled)
    Write-Line ("  - EngineVersion: {0}" -f $s.AMEngineVersion)
    Write-Line ("  - SigVersion: {0}" -f $s.AntivirusSignatureVersion)
    Write-Line ("  - SigLastUpdated: {0}" -f $s.AntivirusSignatureLastUpdated)
    if ($sigAgeHours -ne $null) { Write-Line ("  - SigAgeHours: {0}" -f $sigAgeHours) }
    Write-Line ""
} else {
    Write-Line "Status: Review - Defender status API not available in this context."
    Write-Line ""
}

if ($result.securitycenter_av.Count -gt 0) {
    Write-Line "Security Center AV products detected:"
    foreach ($p in $result.securitycenter_av) {
        Write-Line ("  - {0} (state={1})" -f $p.displayName, $p.productState)
    }
    Write-Line ""
}

if ($result.recent_threats.Count -gt 0) {
    Write-Line "Recent Defender detections (top 20):"
    foreach ($t in $result.recent_threats) {
        Write-Line ("  - {0} SeverityID={1} ActionSuccess={2} Time={3}" -f $t.ThreatName, $t.SeverityID, $t.ActionSuccess, $t.InitialDetectionTime)
    }
    Write-Line ""
} else {
    Write-Line "Recent Defender detections: none (or not accessible)."
    Write-Line ""
}

if ($result.mp_prefs) {
    Write-Line "Selected preferences (best-effort):"
    Write-Line ("  - PUAProtection: {0}" -f $result.mp_prefs.PUAProtection)
    Write-Line ("  - MAPSReporting: {0}" -f $result.mp_prefs.MAPSReporting)
    Write-Line ("  - SubmitSamplesConsent: {0}" -f $result.mp_prefs.SubmitSamplesConsent)
    Write-Line ("  - DisableRealtimeMonitoring: {0}" -f $result.mp_prefs.DisableRealtimeMonitoring)
    Write-Line ("  - DisableScriptScanning: {0}" -f $result.mp_prefs.DisableScriptScanning)
    Write-Line ""
}

if ($result.notes.Count -gt 0) {
    Write-Line "Notes:"
    foreach ($n in $result.notes) { Write-Line ("  - {0}" -f $n) }
    Write-Line ""
}

# JSON (best-effort)
try { ($result | ConvertTo-Json -Depth 7) | Out-File -FilePath $outJson -Encoding utf8 } catch { }

Write-Line "Reports written:"
Write-Line ""
Write-Line ("  - TXT:  {0}" -f $outTxt)
Write-Line ("  - JSON: {0}" -f $outJson)

exit 0
