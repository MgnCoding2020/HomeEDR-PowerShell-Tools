<#
  Cert-ExpiryMonitor.ps1 (Home EDR Dashboard)
  Purpose:
    Read-only certificate expiry report for common Windows certificate stores.

  Outputs:
    - CSV: Certs_Expiring_<Nd>_<yyyyMMdd_HHmm>.csv  (detail)
    - TXT: Certs_Expiring_<Nd>_<yyyyMMdd_HHmm>.txt  (summary)

  Behavior:
    - Includes certs expiring within ThresholdDays OR already expired.
    - Generates a human-readable summary so Beacon can surface what matters.
    - Conservative: only highlights actionable items (private key, personal/machine usage stores).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [int]$ThresholdDays = 30,

    [switch]$IncludeUserStores
)

# -------------------------------
# Setup output folder + filenames
# -------------------------------
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$stamp  = Get-Date -Format 'yyyyMMdd_HHmm'
$outCsv = Join-Path $OutputDir ("Certs_Expiring_{0}d_{1}.csv" -f $ThresholdDays, $stamp)
$outTxt = Join-Path $OutputDir ("Certs_Expiring_{0}d_{1}.txt" -f $ThresholdDays, $stamp)
$enc    = "utf8"

# -------------------------------
# Stores to scan
# -------------------------------
$storesToScan = @(
    'My',
    'WebHosting',
    'Remote Desktop',
    'TrustedPublisher',
    'TrustedPeople',
    'AuthRoot',
    'CA',
    'Root'
)

# -------------------------------
# Helpers: extract EKUs and SANs
# -------------------------------
function Get-EkuText {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    try {
        $ekuExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
        if ($ekuExt) {
            $eku = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ekuExt, $false)
            return ($eku.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName }) -join '; '
        }
    } catch { }
    return ''
}

function Get-SanText {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    try {
        $sanExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
        if ($sanExt) {
            return $sanExt.Format($true) -replace "`r`n", '; ' -replace '\s+', ' '
        }
    } catch { }
    return ''
}

# -------------------------------
# Core: read a store and return expiring certs
# -------------------------------
function Get-StoreResults {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('LocalMachine','CurrentUser')]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$StoreName
    )

    $path = "Cert:\$Scope\$StoreName"
    if (-not (Test-Path $path)) { return @() }

    $now = Get-Date
    $items = @()

    foreach ($c in (Get-ChildItem -Path $path -ErrorAction SilentlyContinue)) {
        $days = [int]([Math]::Floor(($c.NotAfter - $now).TotalDays))

        $status =
            if ($c.NotAfter -lt $now) { 'Expired' }
            elseif ($days -le $ThresholdDays) { 'ExpiringSoon' }
            else { 'OK' }

        if ($status -eq 'OK') { continue }

        $eku = Get-EkuText -Cert $c
        $san = Get-SanText -Cert $c

        $hasPrivKey = $false
        try { $hasPrivKey = $c.HasPrivateKey } catch { }

        $items += [pscustomobject]@{
            StoreScope     = $Scope
            StoreName      = $StoreName
            Subject        = $c.Subject
            Issuer         = $c.Issuer
            NotBefore      = $c.NotBefore
            NotAfter       = $c.NotAfter
            DaysToExpire   = $days
            Status         = $status
            Thumbprint     = $c.Thumbprint
            FriendlyName   = $c.FriendlyName
            HasPrivateKey  = $hasPrivKey
            EnhancedKeyUse = $eku
            SubjectAltName = $san
        }
    }

    return $items
}

# -------------------------------
# Build full result set
# -------------------------------
$results = @()

foreach ($s in $storesToScan) {
    $results += Get-StoreResults -Scope 'LocalMachine' -StoreName $s
}

if ($IncludeUserStores) {
    foreach ($s in $storesToScan) {
        $results += Get-StoreResults -Scope 'CurrentUser' -StoreName $s
    }
}

# -------------------------------
# Output CSV (detail)
# -------------------------------
$columns = @(
    'StoreScope','StoreName','Subject','Issuer','NotBefore','NotAfter',
    'DaysToExpire','Status','Thumbprint','FriendlyName','HasPrivateKey',
    'EnhancedKeyUse','SubjectAltName'
)

if ($results -and $results.Count -gt 0) {
    $results |
        Sort-Object Status, StoreScope, StoreName, DaysToExpire |
        Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
} else {
    ($columns -join ',') | Out-File -FilePath $outCsv -Encoding UTF8
}

# -------------------------------
# Output TXT (summary for Beacon)
# -------------------------------
$now = Get-Date

"Home EDR Dashboard - Certificate Expiry Summary" | Out-File $outTxt -Encoding $enc
("Generated: {0}" -f $now) | Out-File $outTxt -Append -Encoding $enc
("ThresholdDays: {0}" -f $ThresholdDays) | Out-File $outTxt -Append -Encoding $enc
("IncludeUserStores: {0}" -f ([bool]$IncludeUserStores)) | Out-File $outTxt -Append -Encoding $enc
("CSV Detail: {0}" -f $outCsv) | Out-File $outTxt -Append -Encoding $enc
"" | Out-File $outTxt -Append -Encoding $enc

if (-not $results -or $results.Count -eq 0) {
    "Result: OK" | Out-File $outTxt -Append -Encoding $enc
    "" | Out-File $outTxt -Append -Encoding $enc
    ("No certificates found expiring within {0} days." -f $ThresholdDays) | Out-File $outTxt -Append -Encoding $enc
    ("Empty CSV written to: {0}" -f $outCsv) | Out-File $outTxt -Append -Encoding $enc
    Write-Output ("No certificates found expiring within {0} days. Reports written to: {1} , {2}" -f $ThresholdDays, $outTxt, $outCsv)
    exit 0
}

# Actionability rules:
# - Private key certs are usually actionable (service/client auth)
# - Stores that tend to matter more: My, WebHosting, Remote Desktop, TrustedPublisher, TrustedPeople
$importantStores = @('My','WebHosting','Remote Desktop','TrustedPublisher','TrustedPeople')

$expSoon = $results | Where-Object { $_.Status -eq 'ExpiringSoon' }
$expired = $results | Where-Object { $_.Status -eq 'Expired' }

$expSoonPriv = $expSoon | Where-Object { $_.HasPrivateKey -eq $true }
$expiredPriv = $expired | Where-Object { $_.HasPrivateKey -eq $true }

$expSoonImportant = $expSoon | Where-Object { $importantStores -contains $_.StoreName }
$expiredImportant = $expired | Where-Object { $importantStores -contains $_.StoreName }

# Determine a conservative overall result
$resultLevel = "Review"
if (($expSoonPriv.Count -eq 0) -and ($expiredPriv.Count -eq 0) -and ($expSoonImportant.Count -eq 0)) {
    # Most noise: expired trust anchors without private keys
    $resultLevel = "OK"
} elseif ($expSoonPriv.Count -gt 0) {
    $resultLevel = "Needs attention"
}

("Result: {0}" -f $resultLevel) | Out-File $outTxt -Append -Encoding $enc
"" | Out-File $outTxt -Append -Encoding $enc

("Summary counts:") | Out-File $outTxt -Append -Encoding $enc
("  ExpiringSoon: {0}" -f $expSoon.Count) | Out-File $outTxt -Append -Encoding $enc
("  Expired:      {0}" -f $expired.Count) | Out-File $outTxt -Append -Encoding $enc
("  WithPrivateKey (ExpiringSoon): {0}" -f $expSoonPriv.Count) | Out-File $outTxt -Append -Encoding $enc
("  WithPrivateKey (Expired):      {0}" -f $expiredPriv.Count) | Out-File $outTxt -Append -Encoding $enc
"" | Out-File $outTxt -Append -Encoding $enc

# Human-readable interpretation
if ($resultLevel -eq "OK") {
    "What it means:" | Out-File $outTxt -Append -Encoding $enc
    "  No certificates with private keys are expiring soon within the threshold window." | Out-File $outTxt -Append -Encoding $enc
    "  Many entries may be expired trust anchors/intermediates present in the store; these are often legacy or unused." | Out-File $outTxt -Append -Encoding $enc
    "" | Out-File $outTxt -Append -Encoding $enc
    "When to care:" | Out-File $outTxt -Append -Encoding $enc
    "  If you rely on VPN/Wi-Fi EAP, RDP, IIS/WebHosting, or client certificate auth, private-key certificates matter most." | Out-File $outTxt -Append -Encoding $enc
    "" | Out-File $outTxt -Append -Encoding $enc
    "Suggested next step(s):" | Out-File $outTxt -Append -Encoding $enc
    "  No action needed for typical home use." | Out-File $outTxt -Append -Encoding $enc
    "  Avoid deleting root certificates manually; Windows updates manage trust stores." | Out-File $outTxt -Append -Encoding $enc
} elseif ($resultLevel -eq "Review") {
    "What it means:" | Out-File $outTxt -Append -Encoding $enc
    "  Some certificates are expiring soon or are expired, but none clearly indicate an active private-key certificate risk." | Out-File $outTxt -Append -Encoding $enc
    "" | Out-File $outTxt -Append -Encoding $enc
    "Suggested next step(s):" | Out-File $outTxt -Append -Encoding $enc
    "  If you use VPN/Wi-Fi EAP/RDP/IIS or client-auth certs, review the 'Actionable candidates' below." | Out-File $outTxt -Append -Encoding $enc
    "  Otherwise, no action needed." | Out-File $outTxt -Append -Encoding $enc
} else {
    "What it means:" | Out-File $outTxt -Append -Encoding $enc
    "  One or more certificates with a private key are expiring soon. These can impact authentication or services." | Out-File $outTxt -Append -Encoding $enc
    "" | Out-File $outTxt -Append -Encoding $enc
    "Suggested next step(s):" | Out-File $outTxt -Append -Encoding $enc
    "  Identify what uses the certificate (VPN/Wi-Fi auth, RDP, IIS, code signing, etc.)." | Out-File $outTxt -Append -Encoding $enc
    "  Renew/replace via the owning application or IT process." | Out-File $outTxt -Append -Encoding $enc
}

"" | Out-File $outTxt -Append -Encoding $enc
"Actionable candidates (top 15):" | Out-File $outTxt -Append -Encoding $enc

$actionable = @()
$actionable += $expSoonPriv
$actionable += ($expSoonImportant | Where-Object { $_.HasPrivateKey -ne $true })

$actionable |
    Sort-Object DaysToExpire |
    Select-Object -First 15 StoreScope, StoreName, Status, DaysToExpire, FriendlyName, Subject, NotAfter, HasPrivateKey |
    Format-Table -AutoSize | Out-String | Out-File $outTxt -Append -Encoding $enc

"" | Out-File $outTxt -Append -Encoding $enc
"Advanced notes (for savvy users):" | Out-File $outTxt -Append -Encoding $enc
"  - Many expired Root/AuthRoot entries are legacy and not necessarily 'active' problems." | Out-File $outTxt -Append -Encoding $enc
"  - If you need deeper inspection, use certmgr.msc or certlm.msc and verify which certs have private keys." | Out-File $outTxt -Append -Encoding $enc
"  - Avoid deleting trust anchors unless you understand the impact." | Out-File $outTxt -Append -Encoding $enc

Write-Output ("Certificate expiry reports written to: {0} (summary) and {1} (detail)" -f $outTxt, $outCsv)
exit 0
