<#
Hardware-Inventory.ps1 (PowerShell 5.1 compatible)
- NO '??' or '?:' operators
- Writes a sectioned TXT report into -OutputDir (defaults to ./reports)
- Best-effort inventory (read-only). Some fields depend on drivers / permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir = (Join-Path (Get-Location) "reports")
)

# -----------------------------
# Helpers
# -----------------------------
function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Force -Path $Path | Out-Null }
}

function Now-Stamp { (Get-Date).ToString("yyyyMMdd_HHmmss") }

# Null/empty coalesce for PS 5.1
function Coalesce2($a, $b) {
    if ($null -ne $a -and "$a".Trim().Length -gt 0) { return $a }
    return $b
}

function Safe-GetCim([string]$Class, [string]$Namespace = "root\cimv2") {
    try { return Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop }
    catch { return @() }
}

function Safe-Run([scriptblock]$Block) {
    try { & $Block } catch { }
}

# Writer helpers
$script:Lines = New-Object System.Collections.Generic.List[string]
function W([string]$s="") { $script:Lines.Add($s) | Out-Null }
function Section([string]$title) {
    W ""
    W ("=" * 80)
    W $title
    W ("=" * 80)
}

# -----------------------------
# Start
# -----------------------------
Ensure-Dir $OutputDir
$stamp = Now-Stamp
$reportPath = Join-Path $OutputDir ("Hardware_Inventory_{0}.txt" -f $stamp)

W "HARDWARE INVENTORY REPORT"
W ("Generated : {0}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
W ("Host      : {0}" -f $env:COMPUTERNAME)
W ("OutputDir : {0}" -f $OutputDir)

# -----------------------------
# SYSTEM SUMMARY
# -----------------------------
Section "SYSTEM SUMMARY"

$cs = (Safe-GetCim "Win32_ComputerSystem" | Select-Object -First 1)
$os = (Safe-GetCim "Win32_OperatingSystem" | Select-Object -First 1)

if ($cs) {
    W ("Computer Name : {0}" -f $env:COMPUTERNAME)
    W ("Manufacturer  : {0}" -f (Coalesce2 $cs.Manufacturer "Unknown"))
    W ("Model         : {0}" -f (Coalesce2 $cs.Model "Unknown"))
    if ($cs.TotalPhysicalMemory) {
        $gb = [Math]::Round(($cs.TotalPhysicalMemory / 1GB), 1)
        W ("Total RAM     : {0} GB" -f $gb)
    }
}

if ($os) {
    W ("OS Caption    : {0}" -f (Coalesce2 $os.Caption "Unknown"))
    W ("OS Build      : {0}" -f (Coalesce2 $os.BuildNumber "Unknown"))
    W ("OS Version    : {0}" -f (Coalesce2 $os.Version "Unknown"))
}

# -----------------------------
# BIOS / BASEBOARD
# -----------------------------
Section "BIOS / BASEBOARD"

$bios = (Safe-GetCim "Win32_BIOS" | Select-Object -First 1)
$bb   = (Safe-GetCim "Win32_BaseBoard" | Select-Object -First 1)

if ($bios) {
    W ("BIOS Vendor   : {0}" -f (Coalesce2 $bios.Manufacturer "Unknown"))
    W ("BIOS Version  : {0}" -f (Coalesce2 $bios.SMBIOSBIOSVersion $bios.Version))
    W ("BIOS Serial   : {0}" -f (Coalesce2 $bios.SerialNumber "Unknown"))
    if ($bios.ReleaseDate) {
        try {
            $dt = [Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate)
            W ("Release Date  : {0}" -f $dt.ToString())
        } catch { }
    }
}

if ($bb) {
    W ""
    W ("Board Vendor  : {0}" -f (Coalesce2 $bb.Manufacturer "Unknown"))
    W ("Board Product : {0}" -f (Coalesce2 $bb.Product "Unknown"))
    W ("Board Serial  : {0}" -f (Coalesce2 $bb.SerialNumber "Unknown"))
}

# -----------------------------
# SECURE BOOT / TPM (best-effort)
# -----------------------------
Section "SECURE BOOT / TPM (best-effort)"

Safe-Run {
    $tpm = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -ErrorAction Stop
    if ($tpm) {
        W ("TPM Present   : Yes")
        W ("TPM Enabled   : {0}" -f $tpm.IsEnabled_InitialValue)
        W ("TPM Activated : {0}" -f $tpm.IsActivated_InitialValue)
        W ("TPM Owned     : {0}" -f $tpm.IsOwned_InitialValue)
    }
}
Safe-Run {
    $sb = Confirm-SecureBootUEFI
    W ("Secure Boot   : {0}" -f $sb)
}

# -----------------------------
# CPU
# -----------------------------
Section "CPU"

$cpu = (Safe-GetCim "Win32_Processor" | Select-Object -First 1)
if ($cpu) {
    W ("Name          : {0}" -f (Coalesce2 $cpu.Name "Unknown"))
    W ("Cores         : {0}" -f (Coalesce2 $cpu.NumberOfCores "Unknown"))
    W ("Logical       : {0}" -f (Coalesce2 $cpu.NumberOfLogicalProcessors "Unknown"))
    W ("MaxClockMHz   : {0}" -f (Coalesce2 $cpu.MaxClockSpeed "Unknown"))
}

# -----------------------------
# GPU
# -----------------------------
Section "GPU"

$gpus = Safe-GetCim "Win32_VideoController"
if ($gpus.Count -eq 0) { W "No video controllers found." }
foreach ($g in $gpus) {
    W ("Name          : {0}" -f (Coalesce2 $g.Name "Unknown"))
    W ("PNPDeviceID   : {0}" -f (Coalesce2 $g.PNPDeviceID ""))
    W ("Driver Ver    : {0}" -f (Coalesce2 $g.DriverVersion ""))
    W ("Driver Date   : {0}" -f (Coalesce2 $g.DriverDate ""))
    W ("VideoMode     : {0}" -f (Coalesce2 $g.VideoModeDescription ""))
    if ($g.AdapterRAM) {
        $vramGB = [Math]::Round(($g.AdapterRAM / 1GB), 2)
        W ("AdapterRAM    : {0} GB" -f $vramGB)
    }
    W ""
}

# -----------------------------
# MEMORY MODULES (best-effort)
# -----------------------------
Section "MEMORY MODULES (best-effort)"

$mem = Safe-GetCim "Win32_PhysicalMemory"
if ($mem.Count -eq 0) { W "No memory module records found." }
foreach ($m in $mem) {
    $capGB = ""
    if ($m.Capacity) { $capGB = [Math]::Round(($m.Capacity / 1GB), 2) }
    W ("Slot          : {0}" -f (Coalesce2 $m.DeviceLocator ""))
    W ("Manufacturer  : {0}" -f (Coalesce2 $m.Manufacturer "Unknown"))
    W ("PartNumber    : {0}" -f (Coalesce2 $m.PartNumber ""))
    if ($capGB -ne "") { W ("Capacity      : {0} GB" -f $capGB) }
    W ("Speed         : {0}" -f (Coalesce2 $m.Speed ""))
    W ""
}

# -----------------------------
# DISKS (PHYSICAL)
# -----------------------------
Section "DISKS (PHYSICAL)"

$disks = Safe-GetCim "Win32_DiskDrive"
if ($disks.Count -eq 0) { W "No physical disks found." }
foreach ($d in $disks) {
    $sizeGB = ""
    if ($d.Size) { $sizeGB = [Math]::Round(($d.Size / 1GB), 1) }
    W ("Model         : {0}" -f (Coalesce2 $d.Model "Unknown"))
    W ("Interface     : {0}" -f (Coalesce2 $d.InterfaceType ""))
    if ($sizeGB -ne "") { W ("Size          : {0} GB" -f $sizeGB) }
    W ("Serial        : {0}" -f (Coalesce2 $d.SerialNumber ""))
    W ""
}

# -----------------------------
# VOLUMES
# -----------------------------
Section "VOLUMES"

$vols = Safe-GetCim "Win32_LogicalDisk"
if ($vols.Count -eq 0) { W "No logical disks found." }
foreach ($v in $vols) {
    if ($v.DriveType -ne 3) { continue } # local disks only
    $sizeGB = ""
    $freeGB = ""
    if ($v.Size)     { $sizeGB = [Math]::Round(($v.Size / 1GB), 1) }
    if ($v.FreeSpace){ $freeGB = [Math]::Round(($v.FreeSpace / 1GB), 1) }
    W ("Drive         : {0}" -f $v.DeviceID)
    W ("Label         : {0}" -f (Coalesce2 $v.VolumeName ""))
    if ($sizeGB -ne "") { W ("Size          : {0} GB" -f $sizeGB) }
    if ($freeGB -ne "") { W ("Free          : {0} GB" -f $freeGB) }
    W ("FileSystem    : {0}" -f (Coalesce2 $v.FileSystem ""))
    W ""
}

# -----------------------------
# NETWORK (ENABLED)
# -----------------------------
Section "NETWORK (ENABLED)"

$nets = Safe-GetCim "Win32_NetworkAdapter"
$enabled = @()
foreach ($n in $nets) { if ($n.NetEnabled -eq $true) { $enabled += $n } }

if ($enabled.Count -eq 0) { W "No enabled network adapters found." }
foreach ($n in $enabled) {
    W ("Name          : {0}" -f (Coalesce2 $n.Name "Unknown"))
    W ("Connection    : {0}" -f (Coalesce2 $n.NetConnectionID ""))
    W ("MAC           : {0}" -f (Coalesce2 $n.MACAddress ""))
    W ("Manufacturer  : {0}" -f (Coalesce2 $n.Manufacturer ""))
    W ("PNPDeviceID   : {0}" -f (Coalesce2 $n.PNPDeviceID ""))
    W ""
}

# -----------------------------
# AUDIO DEVICES
# -----------------------------
Section "AUDIO DEVICES"

$aud = Safe-GetCim "Win32_SoundDevice"
if ($aud.Count -eq 0) { W "No audio devices found." }
foreach ($a in $aud) {
    W ("Name          : {0}" -f (Coalesce2 $a.Name "Unknown"))
    W ("Manufacturer  : {0}" -f (Coalesce2 $a.Manufacturer "Unknown"))
    W ("Status        : {0}" -f (Coalesce2 $a.Status ""))
    W ("PNPDeviceID   : {0}" -f (Coalesce2 $a.PNPDeviceID ""))
    W ""
}

# -----------------------------
# MONITORS (PnP best-effort)
# -----------------------------
Section "MONITORS (EDID best-effort)"

$pnp = Safe-GetCim "Win32_PnPEntity"
$mons = @()
foreach ($m in $pnp) {
    if ($m.PNPClass -eq "Monitor" -or $m.Service -eq "monitor") { $mons += $m }
}
if ($mons.Count -eq 0) { W "No monitor PnP records found." }
foreach ($m in $mons) {
    W ("Name          : {0}" -f (Coalesce2 $m.Name (Coalesce2 $m.Caption "Monitor")))
    W ("PNPDeviceID   : {0}" -f (Coalesce2 $m.PNPDeviceID ""))
    W ("Manufacturer  : {0}" -f (Coalesce2 $m.Manufacturer ""))
    W ("Status        : {0}" -f (Coalesce2 $m.Status ""))
    W ""
}

# -----------------------------
# CONNECTED DEVICES (PnP count)
# -----------------------------
Section "CONNECTED DEVICES (PnP)"

if ($pnp.Count -gt 0) {
    W ("PnP records   : {0}" -f $pnp.Count)
    # Show a small sample only (keeps report sane)
    W ""
    W "Sample (first 30):"
    $i = 0
    foreach ($d in $pnp) {
        $i++
        if ($i -gt 30) { break }
        W (" - {0}" -f (Coalesce2 $d.Name (Coalesce2 $d.Caption "(device)")))
    }
} else {
    W "No PnP records found."
}

# -----------------------------
# SIGNED DRIVERS (best-effort)
# -----------------------------
Section "SIGNED DRIVERS (best-effort)"

$drv = Safe-GetCim "Win32_PnPSignedDriver"
if ($drv.Count -eq 0) { W "No signed driver records found." }
else {
    W ("Driver records: {0}" -f $drv.Count)
    W ""
    W "Sample (first 30):"
    $i = 0
    foreach ($d in $drv) {
        $i++
        if ($i -gt 30) { break }
        $dn = Coalesce2 $d.DeviceName (Coalesce2 $d.FriendlyName "(driver)")
        $ver = Coalesce2 $d.DriverVersion ""
        W (" - {0}  (v{1})" -f $dn, $ver)
    }
}

W ""
W "END OF REPORT"

$script:Lines | Set-Content -Encoding UTF8 -Path $reportPath
Write-Output $reportPath
exit 0
