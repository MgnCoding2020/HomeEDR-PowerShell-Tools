<#
.SYNOPSIS
Generates CONTROL_EVIDENCE.md from controls/nist-800-53-control-map.yaml

.DESCRIPTION
- Reads your NIST 800-53 mapping YAML
- Looks for matching artifacts in the repo (based on output_path + artifact_pattern)
- Produces a portfolio-friendly CONTROL_EVIDENCE.md table
- Works best on PowerShell 7+ (ConvertFrom-Yaml)
- Includes a lightweight fallback YAML parser for your current simple structure
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$MapPath  = (Join-Path $PSScriptRoot "nist-800-53-control-map.yaml"),
    [string]$OutPath  = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "CONTROL_EVIDENCE.md"),
    [switch]$FailIfMissingArtifacts
)

function Read-MapYaml {
    param([string]$Path)

    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop

    # Preferred: PowerShell 7+ supports ConvertFrom-Yaml
    if (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue) {
        return ($raw | ConvertFrom-Yaml)
    }

    # Fallback parser for the simple shape you're using:
    # CONTROL:
    #   name:
    #   description:
    #   evidence:
    #     - script:
    #       output_path:
    #       artifact_pattern:
    $map = @{}
    $currentControl = $null
    $inEvidence = $false
    $currentEvidence = $null
    $evidenceList = @()

    foreach ($line in ($raw -split "`n")) {
        $l = ($line -replace "`r","")

        if ($l -match '^\s*#') { continue }
        if ($l -match '^\s*$') { continue }

        # New control key (e.g. AU-6:)
        if ($l -match '^\s*([A-Z]{2}-\d+)\s*:\s*$') {
            if ($currentControl) {
                if ($evidenceList.Count -gt 0) { $map[$currentControl]['evidence'] = $evidenceList }
            }
            $currentControl = $Matches[1]
            $map[$currentControl] = @{}
            $evidenceList = @()
            $inEvidence = $false
            $currentEvidence = $null
            continue
        }

        if (-not $currentControl) { continue }

        if ($l -match '^\s*name\s*:\s*(.+)\s*$') {
            $map[$currentControl]['name'] = $Matches[1].Trim()
            continue
        }

        if ($l -match '^\s*description\s*:\s*(.+)\s*$') {
            $map[$currentControl]['description'] = $Matches[1].Trim()
            continue
        }

        if ($l -match '^\s*evidence\s*:\s*$') {
            $inEvidence = $true
            continue
        }

        if ($inEvidence -and ($l -match '^\s*-\s*script\s*:\s*(.+)\s*$')) {
            $currentEvidence = @{
                script = $Matches[1].Trim()
            }
            $evidenceList += $currentEvidence
            continue
        }

        if ($inEvidence -and $currentEvidence -and ($l -match '^\s*output_path\s*:\s*(.+)\s*$')) {
            $currentEvidence['output_path'] = $Matches[1].Trim()
            continue
        }

        if ($inEvidence -and $currentEvidence -and ($l -match '^\s*artifact_pattern\s*:\s*(.+)\s*$')) {
            $currentEvidence['artifact_pattern'] = $Matches[1].Trim()
            continue
        }
    }

    if ($currentControl) {
        if ($evidenceList.Count -gt 0) { $map[$currentControl]['evidence'] = $evidenceList }
    }

    return $map
}

function Find-Artifacts {
    param(
        [string]$BaseDir,
        [string]$Pattern
    )

    if (-not (Test-Path $BaseDir)) { return @() }

    # Support patterns like "Services_Drift_*.csv"
    return Get-ChildItem -Path $BaseDir -File -Recurse -Filter $Pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
}

Write-Host "RepoRoot: $RepoRoot"
Write-Host "MapPath : $MapPath"

$map = Read-MapYaml -Path $MapPath

# Markdown header
$md = @()
$md += "# Control Evidence Matrix (NIST 800-53)"
$md += ""
$md += "This file is auto-generated from `controls/nist-800-53-control-map.yaml`."
$md += ""
$md += "| Control | Control Name | Evidence Script | Evidence Artifacts Found |"
$md += "|---|---|---|---|"

$missing = @()

foreach ($controlKey in ($map.Keys | Sort-Object)) {
    $control = $map[$controlKey]
    $controlName = $control.name
    $evidence = $control.evidence

    if (-not $evidence) {
        $md += "| $controlKey | $controlName | _(none mapped)_ | _(none)_ |"
        continue
    }

    foreach ($e in $evidence) {
        $script = $e.script
        $outRel = $e.output_path
        $pattern = $e.artifact_pattern

        $outDir = Join-Path $RepoRoot $outRel
        $found = Find-Artifacts -BaseDir $outDir -Pattern $pattern

        if ($found.Count -eq 0) {
            $artifactText = "**0 found** (`$outRel$pattern`)"
            $missing += "$controlKey -> $outRel$pattern"
        } else {
            # Show up to 3 newest artifacts (as repo-relative links)
            $top = $found | Select-Object -First 3
            $links = @()
            foreach ($f in $top) {
                $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\','/')
                $rel = $rel -replace '\\','/'
                $links += "[${($f.Name)}]($rel)"
            }
            $artifactText = "$($found.Count) found: " + ($links -join ", ")
        }

        $md += "| $controlKey | $controlName | `$script` | $artifactText |"
    }
}


Set-Content -Path $OutPath -Value ($md -join "`n") -Encoding UTF8
Write-Host "Wrote: $OutPath"

if ($FailIfMissingArtifacts -and $missing.Count -gt 0) {
    Write-Error ("Missing artifacts for:`n- " + ($missing -join "`n- "))
    exit 1
}

exit 0
