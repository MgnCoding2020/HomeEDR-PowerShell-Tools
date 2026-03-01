<#
.SYNOPSIS
  Generates CONTROL_EVIDENCE.md from controls/nist-800-53-control-map.yaml.

.DESCRIPTION
  Reads a simple NIST 800-53 control-to-evidence mapping file and produces a markdown table.

  Two modes:
  - Default: search each entry's output_path (snapshots/, alerts/, etc.)
  - Portfolio/CI (-UseSampleOutput): search sample-output/ recursively (great for GitHub Actions)

.NOTES
  This script is intentionally "simple YAML" compatible.
  It supports the specific mapping structure used in this repo.
#>

[CmdletBinding()]
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$MapPath  = (Join-Path $PSScriptRoot "nist-800-53-control-map.yaml"),
  [string]$OutPath  = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "CONTROL_EVIDENCE.md"),
  [switch]$FailIfMissingArtifacts,
  [switch]$UseSampleOutput
)

# Markdown inline-code delimiter (literal backtick char)
$bt = "`"

function Find-Artifacts {
  <#
    Searches one or more directories (recursively) for files matching a pattern.
    Returns newest-first results.
  #>
  param(
    [string[]]$SearchDirs,
    [string]$Pattern
  )

  $results = @()

  foreach ($dir in $SearchDirs) {
    if (-not (Test-Path $dir)) { continue }
    $results += Get-ChildItem -Path $dir -File -Recurse -Filter $Pattern -ErrorAction SilentlyContinue
  }

  $results | Sort-Object LastWriteTime -Descending
}

function Read-MapYamlSimple {
  <#
    Minimal YAML reader for this repo's simple structure.

    Supports:
      AU-6:
        name: ...
        description: ...
        evidence:
          - script: ...
            output_path: ...
            artifact_pattern: ...
  #>
  param([string]$Path)

  $lines = Get-Content -Path $Path -ErrorAction Stop

  $map = @{}
  $currentControl = $null
  $inEvidence = $false
  $currentEvidence = $null

  foreach ($line in $lines) {
    # normalize line endings just in case
    $l = $line

    # skip blanks and comments
    if ($l -match '^\s*$') { continue }
    if ($l -match '^\s*#') { continue }

    # Control key (e.g., AU-6:)
    if ($l -match '^\s*([A-Z]{2}-\d+)\s*:\s*$') {
      $currentControl = $Matches[1]
      $map[$currentControl] = @{
        name = ""
        description = ""
        evidence = @()
      }
      $inEvidence = $false
      $currentEvidence = $null
      continue
    }

    if (-not $currentControl) { continue }

    # name: ...
    if ($l -match '^\s*name\s*:\s*(.+)\s*$') {
      $map[$currentControl].name = $Matches[1].Trim()
      continue
    }

    # description: ...
    if ($l -match '^\s*description\s*:\s*(.+)\s*$') {
      $map[$currentControl].description = $Matches[1].Trim()
      continue
    }

    # evidence:
    if ($l -match '^\s*evidence\s*:\s*$') {
      $inEvidence = $true
      continue
    }

    # - script: ...
    if ($inEvidence -and ($l -match '^\s*-\s*script\s*:\s*(.+)\s*$')) {
      $currentEvidence = @{
        script = $Matches[1].Trim()
        output_path = ""
        artifact_pattern = ""
      }
      $map[$currentControl].evidence += $currentEvidence
      continue
    }

    if ($inEvidence -and $currentEvidence) {
      if ($l -match '^\s*output_path\s*:\s*(.+)\s*$') {
        $currentEvidence.output_path = $Matches[1].Trim()
        continue
      }
      if ($l -match '^\s*artifact_pattern\s*:\s*(.+)\s*$') {
        $currentEvidence.artifact_pattern = $Matches[1].Trim()
        continue
      }
    }
  }

  return $map
}

Write-Host "RepoRoot        : $RepoRoot"
Write-Host "MapPath         : $MapPath"
Write-Host "OutPath         : $OutPath"
Write-Host "UseSampleOutput : $UseSampleOutput"

$map = Read-MapYamlSimple -Path $MapPath

$sampleDir = Join-Path $RepoRoot "sample-output"
$usingSample = $UseSampleOutput -and (Test-Path $sampleDir)

# Build markdown
$md = @()
$md += "# Control Evidence Matrix (NIST 800-53)"
$md += ""
$md += "This file is auto-generated from `controls/nist-800-53-control-map.yaml`."
$md += ""
if ($usingSample) {
  $md += "> Mode: Portfolio demo (sample-output/)"
} else {
  $md += "> Mode: Repo paths (per YAML output_path)"
}
$md += ""
$md += "| Control | Control Name | Evidence Script | Evidence Artifacts Found |"
$md += "|---|---|---|---|"

$missing = @()

foreach ($controlKey in ($map.Keys | Sort-Object)) {
  $control = $map[$controlKey]
  $controlName = $control.name

  if (-not $control.evidence -or $control.evidence.Count -eq 0) {
    $md += "| $controlKey | $controlName | _(none mapped)_ | _(none)_ |"
    continue
  }

  foreach ($e in $control.evidence) {
    $script  = $e.script
    $outRel  = $e.output_path
    $pattern = $e.artifact_pattern

    # determine search locations
    $searchDirs = @()
    if ($usingSample) {
      $searchDirs = @($sampleDir)
      $searchedNote = "sample-output/**/$pattern"
    } else {
      $searchDirs = @((Join-Path $RepoRoot $outRel))
      $searchedNote = "$outRel$pattern"
    }

    $found = Find-Artifacts -SearchDirs $searchDirs -Pattern $pattern

    if (-not $found -or $found.Count -eq 0) {
      $artifactText = "**0 found** ($bt$searchedNote$bt)"
      $missing += "$controlKey -> $searchedNote"
    } else {
      # show up to 3 newest artifacts with clickable repo-relative links
      $top = $found | Select-Object -First 3

      $links = @()
      foreach ($f in $top) {
        $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\','/')
        $rel = $rel -replace '\\','/'
        $links += "[{0}]({1})" -f $f.Name, $rel
      }

      $artifactText = "{0} found: {1}" -f $found.Count, ($links -join ", ")
    }

    # inline-code formatting for the script name
    $md += "| $controlKey | $controlName | $bt$script$bt | $artifactText |"
  }
}

Set-Content -Path $OutPath -Value ($md -join "`n") -Encoding UTF8
Write-Host "Wrote: $OutPath"

if ($FailIfMissingArtifacts -and $missing.Count -gt 0) {
  Write-Error ("Missing artifacts for:`n- " + ($missing -join "`n- "))
  exit 1
}

exit 0
