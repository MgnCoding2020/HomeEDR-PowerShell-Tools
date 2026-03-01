<#
.SYNOPSIS
  Generates CONTROL_EVIDENCE.md from controls/nist-800-53-control-map.yaml.

.DESCRIPTION
  This script reads a simple NIST 800-53 control-to-evidence mapping YAML, searches the repo
  for matching evidence artifacts, and generates a portfolio-friendly CONTROL_EVIDENCE.md table.

  Why this exists:
  - GRC / governance work often requires traceability: Control -> Evidence Script -> Evidence Artifact
  - This generator turns that mapping into a repeatable "evidence matrix" dashboard.

  Two operating modes:
  1) Default mode (local-style):
     - Searches each mapping's output_path (ex: snapshots/, alerts/) for artifacts.
  2) Portfolio / CI mode (-UseSampleOutput):
     - Searches sample-output/ recursively instead.
     - This makes GitHub Actions produce non-zero "found" counts using sanitized demo evidence.

.NOTES
  - PowerShell 7+ often supports ConvertFrom-Yaml. If unavailable, we use a lightweight fallback parser.
  - YAML structure is intentionally simple:
      AU-6:
        name: ...
        description: ...
        evidence:
          - script: ...
            output_path: ...
            artifact_pattern: ...
#>

[CmdletBinding()]
param(
  # Repo root defaults to one folder above /controls
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

  # YAML map path
  [string]$MapPath  = (Join-Path $PSScriptRoot "nist-800-53-control-map.yaml"),

  # Output markdown file
  [string]$OutPath  = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path "CONTROL_EVIDENCE.md"),

  # If set, fail the script if any mapped artifacts are missing (useful for stricter CI later)
  [switch]$FailIfMissingArtifacts,

  # If set, search sample-output/ for artifacts (best for portfolio + GitHub Actions runners)
  [switch]$UseSampleOutput
)

# Markdown inline-code delimiter (a literal backtick character)
$bt = "`"

function Read-MapYaml {
  param([string]$Path)

  $raw = Get-Content -Path $Path -Raw -ErrorAction Stop

  # Preferred: PowerShell 7.4+ includes ConvertFrom-Yaml.
  # Some environments may not have it, so we gracefully fallback.
  $convertFromYaml = Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue
  if ($convertFromYaml) {
    return ($raw | ConvertFrom-Yaml)
  }

  # Fallback YAML parser for the simple structure used in this project.
  # It is NOT a general-purpose YAML parser — it only supports the mapping style above.
  $map = @{}
  $currentControl = $null
  $inEvidence = $false
  $currentEvidence = $null
  $evidenceList = @()

  foreach ($line in ($raw -split "`n")) {
    $l = ($line -replace "`r", "")

    # Skip comments/blank lines
    if ($l -match '^\s*#') { continue }
    if ($l -match '^\s*$') { continue }

    # New control key (e.g., "AU-6:")
    if ($l -match '^\s*([A-Z]{2}-\d+)\s*:\s*$') {
      # Flush previous control's evidence list
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

    # name: ...
    if ($l -match '^\s*name\s*:\s*(.+)\s*$') {
      $map[$currentControl]['name'] = $Matches[1].Trim()
      continue
    }

    # description: ...
    if ($l -match '^\s*description\s*:\s*(.+)\s*$') {
      $map[$currentControl]['description'] = $Matches[1].Trim()
      continue
    }

    # evidence:
    if ($l -match '^\s*evidence\s*:\s*$') {
      $inEvidence = $true
      continue
    }

    # - script: ...
    if ($inEvidence -and ($l -match '^\s*-\s*script\s*:\s*(.+)\s*$')) {
      $currentEvidence = @{ script = $Matches[1].Trim() }
      $evidenceList += $currentEvidence
      continue
    }

    # output_path: ...
    if ($inEvidence -and $currentEvidence -and ($l -match '^\s*output_path\s*:\s*(.+)\s*$')) {
      $currentEvidence['output_path'] = $Matches[1].Trim()
      continue
    }

    # artifact_pattern: ...
    if ($inEvidence -and $currentEvidence -and ($l -match '^\s*artifact_pattern\s*:\s*(.+)\s*$')) {
      $currentEvidence['artifact_pattern'] = $Matches[1].Trim()
      continue
    }
  }

  # Flush last control
  if ($currentControl) {
    if ($evidenceList.Count -gt 0) { $map[$currentControl]['evidence'] = $evidenceList }
  }

  return $map
}

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

    # -Filter supports patterns like "Services_Drift_*.csv"
    $results += Get-ChildItem -Path $dir -File -Recurse -Filter $Pattern -ErrorAction SilentlyContinue
  }

  return $results | Sort-Object LastWriteTime -Descending
}

Write-Host "RepoRoot        : $RepoRoot"
Write-Host "MapPath         : $MapPath"
Write-Host "OutPath         : $OutPath"
Write-Host "UseSampleOutput : $UseSampleOutput"

$map = Read-MapYaml -Path $MapPath

# Decide where to search for artifacts.
# Default: search each control's configured output_path (snapshots/, alerts/, etc.)
# Portfolio/CI: search sample-output/ instead (so GitHub Actions can "find" your sanitized files).
$sampleDir = Join-Path $RepoRoot "sample-output"
$usingSample = $UseSampleOutput -and (Test-Path $sampleDir)

# Build Markdown output
$md = @()
$md += "# Control Evidence Matrix (NIST 800-53)"
$md += ""
$md += "This file is auto-generated from `controls/nist-800-53-control-map.yaml`."
$md += ""
if ($usingSample) {
  $md += "> Mode: Portfolio demo (`sample-output/`)"
} else {
  $md += "> Mode: Repo paths (per YAML `output_path`)"
}
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
    $script  = $e.script
    $outRel  = $e.output_path
    $pattern = $e.artifact_pattern

    # Determine search directories
    $searchDirs = @()
    if ($usingSample) {
      $searchDirs = @($sampleDir)
    } else {
      $outDir = Join-Path $RepoRoot $outRel
      $searchDirs = @($outDir)
    }

    $found = Find-Artifacts -SearchDirs $searchDirs -Pattern $pattern

    # Create a readable "searched location" note
    $searchedNote = if ($usingSample) {
      "sample-output/**/$pattern"
    } else {
      "$outRel$pattern"
    }

    if ($found.Count -eq 0) {
      $artifactText = "**0 found** ($bt$searchedNote$bt)"
      $missing += "$controlKey -> $searchedNote"
    } else {
      # Show up to 3 newest artifacts as clickable repo-relative links
      $top = $found | Select-Object -First 3

      $links = @()
      foreach ($f in $top) {
        $rel = $f.FullName.Substring($RepoRoot.Length).TrimStart('\','/')
        $rel = $rel -replace '\\','/'
        $links += "[{0}]({1})" -f $f.Name, $rel
      }

      $artifactText = "{0} found: {1}" -f $found.Count, ($links -join ", ")
    }

    # NOTE: We wrap $script in backticks *as code formatting*, not as escaped literal text.
    $md += "| $controlKey | $controlName | $bt$script$bt | $artifactText |"
  }
}

# Write the markdown file
Set-Content -Path $OutPath -Value ($md -join "`n") -Encoding UTF8
Write-Host "Wrote: $OutPath"

# Optional strictness for future CI
if ($FailIfMissingArtifacts -and $missing.Count -gt 0) {
  Write-Error ("Missing artifacts for:`n- " + ($missing -join "`n- "))
  exit 1
}

exit 0
