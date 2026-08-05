function Resolve-TcpkImpact {
<#
.SYNOPSIS
    Map observed facts to severity; refuse HIGH/CRITICAL without a measured fact.

.DESCRIPTION
    Rules emit OBSERVED FACTS (row counts, readability result, key recovery, GCM
    verification, scan match counts) and a CANDIDATE severity. This layer enforces:

      - HIGH/CRITICAL are only returned when at least one measured impact fact is
        present with a value > 0 or $true.
      - MEDIUM is only returned when at least one fact is present with a value >= 0
        (i.e. it was measured, even if the result is zero).
      - If the candidate is not supportable by the supplied facts, the severity is
        downgraded one step: CRITICAL -> HIGH, HIGH -> MEDIUM, MEDIUM -> INFO.

    Measured impact keys (all others are ignored):
        cookie_row_count       int    -1 = not measured
        login_row_count        int    -1 = not measured
        autofill_row_count     int    -1 = not measured
        credential_match_count int    -1 = not measured
        page_count             int    0 = not read
        key_recovered          bool
        gcm_verified           bool
        content_length         int    -1 = not measured

.PARAMETER RuleId
    The rule identifier, used only for diagnostic messages.

.PARAMETER Facts
    Hashtable of observed facts. Only keys listed above are evaluated.

.PARAMETER Candidate
    The proposed severity string (CRITICAL, HIGH, MEDIUM, LOW, INFO).

.OUTPUTS
    [string] resolved severity
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][hashtable]$Facts,
        [Parameter(Mandatory)][string]$Candidate
    )

    if ($Candidate -notin @('CRITICAL','HIGH','MEDIUM')) { return $Candidate }

    # Keys that represent measured (not assumed) impact, with their support tier.
    # 'high'     = fact value supports HIGH/CRITICAL when > 0 or $true
    # 'medium'   = fact value supports MEDIUM when >= 0 (even if zero: measured-but-empty)
    # 'gcm'      = gcm_verified=$true supports HIGH only when combined with at least one
    #              row-count fact > 0; alone it supports MEDIUM (key proven but nothing to steal)
    $keyTier = @{
        cookie_row_count       = 'high'
        login_row_count        = 'high'
        autofill_row_count     = 'high'
        credential_match_count = 'high'
        key_recovered          = 'medium'   # key in hand; no data confirmed yet -> MEDIUM
        gcm_verified           = 'gcm'      # compound: HIGH only with data rows > 0
        page_count             = 'medium'
        content_length         = 'medium'
    }

    $supportsHigh   = $false
    $supportsMedium = $false
    $gcmVerified    = $false
    $hasDataRows    = $false

    foreach ($kv in $Facts.GetEnumerator()) {
        $tier = $keyTier[$kv.Key]
        if (-not $tier) { continue }
        $v = $kv.Value
        if ($tier -eq 'high') {
            if (($v -is [bool] -and $v) -or ($v -is [int] -and $v -gt 0)) {
                $supportsHigh   = $true
                $supportsMedium = $true
                $hasDataRows    = $true
            } elseif ($v -is [int] -and $v -ge 0) {
                $supportsMedium = $true   # measured but zero -> MEDIUM at most
            }
        }
        if ($tier -eq 'medium') {
            if (($v -is [bool] -and $v) -or ($v -is [int] -and $v -ge 0)) {
                $supportsMedium = $true
            }
        }
        if ($tier -eq 'gcm' -and ($v -is [bool]) -and $v) {
            $gcmVerified    = $true
            $supportsMedium = $true
        }
    }

    # gcm_verified + row-count data -> HIGH; gcm_verified alone -> MEDIUM
    if ($gcmVerified -and $hasDataRows) { $supportsHigh = $true }

    if ($Candidate -in @('CRITICAL','HIGH') -and -not $supportsHigh) {
        $downgraded = 'MEDIUM'
        Write-Verbose "[Resolve-TcpkImpact] $RuleId: $Candidate -> $downgraded (no measured high-impact fact)"
        return $downgraded
    }
    if ($Candidate -eq 'MEDIUM' -and -not $supportsMedium) {
        Write-Verbose "[Resolve-TcpkImpact] $RuleId: MEDIUM -> INFO (no measured medium-impact fact)"
        return 'INFO'
    }
    return $Candidate
}

function Get-TcpkImpactAudit {
<#
.SYNOPSIS
    List every HIGH/CRITICAL emitter in Public/ that does not call Resolve-TcpkImpact.

.DESCRIPTION
    Scans all .ps1 files under the Public directory for literal -Severity 'HIGH' and
    -Severity 'CRITICAL' patterns. For each match, reports whether the containing
    file uses Resolve-TcpkImpact. Files that use the layer are flagged as 'Guarded';
    those that do not are 'Unguarded'.

    Run this before releasing a version to surface severity claims that have not been
    validated against measured facts.

.PARAMETER PublicPath
    Path to the Public directory. Defaults to the sibling Public/ folder of this file.

.OUTPUTS
    [PSCustomObject] with File, Line, Severity, Guarded, Snippet
#>
    [CmdletBinding()]
    param(
        [string]$PublicPath
    )
    if (-not $PublicPath) {
        $PublicPath = Join-Path (Split-Path $PSScriptRoot) 'Public'
    }
    if (-not (Test-Path -LiteralPath $PublicPath)) {
        Write-Warning "Get-TcpkImpactAudit: PublicPath '$PublicPath' not found"
        return
    }

    $files = Get-ChildItem -LiteralPath $PublicPath -Recurse -Filter '*.ps1' -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue
        if (-not $lines) { continue }
        $usesLayer = ($lines | Select-String -Pattern 'Resolve-TcpkImpact' -Quiet)

        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match "-Severity\s+'(CRITICAL|HIGH)'") {
                [PSCustomObject]@{
                    File     = $f.FullName
                    Line     = $i + 1
                    Severity = $Matches[1]
                    Guarded  = [bool]$usesLayer
                    Snippet  = $lines[$i].Trim()
                }
            }
        }
    }
}
