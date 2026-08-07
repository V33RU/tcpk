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

.PARAMETER Log
    Optional [ref] to a List[string] or ArrayList. Each downgrade appends one line:
    "CAP1: {RuleId} {FROM}->{TO}; {reason}". Pass the same ref to accumulate entries
    from multiple calls. Append to finding.AdjustmentLog after the call.

.OUTPUTS
    [string] resolved severity
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][hashtable]$Facts,
        [Parameter(Mandatory)][string]$Candidate,
        [ref]$Log
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
        $reason = "no high-tier measured fact (facts supplied: $(($Facts.Keys | Sort-Object) -join ', '))"
        Write-Verbose "[Resolve-TcpkImpact] ${RuleId}: $Candidate -> $downgraded; $reason"
        if ($Log) { $Log.Value.Add("CAP1: ${RuleId} ${Candidate}->$downgraded; $reason") }
        return $downgraded
    }
    if ($Candidate -eq 'MEDIUM' -and -not $supportsMedium) {
        $reason = "no measured medium-impact fact"
        Write-Verbose "[Resolve-TcpkImpact] ${RuleId}: MEDIUM -> INFO; $reason"
        if ($Log) { $Log.Value.Add("CAP1: ${RuleId} MEDIUM->INFO; $reason") }
        return 'INFO'
    }
    return $Candidate
}

function Build-TcpkImpactSentences {
<#
.SYNOPSIS
    Build only the impact sentences for facts that were actually measured.

.DESCRIPTION
    CAP1 - a finding must not name a thing it did not verify is present.
    Pass the same facts hashtable from Resolve-TcpkImpact plus a template
    map.  Only facts that are truthy (bool true, int > 0, non-empty string)
    produce a sentence.  Facts with value 0 or $false are silently omitted -
    their noun does not appear in the description.

.PARAMETER Facts
    The observed-facts hashtable (same one passed to Resolve-TcpkImpact).

.PARAMETER Templates
    Hashtable mapping fact key -> scriptblock: {param($v) "sentence for $v"}.
    The scriptblock receives the measured value and returns a sentence string
    (or empty string / $null to suppress even when the fact is truthy).

.OUTPUTS
    [string[]] - one sentence per truthy fact, in Templates iteration order.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Facts,
        [Parameter(Mandatory)][hashtable]$Templates
    )
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($kv in $Templates.GetEnumerator()) {
        $v = $Facts[$kv.Key]
        if ($null -eq $v) { continue }
        $truthy = ($v -is [bool] -and $v) -or
                  ($v -is [int]  -and $v -gt 0) -or
                  ($v -is [string] -and $v -ne '')
        if (-not $truthy) { continue }
        $sentence = & $kv.Value $v
        if ($sentence) { $out.Add($sentence) }
    }
    return $out.ToArray()
}

function Get-TcpkSeverityAudit {
<#
.SYNOPSIS
    Report raw vs. adjusted severity counts across a set of findings.

.DESCRIPTION
    Parses each finding's AdjustmentLog for "CAP*: {ID} {FROM}->{TO}" entries
    to reconstruct the pre-adjustment severity.  Returns raw and adjusted counts
    per severity level plus a flat list of all adjustment records.

.OUTPUTS
    [PSCustomObject] with RawCounts, AdjustedCounts, Adjustments, Total
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings)

    begin { $all = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($f in $Findings) { if ($f) { $all.Add($f) } } }
    end {
        $sevLevels = @('INFO','LOW','MEDIUM','HIGH','CRITICAL')
        $raw = @{}; $adj = @{}
        foreach ($s in $sevLevels) { $raw[$s] = 0; $adj[$s] = 0 }
        $recs = [System.Collections.Generic.List[object]]::new()

        foreach ($f in $all) {
            $effective = "$($f.Severity)"
            $adj[$effective]++
            # Walk AdjustmentLog to find the FIRST (original) severity
            $original = $effective
            foreach ($entry in @($f.AdjustmentLog)) {
                if ($entry -match 'CAP\d+: \S+ (\w+)->(\w+)') {
                    $original = $Matches[1]  # first log entry = original proposed severity
                    $recs.Add([pscustomobject]@{
                        RuleId = "$($f.RuleId)"
                        From   = $Matches[1]
                        To     = $Matches[2]
                        Entry  = $entry
                    })
                    break
                }
            }
            $raw[$original]++
        }

        return [pscustomobject]@{
            RawCounts      = $raw
            AdjustedCounts = $adj
            Adjustments    = $recs.ToArray()
            Total          = $all.Count
        }
    }
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
