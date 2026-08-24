#requires -Version 5.1
# Private: per-audit COVERAGE manifest. Records, for every check, whether it actually ran,
# was skipped (quick profile), gated (no live process attached), needs elevation, is not
# implemented, or failed -- so "was this audit 100%?" is answerable instead of invisible.
# Written to coverage.json and surfaced in the HTML/Excel reports + a console summary line.

$script:TcpkCoverageStatuses = @('Ran','SkippedQuickProfile','GatedNoProcess','NeedsElevation','NotImplemented','Failed')

function Clear-TcpkCoverage {
    $script:TcpkCoverage = New-Object 'System.Collections.Generic.List[object]'
}

function Add-TcpkCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Ran','SkippedQuickProfile','GatedNoProcess','NeedsElevation','NotImplemented','Failed')][string]$Status,
        [int]$Count = 0,
        [int]$DurationMs = 0
    )
    if (-not $script:TcpkCoverage) { Clear-TcpkCoverage }
    $script:TcpkCoverage.Add([pscustomobject]@{
        name = $Name; status = $Status; count = $Count; durationMs = $DurationMs
    }) | Out-Null
}

function Get-TcpkCoverage {
    # .ToArray() (not @($list)) -- wrapping a generic List in @() throws "Argument types do
    # not match" on PS 5.1. Comma-return keeps it an array through the pipeline.
    if (-not $script:TcpkCoverage) { return @() }
    return , $script:TcpkCoverage.ToArray()
}

# Classify a check's returned findings into a coverage status. Returns 'Ran' unless the
# check emitted ONLY a Confidence='Skipped' stub (the self-skip pattern used by checks that
# need elevation or are not implemented), in which case it maps to the precise reason.
function Get-TcpkCoverageStatusFromFindings {
    [CmdletBinding()] param($Findings)
    $f = @($Findings)
    if (-not $f.Count) { return 'Ran' }
    $skipped = @($f | Where-Object { "$($_.Confidence)" -eq 'Skipped' })
    if ($skipped.Count -eq $f.Count) {
        $rid = "$($skipped[0].RuleId)"
        if ($rid -match 'not-enumerated|not-implemented')      { return 'NotImplemented' }
        if ($rid -match 'not-readable|elevat|requires-admin')  { return 'NeedsElevation' }
    }
    return 'Ran'
}

# Build the coverage manifest object (pure; no IO) so it can be unit-tested.
function New-TcpkCoverageManifest {
    [CmdletBinding()]
    param(
        [bool]$Elevated = $false,
        [string]$ProcessAttached = '',
        $AttachedPid = $null,
        [bool]$OnlineCve = $false,
        [string]$ScanProfile = 'Full',
        [string]$GeneratedAt = ''
    )
    $cov = Get-TcpkCoverage
    $totals = [ordered]@{
        ran            = @($cov | Where-Object { $_.status -eq 'Ran' }).Count
        skippedQuick   = @($cov | Where-Object { $_.status -eq 'SkippedQuickProfile' }).Count
        gated          = @($cov | Where-Object { $_.status -eq 'GatedNoProcess' }).Count
        needsElevation = @($cov | Where-Object { $_.status -eq 'NeedsElevation' }).Count
        notImplemented = @($cov | Where-Object { $_.status -eq 'NotImplemented' }).Count
        failed         = @($cov | Where-Object { $_.status -eq 'Failed' }).Count
        total          = @($cov).Count
    }
    # NB: assign the array AFTER literal construction -- a generic List inside an [ordered]@{}
    # literal throws "Argument types do not match" on PS 5.1.
    $obj = [ordered]@{
        generatedAt     = "$GeneratedAt"
        elevated        = [bool]$Elevated
        processAttached = "$ProcessAttached"
        attachedPid     = $AttachedPid
        onlineCve       = [bool]$OnlineCve
        scanProfile     = "$ScanProfile"
        totals          = $totals
    }
    $obj['checks'] = @($cov)
    [pscustomobject]$obj
}

function Save-TcpkCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dir,
        [bool]$Elevated = $false,
        [string]$ProcessAttached = '',
        $AttachedPid = $null,
        [bool]$OnlineCve = $false,
        [string]$ScanProfile = 'Full',
        [string]$GeneratedAt = ''
    )
    $obj = New-TcpkCoverageManifest -Elevated $Elevated -ProcessAttached $ProcessAttached `
        -AttachedPid $AttachedPid -OnlineCve $OnlineCve -ScanProfile $ScanProfile -GeneratedAt $GeneratedAt
    Save-TcpkJson -Value $path = Join-Path $Dir 'coverage.json'
    $obj -Path $path -Depth 6
    $path
}

# One-line console summary string (so the audit driver can print it without re-deriving).
function Get-TcpkCoverageSummaryLine {
    $m = New-TcpkCoverageManifest
    $t = $m.totals
    "Coverage: {0} ran, {1} gated (no process), {2} need elevation, {3} quick-skip, {4} not implemented, {5} failed (of {6} checks)" -f `
        $t.ran, $t.gated, $t.needsElevation, $t.skippedQuick, $t.notImplemented, $t.failed, $t.total
}

# ---------------------------------------------------------------- readiness ----
#
# Get-TcpkCoverageSummaryLine above states the NUMBERS: "238 ran, 19 gated, 3 need
# elevation...". This states what they MEAN. The distinction matters because a reader has
# to already know what "19 gated" costs them, and most do not.
#
# The failure this guards against is the one that recurs everywhere in this codebase: a
# result that looks clean because the checks that would have found something never ran. A
# packed binary makes most of the static bucket return nothing, and the report comes out
# SHORT and TIDY, which reads like good news.

function Get-TcpkReadinessLine {
<#
.SYNOPSIS
    A one-line verdict on whether an audit's coverage was good enough to trust.

.DESCRIPTION
    Reads the same coverage manifest Get-TcpkCoverageSummaryLine reports, and returns a
    state plus a short reason.

      complete    every check ran
      degraded    some checks did not run, but for reasons an operator controls: no live
                  process attached, no elevation. The result is real as far as it goes.
      unreliable  something made checks unable to SEE the target: a failed check, or a
                  scan-coverage finding reporting a packed binary or an unreadable subtree.
                  A short report here is not evidence of a clean target.

    Failed outranks gated, deliberately. A gated check is a known hole an operator opened
    by not attaching a process; a failed check is one that was expected to work and did
    not, so its silence means nothing at all.

.PARAMETER Findings
    Optional. When supplied, scan.incomplete-coverage findings are read for conditions that
    make a clean result meaningless even though every check "ran": a packed binary, a bundle
    over the extractor ceiling, a failed CVE lookup, an unreadable subtree.

.OUTPUTS
    [pscustomobject] State ('complete' | 'degraded' | 'unreliable' | 'none'), Text, Icon,
                     Ran, Total, Reasons
#>
    [CmdletBinding()]
    param([object[]]$Findings)

    $cov = @(Get-TcpkCoverage)
    if (-not $cov.Count) {
        return [pscustomobject]@{
            State = 'none'; Icon = ''; Text = 'No audit run yet.'
            Ran = 0; Total = 0; Reasons = @()
        }
    }

    $t = (New-TcpkCoverageManifest).totals
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $state = 'complete'

    if ($t.failed -gt 0) {
        $state = 'unreliable'
        $reasons.Add("$($t.failed) check(s) FAILED")
    }

    # Test-TcpkScanCoverage (A44) reports what the scan could not READ, which is a different
    # thing from a check being switched off. It emits ONE rule, scan.incomplete-coverage,
    # and encodes the reason in the severity rather than in the rule id:
    #   MEDIUM  a packed binary, an over-ceiling bundle, or a failed CVE lookup. Each
    #           invalidates a whole family of results, so a short report means nothing.
    #   LOW     an unreadable subtree, a capped text view, an exhausted check budget. A
    #           bounded gap: what was read is still real.
    #   INFO    deliberate limits only (depth caps, refused reparse points, dedup).
    # Reading the severity is therefore reading its verdict, not re-deriving one.
    $scan = @()
    if ($Findings) {
        $scan = @($Findings | Where-Object { "$($_.RuleId)" -eq 'scan.incomplete-coverage' })
    }
    $worst = ''
    foreach ($f in $scan) {
        $sv = "$($f.Severity)"
        if ($sv -eq 'MEDIUM' -or $sv -eq 'HIGH' -or $sv -eq 'CRITICAL') { $worst = 'MEDIUM'; break }
        if ($sv -eq 'LOW') { $worst = 'LOW' }
    }
    if ($worst -eq 'MEDIUM') {
        $state = 'unreliable'
        # Quote the check's own evidence rather than paraphrasing it: it already names the
        # counts (how many binaries were packed, which bundle exceeded the ceiling).
        $ev = "$(@($scan | Where-Object { "$($_.Severity)" -eq 'MEDIUM' })[0].Evidence)"
        if ($ev) { $reasons.Add($ev) } else { $reasons.Add('the scan could not read part of the target') }
    } elseif ($worst -eq 'LOW') {
        if ($state -ne 'unreliable') { $state = 'degraded' }
        $reasons.Add('part of the target was unreadable')
    }

    if ($state -ne 'unreliable') {
        if ($t.gated -gt 0)          { $state = 'degraded'; $reasons.Add("$($t.gated) skipped (no live process)") }
        if ($t.needsElevation -gt 0) { $state = 'degraded'; $reasons.Add("$($t.needsElevation) need elevation") }
        if ($t.skippedQuick -gt 0)   { $state = 'degraded'; $reasons.Add("$($t.skippedQuick) skipped by the quick profile") }
    }

    $icon = switch ($state) { 'complete' { 'OK' } 'degraded' { '!' } default { 'X' } }
    $text = switch ($state) {
        'complete'   { "complete -- all $($t.total) checks ran" }
        'degraded'   { "degraded -- " + ($reasons -join ', ') }
        default      { "unreliable -- " + ($reasons -join '; ') + ". A short report here is not evidence of a clean target." }
    }

    return [pscustomobject]@{
        State = $state; Icon = $icon; Text = $text
        Ran = [int]$t.ran; Total = [int]$t.total; Reasons = $reasons.ToArray()
    }
}

