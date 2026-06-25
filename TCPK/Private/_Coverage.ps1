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
    $path = Join-Path $Dir 'coverage.json'
    $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    $path
}

# One-line console summary string (so the audit driver can print it without re-deriving).
function Get-TcpkCoverageSummaryLine {
    $m = New-TcpkCoverageManifest
    $t = $m.totals
    "Coverage: {0} ran, {1} gated (no process), {2} need elevation, {3} quick-skip, {4} not implemented, {5} failed (of {6} checks)" -f `
        $t.ran, $t.gated, $t.needsElevation, $t.skippedQuick, $t.notImplemented, $t.failed, $t.total
}
