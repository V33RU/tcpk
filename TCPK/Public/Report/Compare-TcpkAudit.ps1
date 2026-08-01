function Compare-TcpkAudit {
<#
.SYNOPSIS
    Diff two TCPK audits: what is NEW, FIXED, REGRESSED, or unchanged since a baseline.

.DESCRIPTION
    Re-tests are the common case: you audited an app, the vendor shipped a fix, you
    audit again. Compare-TcpkAudit takes the two findings.json files (or the two
    output directories that contain them) and reports the delta at the
    (RuleId + location) granularity -- so an aggregated finding that covered 6 files
    is compared file-by-file:

      NEW       present now, absent in the baseline   (a regression or fresh issue)
      FIXED     present in the baseline, absent now   (remediated)
      REGRESSED same location, higher severity now    (got worse)
      unchanged present in both at the same severity

    Returns a delta object; with -OutFile it also writes a plain-text Markdown
    delta report (pure ASCII) suitable for a re-test summary.

.PARAMETER BaselinePath
    The earlier audit: a findings.json file, or a directory containing findings.json.

.PARAMETER CurrentPath
    The later audit: a findings.json file, or a directory containing findings.json.

.PARAMETER OutFile
    Optional path to write a Markdown delta report to.

.PARAMETER NormalizePaths
    Compare locations RELATIVE to each run's own install root instead of by absolute path.

    Without this, two builds installed to different directories -- which is the normal case
    for a version-to-version retest, e.g. C:\App 1.2\lib\a.dll versus C:\App 1.3\lib\a.dll
    -- share no location string, so every finding reports as one FIXED plus one NEW and the
    delta is useless. With it, the longest common directory prefix of each side is stripped
    first, so the same file lines up across versions.

    Off by default so existing behaviour is unchanged. Use it whenever the two runs are of
    the same application from different paths; leave it off when comparing runs of the same
    installed directory, where absolute paths already match.

.OUTPUTS
    [pscustomobject] with New / Fixed / Regressed arrays, UnchangedCount, and Summary.

.EXAMPLE
    Compare-TcpkAudit .\out-v1 .\out-v2 -OutFile .\delta.md

.EXAMPLE
    Compare-TcpkAudit .\out-1.2 .\out-1.3 -NormalizePaths
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$BaselinePath,
        [Parameter(Mandatory, Position = 1)][string]$CurrentPath,
        [string]$OutFile,
        [switch]$NormalizePaths
    )

    # Longest common directory prefix of a run's locations. Used only when -NormalizePaths
    # is set. Returns '' when there is nothing shared, which leaves locations untouched.
    $commonRoot = {
        param($list)
        $paths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($f in $list) {
            if (-not $f) { continue }
            if ($f.PSObject.Properties.Name -contains 'Affected' -and $f.Affected) {
                foreach ($a in @($f.Affected)) { if ("$a" -match '[\\/]') { $paths.Add("$a") } }
            } elseif ($f.File -and "$($f.File)" -match '[\\/]') { $paths.Add("$($f.File)") }
        }
        if ($paths.Count -eq 0) { return '' }
        $split = @($paths | ForEach-Object { , ($_ -split '[\\/]') })
        $min = ($split | ForEach-Object { $_.Count } | Measure-Object -Minimum).Minimum
        $common = New-Object 'System.Collections.Generic.List[string]'
        for ($i = 0; $i -lt ($min - 1); $i++) {
            $seg = $split[0][$i]
            $allSame = $true
            foreach ($s in $split) { if ($s[$i] -ne $seg) { $allSame = $false; break } }
            if (-not $allSame) { break }
            $common.Add($seg)
        }
        if ($common.Count -eq 0) { return '' }
        return (($common -join '\') + '\')
    }

    $resolve = {
        param($p)
        if (Test-Path -LiteralPath $p -PathType Leaf) { return (Resolve-Path -LiteralPath $p).Path }
        $j = Join-Path $p 'findings.json'
        if (Test-Path -LiteralPath $j) { return (Resolve-Path -LiteralPath $j).Path }
        throw "No findings.json found at: $p"
    }
    $load = {
        param($p)
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $data = $raw | ConvertFrom-Json
        if ($null -eq $data) { return @() }
        if ($data -is [System.Array]) { return @($data) }
        if ($data.PSObject.Properties.Name -contains 'findings') { return @($data.findings) }
        return @($data)
    }

    $bPath = & $resolve $BaselinePath
    $cPath = & $resolve $CurrentPath
    $base  = & $load $bPath
    $cur   = & $load $cPath

    $sevRank = @{ INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4 }

    # (RuleId + location) -> compact entry. Aggregated findings (Affected[]) expand
    # so a fix to one of several affected files is detected.
    $entries = {
        param($list, $root)
        $m = [ordered]@{}
        foreach ($f in $list) {
            if (-not $f) { continue }
            $locs = @()
            if ($f.PSObject.Properties.Name -contains 'Affected' -and $f.Affected -and @($f.Affected).Count) { $locs = @($f.Affected) }
            elseif ($f.File) { $locs = @("$($f.File)") }
            else { $locs = @('(global)') }
            foreach ($loc in $locs) {
                # Key on the location relative to this run's own root when normalising, so
                # the same file in two differently-named install directories matches.
                $keyLoc = "$loc"
                if ($root -and $keyLoc.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                    $keyLoc = $keyLoc.Substring($root.Length)
                }
                $k = "$($f.RuleId)|$keyLoc"
                if (-not $m.Contains($k)) {
                    $m[$k] = [pscustomobject]@{
                        Key        = $k
                        RuleId     = "$($f.RuleId)"
                        Location   = "$loc"
                        Severity   = "$($f.Severity)"
                        Confidence = "$($f.Confidence)"
                        Title      = "$($f.Title)"
                    }
                }
            }
        }
        return $m
    }

    $bRoot = ''; $cRoot = ''
    if ($NormalizePaths) {
        $bRoot = & $commonRoot $base
        $cRoot = & $commonRoot $cur
        Write-Verbose "Compare-TcpkAudit: normalising paths. baseline root '$bRoot', current root '$cRoot'"
    }
    $bMap = & $entries $base $bRoot
    $cMap = & $entries $cur  $cRoot

    $new = @(); $fixed = @(); $regressed = @(); $unchanged = 0
    foreach ($k in $cMap.Keys) {
        if (-not $bMap.Contains($k)) { $new += $cMap[$k]; continue }
        $unchanged++
        $bs = $sevRank["$($bMap[$k].Severity)"]; $cs = $sevRank["$($cMap[$k].Severity)"]
        if ($null -ne $bs -and $null -ne $cs -and $cs -gt $bs) {
            $regressed += [pscustomobject]@{
                Key = $k; RuleId = $cMap[$k].RuleId; Location = $cMap[$k].Location
                From = $bMap[$k].Severity; To = $cMap[$k].Severity; Title = $cMap[$k].Title
            }
        }
    }
    foreach ($k in $bMap.Keys) { if (-not $cMap.Contains($k)) { $fixed += $bMap[$k] } }

    $bySev = { param($x) $x | Sort-Object @{ E = { $sevRank["$($_.Severity)"] }; Descending = $true }, RuleId }
    $new   = @(& $bySev $new)
    $fixed = @(& $bySev $fixed)

    $summary = "+$($new.Count) new, -$($fixed.Count) fixed, $($regressed.Count) regressed, $unchanged unchanged"

    if ($OutFile) {
        $L = New-Object 'System.Collections.Generic.List[string]'
        $w = { param($t = '') $L.Add([string]$t) }
        & $w "# TCPK Audit Delta"
        & $w ""
        & $w "- Baseline: ``$bPath``"
        & $w "- Current:  ``$cPath``"
        & $w "- Summary:  $summary"
        & $w ""
        & $w "## New ($($new.Count))"
        & $w ""
        if ($new.Count) { foreach ($e in $new) { & $w "- **[$($e.Severity)]** ``$($e.RuleId)`` -- $($e.Title)`n  - $($e.Location)" } } else { & $w "_none_" }
        & $w ""
        & $w "## Regressed ($($regressed.Count))"
        & $w ""
        if ($regressed.Count) { foreach ($e in $regressed) { & $w "- ``$($e.RuleId)`` $($e.From) -> **$($e.To)** -- $($e.Title)`n  - $($e.Location)" } } else { & $w "_none_" }
        & $w ""
        & $w "## Fixed ($($fixed.Count))"
        & $w ""
        if ($fixed.Count) { foreach ($e in $fixed) { & $w "- [$($e.Severity)] ``$($e.RuleId)`` -- $($e.Title)`n  - $($e.Location)" } } else { & $w "_none_" }
        & $w ""
        & $w "Unchanged: $unchanged"
        Confirm-TcpkParentDir -FilePath $OutFile
        [IO.File]::WriteAllText($OutFile, (($L -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
        Write-TcpkInfo "Delta report written: $OutFile ($summary)"
    }

    [pscustomobject]@{
        Baseline       = $bPath
        Current        = $cPath
        New            = $new
        Fixed          = $fixed
        Regressed      = @($regressed)
        UnchangedCount = $unchanged
        Summary        = $summary
    }
}
