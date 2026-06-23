function Export-TcpkReportMarkdown {
<#
.SYNOPSIS
    Export TCPK findings as a clean Markdown report (client deliverable).

.DESCRIPTION
    A portable, plain-text Markdown report suitable for handing to a client or
    pasting into a ticket / wiki / PR. It leads with an executive summary
    (severity + evidence-tier rollup, the correlated attack paths when present,
    and the top findings), then lists findings grouped by severity carrying the
    same standards mapping as the HTML report: computed CVSS v4.0, CWE, MITRE
    ATT&CK, OWASP TASVS, and the OWASP Desktop App Top 10 (Get-TcpkOwaspDa),
    plus impact, evidence, the affected list, how-to-verify and the fix.

    Pure ASCII; internal [TCPK]/[LLM] process notes are stripped from the
    description (they are triage meta, not client-facing).

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.PARAMETER OutFile
    Path to write the .md to.

.PARAMETER Target
    Optional target string for the header (fallback if no -Profile).

.PARAMETER Profile
    Optional Get-TcpkTargetProfile output; drives the header line.

.OUTPUTS
    [string] the OutFile path.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$Target = '',
        [object]$Profile = $null
    )
    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { if ($f) { $all.Add($f) } } }
    end {
        $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
        $rank = @{ INFO=0; LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4 }
        $generatedAt = (Get-Date).ToUniversalTime().ToString('u')
        $appName = if ($Profile -and $Profile.Name) { "$($Profile.Name)" } elseif ($Target) { "$Target" } else { 'target' }

        $L = New-Object 'System.Collections.Generic.List[string]'
        function _w { param([string]$t = '') $L.Add($t) }
        $clean = { param($d) (("$d") -replace '\s*\[(?:TCPK|LLM)\b[^\]]*\]', '').Trim() }

        _w "# TCPK Security Audit Report"
        _w ""
        _w "- Target: ``$appName``"
        if ($Profile) { _w "- Version: $($Profile.Version)  |  Publisher: $($Profile.Publisher)  |  Type: $($Profile.AppType)" }
        _w "- Generated: $generatedAt UTC"
        _w "- Findings: $($all.Count)"
        _w ""

        # ---- executive summary ----
        _w "## Executive summary"
        _w ""
        _w "| Severity | Count |"
        _w "|----------|-------|"
        foreach ($s in $sevOrder) { $c = @($all | Where-Object { "$($_.Severity)" -eq $s }).Count; if ($c) { _w "| $s | $c |" } }
        _w ""
        $proven    = @($all | Where-Object { "$($_.Confidence)" -match 'Confirmed \((IL|dynamic)\)' }).Count
        $confirmed = (@($all | Where-Object { "$($_.Confidence)" -like 'Confirmed*' }).Count) - $proven
        $inferred  = @($all | Where-Object { "$($_.Confidence)" -in 'Inferred','Unverified' }).Count
        $weak      = @($all | Where-Object { "$($_.Confidence)" -like 'Likely-FP*' -or "$($_.Confidence)" -like 'Uncertain*' }).Count
        _w "Evidence grade: proven (IL/dynamic) $proven; confirmed $confirmed; inferred -- verify $inferred; likely-FP / uncertain $weak."
        _w ""

        $chains = @($all | Where-Object { "$($_.RuleId)" -like 'chain.*' -or "$($_.Module)" -eq 'chain' })
        if ($chains.Count) {
            _w "### Likely attack paths"
            _w ""
            foreach ($c in ($chains | Sort-Object @{ E = { $rank["$($_.Severity)"] }; Descending = $true })) {
                _w "- **[$($c.Severity)]** $($c.Title)"
                if ($c.Fix) { _w "  - Fix: $($c.Fix)" }
            }
            _w ""
        }

        $top = @($all | Where-Object { "$($_.Severity)" -in 'CRITICAL','HIGH' } |
                 Sort-Object @{ E = { $rank["$($_.Severity)"] }; Descending = $true } | Select-Object -First 10)
        if ($top.Count) {
            _w "### Top findings"
            _w ""
            foreach ($t in $top) { _w "- **[$($t.Severity)]** $($t.Title)  (``$($t.RuleId)``, $($t.Confidence))" }
            _w ""
        }

        # ---- findings ----
        _w "## Findings"
        $idx = 0
        foreach ($sev in $sevOrder) {
            $group = @($all | Where-Object { "$($_.Severity)" -eq $sev } |
                       Sort-Object @{ E = { if ("$($_.Confidence)" -like 'Confirmed*') { 0 } else { 1 } } }, @{ E = { "$($_.RuleId)" } })
            if (-not $group.Count) { continue }
            _w ""
            _w "### $sev ($($group.Count))"
            foreach ($f in $group) {
                $idx++
                _w ""
                _w "#### $('{0:D3}' -f $idx). $($f.Title)"
                _w ""
                _w "- Rule: ``$($f.RuleId)``  |  Confidence: $($f.Confidence)"
                $cvss = Get-TcpkCvssVector $f
                if ($cvss.Vector) {
                    $sc = if ($null -ne $cvss.Score) { ('{0:0.0} ' -f $cvss.Score) } else { '' }
                    _w "- CVSS v4.0: $sc``$($cvss.Vector)``"
                }
                if ($f.Cwe) { _w "- CWE: $((@($f.Cwe)) -join ', ')" }
                $att = (Get-TcpkAttackTechnique -RuleId $f.RuleId) -join '; '
                if ($att) { _w "- ATT&CK: $att" }
                $tas = (Get-TcpkTasvsControl -RuleId $f.RuleId | Where-Object { $_ -notmatch '^DA\d' }) -join '; '
                if ($tas) { _w "- OWASP TASVS: $tas" }
                $oda = Get-TcpkOwaspDa -RuleId $f.RuleId
                if ($oda) { _w "- OWASP Desktop Top 10: $oda" }
                $impact = Get-TcpkImpactText $f
                if ($impact) { _w "- Impact: $impact" }
                $desc = & $clean "$($f.Description)"
                if ($desc) { _w ""; _w $desc }
                if ($f.File) { _w ""; _w "- File: ``$($f.File)``" }
                if ($f.Affected -and @($f.Affected).Count) {
                    _w "- Affected ($(@($f.Affected).Count)):"
                    foreach ($a in @($f.Affected)) { _w "  - ``$a``" }
                }
                if ($f.Evidence) { _w "- Evidence: ``$($f.Evidence)``" }
                $verify = Get-TcpkVerifyHint -RuleId $f.RuleId -File $f.File -Evidence $f.Evidence
                if ($verify) { _w ""; _w "Verify:"; _w '```'; foreach ($vl in ("$verify" -split "`r?`n")) { _w $vl }; _w '```' }
                if ($f.Fix) { _w ""; _w "- Fix: $($f.Fix)" }
            }
        }

        _w ""
        _w "---"
        _w ""
        _w "DISCLAIMER -- FOR AUTHORIZED TESTING ONLY. This report was produced by TCPK for"
        _w "authorized security testing. Provided AS IS, without warranty of any kind; any"
        _w "misuse is solely the responsibility of the user."

        Confirm-TcpkParentDir -FilePath $OutFile
        [IO.File]::WriteAllText($OutFile, (($L -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
        Write-TcpkInfo "Markdown written: $OutFile ($($all.Count) findings)"
        return $OutFile
    }
}
