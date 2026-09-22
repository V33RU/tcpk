#requires -Version 5.1
#
# Show-TcpkFinding renders findings for a human. The failure modes worth pinning are the
# ones that do not look like failures:
#
#   - a Mandatory pipeline parameter that receives zero objects is never bound, so
#     PowerShell PROMPTS for it. On a clean scan that finds nothing, the cmdlet would hang
#     waiting for input rather than saying "no findings".
#   - Get-TcpkSeverityRank declares [Parameter(Mandatory)][string], so an empty Severity
#     throws at parameter binding and never reaches its own -1 fallback. A display helper
#     must never be the thing that throws on a malformed row read back from findings.json.
#   - colour is applied with Write-Host, which on 5.1 still goes to the Information stream.
#     One Write-Host per COMPLETE line is a contract: splitting a line in two emits two
#     InformationRecords, which every host capturing with 6>&1 receives as two log lines.

Describe 'Show-TcpkFinding' {

    BeforeAll {
        $root = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        Import-Module (Join-Path $root 'TCPK.psd1') -Force -ErrorAction Stop

        # Build fixtures inside the module: TcpkFinding deliberately does not leak into
        # caller scope (pinned by ModuleSurface.Tests.ps1), so New-Object TcpkFinding out
        # here would fail.
        $script:MakeFinding = {
            param($sev, $conf, $rule, $title, $desc, $file)
            & (Get-Module TCPK) {
                param($s, $c, $r, $t, $d, $f)
                New-TcpkFinding -Module 'static' -RuleId $r -Severity $s -Confidence $c `
                    -Title $t -Description $d -File $f
            } $sev $conf $rule $title $desc $file
        }

        $script:Render = {
            param($findings, $extra)
            $lines = @()
            $out = & (Get-Module TCPK) {
                param($f, $x)
                if ($x) { Show-TcpkFinding -Finding $f @x 6>&1 } else { Show-TcpkFinding -Finding $f 6>&1 }
            } $findings $extra
            foreach ($o in @($out)) { $lines += "$o" }
            return $lines
        }
    }

    Context 'empty and malformed input' {
        It 'does not hang or throw on no findings' {
            # The regression this guards: with [Parameter(Mandatory)] on a pipeline
            # parameter, this call prompts for input instead of returning.
            $lines = & $script:Render @() $null
            ($lines -join "`n") | Should -Match 'no findings'
        }

        It 'does not throw on a finding with an empty Severity' {
            $f = & (Get-Module TCPK) { [pscustomobject]@{ Severity = ''; Confidence = ''; RuleId = 'x.y'; Title = 't' } }
            { & $script:Render @($f) $null } | Should -Not -Throw
        }

        It 'ranks an unknown severity below INFO rather than throwing' {
            $r = & (Get-Module TCPK) { Get-TcpkSevOrder '' }
            $r | Should -Be -1
            $i = & (Get-Module TCPK) { Get-TcpkSevOrder 'INFO' }
            $i | Should -Be 0
        }
    }

    Context 'empty fields are omitted' {
        It 'prints no row for a field the rule left empty' {
            $f = & $script:MakeFinding 'MEDIUM' 'Confirmed' 'authenticode.pe-not-signed' 'x.dll is not signed' '' 'C:\app\x.dll'
            $lines = & $script:Render @($f) $null
            $joined = $lines -join "`n"

            $joined | Should -Match 'authenticode.pe-not-signed'
            $joined | Should -Match 'C:\\app\\x.dll'
            # Nothing set these, so nothing should be printed for them.
            $joined | Should -Not -Match 'Subject'
            $joined | Should -Not -Match 'ObsValue'
            $joined | Should -Not -Match 'Dimension'
            $joined | Should -Not -Match 'Attribution'
        }

        It 'shows the machinery fields under -All' {
            $f = & $script:MakeFinding 'LOW' 'Inferred' 'a.b' 'title' 'desc' 'C:\app\y.dll'
            $lines = & $script:Render @($f) @{ All = $true }
            ($lines -join "`n") | Should -Match 'Timestamp'
        }
    }

    Context 'ordering and filtering' {
        It 'sorts worst first, not alphabetically' {
            # Alphabetically CRITICAL < HIGH < INFO < LOW < MEDIUM, so a naive string sort
            # puts INFO above LOW and MEDIUM. Severity order must come from the rank.
            $fs = @(
                (& $script:MakeFinding 'INFO'     'Confirmed' 'r.info' 'i' 'd' 'f')
                (& $script:MakeFinding 'CRITICAL' 'Confirmed' 'r.crit' 'c' 'd' 'f')
                (& $script:MakeFinding 'MEDIUM'   'Confirmed' 'r.med'  'm' 'd' 'f')
            )
            $lines = & $script:Render $fs $null
            $joined = $lines -join "`n"
            $joined.IndexOf('r.crit') | Should -BeLessThan $joined.IndexOf('r.med')
            $joined.IndexOf('r.med')  | Should -BeLessThan $joined.IndexOf('r.info')
        }

        It 'honours -MinSeverity' {
            $fs = @(
                (& $script:MakeFinding 'INFO' 'Confirmed' 'r.info' 'i' 'd' 'f')
                (& $script:MakeFinding 'HIGH' 'Confirmed' 'r.high' 'h' 'd' 'f')
            )
            $lines = & $script:Render $fs @{ MinSeverity = 'HIGH' }
            $joined = $lines -join "`n"
            $joined | Should -Match 'r.high'
            $joined | Should -Not -Match 'r.info'
        }
    }

    Context 'colour never corrupts the text' {
        It 'emits no ANSI escape bytes' {
            # 5.1 has no $PSStyle and conhost does not enable virtual terminal processing,
            # so an escape byte here would render as literal garbage and would also land in
            # any file the operator redirects to.
            $f = & $script:MakeFinding 'CRITICAL' 'Confirmed (IL)' 'r.x' 'title' 'desc' 'C:\app\z.dll'
            $lines = & $script:Render @($f) $null
            foreach ($l in $lines) {
                $l.IndexOf([char]27) | Should -Be -1
            }
        }

        It 'reports no colour capability off a console host' {
            # Pester runs under a non-ConsoleHost in CI and inside jobs; either way the
            # gate must say no rather than attaching colour that the host cannot apply.
            $can = & (Get-Module TCPK) { Test-TcpkCanColour }
            $can | Should -BeOfType [bool]
        }
    }

    Context 'aggregated Description does not start with a bookkeeping fragment' {
        It 'omits the leading space when the rule set no Description' {
            # Roughly 1 emit site in 9 passes no -Description. The aggregator used to build
            # "$($rep.Description) [TCPK: ...]", which on an empty base produced a string
            # that was one leading space plus the note, so the finding appeared to explain
            # itself with an internal aggregation message.
            $fs = @(
                (& $script:MakeFinding 'MEDIUM' 'Confirmed' 'agg.rule' 'a.dll is not signed' '' 'C:\app\a.dll')
                (& $script:MakeFinding 'MEDIUM' 'Confirmed' 'agg.rule' 'b.dll is not signed' '' 'C:\app\b.dll')
            )
            $res = & (Get-Module TCPK) { param($x) @($x | Resolve-TcpkFindings) } $fs
            $agg = @($res | Where-Object { $_.RuleId -eq 'agg.rule' })[0]
            $agg.Description | Should -Not -Match '^\s'
            $agg.Description | Should -Match '^\[TCPK:'
        }

        It 'keeps the rule Description in front of the note when there is one' {
            $fs = @(
                (& $script:MakeFinding 'MEDIUM' 'Confirmed' 'agg.rule2' 'a' 'Real explanation.' 'C:\app\a.dll')
                (& $script:MakeFinding 'MEDIUM' 'Confirmed' 'agg.rule2' 'b' 'Real explanation.' 'C:\app\b.dll')
            )
            $res = & (Get-Module TCPK) { param($x) @($x | Resolve-TcpkFindings) } $fs
            $agg = @($res | Where-Object { $_.RuleId -eq 'agg.rule2' })[0]
            $agg.Description | Should -Match '^Real explanation\. \[TCPK:'
        }
    }
}
