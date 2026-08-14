#requires -Version 5.1
# Pester 5: Get-TcpkReadinessLine.
#
# Get-TcpkCoverageSummaryLine already states the numbers. This states what they mean, and
# the distinction is the point: "238 ran, 19 gated" requires a reader to already know what
# 19 gated costs them. The case that matters most is 'unreliable', where every check ran
# and the report is still worthless because the scanners could not see the target.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Get-TcpkReadinessLine: no run' {
    It 'reports none when no check has been recorded' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            $r = Get-TcpkReadinessLine
            $r.State | Should -Be 'none'
            $r.Text | Should -Match 'No audit run yet'
        }
    }
}

Describe 'Get-TcpkReadinessLine: complete' {
    It 'reports complete when every check ran' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            1..5 | ForEach-Object { Add-TcpkCoverage -Name "Test-Check$_" -Status 'Ran' }
            $r = Get-TcpkReadinessLine
            $r.State | Should -Be 'complete'
            $r.Ran | Should -Be 5
            $r.Total | Should -Be 5
            $r.Text | Should -Match 'all 5 checks ran'
        }
    }
}

Describe 'Get-TcpkReadinessLine: degraded' {
    It 'names gated checks and how many' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            1..3 | ForEach-Object { Add-TcpkCoverage -Name "Ran$_" -Status 'Ran' }
            1..2 | ForEach-Object { Add-TcpkCoverage -Name "Gated$_" -Status 'GatedNoProcess' }
            $r = Get-TcpkReadinessLine
            $r.State | Should -Be 'degraded'
            $r.Text | Should -Match '2 skipped \(no live process\)'
        }
    }

    It 'reports elevation separately from gating' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            Add-TcpkCoverage -Name 'Ran1' -Status 'Ran'
            Add-TcpkCoverage -Name 'Elev1' -Status 'NeedsElevation'
            $r = Get-TcpkReadinessLine
            $r.State | Should -Be 'degraded'
            $r.Text | Should -Match 'need elevation'
        }
    }

    It 'reports both reasons when both apply' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            Add-TcpkCoverage -Name 'Ran1' -Status 'Ran'
            Add-TcpkCoverage -Name 'G1' -Status 'GatedNoProcess'
            Add-TcpkCoverage -Name 'E1' -Status 'NeedsElevation'
            $r = Get-TcpkReadinessLine
            $r.Reasons.Count | Should -Be 2
        }
    }
}

Describe 'Get-TcpkReadinessLine: unreliable' {
    It 'a FAILED check outranks a gated one' {
        # A gated check is a hole the operator opened by not attaching a process. A failed
        # check was expected to work and did not, so its silence means nothing at all.
        InModuleScope TCPK {
            Clear-TcpkCoverage
            Add-TcpkCoverage -Name 'Ran1' -Status 'Ran'
            Add-TcpkCoverage -Name 'G1' -Status 'GatedNoProcess'
            Add-TcpkCoverage -Name 'F1' -Status 'Failed'
            $r = Get-TcpkReadinessLine
            $r.State | Should -Be 'unreliable'
            $r.Text | Should -Match '1 check\(s\) FAILED'
        }
    }

    It 'a MEDIUM scan.incomplete-coverage makes an all-ran audit unreliable' {
        # The case the whole line exists for: every check ran, so the numbers look perfect,
        # but a packed binary meant the static bucket could not see anything.
        InModuleScope TCPK {
            Clear-TcpkCoverage
            1..9 | ForEach-Object { Add-TcpkCoverage -Name "Ran$_" -Status 'Ran' }
            $f = @([pscustomobject]@{
                RuleId = 'scan.incomplete-coverage'; Severity = 'MEDIUM'
                Evidence = 'packed=3 bigBundle=0 cveFail=0'
            })
            $r = Get-TcpkReadinessLine -Findings $f
            $r.State | Should -Be 'unreliable'
            $r.Text | Should -Match 'packed=3'
            $r.Text | Should -Match 'not evidence of a clean target'
        }
    }

    It 'quotes the check evidence rather than paraphrasing it' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            Add-TcpkCoverage -Name 'Ran1' -Status 'Ran'
            $f = @([pscustomobject]@{
                RuleId = 'scan.incomplete-coverage'; Severity = 'MEDIUM'
                Evidence = 'bundle X exceeded the extractor ceiling at 812 MB'
            })
            (Get-TcpkReadinessLine -Findings $f).Text | Should -Match 'exceeded the extractor ceiling'
        }
    }

    It 'a LOW scan.incomplete-coverage is degraded, not unreliable' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            1..4 | ForEach-Object { Add-TcpkCoverage -Name "Ran$_" -Status 'Ran' }
            $f = @([pscustomobject]@{ RuleId = 'scan.incomplete-coverage'; Severity = 'LOW'; Evidence = 'unreadable=2' })
            (Get-TcpkReadinessLine -Findings $f).State | Should -Be 'degraded'
        }
    }

    It 'an INFO scan.incomplete-coverage leaves a clean run complete' {
        # INFO means deliberate limits only (depth caps, refused reparse points, dedup).
        InModuleScope TCPK {
            Clear-TcpkCoverage
            1..4 | ForEach-Object { Add-TcpkCoverage -Name "Ran$_" -Status 'Ran' }
            $f = @([pscustomobject]@{ RuleId = 'scan.incomplete-coverage'; Severity = 'INFO'; Evidence = 'depthCap=1' })
            (Get-TcpkReadinessLine -Findings $f).State | Should -Be 'complete'
        }
    }

    It 'ignores unrelated findings entirely' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            1..4 | ForEach-Object { Add-TcpkCoverage -Name "Ran$_" -Status 'Ran' }
            $f = @([pscustomobject]@{ RuleId = 'pe.missing-mitigations'; Severity = 'CRITICAL'; Evidence = 'x' })
            (Get-TcpkReadinessLine -Findings $f).State | Should -Be 'complete'
        }
    }
}

Describe 'Get-TcpkReadinessLine: shape' {
    It 'always returns the fields the GUI reads' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            Add-TcpkCoverage -Name 'Ran1' -Status 'Ran'
            $r = Get-TcpkReadinessLine
            foreach ($k in 'State', 'Icon', 'Text', 'Ran', 'Total', 'Reasons') {
                $r.PSObject.Properties[$k] | Should -Not -BeNullOrEmpty
            }
            $r.State | Should -BeIn 'complete', 'degraded', 'unreliable', 'none'
        }
    }
}
