#requires -Version 5.1
# Pester 5 regression guard for the unified autonomous flow (Invoke-TcpkAgentRun). Recon and the
# full audit are MOCKED so the orchestration logic is tested without running a real audit:
#   - all five stages run in order and narrate into one transcript (observe/plan/run/triage/report)
#   - the deterministic breadth comes from Invoke-TcpkAudit; the agent only plans/triages/narrates
#   - a lead no tool can prove is HELD (the no-hallucination contract carries through)
#   - the -Acknowledge gate skips the audit entirely

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Invoke-TcpkAgentRun is exported' {
    It 'is a public cmdlet' {
        Get-Command Invoke-TcpkAgentRun -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Unified flow: recon -> plan -> run -> triage -> report' {
    It 'runs every stage and returns the unified shape' {
        $r = InModuleScope TCPK {
            Mock Get-TcpkAppIdentity {
                [pscustomobject]@{ Name='App'; Version='1.0'; AppType='thick-client'; Runtime='.NET';
                                   Architecture='x64'; Managed=$true; IsElectron=$false }
            }
            Mock Invoke-TcpkAudit {
                @(
                    (New-TcpkFinding -Module T -RuleId 'test.proven' -Severity HIGH -Title 'p' -Confidence 'Confirmed'),
                    (New-TcpkFinding -Module T -RuleId 'test.lead'   -Severity HIGH -Title 'l' -Confidence 'Inferred')
                )
            }
            Invoke-TcpkAgentRun -Target 'X' -Acknowledge 6>$null
        }
        $r.Profile.Managed      | Should -BeTrue
        $r.RunSummary.Findings  | Should -Be 2
        $r.RunSummary.Proven    | Should -Be 1
        $r.RunSummary.Leads     | Should -Be 1
        # The lead no tool can prove is held, never promoted.
        $r.Triage.Summary.Held  | Should -Be 1
        $r.Triage.Summary.Promoted | Should -Be 0
        # One transcript, every phase present.
        foreach ($phase in 'observe','plan','run','triage','report') {
            @($r.Transcript | Where-Object { $_.Phase -eq $phase }).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'The -Acknowledge gate skips the audit' {
    It 'does not run the audit and returns no findings without -Acknowledge' {
        $r = InModuleScope TCPK {
            Mock Get-TcpkAppIdentity { [pscustomobject]@{ Name='App'; AppType='thick'; Runtime='.NET'; Managed=$true; IsElectron=$false } }
            Mock Invoke-TcpkAudit { throw 'audit must not run without -Acknowledge' }
            Invoke-TcpkAgentRun -Target 'X' 6>$null
        }
        $r.RunSummary     | Should -Be $null
        $r.Findings.Count | Should -Be 0
        @($r.Transcript | Where-Object { $_.Message -match 'SKIPPED' }).Count | Should -BeGreaterThan 0
    }
}
