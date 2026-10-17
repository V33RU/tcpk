#requires -Version 5.1
# Pester 5 regression guard for the autonomous lead-triage agent (Invoke-TcpkTriageAgent),
# Phase 1 of the agentic engine. These pin the CONTROLLER logic deterministically -- no LLM,
# no crafted DLL (leads with unknown RuleIds have no call-site sink spec, so the IL confirmer
# passes them through unchanged, which is exactly the "no tool could prove it" path):
#   - proven findings pass through untouched; only leads are worked
#   - a lead no tool can resolve is HELD, never promoted (the no-hallucination contract)
#   - transcript has one entry per lead; counts add up; every finding is preserved
#   - the MaxSteps budget holds the remainder
# End-to-end PROMOTION via the real IL/LLM confirmers is covered by IlVerify/LlmSkeptic tests.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Invoke-TcpkTriageAgent is exported' {
    It 'is a public cmdlet' {
        Get-Command Invoke-TcpkTriageAgent -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Leads are isolated; proven findings pass straight through' {
    It 'works only the leads and preserves every finding' {
        $r = InModuleScope TCPK {
            $proven = New-TcpkFinding -Module T -RuleId 'test.proven' -Severity HIGH -Title 'p' -Confidence 'Confirmed'
            $leadA  = New-TcpkFinding -Module T -RuleId 'test.lead-a' -Severity HIGH -Title 'a' -Confidence 'Inferred'
            $leadB  = New-TcpkFinding -Module T -RuleId 'test.lead-b' -Severity HIGH -Title 'b' -Confidence 'Unverified'
            @($proven, $leadA, $leadB) | Invoke-TcpkTriageAgent 6>$null
        }
        $r.Summary.AlreadyProven | Should -Be 1
        $r.Summary.Leads         | Should -Be 2
        # The proven finding is never a triage step.
        @($r.Transcript | Where-Object { $_.RuleId -eq 'test.proven' }).Count | Should -Be 0
        # Every input finding survives in the refined set (proven + triaged).
        $r.Findings.Count | Should -Be 3
    }
}

Describe 'A lead no tool can resolve is HELD, never promoted' {
    It 'holds unconfirmable leads (no-hallucination contract)' {
        $r = InModuleScope TCPK {
            $leadA = New-TcpkFinding -Module T -RuleId 'test.lead-a' -Severity HIGH -Title 'a' -Confidence 'Inferred'
            $leadB = New-TcpkFinding -Module T -RuleId 'test.lead-b' -Severity HIGH -Title 'b' -Confidence 'Unverified'
            @($leadA, $leadB) | Invoke-TcpkTriageAgent 6>$null
        }
        $r.Summary.Promoted | Should -Be 0
        $r.Summary.Dropped  | Should -Be 0
        $r.Summary.Held     | Should -Be 2
        $r.Held.Count       | Should -Be 2
        $r.Transcript.Count | Should -Be 2
        foreach ($t in $r.Transcript) {
            $t.Verdict | Should -Be 'HOLD'
            $t.After   | Should -Be $t.Before
        }
    }
}

Describe 'MaxSteps budget holds the remainder without running confirmers' {
    It 'runs zero confirmer steps at MaxSteps 0 and holds every lead' {
        $r = InModuleScope TCPK {
            $leadA = New-TcpkFinding -Module T -RuleId 'test.lead-a' -Severity HIGH -Title 'a' -Confidence 'Inferred'
            $leadB = New-TcpkFinding -Module T -RuleId 'test.lead-b' -Severity HIGH -Title 'b' -Confidence 'Unverified'
            @($leadA, $leadB) | Invoke-TcpkTriageAgent -MaxSteps 0 6>$null
        }
        $r.Summary.Steps | Should -Be 0
        $r.Summary.Held  | Should -Be 2
        @($r.Transcript | Where-Object { $_.Stage -eq 'none' }).Count | Should -Be 2
    }
}
