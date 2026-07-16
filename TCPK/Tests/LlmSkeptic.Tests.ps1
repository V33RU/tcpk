#requires -Version 5.1
# Pester 5/6: the adversarial N-vote skeptic (Invoke-TcpkLlmSkepticVote) and the leads-only
# triage policy of Invoke-TcpkLlmCodeJudgment. Invoke-TcpkLlm is mocked, so these run with no
# model and no network -- they prove the vote aggregation, the default-refuted-if-uncertain
# policy, the early-stop, and that a deterministic tier is never second-guessed.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Invoke-TcpkLlmSkepticVote - adversarial N-vote aggregation' {

    It 'promotes on a real majority and early-stops at the majority' {
        InModuleScope TCPK {
            Mock Invoke-TcpkLlm { [pscustomobject]@{ verdict = 'real'; confidence = 'high'; reason = 'constant true' } }
            $v = Invoke-TcpkLlmSkepticVote -System s -User u -Votes 3
            $v.Tier | Should -Be 'Confirmed (LLM)'
            $v.Real | Should -Be 2                          # majority = 2, stops as soon as locked
            Should -Invoke Invoke-TcpkLlm -Times 2 -Exactly
        }
    }

    It 'demotes on a not-real majority' {
        InModuleScope TCPK {
            Mock Invoke-TcpkLlm { [pscustomobject]@{ verdict = 'not-real'; reason = 'ceq comparison' } }
            (Invoke-TcpkLlmSkepticVote -System s -User u -Votes 3).Tier | Should -Be 'Likely-FP (LLM)'
        }
    }

    It 'treats an unparseable ($null) reply as an abstain -> never promotes' {
        InModuleScope TCPK {
            Mock Invoke-TcpkLlm { $null }
            $v = Invoke-TcpkLlmSkepticVote -System s -User u -Votes 3
            $v.Tier    | Should -Be 'Uncertain (LLM)'
            $v.Abstain | Should -Be 3
            $v.Real    | Should -Be 0
        }
    }

    It 'treats a model throw as an abstain -> never promotes' {
        InModuleScope TCPK {
            Mock Invoke-TcpkLlm { throw 'backend down' }
            (Invoke-TcpkLlmSkepticVote -System s -User u -Votes 3).Tier | Should -Be 'Uncertain (LLM)'
        }
    }

    It 'a lone real vote among abstains does not reach majority' {
        InModuleScope TCPK {
            $script:__seq = @(
                [pscustomobject]@{ verdict = 'uncertain' },
                [pscustomobject]@{ verdict = 'real'; reason = 'x' },
                [pscustomobject]@{ verdict = 'uncertain' }
            )
            $script:__i = 0
            Mock Invoke-TcpkLlm { $r = $script:__seq[$script:__i]; $script:__i++; $r }
            $v = Invoke-TcpkLlmSkepticVote -System s -User u -Votes 3
            $v.Real | Should -Be 1
            $v.Tier | Should -Be 'Uncertain (LLM)'
        }
    }

    It 'Votes=1 is a single-shot pass' {
        InModuleScope TCPK {
            Mock Invoke-TcpkLlm { [pscustomobject]@{ verdict = 'real' } }
            $v = Invoke-TcpkLlmSkepticVote -System s -User u -Votes 1
            $v.Tier | Should -Be 'Confirmed (LLM)'
            Should -Invoke Invoke-TcpkLlm -Times 1 -Exactly
        }
    }
}

Describe 'Invoke-TcpkLlmCodeJudgment - leads-only, never overrides deterministic proof' {

    It 'passes a Confirmed (IL) finding through unchanged and never calls the model' {
        InModuleScope TCPK {
            Mock Test-TcpkLlmAvailable { $true }
            Mock Test-TcpkCecilAvailable { $true }
            Mock Invoke-TcpkLlmSkepticVote { throw 'must not be called for a proven finding' }
            $f = New-TcpkFinding -Module static -RuleId 'xxe.dtd-processing-parse' -Severity HIGH -Title t -File 'x.dll' -Confidence 'Confirmed (IL)'
            $out = $f | Invoke-TcpkLlmCodeJudgment
            $out.Confidence | Should -Be 'Confirmed (IL)'
            Should -Invoke Invoke-TcpkLlmSkepticVote -Times 0 -Exactly
        }
    }

    It 'passes a non-code-construct rule through unchanged' {
        InModuleScope TCPK {
            Mock Test-TcpkLlmAvailable { $true }
            Mock Test-TcpkCecilAvailable { $true }
            $f = New-TcpkFinding -Module static -RuleId 'secrets.api-key' -Severity HIGH -Title t -File 'x.dll' -Confidence 'Inferred'
            ($f | Invoke-TcpkLlmCodeJudgment).Confidence | Should -Be 'Inferred'
        }
    }

    It 'returns findings unchanged when the LLM backend is unavailable' {
        InModuleScope TCPK {
            Mock Test-TcpkLlmAvailable { $false }
            $f = New-TcpkFinding -Module static -RuleId 'xxe.dtd-processing-parse' -Severity HIGH -Title t -File 'x.dll' -Confidence 'Inferred'
            ($f | Invoke-TcpkLlmCodeJudgment).Confidence | Should -Be 'Inferred'
        }
    }
}
