#requires -Version 5.1
# Pester 5: LLM Stage-2 wiring into Invoke-TcpkAudit. Deterministic only - no network
# calls (does not require a reachable backend). Verifies the opt-in switches exist and
# the local-only cloud gate classifies providers correctly.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Invoke-TcpkAudit LLM opt-in' {
    It 'exposes -EnableLlm and -AllowCloudLlm' {
        $p = (Get-Command Invoke-TcpkAudit).Parameters
        $p.ContainsKey('EnableLlm')     | Should -BeTrue
        $p.ContainsKey('AllowCloudLlm') | Should -BeTrue
        $p['EnableLlm'].SwitchParameter     | Should -BeTrue
        $p['AllowCloudLlm'].SwitchParameter | Should -BeTrue
    }
}

Describe 'LLM local-only cloud gate' {
    It 'classifies the default (ollama) provider as NOT cloud' {
        $isCloud = & (Get-Module TCPK) { Test-TcpkLlmIsCloud }
        $isCloud | Should -BeFalse
    }
    It 'knows ollama is local and claude/openai/deepseek are cloud' {
        $r = & (Get-Module TCPK) {
            [pscustomobject]@{
                ollama   = $script:TcpkLlmProviders['ollama'].cloud
                claude   = $script:TcpkLlmProviders['claude'].cloud
                openai   = $script:TcpkLlmProviders['openai'].cloud
                deepseek = $script:TcpkLlmProviders['deepseek'].cloud
            }
        }
        $r.ollama   | Should -BeFalse
        $r.claude   | Should -BeTrue
        $r.openai   | Should -BeTrue
        $r.deepseek | Should -BeTrue
    }
}
