#requires -Version 5.1
# Pester 5: LLM Stage-2 wiring into Invoke-TcpkAudit. Deterministic only - no network
# calls (does not require a reachable backend). Verifies the opt-in switches exist and
# the local-only cloud gate classifies providers correctly.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    # Deterministic baseline: Pester shares the module instance across files via
    # `& (Get-Module TCPK)`, so another file can leave a cloud provider / open gate
    # cached. Reset to local ollama so the cloud-gate classification tests are stable.
    & (Get-Module TCPK) {
        Set-TcpkLlmConfig -Provider 'ollama' -Model 'qwen2.5-coder:7b' -BaseUrl '' -ApiKey '' -Enabled $true | Out-Null
        $script:TcpkLlmCloudEnabled = $false
    }
}

AfterAll {
    # Leave a clean baseline for test files that run after this one (these tests set
    # cloud providers + open the gate to exercise the multi-provider wiring).
    & (Get-Module TCPK) {
        Set-TcpkLlmConfig -Provider 'ollama' -Model 'qwen2.5-coder:7b' -BaseUrl '' -ApiKey '' -Enabled $true | Out-Null
        $script:TcpkLlmCloudEnabled = $false
    }
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
    It 'knows ollama is local and claude/openai/gemini/grok/deepseek are cloud' {
        $r = & (Get-Module TCPK) {
            [pscustomobject]@{
                ollama   = $script:TcpkLlmProviders['ollama'].cloud
                claude   = $script:TcpkLlmProviders['claude'].cloud
                openai   = $script:TcpkLlmProviders['openai'].cloud
                gemini   = $script:TcpkLlmProviders['gemini'].cloud
                grok     = $script:TcpkLlmProviders['grok'].cloud
                deepseek = $script:TcpkLlmProviders['deepseek'].cloud
            }
        }
        $r.ollama   | Should -BeFalse
        $r.claude   | Should -BeTrue
        $r.openai   | Should -BeTrue
        $r.gemini   | Should -BeTrue
        $r.grok     | Should -BeTrue
        $r.deepseek | Should -BeTrue
    }
}

Describe 'Multi-provider / free-text model wiring' {
    It 'resolves gemini and grok to their OpenAI-compatible chat endpoints with Bearer auth' {
        $res = & (Get-Module TCPK) {
            $out = @{}
            foreach ($prov in 'gemini','grok') {
                Set-TcpkLlmConfig -Provider $prov -Model '' -BaseUrl '' -ApiKey 'sk-test' -Enabled $true | Out-Null
                $script:TcpkLlmCloudEnabled = $true
                $b = Resolve-TcpkLlmBackend
                $out[$prov] = [pscustomobject]@{
                    Dialect = $b.Dialect
                    Chat    = "$($b.BaseUrl)/chat/completions"
                    Auth    = $b.Headers['Authorization']
                }
            }
            # restore safe local default + blank key
            Set-TcpkLlmConfig -Provider 'ollama' -Model 'qwen2.5-coder:7b' -BaseUrl '' -ApiKey '' -Enabled $true | Out-Null
            [pscustomobject]$out
        }
        $res.gemini.Dialect | Should -Be 'openai'
        $res.gemini.Chat    | Should -Be 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'
        $res.gemini.Auth    | Should -Be 'Bearer sk-test'
        $res.grok.Dialect   | Should -Be 'openai'
        $res.grok.Chat      | Should -Be 'https://api.x.ai/v1/chat/completions'
        $res.grok.Auth      | Should -Be 'Bearer sk-test'
    }

    It 'lets a custom provider point at any OpenAI-compatible endpoint with a free-text model' {
        $res = & (Get-Module TCPK) {
            Set-TcpkLlmConfig -Provider 'custom' -Model 'my-local-model' -BaseUrl 'http://10.0.0.5:8000/v1' -ApiKey 'k' -Enabled $true | Out-Null
            $script:TcpkLlmCloudEnabled = $true
            $b = Resolve-TcpkLlmBackend
            Set-TcpkLlmConfig -Provider 'ollama' -Model 'qwen2.5-coder:7b' -BaseUrl '' -ApiKey '' -Enabled $true | Out-Null
            [pscustomobject]@{ Model = $b.Model; Chat = "$($b.BaseUrl)/chat/completions" }
        }
        $res.Model | Should -Be 'my-local-model'
        $res.Chat  | Should -Be 'http://10.0.0.5:8000/v1/chat/completions'
    }
}

Describe 'Cloud consent is keyed off cloud, not off needsKey' {
    # copilot is the provider where those two diverge: the proxy holds the GitHub auth so
    # no key is typed, but it forwards to GitHub so the target's code does leave the box.
    # Keying the GUI consent off needsKey meant picking copilot never set the gate,
    # Resolve-TcpkLlmBackend threw "is a cloud backend", and the GUI reported
    # Reachable=False having never opened a socket. The proxy log stayed empty, which is
    # what made it look like the proxy was broken.
    It 'copilot is a cloud provider that needs no key' {
        InModuleScope TCPK {
            $p = $script:TcpkLlmProviders['copilot']
            $p.cloud | Should -BeTrue
            $p.needsKey | Should -BeFalse
        }
    }

    It 'refuses copilot until cloud is enabled, even with no key required' {
        InModuleScope TCPK {
            $script:TcpkLlmCloudEnabled = $false
            Set-TcpkLlmConfig -Provider 'copilot' -Model 'gpt-4o' -ApiKey '' -Enabled $true | Out-Null
            { Resolve-TcpkLlmBackend } | Should -Throw -ExpectedMessage '*cloud backend*'
        }
    }

    It 'resolves copilot with NO key once cloud is enabled' {
        InModuleScope TCPK {
            $script:TcpkLlmCloudEnabled = $true
            Set-TcpkLlmConfig -Provider 'copilot' -Model 'gpt-4o' -ApiKey '' -Enabled $true | Out-Null
            $b = Resolve-TcpkLlmBackend
            $b.Provider | Should -Be 'copilot'
            $b.BaseUrl | Should -Be 'http://localhost:4141/v1'
            # no key typed, so no Authorization header is sent; the proxy supplies its own
            $b.Headers.ContainsKey('Authorization') | Should -BeFalse
            $script:TcpkLlmCloudEnabled = $false
        }
    }
}

Describe 'Get-TcpkHttpErrorText' {
    It 'returns the exception message when there is no response body' {
        InModuleScope TCPK {
            $rec = $null
            try { throw 'plain failure' } catch { $rec = $_ }
            Get-TcpkHttpErrorText $rec | Should -Match 'plain failure'
        }
    }

    It 'appends an actionable hint when the body names SAML SSO' {
        InModuleScope TCPK {
            $rec = $null
            try { throw 'Resource protected by organization SAML enforcement' } catch { $rec = $_ }
            $t = Get-TcpkHttpErrorText $rec
            $t | Should -Match 'Configure SSO'
            # the raw text must survive alongside the hint, never be replaced by it
            $t | Should -Match 'SAML enforcement'
        }
    }

    It 'does not add the hint to an unrelated failure' {
        InModuleScope TCPK {
            $rec = $null
            try { throw 'connection refused' } catch { $rec = $_ }
            Get-TcpkHttpErrorText $rec | Should -Not -Match 'Configure SSO'
        }
    }
}

Describe 'Test-TcpkLlm carries the reason' {
    It 'returns Error when the backend cannot even be resolved' {
        InModuleScope TCPK {
            $script:TcpkLlmCloudEnabled = $false
            Set-TcpkLlmConfig -Provider 'copilot' -Model 'gpt-4o' -ApiKey '' -Enabled $true | Out-Null
            $r = Test-TcpkLlm -WarningAction SilentlyContinue
            $r.Reachable | Should -BeFalse
            $r.Error | Should -Match 'cloud backend'
        }
    }
}

