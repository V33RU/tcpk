#requires -Version 5.1
# v2.0.0: tests for the autonomous agent (loop primitives + read-only toolset + the
# discovery-only web routes) and the ldap/clipboard sink-map false-positive fixes.
# No LLM and no compiled DLL are needed -- the deterministic pieces are unit-testable.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Agent: JSON-action parser' {
    It 'parses a fenced JSON tool action' {
        InModuleScope TCPK {
            $c = @'
```json
{"tool":"list_sink_methods","args":{}}
```
'@
            (ConvertFrom-TcpkAgentAction $c).tool | Should -Be 'list_sink_methods'
        }
    }
    It 'extracts a final action from surrounding prose' {
        InModuleScope TCPK {
            (ConvertFrom-TcpkAgentAction 'Here it is: {"final":{"summary":"done"}} thanks').final.summary | Should -Be 'done'
        }
    }
    It 'returns null on non-JSON' {
        InModuleScope TCPK { ConvertFrom-TcpkAgentAction 'no json here' | Should -BeNullOrEmpty }
    }
}

Describe 'Agent: read-only toolset + dedup' {
    It 'exposes only read/analyze tools (no exploit/poc tool)' {
        InModuleScope TCPK {
            $names = @((Get-TcpkAgentTools).name)
            $names | Should -Contain 'list_sink_methods'
            $names | Should -Contain 'inspect_method'
            $names | Should -Contain 'submit_finding'
            $names | Should -Contain 'finish'
            @($names | Where-Object { $_ -match '(?i)exploit|poc|payload|write|delete' }).Count | Should -Be 0
        }
    }
    It 'submit_finding records once, then dedupes the same method' {
        InModuleScope TCPK {
            $ctx = @{ PrimaryDll='Z:\nope.dll'; SinkCache=$null;
                      Findings=(New-Object 'System.Collections.Generic.List[object]')
                      Inspected=(New-Object 'System.Collections.Generic.HashSet[string]')
                      Submitted=(New-Object 'System.Collections.Generic.HashSet[string]'); Done=$false }
            $a = [pscustomobject]@{ method='A.B::M'; severity='high'; title='t'; rationale='r' }
            (Invoke-TcpkAgentTool -Name 'submit_finding' -ToolArgs $a -Ctx $ctx).recorded | Should -Be $true
            (Invoke-TcpkAgentTool -Name 'submit_finding' -ToolArgs $a -Ctx $ctx).recorded | Should -Be $false
            $ctx.Findings.Count | Should -Be 1
        }
    }
    It 'finish ends the loop' {
        InModuleScope TCPK {
            $ctx = @{ Done=$false; Summary='' }
            Invoke-TcpkAgentTool -Name 'finish' -ToolArgs ([pscustomobject]@{ summary='all done' }) -Ctx $ctx | Out-Null
            $ctx.Done | Should -Be $true
            $ctx.Summary | Should -Be 'all done'
        }
    }
}

Describe 'Agent: web routes are discovery-only + auth-gated' {
    BeforeAll {
        $script:st = @{ Token='t'; Port=9; Version='2.0.0'; Stop=$false; Jobs=@{}; AgentJobs=@{}; Psd1='x'; ChkTotal=90 }
    }
    It 'rejects a cloud provider for the autonomous agent (local-only)' {
        InModuleScope TCPK -Parameters @{ st = $st } {
            param($st)
            $req=@{ Method='POST'; Path='/api/agent/auto'; Query=@{}; Headers=@{ host='127.0.0.1:9'; 'x-tcpk-token'='t' }; Body='{"target":"C:\\Windows","provider":"openai"}' }
            (Invoke-TcpkAgenticApi -Request $req -State $st).Status | Should -Be 400
        }
    }
    It 'rejects an invalid target' {
        InModuleScope TCPK -Parameters @{ st = $st } {
            param($st)
            $req=@{ Method='POST'; Path='/api/agent/auto'; Query=@{}; Headers=@{ host='127.0.0.1:9'; 'x-tcpk-token'='t' }; Body='{"target":"Z:\\nope"}' }
            (Invoke-TcpkAgenticApi -Request $req -State $st).Status | Should -Be 400
        }
    }
    It '404s an unknown agent job' {
        InModuleScope TCPK -Parameters @{ st = $st } {
            param($st)
            $req=@{ Method='GET'; Path='/api/agent/auto-status'; Query=@{job='nope'}; Headers=@{ host='127.0.0.1:9'; 'x-tcpk-token'='t' }; Body='' }
            (Invoke-TcpkAgenticApi -Request $req -State $st).Status | Should -Be 404
        }
    }
    It 'requires the session token on agent routes' {
        InModuleScope TCPK -Parameters @{ st = $st } {
            param($st)
            $req=@{ Method='GET'; Path='/api/agent/modules'; Query=@{target='C:\Windows'}; Headers=@{ host='127.0.0.1:9'; 'x-tcpk-token'='WRONG' }; Body='' }
            (Invoke-TcpkAgenticApi -Request $req -State $st).Status | Should -Be 401
        }
    }
}

Describe 'FP fix: ldap / clipboard sinks are namespace-qualified' {
    It 'ldap-query IL sink requires System.DirectoryServices (no bare DirectoryEntry)' {
        InModuleScope TCPK {
            $t = @((Get-TcpkCallsiteSinkMap)['ldap-query'].Sinks | ForEach-Object { "$($_.T)" })
            @($t | Where-Object { $_ -eq 'DirectoryEntry' }).Count | Should -Be 0
            ($t -join ' ') | Should -Match 'System\.DirectoryServices'
        }
    }
    It 'clipboard-access type sink is namespace-qualified (no bare Clipboard)' {
        InModuleScope TCPK {
            $t = @((Get-TcpkCallsiteSinkMap)['clipboard-access'].Sinks | Where-Object { -not $_.Mo } | ForEach-Object { "$($_.T)" })
            @($t | Where-Object { $_ -eq 'Clipboard' }).Count | Should -Be 0
            ($t -join ' ') | Should -Match 'System\.Windows'
        }
    }
    It 'secrets.json ldap-query no longer string-matches bare DirectoryEntry' {
        InModuleScope TCPK {
            $rule = @((Get-TcpkData).callsite_patterns | Where-Object { $_.id -eq 'ldap-query' })[0]
            $rule.patterns | Should -Not -Contain 'DirectoryEntry'
            $rule.patterns | Should -Contain 'System.DirectoryServices'
        }
    }
}
