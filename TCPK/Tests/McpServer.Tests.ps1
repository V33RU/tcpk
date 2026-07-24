#requires -Version 5.1
# Pester 5: the MCP server's JSON-RPC surface (Start-TcpkMcpServer.ps1).
# The server speaks newline-delimited JSON-RPC 2.0 over stdio, so these tests drive it as a
# real child process: write requests to stdin, parse the responses off stdout. One process
# spawn covers every case (module import makes each launch slow), so BeforeAll sends the
# whole batch and the It blocks assert on individual response ids.

BeforeAll {
    $root = Split-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) -Parent
    $script:Server = Join-Path $root 'Start-TcpkMcpServer.ps1'
    $script:Cecil  = Join-Path $root 'tools\ILSpy\Mono.Cecil.dll'

    # A synthetic "completed audit" outDir: findings.json in the shape Invoke-TcpkAudit writes.
    $script:OutDir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-mcp-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null
    @(
        [ordered]@{ Severity = 'HIGH'; Confidence = 'Confirmed (IL)'; RuleId = 'tls.accept-all-certs'
                    Title = 'TLS cert validation accepts ALL certificates'; File = 'App.dll'
                    Evidence = 'callback returns true'; Description = 'd'; Cwe = @('CWE-295') }
        [ordered]@{ Severity = 'LOW'; Confidence = 'Inferred'; RuleId = 'pe.no-aslr'
                    Title = 'DLL without ASLR'; File = 'legacy.dll'
                    Evidence = 'DYNAMICBASE missing'; Description = 'd'; Cwe = @('CWE-119') }
    ) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $script:OutDir 'findings.json') -Encoding UTF8

    $reqs = @(
        @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{} }
        @{ jsonrpc = '2.0'; id = 2; method = 'tools/list'; params = @{} }
        @{ jsonrpc = '2.0'; id = 3; method = 'tools/call'; params = @{ name = 'tcpk_get_findings'; arguments = @{ outDir = $script:OutDir } } }
        @{ jsonrpc = '2.0'; id = 4; method = 'tools/call'; params = @{ name = 'tcpk_get_findings'; arguments = @{ outDir = $script:OutDir; severity = 'HIGH' } } }
        @{ jsonrpc = '2.0'; id = 5; method = 'tools/call'; params = @{ name = 'tcpk_generate_poc'; arguments = @{ module = 'New-TcpkFridaTlsBypass' } } }
        @{ jsonrpc = '2.0'; id = 6; method = 'tools/call'; params = @{ name = 'tcpk_not_a_real_tool'; arguments = @{} } }
        @{ jsonrpc = '2.0'; id = 7; method = 'tools/call'; params = @{ name = 'tcpk_decompile'; arguments = @{ dll = $script:Cecil; method = 'Mono.Cecil.AssemblyDefinition::get_Name' } } }
        @{ jsonrpc = '2.0'; id = 8; method = 'tools/call'; params = @{ name = 'tcpk_recon_profile'; arguments = @{} } }
        @{ jsonrpc = '2.0'; id = 9; method = 'tools/call'; params = @{ name = 'tcpk_decompile'; arguments = @{ dll = $script:Cecil } } }
        # id 10: the gate must NOT open when 'authorized' arrives as the STRING "false"
        # (a JSON boolean coerced to a string) -- [bool]"false" is $true, the bug the gate hardening fixes.
        @{ jsonrpc = '2.0'; id = 10; method = 'tools/call'; params = @{ name = 'tcpk_generate_poc'; arguments = @{ module = 'New-TcpkFridaTlsBypass'; authorized = 'false' } } }
        # id 11: a dir with NO findings.json must return zero findings, not one blank phantom.
        @{ jsonrpc = '2.0'; id = 11; method = 'tools/call'; params = @{ name = 'tcpk_get_findings'; arguments = @{ outDir = ([IO.Path]::GetTempPath()) } } }
    )
    $script:ReqCount = @($reqs).Count
    $reqFile = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-mcp-req-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.jsonl')
    ($reqs | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 10 }) | Set-Content -LiteralPath $reqFile -Encoding UTF8

    # stderr carries the server's diagnostics; swallow it so it is not treated as failure.
    $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $raw = Get-Content -LiteralPath $reqFile | & powershell -NoProfile -ExecutionPolicy Bypass -File $script:Server 2>$null
    $ErrorActionPreference = $prevEap
    Remove-Item -LiteralPath $reqFile -Force -ErrorAction SilentlyContinue

    $script:R = @{}
    foreach ($line in @($raw)) {
        if (-not "$line".Trim().StartsWith('{')) { continue }
        $o = $null; try { $o = $line | ConvertFrom-Json } catch { continue }
        if ($null -ne $o.id) { $script:R["$($o.id)"] = $o }
    }
}

AfterAll {
    if ($script:OutDir -and (Test-Path -LiteralPath $script:OutDir)) {
        Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'MCP protocol handshake' {
    It 'answers every request in the batch' {
        # compare against what was actually sent, so adding a request never breaks this
        @($script:R.Keys).Count | Should -Be $script:ReqCount
    }
    It 'initialize returns a protocol version and serverInfo' {
        $r = $script:R['1'].result
        $r.protocolVersion | Should -Not -BeNullOrEmpty
        $r.serverInfo.name | Should -Be 'tcpk'
        $r.serverInfo.version | Should -Not -BeNullOrEmpty
    }
}

Describe 'tools/list' {
    It 'advertises the decompiler tools alongside the audit tools' {
        $names = @($script:R['2'].result.tools | ForEach-Object { $_.name })
        $names | Should -Contain 'tcpk_list_modules'
        $names | Should -Contain 'tcpk_decompile'
        $names | Should -Contain 'tcpk_audit'
        $names | Should -Contain 'tcpk_get_findings'
    }
    It 'gives every tool a description and an inputSchema' {
        foreach ($t in @($script:R['2'].result.tools)) {
            $t.description | Should -Not -BeNullOrEmpty
            $t.inputSchema.type | Should -Be 'object'
        }
    }
    It 'annotates the gated PoC tool as destructive and the rest as read-only' {
        $tools = @($script:R['2'].result.tools)
        $destructive = @($tools | Where-Object { $_.annotations.destructiveHint } | ForEach-Object { $_.name })
        $destructive | Should -Be @('tcpk_generate_poc')
        ($tools | Where-Object { $_.name -eq 'tcpk_generate_poc' }).annotations.readOnlyHint | Should -BeFalse
        ($tools | Where-Object { $_.name -eq 'tcpk_decompile' }).annotations.readOnlyHint | Should -BeTrue
    }
    It 'flags only the CVE tool as reaching the network' {
        $net = @($script:R['2'].result.tools | Where-Object { $_.annotations.openWorldHint } | ForEach-Object { $_.name })
        $net | Should -Be @('tcpk_cve_match')
    }
}

Describe 'tcpk_get_findings is enriched by the intel model' {
    It 'returns the computed CVSS / CWE / TASVS / verify-hint, not just the raw finding' {
        $d = $script:R['3'].result.content[0].text | ConvertFrom-Json
        $script:R['3'].result.isError | Should -BeFalse
        $d.total | Should -Be 2
        $top = $d.findings[0]
        $top.sev  | Should -Be 'HIGH'          # intel model sorts most-severe first
        $top.rule | Should -Be 'tls.accept-all-certs'
        $top.cvss | Should -Match '^\d+\.\d'   # e.g. "8.5 (High) CVSS:4.0/..."
        $top.cvss | Should -Match 'CVSS:4\.0'
        $top.verify | Should -Not -BeNullOrEmpty
        $top.tasvs  | Should -Not -BeNullOrEmpty
    }
    It 'applies the severity filter against the enriched shape' {
        $d = $script:R['4'].result.content[0].text | ConvertFrom-Json
        $d.count | Should -Be 1
        $d.findings[0].rule | Should -Be 'tls.accept-all-certs'
    }
}

Describe 'tcpk_decompile returns real IL' {
    # Regression guard: the shared engine returns the sink list as 'interesting' and uses
    # 'methods' for a COUNT. The MCP layer republishes it with self-describing names so an
    # agent reading the schema finds the list where the description says it is.
    It 'lists sink-bearing methods under a self-describing sinkMethods array' {
        $d = $script:R['9'].result.content[0].text | ConvertFrom-Json
        $script:R['9'].result.isError | Should -BeFalse
        $d.PSObject.Properties['sinkMethods']     | Should -Not -BeNullOrEmpty
        $d.PSObject.Properties['sinkMethodCount'] | Should -Not -BeNullOrEmpty
        $d.PSObject.Properties['typeCount']       | Should -Not -BeNullOrEmpty
        $d.PSObject.Properties['methodCount']     | Should -Not -BeNullOrEmpty
        # the ambiguous engine field names must NOT leak through this API
        $d.PSObject.Properties['interesting']     | Should -BeNullOrEmpty
        $d.typeCount   | Should -BeGreaterThan 0
        $d.methodCount | Should -BeGreaterThan 0
        $listed = if ($null -eq $d.sinkMethods) { 0 } else { @($d.sinkMethods).Count }
        $listed | Should -Be $d.sinkMethodCount
    }

    It 'disassembles a named method with per-instruction sink flags' {
        $d = $script:R['7'].result.content[0].text | ConvertFrom-Json
        $script:R['7'].result.isError | Should -BeFalse
        $d.method | Should -Be 'Mono.Cecil.AssemblyDefinition::get_Name'
        @($d.il).Count | Should -BeGreaterThan 0
        $d.il[0].off | Should -Match '^IL_[0-9A-F]{4}$'
        $d.il[0].PSObject.Properties['sink'] | Should -Not -BeNullOrEmpty
    }
}

Describe 'safety + error handling' {
    It 'refuses the gated PoC generator without authorized=true' {
        $script:R['5'].result.isError | Should -BeTrue
        "$($script:R['5'].result.content[0].text)" | Should -Match 'authorized'
    }
    It 'does NOT open the gate when authorized arrives as the string "false"' {
        # regression: [bool]"false" is $true, so a mistyped/quoted boolean must not bypass the gate
        $script:R['10'].result.isError | Should -BeTrue
        "$($script:R['10'].result.content[0].text)" | Should -Match 'authorized'
    }
    It 'returns zero findings (no phantom blank) when findings.json is absent' {
        $d = $script:R['11'].result.content[0].text | ConvertFrom-Json
        $script:R['11'].result.isError | Should -BeFalse
        $d.total | Should -Be 0
        $d.count | Should -Be 0
    }
    It 'reports an unknown tool as an error instead of crashing' {
        $script:R['6'].result.isError | Should -BeTrue
        "$($script:R['6'].result.content[0].text)" | Should -Match 'Unknown tool'
    }
    It 'reports a missing required argument as an error instead of crashing' {
        $script:R['8'].result.isError | Should -BeTrue
        "$($script:R['8'].result.content[0].text)" | Should -Match 'target'
    }
}
