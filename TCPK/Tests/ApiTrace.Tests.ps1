#requires -Version 5.1
# Pester 5: the API-tracer parser (ConvertFrom-TcpkApiTrace) turns synthetic TCPKTRACE lines
# into api-trace.* findings; Invoke-TcpkApiTrace -OutScript writes the Frida agent; and the
# cmdlet is gated. The live frida drive (attach/spawn) is verified on the operator's Windows
# box. Parser + generate-only are cross-platform and covered here.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null
}
AfterAll { try { Disable-TcpkExploit | Out-Null } catch {} }

Describe 'ConvertFrom-TcpkApiTrace (parser)' {
    It 'maps a synthetic trace into the expected api-trace.* findings' {
        InModuleScope TCPK {
            $recs = @(
                @{ cat = 'meta'; api = 'ready' },
                @{ cat = 'crypto'; api = 'BCryptOpenAlgorithmProvider'; alg = 'RC4' },
                @{ cat = 'crypto'; api = 'CryptCreateHash'; algid = 32771 },   # 0x8003 = MD5
                @{ cat = 'crypto'; api = 'BCryptOpenAlgorithmProvider'; alg = 'AES' },
                @{ cat = 'process'; api = 'CreateProcessW'; cmd = 'cmd.exe /c whoami' },
                @{ cat = 'process'; api = 'CreateProcessW'; cmd = 'C:\App\helper.exe' },
                @{ cat = 'command'; api = 'system'; cmd = 'sh -c id' },
                @{ cat = 'file'; api = 'WriteFile'; preview = 'cfg password=hunter2 end' },
                @{ cat = 'registry'; api = 'RegSetValueExW'; name = 'ApiToken'; preview = 'xyz' },
                @{ cat = 'dpapi'; api = 'CryptProtectData' }
            )
            $tf = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-tracetest-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.log')
            $lines = $recs | ForEach-Object { 'TCPKTRACE ' + ($_ | ConvertTo-Json -Compress) }
            Set-Content -LiteralPath $tf -Value $lines
            try {
                $f = @(ConvertFrom-TcpkApiTrace -TraceFile $tf)
                $rules = $f | ForEach-Object { $_.RuleId }
                # two weak algorithms (RC4 + MD5), AES does not fire
                (@($f | Where-Object RuleId -eq 'api-trace.weak-crypto-call')).Count | Should -Be 2
                # shell command line -> MEDIUM, plain exe -> INFO
                ($f | Where-Object { $_.RuleId -eq 'api-trace.process-launch' -and $_.Severity -eq 'MEDIUM' }) | Should -Not -BeNullOrEmpty
                ($f | Where-Object { $_.RuleId -eq 'api-trace.process-launch' -and $_.Severity -eq 'INFO' }) | Should -Not -BeNullOrEmpty
                $rules | Should -Contain 'api-trace.command-exec'
                $rules | Should -Contain 'api-trace.plaintext-secret-write'
                $rules | Should -Contain 'api-trace.registry-secret-write'
                $rules | Should -Contain 'api-trace.dpapi-use'
                $rules | Should -Contain 'api-trace.summary'
            } finally { Remove-Item -LiteralPath $tf -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'does not flag strong crypto or a non-secret write' {
        InModuleScope TCPK {
            $tf = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-tracetest2-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.log')
            Set-Content -LiteralPath $tf -Value @(
                'TCPKTRACE {"cat":"crypto","api":"BCryptOpenAlgorithmProvider","alg":"AES"}',
                'TCPKTRACE {"cat":"file","api":"WriteFile","preview":"just some log text"}'
            )
            try {
                $f = @(ConvertFrom-TcpkApiTrace -TraceFile $tf)
                ($f | Where-Object RuleId -eq 'api-trace.weak-crypto-call') | Should -BeNullOrEmpty
                ($f | Where-Object RuleId -eq 'api-trace.plaintext-secret-write') | Should -BeNullOrEmpty
            } finally { Remove-Item -LiteralPath $tf -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Invoke-TcpkApiTrace (gated)' {
    It 'writes the Frida agent with -OutScript' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-agent-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.js')
        try {
            $f = @(Invoke-TcpkApiTrace -OutScript $out)
            $out | Should -Exist
            (Get-Content -LiteralPath $out -Raw) | Should -Match 'TCPKTRACE'
            ($f | Where-Object RuleId -eq 'api-trace.script-generated') | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
    It 'is gated behind Enable-TcpkExploit' {
        Disable-TcpkExploit | Out-Null
        { Invoke-TcpkApiTrace -OutScript (Join-Path ([System.IO.Path]::GetTempPath()) 'x.js') } | Should -Throw
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
}
