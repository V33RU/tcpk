#requires -Version 5.1
# Pester 5: gated active probe - Test-TcpkTlsHandshake. Asserts the cmdlet is exported,
# refuses without Enable-TcpkExploit, and (once enabled) behaves deterministically
# against an unreachable loopback port. A full live handshake is environment-dependent
# and exercised manually.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    try { Disable-TcpkExploit | Out-Null } catch {}
}
AfterAll {
    try { Disable-TcpkExploit | Out-Null } catch {}
}

Describe 'Test-TcpkTlsHandshake (gated)' {
    It 'is exported' {
        Get-Command Test-TcpkTlsHandshake -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'refuses without Enable-TcpkExploit' {
        try { Disable-TcpkExploit | Out-Null } catch {}
        { Test-TcpkTlsHandshake -Endpoint '127.0.0.1:1' } | Should -Throw
    }
    It 'returns tls-handshake.unreachable for a dead port (no throw) once enabled' -Skip:($IsWindows -eq $false) {
        # Test-TcpkTlsHandshake uses the Windows SChannel stack; it returns early off Windows.
        Enable-TcpkExploit -Acknowledge | Out-Null
        $r = @(Test-TcpkTlsHandshake -Endpoint '127.0.0.1:9' -TimeoutMs 1500)
        ($r | Where-Object RuleId -eq 'tls-handshake.unreachable') | Should -Not -BeNullOrEmpty
    }
}

Describe 'Invoke-TcpkComProbe (gated)' {
    It 'is exported' {
        Get-Command Invoke-TcpkComProbe -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'refuses without Enable-TcpkExploit' {
        try { Disable-TcpkExploit | Out-Null } catch {}
        { Invoke-TcpkComProbe -Clsid '{00000000-0000-0000-0000-000000000000}' } | Should -Throw
    }
    It 'requires -Clsid or -ProgId once enabled' -Skip:($IsWindows -eq $false) {
        # Off Windows the cmdlet returns early (Assert-TcpkWindows) before this check,
        # so the arg-guard only fires on Windows.
        Enable-TcpkExploit -Acknowledge | Out-Null
        { Invoke-TcpkComProbe } | Should -Throw
    }
    It 'reports com.not-instantiable for a null CLSID once enabled (no throw)' -Skip:($IsWindows -eq $false) {
        # COM instantiation is Windows-only; off Windows the cmdlet skips (returns nothing).
        Enable-TcpkExploit -Acknowledge | Out-Null
        $r = @(Invoke-TcpkComProbe -Clsid '{00000000-0000-0000-0000-000000000000}' -SkipElevation)
        ($r | Where-Object RuleId -eq 'com.not-instantiable') | Should -Not -BeNullOrEmpty
    }
    It 'skips cleanly off Windows (no throw, no findings) once enabled' -Skip:($IsWindows -eq $true) {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $r = @(Invoke-TcpkComProbe -Clsid '{00000000-0000-0000-0000-000000000000}' 3>$null)
        $r.Count | Should -Be 0
    }
}

Describe 'Invoke-TcpkRpcProbe (gated)' {
    It 'is exported' {
        Get-Command Invoke-TcpkRpcProbe -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'refuses without Enable-TcpkExploit' {
        try { Disable-TcpkExploit | Out-Null } catch {}
        { Invoke-TcpkRpcProbe } | Should -Throw
    }
    It 'enumerates the local endpoint mapper once enabled (Windows)' -Skip:($IsWindows -eq $false) {
        # rpcrt4 RpcMgmtEpEltInq* is Windows-only; off Windows the cmdlet skips.
        Enable-TcpkExploit -Acknowledge | Out-Null
        $r = @(Invoke-TcpkRpcProbe)
        # A live Windows host always has RPC interfaces registered; expect a summary or a
        # graceful rpc.enum-failed, never a throw.
        ($r | Where-Object { $_.RuleId -in 'rpc.endpoints', 'rpc.local-endpoint', 'rpc.enum-failed' }) | Should -Not -BeNullOrEmpty
    }
    It 'skips cleanly off Windows (no throw, no findings) once enabled' -Skip:($IsWindows -eq $true) {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $r = @(Invoke-TcpkRpcProbe 3>$null)
        $r.Count | Should -Be 0
    }
}
